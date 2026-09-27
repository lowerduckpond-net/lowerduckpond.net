"""Actual durable transaction over independently observed, faulted versioned storage."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_m3_archive.storage import S3Client

from scripts import m3_11_retirement_files as files
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_archive import Archives, inventory, records
from scripts.m3_11_retirement_transaction import Retirement


class Store:
    def __init__(self) -> None:
        self.objects = {("one", "v1"): b"first archive", ("two", "v2"): b"second archive"}
        self.deletes: list[dict[str, object]] = []
        self.failure: str | None = None
        self.marker = False
        self.upload = False
        self.truncated = False


class Principal:
    def __init__(self, store: Store, *, readonly: bool) -> None:
        self.store, self.readonly = store, readonly

    def get_bucket_versioning(self, **_: object) -> dict[str, object]:
        return {"Status": "Enabled"}

    def list_objects_v2(self, **_: object) -> dict[str, object]:
        return {
            "IsTruncated": self.store.truncated,
            "Contents": [{"Key": key} for key in sorted({key for key, _ in self.store.objects})],
        }

    def list_object_versions(self, **_: object) -> dict[str, object]:
        return {
            "IsTruncated": False,
            "DeleteMarkers": [{}] if self.store.marker else [],
            "Versions": [
                {"Key": key, "VersionId": version, "IsLatest": True}
                for key, version in self.store.objects
            ],
        }

    def list_multipart_uploads(self, **_: object) -> dict[str, object]:
        return {"IsTruncated": False, "Uploads": [{}] if self.store.upload else []}

    def get_object(self, **arguments: object) -> dict[str, object]:
        raw = self.store.objects[str(arguments["Key"]), str(arguments["VersionId"])]
        return {
            "VersionId": arguments["VersionId"],
            "ContentLength": len(raw),
            "Body": io.BytesIO(raw),
        }

    def delete_object(self, **arguments: object) -> dict[str, object]:
        assert not self.readonly
        self.store.deletes.append(arguments)
        failure, self.store.failure = self.store.failure, None
        if failure == "before":
            raise ConnectionError("request interrupted")
        self.store.objects.pop((str(arguments["Key"]), str(arguments["VersionId"])), None)
        if failure == "after":
            raise ConnectionError("response lost")
        return {"VersionId": arguments["VersionId"]}


class Fixture:
    def __init__(self) -> None:
        self.store = Store()
        self.archives = Archives(
            cast(S3Client, Principal(self.store, readonly=False)),
            cast(S3Client, Principal(self.store, readonly=True)),
            "test-archives",
        )
        self.selected = [
            {
                "key": key,
                "version": version,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            for (key, version), raw in self.store.objects.items()
        ]
        self.running = True
        self.identity = "original"
        self.fail_stop = False

    def initial(self) -> dict[str, object]:
        assert self.running
        return {"identity": self.identity, "original_failure_sha256": "a" * 64}

    def freeze(self, root: Path, intent: dict[str, object]) -> None:
        assert self.identity == intent["identity"]
        self.running = False
        if self.fail_stop:
            self.fail_stop = False
            raise ConnectionError("stop response lost")

    def capture(self, root: Path, intent: dict[str, object]) -> dict[str, object]:
        value: dict[str, object] = {"archives": self.selected}
        files.record(root / "capture.json", value)
        return value

    def guard(self, root: Path, intent: dict[str, object], capture: dict[str, object]) -> None:
        if self.running or self.identity != intent["identity"]:
            raise ValueError("writer restarted or replaced")
        if read_private(root / "capture.json") != capture:
            raise ValueError("capture changed")


@pytest.fixture
def case(tmp_path: Path) -> tuple[Retirement, Fixture]:
    tmp_path.chmod(0o700)
    fixture = Fixture()
    return Retirement(tmp_path, fixture), fixture


def test_exact_retirement_is_separate_from_original_failure(
    case: tuple[Retirement, Fixture],
) -> None:
    transaction, fixture = case
    original = transaction.root.parent / "failure.json"
    files.record(original, {"original_status": "failed"})
    raw = original.read_bytes()
    plan = transaction.prepare()
    assert not fixture.running and not fixture.store.deletes
    digest = str(plan["plan_sha256"])
    result = transaction.retire(digest, acknowledge=True)
    assert result["outcome"] == "archives-retired-fixture-retained"
    assert result["qualification_authority"] == "none"
    assert len(fixture.store.deletes) == len(fixture.selected) and not fixture.store.objects
    assert all(set(call) == {"Bucket", "Key", "VersionId"} for call in fixture.store.deletes)
    assert original.read_bytes() == raw
    assert transaction.retire(digest, acknowledge=True) == result
    assert len(fixture.store.deletes) == len(fixture.selected)
    assert not (transaction.root.parent / "combined.json").exists()
    assert not (transaction.root.parent / "qualification.json").exists()


@pytest.mark.parametrize("failure", ["before", "after"])
@pytest.mark.parametrize("completed", [0, 1])
def test_each_delete_recovers_only_its_durable_pending_version(
    case: tuple[Retirement, Fixture], monkeypatch: pytest.MonkeyPatch, failure: str, completed: int
) -> None:
    transaction, fixture = case
    approved = str(transaction.prepare()["plan_sha256"])
    original_delete = fixture.archives.delete
    calls = 0

    def interrupt(row: dict[str, object]) -> None:
        nonlocal calls
        if calls == completed:
            fixture.store.failure = failure
        calls += 1
        original_delete(row)

    monkeypatch.setattr(fixture.archives, "delete", interrupt)
    with pytest.raises(ConnectionError):
        transaction.retire(approved, acknowledge=True)
    assert (transaction.root / f"delete-{completed:02d}.json").exists()
    assert not (transaction.root / f"deleted-{completed:02d}.json").exists()
    monkeypatch.setattr(fixture.archives, "delete", original_delete)
    assert transaction.retire(approved, acknowledge=True)["versions_retired"] == len(
        fixture.selected
    )
    assert len(fixture.store.deletes) == (3 if failure == "before" else 2)


@pytest.mark.parametrize(
    "change",
    [
        "foreign",
        "missing",
        "marker",
        "upload",
        "duplicate",
        "restart",
        "replacement",
        "copy",
        "intent",
    ],
)
def test_changes_before_authorization_cannot_delete(
    case: tuple[Retirement, Fixture], change: str
) -> None:
    transaction, fixture = case
    approved = str(transaction.prepare()["plan_sha256"])
    if change == "foreign":
        fixture.store.objects["foreign", "v3"] = b"unowned"
    elif change == "missing":
        fixture.store.objects.pop(("one", "v1"))
    elif change == "duplicate":
        fixture.store.objects["one", "v3"] = b"ambiguous"
    elif change in {"marker", "upload"}:
        setattr(fixture.store, change, True)
    elif change == "restart":
        fixture.running = True
    elif change == "replacement":
        fixture.identity = "replacement"
    elif change == "copy":
        (transaction.root / "archive-00.bin").write_bytes(b"changed bytes")
    else:
        (transaction.root / "preparation.json").write_bytes(b'{"changed":true}')
    with pytest.raises(ValueError):
        transaction.retire(approved, acknowledge=True)
    assert fixture.store.deletes == []
    assert not (transaction.root / "authorization.json").exists()


def test_foreign_object_after_lost_response_prevents_remaining_deletes(
    case: tuple[Retirement, Fixture],
) -> None:
    transaction, fixture = case
    approved = str(transaction.prepare()["plan_sha256"])
    fixture.store.failure = "after"
    with pytest.raises(ConnectionError):
        transaction.retire(approved, acknowledge=True)
    fixture.store.objects["foreign", "v3"] = b"unowned"
    with pytest.raises(ValueError):
        transaction.retire(approved, acknowledge=True)
    assert len(fixture.store.deletes) == 1
    assert ("foreign", "v3") in fixture.store.objects


@pytest.mark.parametrize("acknowledge,digest", [(False, "same"), (True, "b" * 64)])
def test_approval_is_for_one_exact_plan(
    case: tuple[Retirement, Fixture], acknowledge: bool, digest: str
) -> None:
    transaction, fixture = case
    prepared = transaction.prepare()
    approved = str(prepared["plan_sha256"]) if digest == "same" else digest
    with pytest.raises(ValueError, match="explicit approval"):
        transaction.retire(approved, acknowledge=acknowledge)
    assert not fixture.store.deletes


def test_interrupted_stop_and_preparation_reuse_original_intent(
    case: tuple[Retirement, Fixture],
) -> None:
    transaction, fixture = case
    fixture.fail_stop = True
    with pytest.raises(ConnectionError):
        transaction.prepare()
    raw = (transaction.root / "preparation.json").read_bytes()
    assert transaction.prepare()["stage"] == "prepared"
    assert (transaction.root / "preparation.json").read_bytes() == raw


def test_empty_preparation_directory_is_resumable(case: tuple[Retirement, Fixture]) -> None:
    transaction, _ = case
    transaction.root.mkdir(mode=0o700)
    assert transaction.prepare()["stage"] == "prepared"


@pytest.mark.parametrize("fault", ["truncated", "marker", "upload"])
def test_provider_ambiguity_rejects(fault: str) -> None:
    store = Store()
    setattr(store, fault, True)
    with pytest.raises(ValueError):
        inventory(cast(S3Client, Principal(store, readonly=True)), "test-archives")


@pytest.mark.parametrize(
    "bad",
    [
        [],
        [{}],
        [{"key": "one", "version": "v1", "size": 120 * 1024 * 1024 + 1, "sha256": "a" * 64}],
    ],
)
def test_record_bounds_reject(bad: object) -> None:
    with pytest.raises(ValueError):
        records(bad)
