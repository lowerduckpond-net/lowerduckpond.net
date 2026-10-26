"""One irreversible submission over the real bounded two-principal inventory."""

from __future__ import annotations

import hashlib
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts import m3_11_frozen_retirement as frozen
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_files import digest, record
from scripts.qualification_disposition import require_available

from .test_m3_11_retirement_transaction import Fixture as StorageFixture


class Fixture(StorageFixture):
    def __init__(self) -> None:
        super().__init__()
        self.store.objects = {("archives/example.zip", "exact-version"): b"preserved"}
        self.held = False
        self.changed = False
        self.guards = 0

    @contextmanager
    def locked(self, _plan: dict[str, object]) -> Iterator[None]:
        assert not self.held
        self.held = True
        try:
            yield
        finally:
            self.held = False

    def guard(self, _plan: dict[str, object]) -> None:  # type: ignore[override]
        assert self.held
        self.guards += 1
        if self.changed:
            raise ValueError("unchanged original evidence required")

    def before_disposition(self) -> None:
        assert self.held

    @contextmanager
    def submission(self) -> Iterator[None]:
        assert self.held
        yield


@pytest.fixture
def case(tmp_path: Path) -> tuple[frozen.FrozenRetirement, Fixture, dict[str, object]]:
    tmp_path.chmod(0o700)
    fixture = Fixture()
    value = {
        "format": frozen.FORMAT,
        "original_run": str(tmp_path),
        "producing_attempt": str(uuid.uuid7()),
        "consumer_attempt": str(uuid.uuid7()),
        "lease_id": str(uuid.uuid7()),
        "manifest_sha256": "a" * 64,
        "implementation_revision": "b" * 40,
        "fixture_sha256": "c" * 64,
        "evidence_sha256": "d" * 64,
        "retained": frozen.RETAINED,
        "archive": {
            "bucket": "test-archives",
            "key": "archives/example.zip",
            "version": "exact-version",
            "size": 9,
            "sha256": hashlib.sha256(b"preserved").hexdigest(),
        },
    }
    approval = {
        "format": frozen.AUTHORIZATION,
        "plan_sha256": digest(value),
        "approved_at": (datetime.now(UTC) - timedelta(days=10)).isoformat(),
        "approval_reference_sha256": "e" * 64,
        "acknowledge_exact_version_loss": True,
        "acknowledge_permanent_fixture_retirement": True,
        "acknowledge_separate_closeout_required": True,
    }
    return frozen.FrozenRetirement(value, fixture), fixture, approval


def test_one_exact_version_and_permanent_fixture_fence(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
) -> None:
    transaction, fixture, approval = case
    record(transaction.run / "failure.json", {"qualification": "failed"})
    original = (transaction.run / "failure.json").read_bytes()
    result = transaction.execute(approval)
    assert fixture.store.deletes == [
        {
            "Bucket": "test-archives",
            "Key": "archives/example.zip",
            "VersionId": "exact-version",
        }
    ]
    assert result["qualification_authority"] == "none"
    assert result["fixture_execution"] == "permanently-excluded"
    assert result["fixture_disposal"] == "separately-authorized-closeout-required"
    assert result["lease_released"] is result["credential_cleanup_complete"] is False
    assert (transaction.run / "failure.json").read_bytes() == original
    with pytest.raises(ValueError, match="permanently"):
        require_available(transaction.run)
    with pytest.raises(ValueError, match="no replay"):
        transaction.execute(approval)
    observation = transaction.execute(approval, reconcile_only=True)
    assert observation["version_state"] == "absent"
    assert observation["recorded_retirement"] is True
    assert len(fixture.store.deletes) == 1


@pytest.mark.parametrize("failure", ["before", "after"])
def test_lost_response_never_replays_even_when_version_still_visible(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]], failure: str
) -> None:
    transaction, fixture, approval = case
    fixture.store.failure = failure
    with pytest.raises(ConnectionError):
        transaction.execute(approval)
    with pytest.raises(ValueError, match="no replay"):
        transaction.execute(approval)
    observation = transaction.execute(approval, reconcile_only=True)
    assert observation["version_state"] == ("present" if failure == "before" else "absent")
    assert observation["recorded_retirement"] is False
    assert not (transaction.root / "absence.json").exists()
    assert not (transaction.root / "retired.json").exists()
    assert len(fixture.store.deletes) == 1


@pytest.mark.parametrize("change", ["foreign", "marker", "upload", "truncated", "guard"])
def test_no_disposition_or_mutation_when_original_readiness_fails(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]], change: str
) -> None:
    transaction, fixture, approval = case
    if change == "foreign":
        fixture.store.objects["unexpected", "version"] = b"do not delete"
    elif change == "guard":
        fixture.changed = True
    else:
        setattr(fixture.store, change, True)
    with pytest.raises(ValueError):
        transaction.execute(approval)
    assert not fixture.store.deletes and not transaction.root.exists()


@pytest.mark.parametrize(
    "key",
    [
        "plan_sha256",
        "acknowledge_exact_version_loss",
        "acknowledge_permanent_fixture_retirement",
        "acknowledge_separate_closeout_required",
        "approved_at",
    ],
)
def test_source_work_or_old_plan_is_not_execution_approval(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]], key: str
) -> None:
    transaction, fixture, approval = case
    approval[key] = "wrong" if key.endswith("sha256") else False
    with pytest.raises(ValueError):
        transaction.execute(approval)
    assert fixture.guards == 0 and not fixture.store.deletes and not transaction.root.exists()


@pytest.mark.parametrize(
    "location",
    [
        "directory",
        "plan.json",
        "authorization.json",
        "delete-submitted.json",
        "absence.json",
        "retired.json",
    ],
)
def test_crash_after_durable_write_never_replays_submission(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    transaction, fixture, approval = case
    original_record, original_reserve = record, frozen.reserve

    def crash_record(path: Path, value: dict[str, object]) -> None:
        if location == "directory":
            raise OSError("crash before plan")
        original_record(path, value)
        if path.name == location:
            raise OSError("crash after record")

    def crash_reserve(path: Path, value: dict[str, object]) -> None:
        original_reserve(path, value)
        if path.name == location:
            raise OSError("crash after reservation")

    monkeypatch.setattr(frozen, "record", crash_record)
    monkeypatch.setattr(frozen, "reserve", crash_reserve)
    with pytest.raises(OSError):
        transaction.execute(approval)
    first = len(fixture.store.deletes)
    monkeypatch.setattr(frozen, "record", original_record)
    monkeypatch.setattr(frozen, "reserve", original_reserve)
    with pytest.raises((ValueError, OSError)):
        transaction.execute(approval)
    assert len(fixture.store.deletes) <= 1
    if location in {"delete-submitted.json", "absence.json", "retired.json"}:
        assert len(fixture.store.deletes) == first


@pytest.mark.parametrize("name", ["delete-submitted.json", "delete-submitted.json.partial"])
@pytest.mark.parametrize("kind", ["empty", "malformed", "symlink"])
def test_torn_or_partial_reservation_never_replayed(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]], name: str, kind: str
) -> None:
    transaction, fixture, approval = case
    transaction.root.mkdir(mode=0o700)
    record(transaction.root / "plan.json", transaction.plan)
    record(transaction.root / "authorization.json", approval)
    path = transaction.root / name
    if kind == "symlink":
        path.symlink_to(transaction.root / "absent")
    else:
        path.write_bytes(b"" if kind == "empty" else b"not-json")
        path.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        transaction.execute(approval)
    assert not fixture.store.deletes


def test_independent_absence_does_not_follow_http_ack_alone(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, fixture, approval = case
    monkeypatch.setattr(fixture.archives, "delete", lambda _row: None)
    with pytest.raises(ValueError, match="absence"):
        transaction.execute(approval)
    assert not (transaction.root / "absence.json").exists()
    assert not (transaction.root / "retired.json").exists()
    with pytest.raises(ValueError, match="no replay"):
        transaction.execute(approval)


def test_insufficient_effect_reserve_never_commits_permanent_disposition(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, fixture, approval = case
    observations: list[object] = []
    observed = fixture.archives.observed

    def inventory() -> list[tuple[str, str]]:
        result = observed()
        observations.append(result)
        return result

    def insufficient() -> None:
        assert fixture.held and fixture.guards > 0
        assert observations == [[("archives/example.zip", "exact-version")]]
        assert not transaction.root.exists()
        raise TimeoutError("required post-effect reserve no longer fits")

    monkeypatch.setattr(fixture.archives, "observed", inventory)
    monkeypatch.setattr(fixture, "before_disposition", insufficient)
    before = journal_snapshot(transaction.run)
    with pytest.raises(TimeoutError):
        transaction.execute(approval)
    assert journal_snapshot(transaction.run) == before
    assert not transaction.root.exists() and not fixture.store.deletes


def test_changed_authorization_does_not_adopt_prior_submission(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
) -> None:
    transaction, fixture, approval = case
    fixture.store.failure = "after"
    with pytest.raises(ConnectionError):
        transaction.execute(approval)
    approval["approval_reference_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="journal"):
        transaction.execute(approval, reconcile_only=True)
    assert len(fixture.store.deletes) == 1
    pending = read_private(transaction.root / "delete-submitted.json")
    assert pending["archive"] == cast(dict[str, object], transaction.plan["archive"])


def journal_snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    """Reading cannot renew, rewrite or complete any authoritative journal file."""
    result: dict[str, tuple[object, ...]] = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        result[str(path.relative_to(root))] = (
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None,
        )
    return result


@pytest.mark.parametrize("state", ["present", "absent", "complete"])
def test_reconciliation_observes_without_authoritative_journal_writes(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    transaction, fixture, approval = case
    if state == "complete":
        transaction.execute(approval)
    else:
        fixture.store.failure = "before" if state == "present" else "after"
        with pytest.raises(ConnectionError):
            transaction.execute(approval)
    before = journal_snapshot(transaction.run)
    submissions = len(fixture.store.deletes)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("read-only reconciliation attempted a journal or provider mutation")

    monkeypatch.setattr(frozen, "record", forbidden)
    monkeypatch.setattr(frozen, "reserve", forbidden)
    monkeypatch.setattr(fixture.archives, "delete", forbidden)
    observation = transaction.execute(approval, reconcile_only=True)
    assert observation == {
        "format": "lowerduckpond-m3-11-frozen-archive-observation-v1",
        "plan_sha256": digest(transaction.plan),
        "authorization_sha256": digest(approval),
        "observed_at": observation["observed_at"],
        "version_state": "present" if state == "present" else "absent",
        "recorded_retirement": state == "complete",
        "qualification_authority": "none",
        "lease_released": False,
        "credential_cleanup_complete": False,
    }
    assert (
        datetime.fromisoformat(str(approval["approved_at"]))
        <= datetime.fromisoformat(str(observation["observed_at"]))
        <= datetime.now(UTC)
    )
    assert journal_snapshot(transaction.run) == before
    assert len(fixture.store.deletes) == submissions


@pytest.mark.parametrize(
    "state",
    [
        "fresh",
        "unsubmitted",
        "partial",
        "malformed-submission",
        "malformed-absence",
        "malformed-retired",
    ],
)
def test_read_only_reconciliation_does_not_repair_incomplete_or_malformed_journal(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    transaction, fixture, approval = case
    if state == "unsubmitted":
        transaction.root.mkdir(mode=0o700)
        record(transaction.root / "plan.json", transaction.plan)
        record(transaction.root / "authorization.json", approval)
    elif state != "fresh":
        if state.startswith("malformed-") and state != "malformed-submission":
            transaction.execute(approval)
            target = state.removeprefix("malformed-") + ".json"
        else:
            fixture.store.failure = "after"
            with pytest.raises(ConnectionError):
                transaction.execute(approval)
            target = (
                "delete-submitted.json.partial" if state == "partial" else "delete-submitted.json"
            )
        (transaction.root / target).write_bytes(b"not a valid bound record")
        (transaction.root / target).chmod(0o600)
    before = journal_snapshot(transaction.run)
    submissions = len(fixture.store.deletes)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("read-only reconciliation attempted a journal or provider mutation")

    monkeypatch.setattr(frozen, "record", forbidden)
    monkeypatch.setattr(frozen, "reserve", forbidden)
    monkeypatch.setattr(fixture.archives, "delete", forbidden)
    with pytest.raises((ValueError, OSError)):
        transaction.execute(approval, reconcile_only=True)
    assert journal_snapshot(transaction.run) == before
    assert len(fixture.store.deletes) == submissions


def test_final_guard_cannot_relabel_stale_empty_inventory_as_completion(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, fixture, approval = case
    observed = fixture.archives.observed
    guard = fixture.guard
    emptied = []

    def inventory() -> list[tuple[str, str]]:
        result = observed()
        if not result:
            emptied.append(True)
        return result

    def changed(plan: dict[str, object]) -> None:
        guard(plan)
        if emptied:
            fixture.store.objects["unexpected", "new-version"] = b"do not delete"

    monkeypatch.setattr(fixture.archives, "observed", inventory)
    monkeypatch.setattr(fixture, "guard", changed)
    with pytest.raises(ValueError):
        transaction.execute(approval)
    assert len(fixture.store.deletes) == 1
    assert not (transaction.root / "absence.json").exists()
    assert not (transaction.root / "retired.json").exists()
    assert fixture.store.objects["unexpected", "new-version"] == b"do not delete"


def test_final_observation_uses_inventory_after_slow_guard(
    case: tuple[frozen.FrozenRetirement, Fixture, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction, fixture, approval = case
    fixture.store.failure = "after"
    with pytest.raises(ConnectionError):
        transaction.execute(approval)
    before = journal_snapshot(transaction.root)
    original = fixture.guard
    calls = []

    def guard(plan: dict[str, object]) -> None:
        original(plan)
        calls.append(True)
        if len(calls) == 3:  # noqa: PLR2004 - final guard after initial and journal checks
            fixture.store.objects["archives/example.zip", "exact-version"] = b"preserved"

    monkeypatch.setattr(fixture, "guard", guard)
    result = transaction.execute(approval, reconcile_only=True)
    assert result["version_state"] == "present"
    assert not result["recorded_retirement"]
    assert journal_snapshot(transaction.root) == before
    assert len(fixture.store.deletes) == 1
