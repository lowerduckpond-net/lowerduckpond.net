"""Exact deletion, permanent remote exclusion and faults across workspace loss."""

from __future__ import annotations

import hashlib
import shutil
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import m3_11_custody_plan as schema
from scripts.m3_11_custody_retirement import CustodyRetirement
from scripts.m3_11_retirement_files import digest, record
from scripts.m3_11_unattended.model import LifecycleError, stamp

from .test_m3_11_frozen_retirement import Fixture as StorageFixture


class Fixture(StorageFixture):
    def __init__(self, root: Path) -> None:
        super().__init__()
        self.root = root
        self.external: dict[str, object] | None = None
        self.fail_publish = False
        self.after_publish_change = False
        self.completion: dict[str, object] | None = None

    def guard(self) -> None:  # type: ignore[override]
        super().guard({})

    def verify_custody(self) -> None:
        self.guard()

    def exclusion(self) -> dict[str, object] | None:
        return deepcopy(self.external)

    def publish_exclusion(self, value: dict[str, object], *, spool: Path) -> None:
        assert self.external is None and spool.is_dir()
        self.external = deepcopy(value)
        if self.fail_publish:
            raise ConnectionError("synthetic lost publication response")
        if self.after_publish_change:
            self.store.objects["foreign", "version"] = b"retained"

    def require_exclusion(self, value: dict[str, object]) -> None:
        assert self.external == value

    def record_completion(self, value: dict[str, object]) -> None:
        self.completion = value


def approved_plan() -> dict[str, object]:
    return {
        "format": schema.FORMAT,
        "fixture_id": str(uuid.uuid7()),
        "source_workspace_id": "11111111-1111-4111-8111-111111111111",
        "historical_lease_id": str(uuid.uuid7()),
        "historical_manifest_sha256": "a" * 64,
        "custody_sha256": "b" * 64,
        "evidence_sha256": "c" * 64,
        "cleanup_contract_sha256": "d" * 64,
        "current_lease_id": str(uuid.uuid7()),
        "current_manifest_sha256": "e" * 64,
        "implementation_revision": "f" * 40,
        "runtime": {
            "workspace_id": "22222222-2222-4222-8222-222222222222",
            "daemon_id": "33333333-3333-4333-8333-333333333333",
            "evidence_volume_created_at": "2026-10-26T00:00:00Z",
            "image": "sha256:" + "1" * 64,
        },
        "archive": {
            "bucket": "test-archives",
            "key": "archives/example.zip",
            "version": "exact-version",
            "size": 9,
            "sha256": hashlib.sha256(b"preserved").hexdigest(),
        },
        "retained": schema.RETAINED,
    }


def approval(value: dict[str, object]) -> dict[str, object]:
    return {
        "format": schema.AUTHORIZATION,
        "plan_sha256": digest(value),
        "approved_at": stamp(datetime.now(UTC) - timedelta(minutes=1)),
        "approval_reference_sha256": "a" * 64,
        "acknowledge_exact_version_loss": True,
        "acknowledge_permanent_fixture_retirement": True,
        "acknowledge_current_lease_cleanup_owed": True,
        "acknowledge_exclusive_archive_writers": True,
    }


@pytest.fixture
def case(tmp_path: Path) -> tuple[CustodyRetirement, Fixture, dict[str, object]]:
    tmp_path.chmod(0o700)
    fixture, value = Fixture(tmp_path), approved_plan()
    return CustodyRetirement(value, fixture), fixture, approval(value)


def test_exact_delete_keeps_original_history_and_current_cleanup_owed(
    case: tuple[CustodyRetirement, Fixture, dict[str, object]],
    tmp_path: Path,
) -> None:
    transaction, fixture, allowed = case
    original = tmp_path / "sealed-history"
    original.mkdir(mode=0o700)
    record(original / "failure.json", {"qualification": "failed", "lease": "closed"})
    before = (original / "failure.json").read_bytes()
    result = transaction.execute(allowed)
    assert fixture.store.deletes == [
        {"Bucket": "test-archives", "Key": "archives/example.zip", "VersionId": "exact-version"}
    ]
    assert result["historical_lease_closed"] is True
    assert result["current_lease_cleanup_complete"] is False
    assert result["source_workspace_changed"] is False
    assert result["qualification_authority"] == "none"
    assert fixture.completion == result
    assert (original / "failure.json").read_bytes() == before
    assert sorted(path.name for path in original.iterdir()) == ["failure.json"]
    with pytest.raises(ValueError, match="no replay"):
        transaction.execute(allowed)


@pytest.mark.parametrize("failure", ["before", "after", "publish", "inventory"])
def test_consumed_uncertainty_never_replays(
    case: tuple[CustodyRetirement, Fixture, dict[str, object]],
    failure: str,
) -> None:
    transaction, fixture, allowed = case
    if failure == "publish":
        fixture.fail_publish = True
    elif failure == "inventory":
        fixture.after_publish_change = True
    else:
        fixture.store.failure = failure
    with pytest.raises((ValueError, ConnectionError)):
        transaction.execute(allowed)
    assert fixture.external is not None and fixture.completion is None
    with pytest.raises(ValueError, match="no replay"):
        transaction.execute(allowed)
    assert len(fixture.store.deletes) == (0 if failure in {"publish", "inventory"} else 1)
    assert not (transaction.root / "retired.json").exists()
    if failure != "inventory":
        observed = transaction.execute(allowed, observe_only=True)
        assert observed["version_state"] == ("absent" if failure == "after" else "present")
        assert observed["provider_delete_submissions"] == 0
        assert fixture.completion is None


def test_remote_exclusion_survives_total_local_loss_and_new_plan(
    case: tuple[CustodyRetirement, Fixture, dict[str, object]],
    tmp_path: Path,
) -> None:
    transaction, fixture, allowed = case
    transaction.execute(allowed)
    shutil.rmtree(transaction.root.parent)
    new_plan = {
        **transaction.plan,
        "current_lease_id": str(uuid.uuid7()),
        "current_manifest_sha256": "2" * 64,
    }
    replacement_root = tmp_path / "new-workspace"
    replacement_root.mkdir(mode=0o700)
    fixture.root = replacement_root
    replacement = CustodyRetirement(new_plan, fixture)
    with pytest.raises(ValueError, match="no replay"):
        replacement.execute(approval(new_plan))
    observed = replacement.execute(approval(new_plan), observe_only=True)
    assert observed["version_state"] == "absent" and len(fixture.store.deletes) == 1
    assert not replacement.root.exists()


@pytest.mark.parametrize("fault", ["foreign", "marker", "upload", "truncated", "guard"])
def test_no_durable_exclusion_when_readiness_fails(
    case: tuple[CustodyRetirement, Fixture, dict[str, object]],
    fault: str,
) -> None:
    transaction, fixture, allowed = case
    if fault == "foreign":
        fixture.store.objects["foreign", "version"] = b"retained"
    elif fault == "guard":
        fixture.changed = True
    else:
        setattr(fixture.store, fault, True)
    with pytest.raises(ValueError):
        transaction.execute(allowed)
    assert fixture.external is None and not transaction.root.exists() and not fixture.store.deletes


@pytest.mark.parametrize(
    "field",
    [
        "plan_sha256",
        "approved_at",
        "acknowledge_exact_version_loss",
        "acknowledge_permanent_fixture_retirement",
        "acknowledge_current_lease_cleanup_owed",
        "acknowledge_exclusive_archive_writers",
    ],
)
def test_concrete_approval_is_required_before_any_effect(
    case: tuple[CustodyRetirement, Fixture, dict[str, object]],
    field: str,
) -> None:
    transaction, fixture, allowed = case
    allowed[field] = False
    with pytest.raises((ValueError, TypeError, LifecycleError)):
        transaction.execute(allowed)
    assert fixture.external is None and not transaction.root.exists() and not fixture.store.deletes


def test_workspace_uuid4_is_distinct_from_lease_uuid7() -> None:
    value = approved_plan()
    assert schema.plan(value) == value
    value["current_lease_id"] = value["source_workspace_id"]
    with pytest.raises((ValueError, LifecycleError)):
        schema.plan(value)


def test_historical_identity_cannot_be_adopted_as_current_authority() -> None:
    value = approved_plan()
    value["current_lease_id"] = value["historical_lease_id"]
    with pytest.raises(ValueError, match="historical credentials"):
        schema.plan(value)
