from __future__ import annotations

import fcntl
import os
import time
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import LockManager
from lowerduckpond_static_host_agent import audit_archive_admission as admission
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_health as health
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from test_audit_archive_admission import NOW, available_capacity, grant_protection
from test_audit_archive_formats import IDENTITY
from test_audit_archive_store import put
from test_audit_archive_store import state as state  # noqa: PLC0414 - private local fixture

ENVIRONMENT = {
    "RESTIC_REPOSITORY": IDENTITY.locator,
    "LOWERDUCKPOND_BACKUP_NODE_NAME": IDENTITY.node_name,
}


@pytest.fixture
def protected(state: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    with LockManager.initialize(state / "locks", expected_owner=os.geteuid()):
        pass
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", available_capacity)
    grant_protection(state)
    return state


def inspect(path: Path, environment: dict[str, str] | None = None) -> health.ProtectionHealth:
    return health.inspect_protection_health(
        path, ENVIRONMENT if environment is None else environment, expected_owner=os.geteuid()
    )


def test_local_fresh_bound_proof_exports_only_fixed_counts_and_categories(protected: Path) -> None:
    result = inspect(protected)
    assert result == health.ProtectionHealth(None, 1, 1)
    assert "lowerduckpond_audit_protection_verified 1\n" in result.metrics()
    assert IDENTITY.locator not in result.metrics()
    assert "test-node" not in result.metrics()
    assert all(f'category="{name}"}} 0' in result.metrics() for name in health.CATEGORIES)


@pytest.mark.parametrize(
    "fault", ["missing", "stale", "future", "head", "scope", "node", "missing-env"]
)
def test_health_rejects_missing_stale_and_wrong_scope_cached_proof(
    protected: Path, fault: str
) -> None:
    environment = dict(ENVIRONMENT)
    status = grant_protection(protected)
    if fault == "missing":
        (protected / "audit/archive/protection-status.json").unlink()
    elif fault in {"stale", "future"}:
        grant_protection(protected, timestamp=NOW - 86401 if fault == "stale" else NOW + 1)
    elif fault == "head":
        put(
            protected,
            "audit/archive/protection-status.json",
            {**status, "headDigest": framed_digest(formats.HEAD_FORMAT, b"other")},
        )
    elif fault == "scope":
        environment["RESTIC_REPOSITORY"] = "s3:https://nyc3.example.test/backups/other"
    elif fault == "node":
        environment["LOWERDUCKPOND_BACKUP_NODE_NAME"] = "other-node"
    else:
        environment.clear()
    assert inspect(protected, environment).category == "protection"


@pytest.mark.parametrize("category", health.CATEGORIES)
def test_recorded_fixed_failure_categories_are_retained(protected: Path, category: str) -> None:
    status = grant_protection(protected)
    status.update(
        category=category, protectedInventoryDigest=None, protectedSnapshotCount=0, protectedBytes=0
    )
    put(protected, "audit/archive/protection-status.json", status)
    result = inspect(protected)
    assert result.category == category
    assert f'category="{category}"}} 1' in result.metrics()
    assert result.snapshot_count == 0


def test_unsafe_or_missing_index_authority_is_critical_without_repair(protected: Path) -> None:
    (protected / "audit/archive/head.json").unlink()
    assert inspect(protected).category == "index-corruption"
    assert not (protected / "audit/archive/head.json").exists()


def test_capacity_reports_exhaustion_before_ordinary_work_borrows_reserve(
    protected: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(formats, "MAX_ARCHIVE_METADATA_BYTES", 1024 * 1024)
    assert inspect(protected).category == "resource-exhaustion"


def test_health_does_not_wait_for_state_mutation_or_touch_any_authority(protected: Path) -> None:
    before = {path.name: path.read_bytes() for path in (protected / "audit/archive").iterdir()}
    with (protected / "locks/tenant-state.lock").open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX)
        assert inspect(protected).category == "protection"
    assert before == {
        path.name: path.read_bytes() for path in (protected / "audit/archive").iterdir()
    }
