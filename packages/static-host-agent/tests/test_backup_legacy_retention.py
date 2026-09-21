from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import backup_legacy_retention as legacy
from lowerduckpond_static_host_agent.audit_archive_coordinator import ProtectionPaths
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from test_audit_archive_coordinator import GENESIS, KEEP, REMOVE, Repository
from test_audit_archive_coordinator import (
    remote as remote,  # noqa: PLC0414 - initialized root/lease fixture
)
from test_audit_archive_store import state as state  # noqa: PLC0414 - dependency of remote fixture


@pytest.fixture
def unmigrated(remote: Repository, monkeypatch: pytest.MonkeyPatch) -> Repository:
    for name in (
        "platform/audit-lineage.json",
        "locks/audit-lineage-genesis.json",
        "audit/archive/head.json",
    ):
        (remote.root / name).unlink()
    (remote.root / "audit/archive").rmdir()
    del remote.snapshots[GENESIS]
    monkeypatch.setattr(legacy, "discover_repository", remote.discover)

    def selection(
        _identity: RepositoryIdentity,
        _snapshots: tuple[RepositorySnapshot, ...],
        protected: frozenset[str],
        _environment: Mapping[str, str],
    ) -> tuple[str, ...]:
        remote.network("selection")
        assert not protected
        return (REMOVE,)

    def forget(ids: tuple[str, ...], _environment: Mapping[str, str]) -> None:
        remote.network("forget")
        assert ids == (REMOVE,)
        if remote.fault != "forget-no-effect":
            del remote.snapshots[REMOVE]
        if remote.fault == "new-protected-evidence":
            remote.snapshots[GENESIS] = RepositorySnapshot(
                GENESIS, "other-node", ("lowerduckpond-audit-lineage",)
            )

    def prune(_environment: Mapping[str, str]) -> None:
        remote.network("prune")

    monkeypatch.setattr(legacy, "ordinary_retention_ids", selection)
    monkeypatch.setattr(legacy, "forget_exact_ids", forget)
    monkeypatch.setattr(legacy, "prune_repository", prune)
    monkeypatch.setattr(legacy, "check_repository", remote.check)
    return remote


def maintain(remote: Repository) -> None:
    legacy.maintain_archive_free_repository(
        ProtectionPaths(remote.root), {}, expected_owner=os.geteuid()
    )


def test_unmigrated_ordinary_retention_has_separate_bounded_destructive_phases(
    unmigrated: Repository,
) -> None:
    maintain(unmigrated)
    assert unmigrated.events == [
        "discover",
        "check",
        "selection",
        "forget",
        "discover",
        "prune",
        "check",
        "discover",
    ]
    assert set(unmigrated.snapshots) == {KEEP}
    assert not (unmigrated.root / "audit/archive").exists()


@pytest.mark.parametrize(
    "tag",
    [
        "lowerduckpond-audit-lineage",
        "lowerduckpond-audit-archive",
        "rotation-any",
        "lineage-any",
        "repository-any",
        "capture-any",
    ],
)
def test_any_remote_protected_marker_forbids_legacy_retention(
    unmigrated: Repository, tag: str
) -> None:
    unmigrated.snapshots[GENESIS] = RepositorySnapshot(GENESIS, "other-node", (tag, "scheduled"))
    with pytest.raises(BackupIdentityError, match="coherent"):
        maintain(unmigrated)
    assert unmigrated.events == ["discover"]
    assert REMOVE in unmigrated.snapshots


@pytest.mark.parametrize(
    "path", ["platform/audit-lineage.json", "locks/audit-lineage-genesis.json", "audit/archive"]
)
@pytest.mark.parametrize("kind", ["regular", "dangling-symlink"])
def test_local_migration_markers_forbid_legacy_even_when_remote_evidence_was_lost(
    unmigrated: Repository, path: str, kind: str
) -> None:
    target: Path = unmigrated.root / path
    if kind == "regular":
        target.write_bytes(b"existing authority")
    else:
        target.symlink_to("missing")
    with pytest.raises(BackupIdentityError, match="coherent"):
        maintain(unmigrated)
    assert unmigrated.events == ["discover"]


@pytest.mark.parametrize("fault", ["forget-no-effect", "new-protected-evidence"])
def test_incomplete_forget_or_new_protected_evidence_forbids_prune(
    unmigrated: Repository, fault: str
) -> None:
    unmigrated.fault = fault
    with pytest.raises(BackupIdentityError):
        maintain(unmigrated)
    assert "prune" not in unmigrated.events
    assert KEEP in unmigrated.snapshots


def test_repository_integrity_failure_precedes_any_legacy_retention(unmigrated: Repository) -> None:
    unmigrated.fault = "check"
    with pytest.raises(RuntimeError):
        maintain(unmigrated)
    assert unmigrated.events == ["discover", "check"]
    assert REMOVE in unmigrated.snapshots
