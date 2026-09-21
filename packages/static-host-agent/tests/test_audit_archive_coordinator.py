from __future__ import annotations

import fcntl
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import LockManager
from lowerduckpond_static_host_agent import audit_archive_coordinator as coordinator
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent.audit_archive_inventory import ProtectedProof
from lowerduckpond_static_host_agent.audit_archive_store import ArchivePrefix
from lowerduckpond_static_host_agent.backup_identity import (
    BackupIdentityError,
    RepositoryIdentity,
    framed_digest,
)
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot, lineage_tags
from lowerduckpond_static_host_agent.durable import DurabilityBoundary
from test_audit_archive_admission import available_capacity
from test_audit_archive_formats import IDENTITY
from test_audit_archive_store import lineage, put, read
from test_audit_archive_store import state as state  # noqa: PLC0414 - shared private fixture

GENESIS = "e" * 64
REMOVE = "a" * 64
KEEP = "b" * 64


@dataclass
class Repository:
    root: Path
    paths: coordinator.ProtectionPaths
    snapshots: dict[str, RepositorySnapshot]
    events: list[str]
    fault: str | None = None
    proof_version: int = 0

    def network(self, event: str) -> None:
        # A separate file description cannot take EX if the caller retained its
        # state lease. Every simulated network/destructive boundary proves this.
        with (self.root / "locks/tenant-state.lock").open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        self.events.append(event)

    def discover(
        self, _environment: Mapping[str, str]
    ) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
        self.network("discover")
        return IDENTITY, tuple(self.snapshots.values())

    def genesis(
        self,
        _identity: RepositoryIdentity,
        _snapshots: tuple[RepositorySnapshot, ...],
        _environment: Mapping[str, str],
    ) -> dict[str, object] | None:
        self.network("genesis")
        return lineage(self.root) if GENESIS in self.snapshots else None

    def proof(
        self,
        _identity: RepositoryIdentity,
        _snapshots: tuple[RepositorySnapshot, ...],
        _lineage: dict[str, object],
        _prefix: ArchivePrefix,
        _environment: Mapping[str, str],
        *,
        workspace: Path,
        expected_owner: int,
        expected_group: int,
    ) -> ProtectedProof:
        self.network("proof")
        assert workspace == self.paths.workspace
        assert expected_owner == os.geteuid() and expected_group == os.getegid()
        if self.fault == "proof":
            raise BackupIdentityError("remote protected proof unavailable")
        return ProtectedProof(
            (GENESIS,),
            framed_digest(
                journal.PROTECTION_INVENTORY_FORMAT,
                canonical_json_bytes({"version": self.proof_version}),
            ),
            1024,
            (),
            None,
        )

    def selection(
        self,
        _identity: RepositoryIdentity,
        _snapshots: tuple[RepositorySnapshot, ...],
        protected: frozenset[str],
        _environment: Mapping[str, str],
    ) -> tuple[str, ...]:
        self.network("selection")
        assert protected == frozenset({GENESIS})
        return (REMOVE,)

    def forget(self, ids: tuple[str, ...], _environment: Mapping[str, str]) -> None:
        self.network("forget")
        intent = read(self.root).maintenance_intent
        assert intent is not None and intent["phase"] == "prepared"
        assert ids == tuple(value for value in (REMOVE,) if value in self.snapshots)
        if self.fault == "forget-no-effect":
            return
        if self.fault == "forget-before-effect":
            raise RuntimeError("injected forget failure")
        for snapshot_id in ids:
            del self.snapshots[snapshot_id]
        if self.fault == "forget-lost-response":
            raise RuntimeError("injected forget failure")
        if self.fault == "forget-loses-proof":
            self.proof_version += 1

    def prune(self, _environment: Mapping[str, str]) -> None:
        self.network("prune")
        intent = read(self.root).maintenance_intent
        assert intent is not None and intent["phase"] == "pruning"
        assert REMOVE not in self.snapshots and GENESIS in self.snapshots
        if self.fault == "prune":
            raise RuntimeError("injected prune failure")

    def check(self, _environment: Mapping[str, str]) -> None:
        self.network("check")
        if self.fault == "check":
            raise RuntimeError("injected check failure")
        if self.fault == "check-loses-proof":
            self.proof_version += 1

    def maintain(self, hook: local.ArchiveFailureHook | None = None) -> coordinator.VerifiedArchive:
        return coordinator.maintain_archive(
            self.paths,
            {},
            expected_owner=os.geteuid(),
            expected_group=os.getegid(),
            failure_hook=hook,
        )

    def verify(self, *, initialize: bool = False) -> coordinator.VerifiedArchive:
        return coordinator.verify_archive(
            self.paths,
            {},
            expected_owner=os.geteuid(),
            expected_group=os.getegid(),
            initialize=initialize,
        )


@pytest.fixture
def remote(state: Path, monkeypatch: pytest.MonkeyPatch) -> Repository:
    with LockManager.initialize(state / "locks", expected_owner=os.geteuid()):
        pass
    repository = Repository(
        state,
        coordinator.ProtectionPaths(state, state.parent / "verification"),
        {
            GENESIS: RepositorySnapshot(GENESIS, IDENTITY.node_name, lineage_tags(lineage(state))),
            REMOVE: RepositorySnapshot(REMOVE, IDENTITY.node_name, ("scheduled",), ("/ordinary",)),
            KEEP: RepositorySnapshot(KEEP, IDENTITY.node_name, ("scheduled",), ("/ordinary",)),
        },
        [],
    )
    monkeypatch.setattr(local, "measure_filesystem_capacity_descriptor", available_capacity)
    for name, function in (
        ("discover_repository", repository.discover),
        ("repository_genesis", repository.genesis),
        ("verify_protected_inventory", repository.proof),
        ("ordinary_retention_ids", repository.selection),
        ("forget_exact_ids", repository.forget),
        ("prune_repository", repository.prune),
        ("check_repository", repository.check),
    ):
        monkeypatch.setattr(coordinator, name, function)
    return repository


def test_success_proves_protection_between_each_separate_destructive_phase(
    remote: Repository,
) -> None:
    verified = remote.maintain()
    assert verified.local.prefix.maintenance_intent is None
    assert set(remote.snapshots) == {GENESIS, KEEP}
    assert remote.events == [
        "discover",
        "genesis",
        "proof",
        "selection",
        "forget",
        "discover",
        "genesis",
        "proof",
        "prune",
        "check",
        "discover",
        "genesis",
        "proof",
    ]
    assert verified.local.prefix.protection_status is not None
    assert verified.local.prefix.protection_status["category"] == "verified"


@pytest.mark.parametrize(
    "fault",
    [
        "proof",
        "forget-no-effect",
        "forget-before-effect",
        "forget-lost-response",
        "forget-loses-proof",
    ],
)
def test_failed_pre_prune_proof_preserves_intent_and_never_prunes(
    remote: Repository, fault: str
) -> None:
    remote.fault = fault
    with pytest.raises((BackupIdentityError, RuntimeError)):
        remote.maintain()
    assert "prune" not in remote.events and "check" not in remote.events
    prefix = read(remote.root)
    assert (
        prefix.protection_status is not None
        and prefix.protection_status["category"] == "protection"
    )
    if fault != "proof":
        assert (
            prefix.maintenance_intent is not None
            and prefix.maintenance_intent["phase"] == "prepared"
        )
    assert GENESIS in remote.snapshots and KEEP in remote.snapshots


@pytest.mark.parametrize("fault", ["forget-before-effect", "forget-lost-response"])
def test_resumed_forget_uses_saved_ids_without_new_retention_selection(
    remote: Repository, fault: str
) -> None:
    remote.fault = fault
    with pytest.raises(RuntimeError):
        remote.maintain()
    original = read(remote.root).maintenance_intent
    assert original is not None
    remote.fault = None
    remote.events.clear()
    result = remote.maintain()
    assert "selection" not in remote.events
    assert result.local.prefix.maintenance_intent is None
    assert set(remote.snapshots) == {GENESIS, KEEP}


@pytest.mark.parametrize("fault", ["prune", "check"])
def test_interrupted_prune_recovery_revalidates_before_resuming_prune(
    remote: Repository, fault: str
) -> None:
    remote.fault = fault
    with pytest.raises(RuntimeError):
        remote.maintain()
    intent = read(remote.root).maintenance_intent
    assert intent is not None and intent["phase"] == "pruning"
    remote.fault = None
    remote.events.clear()
    remote.maintain()
    assert remote.events == [
        "discover",
        "genesis",
        "proof",
        "check",
        "discover",
        "genesis",
        "proof",
        "prune",
        "check",
        "discover",
        "genesis",
        "proof",
    ]
    assert read(remote.root).maintenance_intent is None


def test_changed_protection_after_prune_cannot_report_success(remote: Repository) -> None:
    remote.fault = "check-loses-proof"
    with pytest.raises(BackupIdentityError, match="protection changed"):
        remote.maintain()
    prefix = read(remote.root)
    assert prefix.maintenance_intent is not None and prefix.maintenance_intent["phase"] == "pruning"
    assert (
        prefix.protection_status is not None
        and prefix.protection_status["category"] == "protection"
    )


def test_saved_intent_cannot_reclassify_protected_snapshot_as_ordinary(remote: Repository) -> None:
    remote.fault = "forget-before-effect"
    with pytest.raises(RuntimeError):
        remote.maintain()
    intent = read(remote.root).maintenance_intent
    assert intent is not None
    put(remote.root, "audit/archive/maintenance-intent.json", {**intent, "removeIds": [GENESIS]})
    remote.events.clear()
    remote.fault = None
    with pytest.raises((BackupIdentityError, RuntimeError)):
        remote.maintain()
    assert not {"forget", "prune", "check"}.intersection(remote.events)
    assert GENESIS in remote.snapshots


@pytest.mark.parametrize("occurrence", [1, 2, 3, 4])
@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_every_maintenance_intent_publication_resumes_safely(
    remote: Repository, occurrence: int, boundary: DurabilityBoundary
) -> None:
    observed = 0

    def interrupt(name: str, step: DurabilityBoundary) -> None:
        nonlocal observed
        if name == "maintenance-intent.json" and step == boundary:
            observed += 1
            if observed == occurrence:
                raise RuntimeError("interrupted durable boundary")

    with pytest.raises(RuntimeError):
        remote.maintain(interrupt)
    assert observed == occurrence
    assert GENESIS in remote.snapshots and KEEP in remote.snapshots
    prior_prunes = remote.events.count("prune")
    remote.events.clear()
    remote.maintain()
    assert prior_prunes + remote.events.count("prune") >= 1
    pruning_publication, checked_publication = 3, 4
    if occurrence == pruning_publication and boundary in {
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    }:
        # Pruning intent is durable, but the child has never started.
        assert prior_prunes == 0 and remote.events.count("prune") == 1
    if occurrence == checked_publication and boundary in {
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    }:
        # Checked proves that prune and its postconditions completed already.
        assert prior_prunes == 1 and "prune" not in remote.events
    assert read(remote.root).maintenance_intent is None
    assert REMOVE not in remote.snapshots


def test_lost_genesis_closes_ordinary_admission_without_remote_mutation(remote: Repository) -> None:
    remote.verify()
    del remote.snapshots[GENESIS]
    remote.events.clear()
    with pytest.raises(BackupIdentityError):
        remote.maintain()
    assert remote.events == ["discover", "genesis"]
    status = read(remote.root).protection_status
    assert status is not None and status["category"] == "protection"


def test_explicit_empty_initialization_must_complete_full_proof(remote: Repository) -> None:
    (remote.root / "audit/archive/head.json").unlink()
    remote.fault = "proof"
    with pytest.raises(BackupIdentityError):
        remote.verify(initialize=True)
    status = read(remote.root).protection_status
    assert status is not None and status["category"] == "protection"
    remote.fault = None
    verified = remote.verify(initialize=True)
    assert verified.local.prefix.protection_status is not None
    assert verified.local.prefix.protection_status["category"] == "verified"


@pytest.mark.parametrize("fault", ["check", "check-loses-proof"])
def test_resumed_prune_requires_integrity_and_fresh_protection_before_launch(
    remote: Repository, fault: str
) -> None:
    remote.fault = "prune"
    with pytest.raises(RuntimeError):
        remote.maintain()
    remote.fault = fault
    remote.events.clear()
    with pytest.raises((RuntimeError, BackupIdentityError)):
        remote.maintain()
    assert "prune" not in remote.events and "forget" not in remote.events
    intent = read(remote.root).maintenance_intent
    assert intent is not None and intent["phase"] == "pruning"
