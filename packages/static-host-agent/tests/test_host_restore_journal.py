from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, StatePathError
from lowerduckpond_static_host_agent.host_restore_gate import (
    close_gate,
    open_gate,
    restore_admission,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)

RESTORE = "0198d17f-6f4a-7000-8000-000000000001"
CAPTURE = "0198d17f-6f4a-7000-8000-000000000002"
LINEAGE = "0198d17f-6f4a-7000-8000-000000000003"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    result = tmp_path / "recovery"
    result.mkdir(mode=0o700)
    return result


@pytest.fixture
def journal() -> RestoreJournal:
    formats = {
        "backupDescriptor": "lowerduckpond-static-backup-v1",
        "repository": "lowerduckpond-backup-repository-binding-v1",
        "originalArtifact": "lowerduckpond-static-host-agent-artifact-v1",
        "trustedInputs": "lowerduckpond-host-restore-inputs-v1",
        "destination": "lowerduckpond-host-restore-destination-v1",
        "sourceFence": "lowerduckpond-host-restore-source-fence-v1",
    }
    return RestoreJournal(
        RESTORE,
        "a" * 64,
        CAPTURE,
        LINEAGE,
        {key: framed_digest(value, b"bound input") for key, value in formats.items()},
    )


def admitted(root: Path, *, caddy: bool = False) -> bool:
    return restore_admission(root, owner=os.geteuid(), caddy=caddy)


def test_every_phase_keeps_mutation_closed_and_caddy_requires_installed_evidence(
    root: Path, journal: RestoreJournal
) -> None:
    assert admitted(root)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        close_gate(store, RESTORE)
        assert not admitted(root, caddy=True)
        store.begin(journal)
        for phase in PHASES[1:]:
            before = journal.digest
            journal = store.advance(journal, phase, {"phaseEvidence": phase.value})
            assert journal.previous == before
            assert not admitted(root)
            assert admitted(root, caddy=True) == (
                PHASES.index(phase) >= PHASES.index(RestorePhase.INSTALLED)
            )
        open_gate(store)
    assert admitted(root) and admitted(root, caddy=True)
    # Missing/damaged evidence after completion cannot reopen service.
    (root / "verified.json").unlink()
    with pytest.raises(FileNotFoundError):
        admitted(root)


def test_completed_provenance_cannot_be_bypassed_by_removing_only_current_journal(
    root: Path,
    journal: RestoreJournal,
) -> None:
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        close_gate(store, RESTORE)
        store.begin(journal)
        for phase in PHASES[1:]:
            journal = store.advance(journal, phase, {"phaseEvidence": phase.value})
        open_gate(store)
    (root / "host-restore.json").unlink()
    with pytest.raises(HostRestoreError, match="lost its journal"):
        admitted(root)
    with pytest.raises(HostRestoreError, match="lost its journal"):
        admitted(root, caddy=True)


@pytest.mark.parametrize("boundary", list(DurabilityBoundary))
def test_interruption_never_opens_gate_or_advances_without_immutable_receipt(
    root: Path, journal: RestoreJournal, boundary: DurabilityBoundary
) -> None:
    def fail(actual: DurabilityBoundary) -> None:
        if actual is boundary:
            raise RuntimeError("interrupted")

    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        close_gate(store, RESTORE)
        store.begin(journal)
        try:
            store.advance(journal, RestorePhase.RESTORED, {"inventory": "exact"}, failure_hook=fail)
        except RuntimeError as error:
            assert str(error) == "interrupted"
    assert not admitted(root) and not admitted(root, caddy=True)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        current = store.read()
        assert current is not None
        if current.phase is RestorePhase.PREPARED:
            current = store.advance(current, RestorePhase.RESTORED, {"inventory": "exact"})
        assert current.phase is RestorePhase.RESTORED
        assert current.previous == journal.digest


def test_stale_coordinator_skipped_phase_conflicting_receipt_and_gate_loss_fail_closed(
    root: Path, journal: RestoreJournal
) -> None:
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        close_gate(store, RESTORE)
        store.begin(journal)
        with pytest.raises(BlockingIOError), RestoreStore.locked(root, owner=os.geteuid()):
            pytest.fail("concurrent coordinator obtained the lease")
        with pytest.raises(HostRestoreError, match="compare-and-swap"):
            store.advance(journal, RestorePhase.INSTALLED, {})
        store.immutable("restored.json", canonical_json_bytes({"inventory": "first"}))
        with pytest.raises(HostRestoreError, match="conflicts"):
            store.advance(journal, RestorePhase.RESTORED, {"inventory": "other"})
        current = store.advance(journal, RestorePhase.RESTORED, {"inventory": "first"})
        with pytest.raises(HostRestoreError, match="compare-and-swap"):
            store.advance(journal, RestorePhase.RESTORED, {"inventory": "first"})
        with pytest.raises(HostRestoreError, match="not durable"):
            open_gate(store)
        assert store.read() == current
    (root / "restore-gate.json").unlink()
    assert not admitted(root, caddy=True)


@pytest.mark.parametrize(
    "damage", ["unknown", "short-id", "duplicate", "noncanonical", "missing-receipt", "coercion"]
)
def test_hostile_journal_cannot_supply_restore_authority(
    journal: RestoreJournal, damage: str
) -> None:
    value = json.loads(journal.to_bytes())
    if damage == "unknown":
        value["open"] = True
    elif damage == "short-id":
        value["snapshotId"] = "abc123"
    elif damage == "missing-receipt":
        value["phase"] = "complete"
    elif damage == "coercion":
        value["phase"] = 1
    raw = canonical_json_bytes(value)
    if damage == "duplicate":
        raw = raw.replace(b'{"bindings":', b'{"schema":"other","bindings":', 1)
    elif damage == "noncanonical":
        raw += b"\n"
    with pytest.raises((HostRestoreError, BackupIdentityError, ValueError)):
        RestoreJournal.from_bytes(raw)


def test_changed_destination_and_unsafe_lock_are_not_new_attempt_authority(
    root: Path, journal: RestoreJournal
) -> None:
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        store.begin(journal)
        with pytest.raises(HostRestoreError, match="conflicts"):
            store.begin(replace(journal, snapshot_id="b" * 64))
    lock = root / "host-restore.lock"
    inode = lock.stat().st_ino
    lock.write_bytes(b"unsafe")
    with (
        pytest.raises((HostRestoreError, StatePathError)),
        RestoreStore.locked(root, owner=os.geteuid()),
    ):
        pytest.fail("unsafe lease was accepted")
    assert lock.stat().st_ino == inode and lock.read_bytes() == b"unsafe"
