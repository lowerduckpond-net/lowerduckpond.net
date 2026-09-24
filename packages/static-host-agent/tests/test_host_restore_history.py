from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.host_restore_decisions import (
    commit_decision,
    read_decision,
    seal_decisions,
)
from lowerduckpond_static_host_agent.host_restore_gate import (
    INGRESS,
    close_gate,
    ingress_record,
    open_gate,
)
from lowerduckpond_static_host_agent.host_restore_history import (
    INVENTORY_NAME,
    MAX_HISTORY,
    import_prior_provenance,
    provenance_stores,
    require_backup_provenance,
    seal_provenance,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_routes import begin

NAME = "export-retirement-0198d17f-6f4a-7000-8000-000000000081.json"
PAYLOAD: dict[str, object] = {"kind": "export-retirement", "authority": "original"}
NEXT = "0198d17f-6f4a-7000-8000-000000000082"


def complete(store: RestoreStore, decisions: list[dict[str, object]]) -> None:
    current = store.read()
    assert current is not None
    current = store.advance(current, RestorePhase.RECONCILED, {"decisions": decisions})
    for phase in (RestorePhase.RUNTIME_PREPARED, RestorePhase.INSTALLED, RestorePhase.VERIFIED):
        current = store.advance(current, phase, {"testPhase": phase.value})
    digest = seal_provenance(store)
    assert seal_provenance(store) == digest
    store.advance(current, RestorePhase.COMPLETE, {"provenanceInventory": digest})
    open_gate(store)


def prior(source: Path, journal: RestoreJournal) -> dict[str, bytes]:
    source.mkdir(mode=0o700)
    with RestoreStore.locked(source, owner=os.geteuid()) as store:
        close_gate(store, journal.restore_id)
        begin(store, journal)
        decision = commit_decision(store, NAME, PAYLOAD)
        complete(store, [decision])
    require_backup_provenance(source, owner=os.geteuid())
    return {path.name: path.read_bytes() for path in source.iterdir()}


@pytest.mark.parametrize(
    "boundary", ["receipt", "rename", "source-sync", "target-sync", "parent-sync"]
)
def test_prior_rename_resumes_every_durability_boundary_without_rewriting_original_provenance(
    tmp_path: Path, journal: RestoreJournal, boundary: str
) -> None:
    source = tmp_path / "candidate"
    original = prior(source, journal)
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        next_journal = replace(journal, restore_id=NEXT)
        close_gate(store, NEXT)
        begin(store, next_journal)

        def interrupt(actual: str) -> None:
            if actual == boundary:
                raise RuntimeError("interrupted")

        with pytest.raises(RuntimeError, match="interrupted"):
            import_prior_provenance(store, source, failure_hook=interrupt)
        import_prior_provenance(store, source)
        import_prior_provenance(store, source)
        assert not source.exists()
        assert store.read().restore_id == NEXT  # type: ignore[union-attr]
        assert (root / "restore-gate.json").exists()
        restored = root / "history" / journal.restore_id
        assert {path.name: path.read_bytes() for path in restored.iterdir()} == original
        assert read_decision(root, NAME, owner=os.geteuid(), private_reconciliation=True) == PAYLOAD
        complete(store, [])
    require_backup_provenance(root, owner=os.geteuid())
    assert read_decision(root, NAME, owner=os.geteuid()) == PAYLOAD


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "lost",
        "altered",
        "mode",
        "hardlink",
        "symlink",
        "gate",
        "ingress",
        "inventory",
        "unjournaled",
    ],
)
def test_backup_rejects_incomplete_unknown_or_changed_recovery_provenance(
    tmp_path: Path, journal: RestoreJournal, fault: str
) -> None:
    source = tmp_path / "recovery"
    prior(source, journal)
    if fault == "unknown":
        path = source / "unknown.json"
        path.write_bytes(canonical_json_bytes({"unknown": True}))
        path.chmod(0o600)
    elif fault == "lost":
        (source / NAME).unlink()
    elif fault == "altered":
        path = source / NAME
        path.write_bytes(path.read_bytes().replace(b"original", b"modified"))
    elif fault == "mode":
        (source / NAME).chmod(0o644)
    elif fault == "hardlink":
        os.link(source / NAME, tmp_path / "external")
    elif fault == "symlink":
        path = source / NAME
        path.rename(tmp_path / NAME)
        path.symlink_to(tmp_path / NAME)
    elif fault == "gate":
        with RestoreStore.locked(source, owner=os.geteuid()) as store:
            close_gate(store, journal.restore_id)
    elif fault == "ingress":
        with RestoreStore.locked(source, owner=os.geteuid()) as store:
            store.immutable(INGRESS[0], ingress_record(store))
    elif fault == "inventory":
        (source / INVENTORY_NAME).write_bytes(canonical_json_bytes({"files": []}))
    elif fault == "unjournaled":
        (source / "host-restore.json").unlink()
    with pytest.raises((HostRestoreError, StatePathError, FileNotFoundError)):
        require_backup_provenance(source, owner=os.geteuid())


def test_ancestor_decision_still_requires_its_original_phase_binding(
    tmp_path: Path, journal: RestoreJournal
) -> None:
    source = tmp_path / "candidate"
    prior(source, journal)
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        begin(store, replace(journal, restore_id=NEXT))
        import_prior_provenance(store, source)
        path = root / "history" / journal.restore_id / NAME
        path.write_bytes(path.read_bytes().replace(b"original", b"modified"))
        with pytest.raises(HostRestoreError, match="reconciled_history"):
            read_decision(root, NAME, owner=os.geteuid(), private_reconciliation=True)


@pytest.mark.parametrize("damage", ["source", "target", "history", "prior-journal"])
def test_interrupted_import_cannot_adopt_an_unknown_inode_or_prior_transaction(
    tmp_path: Path, journal: RestoreJournal, damage: str
) -> None:
    source = tmp_path / "candidate"
    prior(source, journal)
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        begin(store, replace(journal, restore_id=NEXT))

        def interrupt(actual: str) -> None:
            if actual == "receipt":
                raise RuntimeError("receipt synced")

        with pytest.raises(RuntimeError):
            import_prior_provenance(store, source, failure_hook=interrupt)
        if damage == "source":
            source.rename(tmp_path / "original")
            source.mkdir(mode=0o700)
        elif damage == "target":
            (root / "history").mkdir(mode=0o700)
            (root / "history" / journal.restore_id).mkdir(mode=0o700)
        elif damage == "history":
            (root / "history").symlink_to(source, target_is_directory=True)
        else:
            (source / "complete.json").unlink()
        with pytest.raises((HostRestoreError, StatePathError, FileNotFoundError)):
            import_prior_provenance(store, source)
        assert store.read().phase is RestorePhase.VALIDATED  # type: ignore[union-attr]


def test_bounded_nested_history_is_linear_and_missing_or_extra_ancestor_blocks(
    tmp_path: Path, journal: RestoreJournal
) -> None:
    source = tmp_path / "candidate-0"
    prior(source, journal)
    for generation in range(1, MAX_HISTORY):
        destination = tmp_path / f"candidate-{generation}"
        destination.mkdir(mode=0o700)
        current_id = f"0198d17f-6f4a-7000-8000-{generation + 100:012d}"
        with RestoreStore.locked(destination, owner=os.geteuid()) as store:
            begin(store, replace(journal, restore_id=current_id))
            import_prior_provenance(store, source)
            complete(store, [])
            with provenance_stores(store, deep=True) as stores:
                assert len(stores) == generation + 1
        source = destination
    require_backup_provenance(source, owner=os.geteuid())
    with (
        RestoreStore.locked(source, owner=os.geteuid()) as store,
        provenance_stores(store, deep=True) as stores,
    ):
        assert len(stores) == MAX_HISTORY
    assert read_decision(source, NAME, owner=os.geteuid()) == PAYLOAD
    destination = tmp_path / "over-limit"
    destination.mkdir(mode=0o700)
    with RestoreStore.locked(destination, owner=os.geteuid()) as store:
        begin(store, replace(journal, restore_id=NEXT))
        with pytest.raises(HostRestoreError, match="history_bound"):
            import_prior_provenance(store, source)
    (source / "history" / NEXT).mkdir(mode=0o700)
    with pytest.raises(HostRestoreError, match="unclassified"):
        require_backup_provenance(source, owner=os.geteuid())


def test_empty_provenance_is_allowed_but_incomplete_restore_cannot_be_backed_up(
    tmp_path: Path, journal: RestoreJournal
) -> None:
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    require_backup_provenance(root, owner=os.geteuid())
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        require_backup_provenance(root, owner=os.geteuid())
        store.begin(journal)
        for phase in PHASES[1:-1]:
            with pytest.raises(HostRestoreError, match="incomplete"):
                require_backup_provenance(root, owner=os.geteuid())
            journal = store.advance(journal, phase, {})


def test_large_decision_set_is_bound_outside_journal_and_drift_cannot_be_hidden(
    tmp_path: Path, journal: RestoreJournal
) -> None:
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        begin(store, journal)
        commit_decision(store, NAME, PAYLOAD)
        original = (root / NAME).read_bytes()
        # Independent prepared on-disk fixture, beyond the journal's byte bound.
        # seal_decisions must read and bind the whole set, not truncate its tail.
        large_decision_count = 1600
        for number in range(large_decision_count):
            name = f"export-retirement-0198d17f-6f4a-7000-8000-{number + 200:012d}.json"
            path = root / name
            path.write_bytes(original)
            path.chmod(0o600)
        digest = seal_decisions(store)
        assert seal_decisions(store) == digest
        ledger = (root / "decisions.json").read_bytes()
        assert len(ledger) > MAX_RESTORE_BYTES
        rows = decode_json_object(ledger, maximum_bytes=2 * 1024 * 1024)["decisions"]
        assert isinstance(rows, list)
        assert len(rows) == large_decision_count + 1
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisionsDigest": digest})
        assert len(current.to_bytes()) < MAX_RESTORE_BYTES
        assert read_decision(root, NAME, owner=os.geteuid()) == PAYLOAD
        changed = ledger.replace(NAME.encode(), NAME.replace("0081", "0091").encode())
        assert changed != ledger
        (root / "decisions.json").write_bytes(changed)
        with pytest.raises(HostRestoreError, match="ledger_invalid"):
            read_decision(root, NAME, owner=os.geteuid())
