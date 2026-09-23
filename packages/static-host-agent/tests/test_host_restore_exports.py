from __future__ import annotations

import os
from multiprocessing import get_context
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.export_delivery import ExportDelivery
from lowerduckpond_static_host_agent.export_handler import ExportCommitBoundary
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_decisions import read_decision
from lowerduckpond_static_host_agent.host_restore_exports import (
    abandon_uncommitted_export,
    finish_export_intent,
    retire_restored_export,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordError,
    StateRecordPath,
    StateRepository,
)
from test_export_handler import _KILLED_STATUS, _NOW, _execute, _issue, _killed_export, _source
from test_export_handler import _filesystem as _filesystem  # noqa: PLC0414 - actual export fixture
from test_host_restore_journal import journal as journal  # noqa: PLC0414


@pytest.mark.parametrize(
    "boundary",
    [
        ExportCommitBoundary.INTENT_SYNC,
        ExportCommitBoundary.BUNDLE_PUBLISHED,
        ExportCommitBoundary.AUDIT_SYNC,
    ],
)
def test_excluded_uncommitted_export_retries_only_without_audit(
    tmp_path: Path, journal: RestoreJournal, boundary: ExportCommitBoundary
) -> None:
    state, releases, _ = _source(tmp_path)
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        job_id = _issue(repository)
    process = get_context("fork").Process(
        target=_killed_export, args=(state, releases, job_id, boundary)
    )
    process.start()
    try:
        process.join(20)
        assert not process.is_alive() and process.exitcode == _KILLED_STATUS
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
    # Restic excludes the entire export spool, including private construction.
    with (
        ExportSpool(state, expected_owner=os.geteuid()) as spool,
        spool.locks.acquire(LockName.EXPORT, mode=LockMode.EXCLUSIVE),
    ):
        completed = spool.completed_job_id()
        if completed is not None:
            spool.remove_completed(completed)
        spool.discard_workspace()
    recovery = state.parent / "recovery"
    recovery.mkdir(mode=0o700)
    with (
        RestoreStore.locked(recovery, owner=os.geteuid()) as store,
        StateRepository(state, expected_owner=os.geteuid()) as repository,
        repository.publication_transaction() as transaction,
    ):
        store.begin(journal)
        current = store.advance(journal, RestorePhase.RESTORED, {"captured": True})
        current = store.advance(current, RestorePhase.VALIDATED, {"measured": True})
        identity = transaction.measure_intent_records().records[0]
        original = transaction.read_intent(identity.intent_id)[1].document
        if boundary is ExportCommitBoundary.AUDIT_SYNC:
            with pytest.raises(HostRestoreError, match="source_changed"):
                abandon_uncommitted_export(store, transaction, job_id, identity.intent_id)
            assert transaction.read_intent(identity.intent_id)[1].document == original
            return
        decision = abandon_uncommitted_export(store, transaction, job_id, identity.intent_id)
        assert (
            abandon_uncommitted_export(store, transaction, job_id, identity.intent_id) == decision
        )
        assert not transaction.measure_intent_records().records
        with pytest.raises(FileNotFoundError):
            transaction.read(StateRecordPath.authorization_result(job_id))
        store.advance(current, RestorePhase.RECONCILED, {"decisions": [decision]})
    assert _execute(state, releases, job_id).result["status"] == "succeeded"


@pytest.mark.parametrize("claimed", [False, True])
def test_lost_delivery_replays_exact_result_without_recreating_or_extending_export(
    tmp_path: Path,
    journal: RestoreJournal,
    claimed: bool,
) -> None:
    state, releases, _manifest = _source(tmp_path)
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        job_id = _issue(repository)
    if claimed:
        process = get_context("fork").Process(
            target=_killed_export, args=(state, releases, job_id, ExportCommitBoundary.RESULT_SYNC)
        )
        process.start()
        try:
            process.join(20)
            assert not process.is_alive() and process.exitcode == _KILLED_STATUS
        finally:
            if process.is_alive():
                process.kill()
                process.join(10)
            process.close()
        with StateRepository(state, expected_owner=os.geteuid()) as repository:
            result = repository.read(StateRecordPath.authorization_result(job_id)).document
    else:
        result = _execute(state, releases, job_id).result
    (state / "exports" / f"{job_id}.zip").unlink()
    result_path = state / "authorization/results" / f"{job_id}.json"
    result_bytes = result_path.read_bytes()
    recovery = state.parent / "recovery"
    recovery.mkdir(mode=0o700)
    with (
        RestoreStore.locked(recovery, owner=os.geteuid()) as store,
        StateRepository(
            state, expected_owner=os.geteuid(), private_reconciliation=True
        ) as repository,
        repository.publication_transaction() as transaction,
    ):
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        captured = job.document
        assert captured["phase"] == ("claimed" if claimed else "completed")
        store.begin(journal)
        current = store.advance(journal, RestorePhase.RESTORED, {"captured": True})
        current = store.advance(current, RestorePhase.VALIDATED, {"measured": True})
        decision = retire_restored_export(store, transaction, captured, result)
        assert retire_restored_export(store, transaction, captured, result) == decision
        with pytest.raises(HostRestoreError, match="uncommitted"):
            read_decision(recovery, str(decision["name"]), owner=os.geteuid())
        finish_export_intent(transaction, job_id)
        store.advance(current, RestorePhase.RECONCILED, {"decisions": [decision]})
    for _ in range(2):
        assert _execute(state, releases, job_id).result == result
    with (
        StateRepository(state, expected_owner=os.geteuid()) as repository,
        ExportSpool(state, expected_owner=os.geteuid()) as spool,
    ):
        delivery = ExportDelivery(repository, spool, now=lambda: _NOW)
        with delivery.download(job_id, result) as remaining:
            assert remaining is None
        stored = repository.read(StateRecordPath.authorization_job(job_id)).document
        assert stored["acceptedAt"] == captured["acceptedAt"]
        assert stored["exportDelivery"] == captured["exportDelivery"] == "unacknowledged"
        assert stored["executionValidated"] is True
        assert result_path.read_bytes() == result_bytes
        assert not list((state / "exports").iterdir())


@pytest.mark.parametrize(
    "fault", ["unbound", "decision", "result", "job", "regenerated", "missing"]
)
def test_retirement_is_not_a_generic_missing_bundle_exception(
    tmp_path: Path,
    journal: RestoreJournal,
    fault: str,
) -> None:
    state, releases, _manifest = _source(tmp_path)
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        job_id = _issue(repository)
    result = _execute(state, releases, job_id).result
    bundle = state / "exports" / f"{job_id}.zip"
    delivery_bytes = bundle.read_bytes()
    bundle.unlink()
    recovery = state.parent / "recovery"
    recovery.mkdir(mode=0o700)
    with (
        RestoreStore.locked(recovery, owner=os.geteuid()) as store,
        StateRepository(state, expected_owner=os.geteuid()) as repository,
        repository.publication_transaction() as transaction,
    ):
        job = transaction.read(StateRecordPath.authorization_job(job_id)).document
        store.begin(journal)
        current = store.advance(journal, RestorePhase.RESTORED, {"captured": True})
        current = store.advance(current, RestorePhase.VALIDATED, {"measured": True})
        decision = retire_restored_export(store, transaction, job, result)
        store.advance(
            current,
            RestorePhase.RECONCILED,
            {"decisions": [] if fault == "unbound" else [decision]},
        )
        path = recovery / str(decision["name"])
        if fault == "decision":
            path.write_bytes(b"{}\n")
        elif fault == "result":
            result = {
                **result,
                "exportBundle": {"digest": {"format": "sha256", "value": "0" * 64}, "size": 1},
            }
        elif fault == "job":
            job = {**job, "operatorPrincipal": "another@example.test"}
        elif fault == "regenerated":
            bundle.write_bytes(delivery_bytes)
            bundle.chmod(0o600)
        elif fault == "missing":
            path.unlink()
        if fault == "missing":
            assert not transaction.restored_export_retired(job, result)
        else:
            with pytest.raises((HostRestoreError, StateRecordError, ValueError, RuntimeError)):
                transaction.restored_export_retired(job, result)
    if fault in {"result", "job"}:
        assert _execute(state, releases, job_id).result["status"] == "succeeded"
    else:
        with pytest.raises((HostRestoreError, StateRecordError, ValueError, RuntimeError)):
            _execute(state, releases, job_id)
