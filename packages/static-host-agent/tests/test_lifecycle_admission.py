from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import archive_handler, archive_journal, archive_prepare
from lowerduckpond_static_host_agent.archive_abort import finalize_failed_construction
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal, ArchiveRetirementJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS, AuditCapacityError
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.correlations import CorrelationAdmission, CorrelationResolution
from lowerduckpond_static_host_agent.execution import AuthorizationExecutor
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer, VerifiedArtifact
from lowerduckpond_static_host_agent.job_runtime import StartupReconciler
from lowerduckpond_static_host_agent.locks import LockName, StateBusyError
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.state_inventory import (
    DEFAULT_STATE_INVENTORY_LIMITS,
    StateAdmissionRejectedError,
    StateInventoryProjection,
    StateInventoryReservation,
)
from test_archive_activate import _activate, _prepared
from test_archive_handler import _host
from test_archive_journal import (
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    OpenGate,
    _entropy,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)
from test_job_runtime import _CaptureHandoff
from test_restore_commit import _restore, _restoring


def _spare_inodes(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    filesystem = FilesystemCapacity(1, 4096, 8_000_000, 7_000_000, 1_000_000, 100_000 + count)
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _self: filesystem,
    )


def _assert_no_local_intent(tmp_path: Path) -> None:
    with (
        StateRepository(tmp_path / "state", expected_owner=_OWNER) as repository,
        repository.publication_transaction() as transaction,
    ):
        assert all(
            transaction.read_intent(value.intent_id)[1].document["kind"] != "TransactionIntent"
            for value in transaction.measure_intent_records().records
        )


@pytest.mark.parametrize("spare,accepted", [(6, False), (7, True)])
def test_archive_admits_its_intent_and_terminal_batch_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spare: int, accepted: bool
) -> None:
    preparing = _prepared(
        tmp_path, "active", before_prepare=lambda: _spare_inodes(monkeypatch, spare)
    )
    if not accepted:
        with pytest.raises(CapacityRejectedError, match="free-inode floor"), preparing:
            pytest.fail("archive published an intent without capacity for its terminal batch")
        _assert_no_local_intent(tmp_path)
    else:
        with preparing as (journal, store, prepared, runtime):
            _spare_inodes(monkeypatch, spare - 1)
            _activate(journal, store, prepared, runtime)
            journal.finish(prepared.plan.construction_intent_id)
            assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize("spare,accepted", [(6, False), (7, True)])
def test_restore_admits_its_intent_and_terminal_batch_after_writing_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spare: int, accepted: bool
) -> None:
    preparing = _restoring(
        tmp_path, monkeypatch, before_prepare=lambda: _spare_inodes(monkeypatch, spare)
    )
    if not accepted:
        with pytest.raises(CapacityRejectedError, match="free-inode floor"), preparing:
            pytest.fail("restore published an intent without capacity for its terminal batch")
        _assert_no_local_intent(tmp_path)
        assert not list((tmp_path / "sites/.staging").iterdir())
    else:
        with preparing as (journal, store, prepared, runtime):
            _spare_inodes(monkeypatch, spare - 1)
            _restore(journal, store, prepared, runtime)
            journal.finish(str(prepared.retirement.document["intentId"]))
            assert not journal.repository.measure_intent_records().records


def test_archive_requires_terminal_audit_headroom_before_any_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        # Enough for the old journal-only check, but not the terminal audit segment.
        available = (5 * 1024**3 + 1024**2) // 4096
        filesystem = FilesystemCapacity(1, 4096, 8_000_000, available, 4_000_000, 3_000_000)
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
            lambda _self: filesystem,
        )
        with pytest.raises(CapacityRejectedError, match="free-block floor"):
            journal.construct(job_id, snapshot, now=_NOW)
        assert "put" not in remote.calls
        assert not remote.versions
        assert not journal.repository.measure_intent_records().records


def test_restore_cannot_cancel_retirement_after_its_local_intent_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _restoring(tmp_path, monkeypatch) as (journal, store, prepared, runtime):
        before = journal.repository.measure_intent_records().records
        retirement = ArchiveRetirementJournal(
            journal.repository, journal.spool, bucket=journal.remote.bucket
        )
        assert not retirement.cancel_unstarted_retirement(
            str(prepared.job.document["jobId"]), prepared.retirement
        )
        assert journal.repository.measure_intent_records().records == before
        _restore(journal, store, prepared, runtime)
        journal.finish(str(prepared.retirement.document["intentId"]))
        assert not journal.repository.measure_intent_records().records


def test_archive_retires_an_upload_if_later_capacity_refuses_local_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise CapacityRejectedError("terminal batch no longer fits")

    with _host(tmp_path) as (executor, job_id, repository, remote, runtime, futures):
        source = repository.read(StateRecordPath.tenant_desired(_TENANT))
        selected = runtime.active
        monkeypatch.setattr(archive_prepare, "admit_archive_records", refuse)
        outcome = executor.execute(job_id)
        assert outcome.result["status"] == "failed"
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).revision == source.revision
        assert runtime.active == runtime.running == selected
        assert "discarded" in runtime.events
        assert remote.calls.count("put") == 1
        assert not remote.versions
        assert not repository.measure_intent_records().records
        for future in futures:
            future.result(timeout=5)


@pytest.mark.parametrize("ceiling", ["records", "bytes", "audit"])
def test_archive_admits_logical_terminal_capacity_before_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ceiling: str
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        if ceiling == "audit":
            monkeypatch.setattr(
                archive_journal,
                "DEFAULT_AUDIT_LIMITS",
                replace(DEFAULT_AUDIT_LIMITS, maximum_ordinary_bytes=0),
            )
        else:
            inventory = journal.repository.measure_inventory()
            allocated = inventory.authorization_allocated_bytes
            limits = replace(
                DEFAULT_STATE_INVENTORY_LIMITS,
                **(
                    {"maximum_authorization_records": inventory.authorization_record_count}
                    if ceiling == "records"
                    else {"maximum_authorization_allocated_bytes": allocated}
                ),
            )
            original = _StateTransaction.admit_inventory

            def admit(
                transaction: _StateTransaction, reservation: StateInventoryReservation
            ) -> StateInventoryProjection:
                return original(transaction, reservation, limits=limits)

            monkeypatch.setattr(_StateTransaction, "admit_inventory", admit)
        with pytest.raises((StateAdmissionRejectedError, AuditCapacityError)):
            journal.construct(job_id, snapshot, now=_NOW)
        assert "put" not in remote.calls
        assert not journal.repository.measure_intent_records().records


def test_construction_preserves_terminal_capacity_while_exact_retries_remain_available(
    tmp_path: Path,
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        issuer = AuthorizationIssuer(journal.repository, gate=OpenGate(), entropy=_entropy)
        request = cast(
            dict[str, object],
            journal.repository.read(StateRecordPath.authorization_job(job_id)).document["request"],
        )

        def issue(candidate: dict[str, object]) -> object:
            return issuer.issue(
                canonical_json_bytes(candidate),
                operator_principal="operator@example.test",
                now=_NOW + timedelta(seconds=1),
                artifact=None,
            )

        before = journal.repository.measure_inventory()
        issue(request)
        new_request = {**request, "correlationId": "0198d17f-6f4a-7000-8000-000000000010"}
        with pytest.raises(StateBusyError, match=r"export.lock is busy"):
            issue(new_request)
        assert journal.repository.measure_inventory() == before
        finalize_failed_construction(journal.repository, journal.spool, job_id)
        journal.finish(str(uploaded.construction.document["intentId"]))
        issue(new_request)


@pytest.mark.parametrize("source_drift", [False, True])
def test_pending_jobs_cannot_spend_construction_terminal_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_drift: bool
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        pending = AuthorizationIssuer(journal.repository, gate=OpenGate(), entropy=_entropy).issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": "suspend",
                    "tenantId": _TENANT,
                    "correlationId": "0198d17f-6f4a-7000-8000-000000000010",
                }
            ),
            operator_principal="operator@example.test",
            now=_NOW + timedelta(seconds=1),
            artifact=None,
        )
        inventory = journal.repository.measure_inventory()
        limits = replace(
            DEFAULT_STATE_INVENTORY_LIMITS,
            maximum_authorization_records=inventory.authorization_record_count + 1,
        )
        admit = _StateTransaction.admit_inventory

        def limited_admit(
            transaction: _StateTransaction, reservation: StateInventoryReservation
        ) -> StateInventoryProjection:
            return admit(transaction, reservation, limits=limits)

        with monkeypatch.context() as patch:
            patch.setattr(_StateTransaction, "admit_inventory", limited_admit)
            uploaded = journal.construct(job_id, snapshot, now=_NOW)
            if source_drift:
                desired_path = StateRecordPath.tenant_desired(_TENANT)
                source = journal.repository.read(desired_path)
                changed = source.document
                cast(dict[str, object], cast(dict[str, object], changed["spec"])["quotas"])[
                    "storageMiB"
                ] = 99
                journal.repository.compare_and_swap(desired_path, source.revision, changed)
            (tmp_path / "state" / "intake").mkdir(mode=0o700)
            with ArtifactIntake(tmp_path / "state", expected_owner=_OWNER) as intake:
                executor = AuthorizationExecutor(journal.repository, intake)
                with pytest.raises(StateBusyError, match=r"export.lock is busy"):
                    executor.execute(pending.job_id)
            assert journal.repository.measure_inventory() == inventory
            assert journal.repository.inspect_audit().entry_count == 0
            assert (
                journal.repository.read(StateRecordPath.authorization_job(pending.job_id)).document[
                    "phase"
                ]
                == "pending"
            )
            finalize_failed_construction(journal.repository, journal.spool, job_id)
            journal.finish(str(uploaded.construction.document["intentId"]))
            assert not remote.versions
            assert not journal.repository.measure_intent_records().records
        with ArtifactIntake(tmp_path / "state", expected_owner=_OWNER) as intake:
            result = AuthorizationExecutor(journal.repository, intake).execute(pending.job_id)
            assert result.result["status"] == "failed"


def test_failed_construction_retires_only_its_upload_after_source_drift_and_collection(
    tmp_path: Path,
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        desired_path = StateRecordPath.tenant_desired(_TENANT)
        source = journal.repository.read(desired_path)
        changed = source.document
        cast(dict[str, object], cast(dict[str, object], changed["spec"])["quotas"])[
            "storageMiB"
        ] = 99
        drifted = journal.repository.compare_and_swap(desired_path, source.revision, changed)
        deployment_path = StateRecordPath.tenant_deployment(_TENANT, snapshot.deployment["id"])
        (tmp_path / "state").joinpath(*deployment_path.components).unlink()
        result = finalize_failed_construction(journal.repository, journal.spool, job_id).result
        assert result["archiveRecord"] == uploaded.record
        journal.finish(str(uploaded.construction.document["intentId"]))
        assert not remote.versions
        assert not journal.repository.measure_intent_records().records
        assert journal.repository.read(desired_path).revision == drifted.revision


def test_archive_handler_routes_prepublication_drift_through_durable_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def drift(*_args: object, **_kwargs: object) -> None:
        raise archive_prepare.ArchiveAuthorityDriftError("selected runtime drifted")

    with _host(tmp_path) as (executor, job_id, repository, remote, _runtime, futures):
        monkeypatch.setattr(archive_handler, "prepare_archive_transition", drift)
        assert executor.execute(job_id).result["status"] == "failed"
        assert not remote.versions
        assert not repository.measure_intent_records().records
        for future in futures:
            future.result(timeout=5)


@pytest.mark.parametrize("missing_copy", ["job", "correlation"])
def test_pair_repairs_wait_for_construction_without_blocking_owner_recovery(  # noqa: PLR0915 - interrupted admission, restart, owner recovery, and resumed repair
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_copy: str
) -> None:
    remote = MemoryRemote()
    root = tmp_path / "state"
    payload = b"durable intake must survive deferred pair repair"
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation = "0198d17f-6f4a-7000-8000-000000000010"
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        pending = AuthorizationIssuer(journal.repository, gate=OpenGate(), entropy=_entropy).issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": "deploy",
                    "tenantId": _TENANT,
                    "correlationId": correlation,
                    "artifact": {"size": artifact.size, "sha256": artifact.sha256},
                }
            ),
            operator_principal="operator@example.test",
            now=_NOW + timedelta(seconds=1),
            artifact=artifact,
        )
        # Reproduce an admitted intake and interrupted pair from durable files.
        (root / "intake").mkdir(mode=0o700)
        artifact_path = root / "intake" / f"{correlation}.artifact"
        artifact_path.write_bytes(payload)
        artifact_path.chmod(0o600)
        missing = (
            StateRecordPath.authorization_job(pending.job_id)
            if missing_copy == "job"
            else StateRecordPath.authorization_correlation(correlation)
        )
        missing_path = root.joinpath(*missing.components)
        missing_path.unlink()
        inventory = journal.repository.measure_inventory()
        limits = replace(
            DEFAULT_STATE_INVENTORY_LIMITS,
            maximum_authorization_records=inventory.authorization_record_count + 1,
        )
        original_admit = _StateTransaction.admit_inventory
        monkeypatch.setattr(
            _StateTransaction,
            "admit_inventory",
            lambda tx, reservation, **_kwargs: original_admit(tx, reservation, limits=limits),
        )
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        archive_remote = journal.remote

    # Startup holds intake before state; the interrupted construction has
    # released its process locks while its durable reservation remains.
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ArtifactIntake(root, expected_owner=_OWNER) as intake,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        admission = CorrelationAdmission(repository, limits=limits)
        binding = {
            key: pending.document[key]
            for key in ("operatorPrincipal", "request", "requestDigest", "artifact")
        }
        retries: tuple[Callable[[], CorrelationResolution | None], ...] = (
            lambda: admission.resolve(pending.document, now=_NOW + timedelta(seconds=1)),
            lambda: admission.find_retry(correlation, binding=binding),
        )
        for retry in retries:
            if missing_copy == "job":
                with pytest.raises(StateBusyError, match=r"export.lock is busy"):
                    retry()
            else:
                resolved = retry()
                assert resolved is not None
                assert resolved.job.document["jobId"] == pending.job_id
                assert resolved.repaired_records == 0
        assert admission.reconcile().repaired_records == 0
        owner = repository.read(StateRecordPath.authorization_job(job_id)).document
        owner_request = cast(dict[str, object], owner["request"])
        assert (
            admission.find_retry(
                owner_request["correlationId"], binding={key: owner[key] for key in binding}
            )
            is not None
        )
        handoff = _CaptureHandoff()
        startup = StartupReconciler(repository, intake, handoff).reconcile()
        assert job_id in startup.enqueued_jobs
        assert (pending.job_id in startup.enqueued_jobs) is (missing_copy == "correlation")
        assert startup.deferred_jobs == int(missing_copy == "job")
        assert startup.removed_intake_entries == 0
        assert not missing_path.exists()
        assert repository.measure_inventory().authorization_record_count == (
            inventory.authorization_record_count
        )
        with spool.locks.acquire(LockName.EXPORT):
            quarantine = ArchiveQuarantine(
                root, bucket=archive_remote.bucket, expected_owner=_OWNER, locks=spool.locks
            )
            resumed_journal = ArchiveJournal(
                repository,
                spool,
                archive_remote,
                expected_owner=_OWNER,
                quarantine=quarantine.record,
                require_quarantine_empty=quarantine.require_empty,
            )
            finalize_failed_construction(repository, spool, job_id)
            resumed_journal.finish(str(uploaded.construction.document["intentId"]))
        assert not remote.versions
        assert not repository.measure_intent_records().records
        monkeypatch.setattr(_StateTransaction, "admit_inventory", original_admit)
        resumed = StartupReconciler(repository, intake, handoff).reconcile()
        assert resumed.repaired_pairs == 1
        assert pending.job_id in resumed.enqueued_jobs
        assert missing_path.exists()
        assert resumed.removed_intake_entries == 0
        assert artifact_path.read_bytes() == payload


def test_pending_failure_cannot_displace_a_prepared_restore_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pending_ids: list[str] = []

    def admit_pending() -> None:
        with StateRepository(tmp_path / "state", expected_owner=_OWNER) as repository:
            pending = AuthorizationIssuer(repository, gate=OpenGate(), entropy=_entropy).issue(
                canonical_json_bytes(
                    {
                        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                        "kind": "OperationRequest",
                        "operation": "delete",
                        "tenantId": _TENANT,
                        "correlationId": "0198d17f-6f4a-7000-8000-000000000020",
                    }
                ),
                operator_principal="operator@example.test",
                now=_NOW + timedelta(seconds=1),
                artifact=None,
            )
            pending_ids.append(pending.job_id)

    with _restoring(tmp_path, monkeypatch, before_retirement=admit_pending) as (
        journal,
        store,
        prepared,
        runtime,
    ):
        (tmp_path / "state/intake").mkdir(mode=0o700, exist_ok=True)
        audit = journal.repository.inspect_audit()
        pending_path = StateRecordPath.authorization_job(pending_ids[0])
        pending = journal.repository.read(pending_path)
        with (
            ArtifactIntake(tmp_path / "state", expected_owner=_OWNER) as intake,
            pytest.raises(StateBusyError, match=r"export.lock is busy"),
        ):
            AuthorizationExecutor(journal.repository, intake).execute(pending_ids[0])
        assert journal.repository.inspect_audit() == audit
        assert journal.repository.read(pending_path).revision == pending.revision
        with pytest.raises(FileNotFoundError):
            journal.repository.read(StateRecordPath.authorization_result(pending_ids[0]))
        _restore(journal, store, prepared, runtime)
        journal.finish(str(prepared.retirement.document["intentId"]))
        assert not journal.repository.measure_intent_records().records
