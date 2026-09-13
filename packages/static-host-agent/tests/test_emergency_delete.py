from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from lowerduckpond_static_contracts import manifest_digest, request_digest
from lowerduckpond_static_host_agent import emergency_entrypoint, entrypoints
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine, quarantine_present
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.audit import AuditAppend, AuditLimits, AuditState
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.correlations import (
    CorrelationAdmission,
    CorrelationConflictError,
)
from lowerduckpond_static_host_agent.create_commit import finalize_create_transition
from lowerduckpond_static_host_agent.emergency_delete import (
    EmergencyDeletion,
    EmergencyDeletionError,
)
from lowerduckpond_static_host_agent.emergency_remote import finish_emergency_retirement
from lowerduckpond_static_host_agent.execution import _later_audited_results
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from test_archive_activate import _activate, _prepared
from test_archive_journal import (
    _BUCKET,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    fixture,
    setup_root,
    write,
)
from test_correlations import _BASE_TIME, _candidate
from test_create_commit import _prepared_create, _state_root
from test_route_commit import _Entropy, _Runtime

_CORRELATION = "0198d17f-6f4a-7000-8000-000000000030"
_REASON = "verified administrative deletion"
_PRINCIPAL = "ldp-admin"


class InterruptedEmergencyError(BaseException):
    pass


class _EmergencyRuntime(_Runtime):
    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        if generation_id not in self.snapshots:
            raise FileNotFoundError
        return super().read_generation_route_snapshot(generation_id)


@contextmanager
def _emergency(
    tmp_path: Path, lifecycle: str
) -> Iterator[tuple[EmergencyDeletion, str, MemoryRemote]]:
    memory = MemoryRemote()
    remote = ArchiveRemoteStore(memory, bucket=_BUCKET)
    tenant = _TENANT
    runtime = _EmergencyRuntime()
    if lifecycle == "archived":
        with _prepared(tmp_path, "active") as (journal, store, prepared, archive_runtime):
            _activate(journal, store, prepared, archive_runtime)
            journal.finish(prepared.plan.construction_intent_id)
            remote = journal.remote
            runtime.active, runtime.running = archive_runtime.active, archive_runtime.running
        root, releases = tmp_path / "state", tmp_path / "sites"
    elif lifecycle == "undeployed":
        root = _state_root(tmp_path)
        (root / "exports").mkdir(mode=0o700)
        write(root, StateRecordPath.platform_namespace(), fixture("platform-namespace.json"))
        repository, job, creation = _prepared_create(root)
        with repository, repository.publication_transaction() as transaction:
            finalize_create_transition(transaction, job, creation)
        tenant = creation.tenant_id
        releases = tmp_path / "sites"
        releases.mkdir(mode=0o710)
        (releases / ".staging").mkdir(mode=0o700)
    else:
        root, releases = setup_root(tmp_path)
        releases.chmod(0o710)
        (releases / ".staging").mkdir(mode=0o700)
        if lifecycle == "suspended":
            with StateRepository(root, expected_owner=_OWNER) as repository:
                source = repository.read(StateRecordPath.tenant_desired(tenant)).document
                cast(dict[str, object], source["spec"])["desiredState"] = lifecycle
                observed = repository.read(StateRecordPath.tenant_observed(tenant)).document
            observed.update(
                observedState=lifecycle,
                runtimeGenerationId=None,
                desiredManifestDigest=manifest_digest(source).to_dict(),
            )
            write(root, StateRecordPath.tenant_desired(tenant), source)
            write(root, StateRecordPath.tenant_observed(tenant), observed)
    memory = cast(MemoryRemote, remote.client)
    memory.require_intent = False
    memory.expected_intent = root / "intents"
    with (
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        DeploymentReleaseStore(
            releases,
            releases / ".staging",
            expected_owner=_OWNER,
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store,
    ):
        with repository.publication_transaction() as transaction:
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
        quarantine = ArchiveQuarantine(
            root, bucket=remote.bucket, expected_owner=_OWNER, locks=spool.locks
        )
        journal = ArchiveJournal(
            repository,
            spool,
            remote,
            expected_owner=_OWNER,
            quarantine=quarantine.record,
            require_quarantine_empty=quarantine.require_empty,
        )
        handler = EmergencyDeletion(
            repository,
            spool,
            cast(CaddyRuntime, runtime),
            store,
            cleanup=partial(finish_emergency_retirement, journal),
            now=lambda: _NOW,
            clock=lambda: 1_790_000_000_000,
            entropy=_Entropy(),
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )
        yield handler, tenant, memory


@pytest.mark.parametrize("lifecycle", ["undeployed", "active", "suspended", "archived"])
@pytest.mark.parametrize(
    "boundary",
    [
        None,
        "authority-sync",
        "candidate-published",
        "candidate-selected",
        "audit-sync",
        "state-record-removed",
        "tenant-removed",
        "result-sync",
        "intent-removed",
        "remote-cleaned",
    ],
)
def test_emergency_deletion_recovers_with_distinct_administrator_authority(
    tmp_path: Path, lifecycle: str, boundary: str | None
) -> None:
    with _emergency(tmp_path, lifecycle) as (handler, tenant, memory):

        def interrupt(value: str) -> None:
            if value == boundary:
                raise InterruptedEmergencyError

        if boundary is not None:
            handler.hook = interrupt
            with pytest.raises(InterruptedEmergencyError):
                handler.execute(tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON)
        handler.hook = lambda _value: None
        result = handler.execute(
            tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON
        )
        assert result["provenance"] == {
            "kind": "emergency-administrator",
            "operatorPrincipal": _PRINCIPAL,
            "reason": _REASON,
        }
        assert not (tmp_path / "state" / "tenants" / tenant).exists()
        assert not (tmp_path / "sites" / tenant).exists()
        assert not memory.versions
        assert not handler.repository.measure_intent_records().records
        assert (
            handler.execute(tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON)
            == result
        )
        with pytest.raises(EmergencyDeletionError):
            handler.execute(
                tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason="another reason"
            )


@pytest.mark.parametrize("lifecycle", ["undeployed", "archived"])
def test_emergency_tombstone_remains_visible_to_ordinary_result_history(
    tmp_path: Path, lifecycle: str
) -> None:
    with _emergency(tmp_path, lifecycle) as (handler, tenant, _memory):
        with handler.repository.publication_transaction() as transaction:
            earlier = transaction.read(
                StateRecordPath.authorization_result(
                    transaction.measure_authorization_records().result_ids[0]
                )
            ).document
        result = handler.execute(
            tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON
        )
        with handler.repository.publication_transaction() as transaction:
            later = _later_audited_results(transaction, earlier)
        assert tuple(value.result for value in later) == (result,)


@pytest.mark.parametrize(
    "collision,audit_only", [("correlation", False), ("job", False), ("correlation", True)]
)
def test_completed_emergency_authority_cannot_be_reused_by_ordinary_admission(
    tmp_path: Path, collision: str, audit_only: bool
) -> None:
    with _emergency(tmp_path, "undeployed") as (handler, tenant, _memory):
        handler.execute(tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON)
        assert not handler.repository.measure_intent_records().records
        if audit_only:
            (tmp_path / "state").joinpath(
                *StateRecordPath.emergency_result(_CORRELATION).components
            ).unlink()
        candidate = _candidate(99)
        if collision == "job":
            candidate["jobId"] = _CORRELATION
        else:
            request = cast(dict[str, object], candidate["request"])
            request["correlationId"] = _CORRELATION
            candidate["requestDigest"] = request_digest(request).to_dict()
        CorrelationAdmission(handler.repository).reconcile()
        before = handler.repository.measure_inventory()
        with pytest.raises(CorrelationConflictError):
            CorrelationAdmission(handler.repository).resolve(candidate, now=_BASE_TIME)
        assert handler.repository.measure_inventory() == before


@pytest.mark.parametrize("boundary", [None, "audit-sync"])
def test_emergency_deletion_uses_the_administrator_audit_reserve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str | None
) -> None:
    limits = AuditLimits(maximum_ordinary_bytes=0)
    admit = _StateTransaction.admit_audit_append
    append = _StateTransaction.append_audit

    def limited_admit(
        transaction: _StateTransaction, document: dict[str, object], *, administrator: bool = False
    ) -> AuditState:
        return admit(transaction, document, administrator=administrator, limits=limits)

    def limited_append(
        transaction: _StateTransaction, document: dict[str, object], *, administrator: bool = False
    ) -> AuditAppend:
        return append(transaction, document, administrator=administrator, limits=limits)

    with _emergency(tmp_path, "undeployed") as (handler, tenant, _memory):
        monkeypatch.setattr(_StateTransaction, "admit_audit_append", limited_admit)
        monkeypatch.setattr(_StateTransaction, "append_audit", limited_append)

        def interrupt(value: str) -> None:
            if value == boundary:
                raise InterruptedEmergencyError

        if boundary is not None:
            handler.hook = interrupt
            with pytest.raises(InterruptedEmergencyError):
                handler.execute(tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON)
        handler.hook = lambda _value: None
        result = handler.execute(
            tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON
        )
        assert result["status"] == "succeeded"
        assert not handler.repository.measure_intent_records().records
        state = handler.repository.inspect_audit()
        assert (
            limits.maximum_ordinary_bytes
            < state.allocated_bytes
            <= limits.maximum_administrator_bytes
        )


@pytest.mark.parametrize("inventory_failure", [False, True])
def test_root_recovery_resolves_quarantine_after_emergency_retirement_disappears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inventory_failure: bool
) -> None:
    with _emergency(tmp_path, "archived") as (handler, tenant, _memory):
        cleanup = cast(partial[None], handler.cleanup)

        def fail_after_retirement(
            retirement: dict[str, object] | None, audit: dict[str, object]
        ) -> None:
            cleanup(retirement, audit)
            journal = cast(ArchiveJournal, cleanup.args[0])
            quarantine = ArchiveQuarantine(
                tmp_path / "state",
                bucket=journal.remote.bucket,
                expected_owner=_OWNER,
                locks=journal.spool.locks,
            )
            quarantine.record(None)
            if inventory_failure:
                with monkeypatch.context() as patch:

                    def unavailable() -> None:
                        raise TimeoutError("inventory unavailable")

                    patch.setattr(journal.remote, "inventory", unavailable)
                    quarantine.resolve(journal.repository, journal.remote)
            raise OSError("exit after retirement, before quarantine resolution")

        handler.cleanup = fail_after_retirement
        with pytest.raises((OSError, TimeoutError)):
            handler.execute(tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON)
        journal = cast(ArchiveJournal, cleanup.args[0])
        assert not journal.repository.measure_intent_records().records
        assert (tmp_path / "state/platform/archive-quarantine.json").exists()
        remote = journal.remote
        calls = tuple(cast(MemoryRemote, remote.client).calls)
    _local_recovery_entrypoint(tmp_path, monkeypatch)
    monkeypatch.setattr(
        emergency_entrypoint,
        "load_archive_configuration",
        lambda: SimpleNamespace(remote_store=lambda: remote),
    )
    assert emergency_entrypoint.emergency_delete_main(["--recover"]) == 0
    assert not (tmp_path / "state/platform/archive-quarantine.json").exists()
    assert cast(MemoryRemote, remote.client).calls[len(calls) :].count("delete") == 0


def _local_recovery_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr(entrypoints, "_STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(
        emergency_entrypoint,
        "StateRepository",
        lambda path, expected_owner: StateRepository(path, expected_owner=_OWNER),
    )
    monkeypatch.setattr(
        emergency_entrypoint,
        "ExportSpool",
        lambda path, expected_owner: ExportSpool(path, expected_owner=_OWNER),
    )
    monkeypatch.setattr(
        emergency_entrypoint,
        "ArchiveQuarantine",
        lambda path, bucket, expected_owner, locks: ArchiveQuarantine(
            path, bucket=bucket, expected_owner=_OWNER, locks=locks
        ),
    )
    monkeypatch.setattr(
        emergency_entrypoint,
        "quarantine_present",
        lambda path, expected_owner, locks: quarantine_present(
            path, expected_owner=_OWNER, locks=locks
        ),
    )


def test_idle_root_recovery_needs_no_archive_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _emergency(tmp_path, "active"):
        _local_recovery_entrypoint(tmp_path, monkeypatch)

        def unexpected_configuration() -> None:
            pytest.fail("idle recovery attempted to load archive credentials")

        monkeypatch.setattr(
            emergency_entrypoint, "load_archive_configuration", unexpected_configuration
        )
        assert emergency_entrypoint.emergency_delete_main(["--recover"]) == 0
