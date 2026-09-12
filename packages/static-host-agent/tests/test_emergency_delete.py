from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import manifest_digest
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.create_commit import finalize_create_transition
from lowerduckpond_static_host_agent.emergency_delete import (
    EmergencyDeletion,
    EmergencyDeletionError,
)
from lowerduckpond_static_host_agent.emergency_remote import finish_emergency_retirement
from lowerduckpond_static_host_agent.execution import _later_audited_results
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
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
