from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.create_commit import finalize_create_transition
from lowerduckpond_static_host_agent.delete_commit import DeleteCommitBoundary
from lowerduckpond_static_host_agent.delete_publication import (
    PreparedDeleteTransition,
    activate_delete_transition,
    prepare_delete_transition,
    reconstruct_delete_transition,
)
from lowerduckpond_static_host_agent.delete_state import DeleteStateError
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes
from test_archive_activate import _activate, _prepared
from test_archive_journal import (
    _BUCKET,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    OpenGate,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    fixture,
    write,
)
from test_create_commit import _prepared_create, _state_root
from test_route_commit import _Entropy, _Runtime


class InterruptedDeleteError(BaseException):
    pass


@contextmanager
def _deleting(
    tmp_path: Path, *, archived: bool
) -> Iterator[tuple[ArchiveJournal, DeploymentReleaseStore, PreparedDeleteTransition, _Runtime]]:
    if archived:
        with _prepared(tmp_path, "active") as (archive_journal, store, archive_prepared, runtime):
            _activate(archive_journal, store, archive_prepared, runtime)
            archive_journal.finish(archive_prepared.plan.construction_intent_id)
            remote = archive_journal.remote
        root, releases, tenant = tmp_path / "state", tmp_path / "sites", _TENANT
    else:
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
        remote = ArchiveRemoteStore(MemoryRemote(), bucket=_BUCKET)
        runtime = _Runtime()
    memory = cast(MemoryRemote, remote.client)
    memory.require_intent = False
    memory.expected_intent = root / "intents"
    with (
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.locks.acquire(LockName.EXPORT),
        DeploymentReleaseStore(
            releases,
            releases / ".staging",
            expected_owner=_OWNER,
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store,
    ):
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
        issued = AuthorizationIssuer(repository, gate=OpenGate(), entropy=_Entropy()).issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": "delete",
                    "tenantId": tenant,
                    "correlationId": "0198d17f-6f4a-7000-8000-000000000010",
                }
            ),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        with repository.publication_transaction() as transaction:
            path = StateRecordPath.authorization_job(issued.job_id)
            job = transaction.read(path)
            claimed = job.document
            claimed["phase"] = "claimed"
            current = transaction.compare_and_swap(path, job.revision, claimed)
            claimed.update(
                dispatchDeploymentIds=list(transaction.tenant_deployment_ids(tenant)),
                dispatchArchiveDeploymentIds=list(transaction.tenant_archive_ids(tenant)),
            )
            transaction.bind_dispatch_authority(path, current.revision, claimed)
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
        retirement = journal.prepare_retirement(issued.job_id, now=_NOW) if archived else None
        prepared = prepare_delete_transition(
            repository,
            spool,
            cast(CaddyRuntime, runtime),
            OpenGate(),
            issued.job_id,
            retirement,
            now=_NOW,
            clock=lambda: 1_789_000_001_000,
            entropy=_Entropy(),
        )
        yield journal, store, prepared, runtime


def _delete(
    journal: ArchiveJournal,
    store: DeploymentReleaseStore,
    prepared: PreparedDeleteTransition,
    runtime: _Runtime,
    *,
    boundary: DeleteCommitBoundary | None = None,
) -> None:
    def interrupt(current: DeleteCommitBoundary) -> None:
        if current == boundary:
            raise InterruptedDeleteError

    result = activate_delete_transition(
        journal.repository,
        journal.spool,
        cast(CaddyRuntime, runtime),
        store,
        OpenGate(),
        prepared,
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
        failure_hook=interrupt,
    )
    assert result.result == prepared.plan.result


@pytest.mark.parametrize(
    "archived,boundary",
    [
        (archived, boundary)
        for archived in (False, True)
        for boundary in (None, *DeleteCommitBoundary)
        if archived or boundary != DeleteCommitBoundary.RELEASE_REMOVED
    ],
)
def test_delete_recovers_each_durable_boundary_and_retains_permanent_evidence(
    tmp_path: Path, archived: bool, boundary: DeleteCommitBoundary | None
) -> None:
    with _deleting(tmp_path, archived=archived) as (journal, store, prepared, runtime):
        tenant = prepared.plan.tenant_id
        if boundary is not None:
            with pytest.raises(InterruptedDeleteError):
                _delete(journal, store, prepared, runtime, boundary=boundary)
            if archived:
                assert cast(MemoryRemote, journal.remote.client).versions
        if boundary != DeleteCommitBoundary.INTENT_REMOVED:
            recovered = reconstruct_delete_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                OpenGate(),
                str(prepared.job.document["jobId"]),
            )
            _delete(journal, store, recovered, runtime)
        assert not (tmp_path / "state" / "tenants" / tenant).exists()
        assert not (tmp_path / "sites" / tenant).exists()
        assert runtime.active == runtime.running == prepared.candidate_manifest.generation_id
        with journal.repository.publication_transaction() as transaction:
            assert tenant not in transaction.measure_inventory().tenant_ids
            assert transaction.tenant_has_identity_history(tenant)
            assert not transaction.tenant_has_creation_history(tenant)
            audit = transaction.inspect_audit_correlation(prepared.plan.intent["correlationId"])
            assert audit.entry == prepared.plan.audit_entry
        if prepared.retirement is not None:
            assert cast(MemoryRemote, journal.remote.client).versions
            journal.finish(str(prepared.retirement.document["intentId"]))
            assert not cast(MemoryRemote, journal.remote.client).versions
        assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize("archived", [False, True])
@pytest.mark.parametrize(
    "target", ["desired.json", "observed.json", "archives", "deployments", "."]
)
def test_delete_recovers_unlink_or_rmdir_before_parent_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, archived: bool, target: str
) -> None:
    if not archived and target == "archives":
        pytest.skip("never-deployed state has no archive directory")
    with _deleting(tmp_path, archived=archived) as (journal, store, prepared, runtime):
        tenant_root = tmp_path / "state" / "tenants" / prepared.plan.tenant_id
        removed = tenant_root if target == "." else tenant_root / target
        parent = removed.parent
        sync = os.fsync
        interrupted = False

        def fail_sync(descriptor: int) -> None:
            nonlocal interrupted
            if (
                not interrupted
                and Path(f"/proc/self/fd/{descriptor}").readlink() == parent
                and not removed.exists()
            ):
                interrupted = True
                raise InterruptedDeleteError
            sync(descriptor)

        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", fail_sync)
            with pytest.raises(InterruptedDeleteError):
                _delete(journal, store, prepared, runtime)
        assert interrupted
        assert journal.repository.tenant_has_identity_history(prepared.plan.tenant_id)
        recovered = reconstruct_delete_transition(
            journal.repository,
            journal.spool,
            cast(CaddyRuntime, runtime),
            OpenGate(),
            str(prepared.job.document["jobId"]),
        )
        _delete(journal, store, recovered, runtime)
        assert not tenant_root.exists()
        if prepared.retirement is not None:
            journal.finish(str(prepared.retirement.document["intentId"]))
        assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize("archived", [False, True])
def test_delete_preserves_unrecognized_state_entry(tmp_path: Path, archived: bool) -> None:
    with _deleting(tmp_path, archived=archived) as (journal, store, prepared, runtime):
        unknown = tmp_path / "state" / "tenants" / prepared.plan.tenant_id / "unexpected"
        unknown.write_bytes(b"must remain")

        with pytest.raises(DeleteStateError):
            _delete(journal, store, prepared, runtime)
        assert unknown.read_bytes() == b"must remain"
        with pytest.raises(FileNotFoundError):
            journal.repository.read(
                StateRecordPath.authorization_result(prepared.job.document["jobId"])
            )
