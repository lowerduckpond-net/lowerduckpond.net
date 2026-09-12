from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest
import test_archive_journal as journal_fixtures
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.archive_bundle import (
    RemoteArchiveBundleSource,
    fetch_archive_bundle,
)
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.restore_activate import activate_restore_transition
from lowerduckpond_static_host_agent.restore_commit import RestoreCommitBoundary
from lowerduckpond_static_host_agent.restore_prepare import (
    PreparedRestoreTransition,
    prepare_restore_transition,
    reconstruct_restore_transition,
)
from test_archive_activate import _activate, _prepared
from test_archive_journal import (  # noqa: F401 - capacity fixture
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    OpenGate,
    capacity,
)
from test_route_commit import _Entropy, _Runtime


class InterruptedRestoreError(BaseException):
    pass


@contextmanager
def _restoring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, predecessors: bool = False
) -> Iterator[tuple[ArchiveJournal, DeploymentReleaseStore, PreparedRestoreTransition, _Runtime]]:
    for module in ("portable_bundle", "zip_structure"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.measure_filesystem_capacity_descriptor",
            lambda fd: FilesystemCapacity(
                os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
            ),
        )
    if predecessors:
        original_setup = journal_fixtures.setup_root

        def setup_with_history(path: Path) -> tuple[Path, Path]:
            root, releases = original_setup(path)
            with StateRepository(root, expected_owner=_OWNER) as repository:
                previous = repository.read(
                    StateRecordPath.tenant_deployment(_TENANT, journal_fixtures._DEPLOYMENT)
                ).document
            for identity in (
                "0191e2c5-0000-7000-8000-000000000001",
                "0191e2c6-0000-7000-8000-000000000001",
            ):
                record = {**previous, "id": identity}
                journal_fixtures.write(
                    root, StateRecordPath.tenant_deployment(_TENANT, identity), record
                )
                release = releases / _TENANT / "releases" / identity
                release.mkdir()
                (release / "index.html").write_text("archived bytes", encoding="ascii")
                (release / "index.html").chmod(0o644)
            return root, releases

        monkeypatch.setattr(journal_fixtures, "setup_root", setup_with_history)
    with _prepared(tmp_path, "active") as (archive_journal, store, prepared, runtime):
        _activate(archive_journal, store, prepared, runtime)
        archive_journal.finish(prepared.plan.construction_intent_id)
        remote = archive_journal.remote
        cast(MemoryRemote, remote.client).require_intent = False
        archive = prepared.plan.archive_record
    root, releases = tmp_path / "state", tmp_path / "sites"
    with (
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.locks.acquire(LockName.INTAKE),
        spool.construction(),
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
                    "operation": "restore",
                    "tenantId": _TENANT,
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
            ids = list(transaction.tenant_deployment_ids(_TENANT))
            claimed.update(
                dispatchDeploymentIds=ids,
                dispatchArchiveDeploymentIds=[archive["deploymentId"]],
                dispatchSourceReleaseTreeDigest=archive["releaseTreeDigest"],
                dispatchTenantIds=[_TENANT],
                dispatchTenantRecordHistories=[
                    {
                        "tenantId": _TENANT,
                        "archiveDeploymentIds": [archive["deploymentId"]],
                        "deploymentIds": ids,
                    }
                ],
            )
            transaction.bind_dispatch_authority(path, current.revision, claimed)
            source = transaction.read(StateRecordPath.tenant_desired(_TENANT)).document
        fetch_archive_bundle(
            RemoteArchiveBundleSource(remote),
            spool,
            archive,
            source,
            job_id=issued.job_id,
            expected_owner=_OWNER,
        )
        retirement = journal.prepare_retirement(issued.job_id, now=_NOW)
        restoration = prepare_restore_transition(
            repository,
            spool,
            cast(CaddyRuntime, runtime),
            store,
            OpenGate(),
            issued.job_id,
            str(retirement.document["intentId"]),
            now=_NOW,
            clock=lambda: 1_789_000_001_000,
            entropy=_Entropy(),
        )
        yield journal, store, restoration, runtime


def _restore(
    journal: ArchiveJournal,
    store: DeploymentReleaseStore,
    prepared: PreparedRestoreTransition,
    runtime: _Runtime,
    *,
    boundary: RestoreCommitBoundary | None = None,
) -> None:
    def reload(_source: PinnedCaddyGeneration, candidate: PinnedCaddyGeneration) -> None:
        runtime.running = candidate.manifest.generation_id

    def restore(source: PinnedCaddyGeneration) -> None:
        runtime.running = source.manifest.generation_id

    def verify(generation: PinnedCaddyGeneration) -> None:
        if runtime.running != generation.manifest.generation_id:
            raise RuntimeError("generation is not running")

    def interrupt(current: RestoreCommitBoundary) -> None:
        if current == boundary:
            raise InterruptedRestoreError

    result = activate_restore_transition(
        journal.repository,
        journal.spool,
        cast(CaddyRuntime, runtime),
        store,
        OpenGate(),
        prepared,
        reloader=reload,
        restorer=restore,
        verifier=verify,
        failure_hook=interrupt,
    )
    assert result.result == prepared.plan.result


@pytest.mark.parametrize(
    "boundary",
    [
        None,
        *(
            value
            for value in RestoreCommitBoundary
            if value
            not in {RestoreCommitBoundary.RELEASE_REMOVED, RestoreCommitBoundary.DEPLOYMENT_REMOVED}
        ),
    ],
)
def test_restore_commit_recovers_every_durable_boundary_and_retires_only_after_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: RestoreCommitBoundary | None
) -> None:
    with _restoring(tmp_path, monkeypatch) as (journal, store, prepared, runtime):
        memory = cast(MemoryRemote, journal.remote.client)
        calls = tuple(memory.calls)
        if boundary is not None:
            with pytest.raises(InterruptedRestoreError):
                _restore(journal, store, prepared, runtime, boundary=boundary)
            assert memory.versions
            assert tuple(memory.calls) == calls
        if boundary != RestoreCommitBoundary.INTENT_REMOVED:
            recovered = reconstruct_restore_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                store,
                OpenGate(),
                str(prepared.job.document["jobId"]),
            )
            _restore(journal, store, recovered, runtime)
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).document
            == prepared.plan.manifest
        )
        assert (
            journal.repository.read(StateRecordPath.tenant_observed(_TENANT)).document
            == prepared.plan.observed_state
        )
        assert runtime.active == runtime.running == prepared.candidate_manifest.generation_id
        with journal.repository.publication_transaction() as transaction:
            assert transaction.tenant_archive_ids(_TENANT) == ()
            assert store.published_inventory(publication_lock=transaction).tenant_releases == (
                (
                    _TENANT,
                    (
                        cast(dict[str, object], prepared.retirement.document["archiveRecord"])[
                            "deploymentId"
                        ],
                        prepared.plan.deployment["id"],
                    ),
                ),
            )
        assert memory.versions
        journal.finish(str(prepared.retirement.document["intentId"]))
        assert memory.versions == []
        assert journal.repository.measure_intent_records().records == ()


@pytest.mark.parametrize(
    "boundary", [RestoreCommitBoundary.RELEASE_REMOVED, RestoreCommitBoundary.DEPLOYMENT_REMOVED]
)
def test_restore_retention_cleanup_recovers_each_removal_with_source_still_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: RestoreCommitBoundary
) -> None:
    with _restoring(tmp_path, monkeypatch, predecessors=True) as (
        journal,
        store,
        prepared,
        runtime,
    ):
        with pytest.raises(InterruptedRestoreError):
            _restore(journal, store, prepared, runtime, boundary=boundary)
        assert cast(MemoryRemote, journal.remote.client).versions
        recovered = reconstruct_restore_transition(
            journal.repository,
            journal.spool,
            cast(CaddyRuntime, runtime),
            store,
            OpenGate(),
            str(prepared.job.document["jobId"]),
        )
        _restore(journal, store, recovered, runtime)
        with journal.repository.publication_transaction() as transaction:
            histories = transaction.tenant_deployment_ids(_TENANT)
            assert histories == (
                "0191e2c6-0000-7000-8000-000000000001",
                journal_fixtures._DEPLOYMENT,
                prepared.plan.deployment["id"],
            )
            assert store.published_inventory(publication_lock=transaction).tenant_releases == (
                (_TENANT, histories),
            )
        journal.finish(str(prepared.retirement.document["intentId"]))
        assert not journal.repository.measure_intent_records().records
