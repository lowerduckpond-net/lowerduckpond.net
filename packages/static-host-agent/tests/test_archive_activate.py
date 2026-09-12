from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent.archive_activate import activate_archive_transition
from lowerduckpond_static_host_agent.archive_commit import ArchiveCommitBoundary
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_prepare import (
    PreparedArchiveTransition,
    prepare_archive_transition,
)
from lowerduckpond_static_host_agent.archive_recover import reconstruct_archive_transition
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes
from test_archive_journal import (
    _DEPLOYMENT,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    OpenGate,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)
from test_route_commit import _Entropy, _Runtime


class SimulatedCrashError(RuntimeError):
    pass


@contextmanager
def _prepared(
    tmp_path: Path, lifecycle: str, *, selected_generation: str | None = None
) -> Iterator[tuple[ArchiveJournal, DeploymentReleaseStore, PreparedArchiveTransition, _Runtime]]:
    with prepared_source(tmp_path, MemoryRemote(), lifecycle=lifecycle) as (
        journal,
        job_id,
        snapshot,
        _quarantine,
    ):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        runtime = _Runtime()
        with journal.repository.publication_transaction() as transaction:
            observed = transaction.read(StateRecordPath.tenant_observed(_TENANT)).document
            runtime.active = selected_generation or cast(
                str, observed["runtimeGenerationId"] or runtime.active
            )
            runtime.running = runtime.active
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
            path = StateRecordPath.authorization_job(job_id)
            job = transaction.read(path)
            bound = job.document
            bound["dispatchDeploymentIds"] = list(transaction.tenant_deployment_ids(_TENANT))
            transaction.bind_dispatch_authority(path, job.revision, bound)
        root = tmp_path / "sites"
        root.chmod(0o710)
        (root / ".staging").mkdir(mode=0o700)
        with DeploymentReleaseStore(
            root,
            root / ".staging",
            expected_owner=_OWNER,
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store:
            prepared = prepare_archive_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                OpenGate(),
                job_id,
                uploaded.construction.document["intentId"],
                now=_NOW,
                clock=lambda: 1_789_000_000_000,
                entropy=_Entropy(),
            )
            yield journal, store, prepared, runtime


def _activate(
    journal: ArchiveJournal,
    store: DeploymentReleaseStore,
    prepared: PreparedArchiveTransition,
    runtime: _Runtime,
) -> None:
    result = activate_archive_transition(
        journal.repository,
        journal.spool,
        cast(CaddyRuntime, runtime),
        store,
        OpenGate(),
        prepared,
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
    )
    assert result.result == prepared.plan.result


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_archive_activates_complete_candidate_before_local_commit(
    tmp_path: Path, lifecycle: str
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, store, prepared, runtime):
        _activate(journal, store, prepared, runtime)
        assert runtime.active == runtime.running == prepared.candidate_manifest.generation_id
        assert runtime.snapshots[runtime.active].tenants == ()
        assert (tmp_path / "sites" / _TENANT / "releases").is_dir()
        assert "restored" not in runtime.events
        journal.finish(prepared.plan.construction_intent_id)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_archive_reload_failure_preserves_exact_source_routes_and_releases(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, store, prepared, runtime):
        source = runtime.active

        def fail(_source: PinnedCaddyGeneration, candidate: PinnedCaddyGeneration) -> None:
            runtime.running = candidate.manifest.generation_id
            raise TimeoutError("partial reload")

        with pytest.raises(TimeoutError, match="partial reload"):
            activate_archive_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                store,
                OpenGate(),
                prepared,
                reloader=fail,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
        assert runtime.active == runtime.running == source
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).document
            == prepared.plan.intent["sourceManifest"]
        )
        assert (tmp_path / "sites" / _TENANT / "releases" / _DEPLOYMENT / "index.html").exists()
        with pytest.raises(FileNotFoundError):
            journal.repository.read(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT))
        _activate(journal, store, prepared, runtime)
        journal.finish(prepared.plan.construction_intent_id)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
@pytest.mark.parametrize(
    "boundary",
    [
        ArchiveCommitBoundary.ARCHIVE_RECORD_SYNC,
        ArchiveCommitBoundary.RELEASE_VERIFIED,
        ArchiveCommitBoundary.RESULT_SYNC,
    ],
)
def test_archive_recovers_forward_after_local_commit_begins(
    tmp_path: Path,
    lifecycle: str,
    boundary: ArchiveCommitBoundary,
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, store, prepared, runtime):
        source = runtime.active

        def interrupt(observed: ArchiveCommitBoundary) -> None:
            if observed is boundary:
                raise SimulatedCrashError

        with pytest.raises(SimulatedCrashError):
            activate_archive_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                store,
                OpenGate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
                commit_failure_hook=interrupt,
            )
        runtime.running = source
        runtime.events.clear()
        _activate(journal, store, prepared, runtime)
        assert runtime.active == runtime.running == prepared.candidate_manifest.generation_id
        assert "restored" not in runtime.events
        journal.finish(prepared.plan.construction_intent_id)


def test_archive_capacity_failure_during_recovery_keeps_no_route_candidate_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _prepared(tmp_path, "active") as (journal, store, prepared, runtime):
        source = runtime.active

        def interrupt(boundary: ArchiveCommitBoundary) -> None:
            if boundary is ArchiveCommitBoundary.RELEASE_VERIFIED:
                raise SimulatedCrashError

        with pytest.raises(SimulatedCrashError):
            activate_archive_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                store,
                OpenGate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
                commit_failure_hook=interrupt,
            )
        runtime.running = source
        runtime.events.clear()
        with monkeypatch.context() as limited:
            limited.setattr(
                "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
                lambda _self: FilesystemCapacity(1, 4096, 8_000_000, 0, 4_000_000, 3_000_000),
            )
            with pytest.raises(CapacityRejectedError):
                recovered = reconstruct_archive_transition(
                    journal.repository,
                    journal.spool,
                    cast(CaddyRuntime, runtime),
                    OpenGate(),
                    prepared.job.document["jobId"],
                )
                _activate(journal, store, recovered, runtime)
        assert runtime.active == runtime.running == prepared.candidate_manifest.generation_id
        assert "restored" not in runtime.events
        _activate(journal, store, prepared, runtime)
        journal.finish(prepared.plan.construction_intent_id)
