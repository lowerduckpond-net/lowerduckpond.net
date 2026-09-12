from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent.archive_activate import activate_archive_transition
from lowerduckpond_static_host_agent.archive_commit import ArchiveCommitBoundary
from lowerduckpond_static_host_agent.archive_recover import (
    ArchiveRecoveryError,
    reconstruct_archive_transition,
)
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.lifecycle_plan import LifecyclePlanError
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.route_snapshot import TenantRouteSnapshot
from test_archive_activate import SimulatedCrashError, _activate, _prepared
from test_archive_journal import (
    OpenGate,
    capacity,  # noqa: F401 - shared autouse capacity fixture
)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
@pytest.mark.parametrize(
    "boundary",
    [value for value in ArchiveCommitBoundary if value is not ArchiveCommitBoundary.INTENT_REMOVED],
)
def test_archive_recovery_reconstructs_every_partial_commit_from_durable_evidence(
    tmp_path: Path,
    lifecycle: str,
    boundary: ArchiveCommitBoundary,
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, store, prepared, runtime):

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
        recovered = reconstruct_archive_transition(
            journal.repository,
            journal.spool,
            cast(CaddyRuntime, runtime),
            OpenGate(),
            prepared.job.document["jobId"],
        )
        assert recovered.plan == prepared.plan
        _activate(journal, store, recovered, runtime)
        journal.finish(prepared.plan.construction_intent_id)
        assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize(
    "defect", ["source-snapshot", "candidate-snapshot", "construction", "lost-construction"]
)
def test_archive_recovery_rejects_changed_generation_or_construction_evidence(
    tmp_path: Path,
    defect: str,
) -> None:
    with _prepared(tmp_path, "active") as (journal, _store, prepared, runtime):
        selected = runtime.active
        if defect == "source-snapshot":
            before = runtime.snapshots[selected]
            runtime.snapshots[selected] = TenantRouteSnapshot(before.platform_namespace, ())
        elif defect == "candidate-snapshot":
            runtime.snapshots[prepared.candidate_manifest.generation_id] = deepcopy(
                runtime.snapshots[selected]
            )
        elif defect == "construction":
            path = StateRecordPath.archive_construction_intent(prepared.plan.construction_intent_id)
            stored = journal.repository.read(path)
            changed = stored.document
            changed["versionId"] = "another-version"
            journal.repository.compare_and_swap(path, stored.revision, changed)
        else:
            path = StateRecordPath.archive_construction_intent(prepared.plan.construction_intent_id)
            (tmp_path / "state").joinpath(*path.components).unlink()
        runtime.events.clear()
        with pytest.raises((ArchiveRecoveryError, LifecyclePlanError)):
            reconstruct_archive_transition(
                journal.repository,
                journal.spool,
                cast(CaddyRuntime, runtime),
                OpenGate(),
                prepared.job.document["jobId"],
            )
        assert runtime.active == selected
        assert not any(event.startswith("selected:") for event in runtime.events)


def test_archive_recovery_preserves_observed_source_and_newer_complete_host_generation(
    tmp_path: Path,
) -> None:
    selected = "0198d17f-6f4a-7000-8000-000000000999"
    with _prepared(tmp_path, "active", selected_generation=selected) as (
        journal,
        store,
        prepared,
        runtime,
    ):
        recovery = cast(dict[str, object], prepared.plan.intent["archiveRecovery"])
        observed = cast(dict[str, object], recovery["sourceObservedState"])
        assert observed["runtimeGenerationId"] != selected
        assert recovery["sourceRuntimeGenerationId"] == selected
        reconstructed = reconstruct_archive_transition(
            journal.repository,
            journal.spool,
            cast(CaddyRuntime, runtime),
            OpenGate(),
            prepared.job.document["jobId"],
        )
        assert reconstructed.plan == prepared.plan

        def reload(source: PinnedCaddyGeneration, candidate: PinnedCaddyGeneration) -> None:
            assert source.manifest.generation_id == selected
            assert runtime.active == candidate.manifest.generation_id
            runtime.running = candidate.manifest.generation_id

        activate_archive_transition(
            journal.repository,
            journal.spool,
            cast(CaddyRuntime, runtime),
            store,
            OpenGate(),
            reconstructed,
            reloader=reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )
        journal.finish(prepared.plan.construction_intent_id)
