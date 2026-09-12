from __future__ import annotations

from pathlib import Path
from typing import cast

import lowerduckpond_static_host_agent.archive_prepare as prepare_module
import pytest
from lowerduckpond_static_host_agent.archive_prepare import (
    ArchiveAuthorityDriftError,
    ArchivePreparationError,
    prepare_archive_transition,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import HostCapacityLimits
from lowerduckpond_static_host_agent.lifecycle_plan import ArchiveTransitionPlan
from lowerduckpond_static_host_agent.repository import StateRecordPath, _StateTransaction
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from test_archive_journal import (
    _DEPLOYMENT,
    _NOW,
    _TENANT,
    MemoryRemote,
    OpenGate,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)
from test_route_commit import _Entropy, _Runtime


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_archive_preparation_retains_live_source_until_complete_candidate_is_durable(
    tmp_path: Path,
    lifecycle: str,
) -> None:
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
            runtime.active = cast(str, observed["runtimeGenerationId"] or runtime.active)
            runtime.running = runtime.active
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
        source_generation = runtime.active
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
        assert runtime.active == runtime.running == source_generation
        assert runtime.snapshots[prepared.candidate_manifest.generation_id].tenants == ()
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).document
            == snapshot.source_manifest
        )
        assert (
            journal.repository.read(StateRecordPath.tenant_observed(_TENANT)).document == observed
        )
        with pytest.raises(FileNotFoundError):
            journal.repository.read(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT))
        assert (
            journal.repository.read(
                StateRecordPath.transaction_intent(prepared.plan.intent_id)
            ).document
            == prepared.plan.intent
        )
        assert {
            entry.intent_id for entry in journal.repository.measure_intent_records().records
        } == {
            prepared.plan.intent_id,
            uploaded.construction.document["intentId"],
        }
        assert prepared.job.document["dispatchSourceObservedState"] == observed
        assert prepared.job.document["dispatchSourceRouteSet"] == (
            "both" if lifecycle == "active" else "absent"
        )


@pytest.mark.parametrize("defect", ["source-drift", "selected-routes"])
def test_archive_preparation_rejects_state_or_runtime_drift_before_publishing_candidate(
    tmp_path: Path,
    defect: str,
) -> None:
    with prepared_source(tmp_path, MemoryRemote()) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        runtime = _Runtime()
        with journal.repository.publication_transaction() as transaction:
            observed = transaction.read(StateRecordPath.tenant_observed(_TENANT)).document
            runtime.active = cast(str, observed["runtimeGenerationId"])
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
            if defect == "selected-routes":
                runtime.snapshots[runtime.active] = TenantRouteSnapshot(
                    runtime.snapshots[runtime.active].platform_namespace, ()
                )
            elif defect == "source-drift":
                path = StateRecordPath.tenant_desired(_TENANT)
                current = transaction.read(path)
                changed = current.document
                cast(dict[str, object], changed["metadata"])["slug"] = "changed-slug"
                transaction.compare_and_swap(path, current.revision, changed)
        with pytest.raises(ArchiveAuthorityDriftError):
            prepare_archive_transition(
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
        assert "published" not in runtime.events
        assert len(journal.repository.measure_intent_records().records) == 1


@pytest.mark.parametrize("after_write", [False, True])
def test_archive_preparation_retains_only_candidates_bound_by_durable_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after_write: bool,
) -> None:
    class SimulatedWriteError(RuntimeError):
        pass

    original = prepare_module._publish_intent

    def fail(
        transaction: _StateTransaction,
        plan: ArchiveTransitionPlan,
        *,
        capacity_limits: HostCapacityLimits,
    ) -> None:
        if after_write:
            original(transaction, plan, capacity_limits=capacity_limits)
        raise SimulatedWriteError

    with prepared_source(tmp_path, MemoryRemote()) as (journal, job_id, _snapshot, _quarantine):
        uploaded = journal.construct(job_id, _snapshot, now=_NOW)
        runtime = _Runtime()
        with journal.repository.publication_transaction() as transaction:
            observed = transaction.read(StateRecordPath.tenant_observed(_TENANT)).document
            runtime.active = cast(str, observed["runtimeGenerationId"])
            runtime.running = runtime.active
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
        monkeypatch.setattr(prepare_module, "_publish_intent", fail)
        with pytest.raises(ArchivePreparationError if after_write else SimulatedWriteError):
            prepare_archive_transition(
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
        assert runtime.active == runtime.running
        assert ("discarded" in runtime.events) is not after_write
        assert len(journal.repository.measure_intent_records().records) == 1 + int(after_write)
