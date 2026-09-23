from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent.backup_caddy import (
    CaddyBackupEvidence,
    CaddyGenerationEvidence,
)
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput, build_tenant_caddy_routes
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartTarget
from lowerduckpond_static_host_agent.create_commit import CreateCommitBoundary
from lowerduckpond_static_host_agent.host_restore_create import reconcile_create
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.lifecycle_plan import CreateTransitionPlan
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from test_create_commit import _capacity_isolated as _capacity_isolated  # noqa: PLC0414
from test_create_commit import _fixture, _prepared_create, _state_root
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin


def prepare(tmp_path: Path) -> tuple[StateRepository, StoredContract, CreateTransitionPlan]:
    repository, job, plan = _prepared_create(_state_root(tmp_path))
    repository.create_immutable(
        StateRecordPath.platform_namespace(), _fixture("platform-namespace.json")
    )
    correlation = {**job.document, "phase": "pending"}
    request = cast(dict[str, object], correlation["request"])
    repository.create_immutable(
        StateRecordPath.authorization_correlation(request["correlationId"]), correlation
    )
    return repository, job, plan


def evidence(plan: CreateTransitionPlan, choice: str) -> CaddyBackupEvidence:
    recorded = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    identifier = str(recorded[choice + "RuntimeGenerationId"])
    routes = build_tenant_caddy_routes(
        platform_namespace=_fixture("platform-namespace.json"),
        tenants=()
        if choice == "source"
        else (TenantRouteInput(plan.manifest, plan.observed_state, None),),
        runtime_generation_id=identifier,
        origin_pull_ca_der=CA,
        origin_pull_required=True,
    )
    return CaddyBackupEvidence(
        identifier,
        None,
        (
            CaddyGenerationEvidence(
                CaddyStartTarget(identifier, "a" * 64),
                cast(dict[str, str], routes.route_metadata["routeStateDigest"]),
            ),
        ),
    )


@pytest.mark.parametrize("prefix", ["absent", "namespace", "desired", "complete"])
@pytest.mark.parametrize("choice", ["source", "candidate"])
def test_create_restores_exact_absence_or_completes_original_undeployed_identity(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    prefix: str,
    choice: str,
) -> None:
    repository, job, plan = prepare(tmp_path)
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        selected = evidence(plan, choice)
        begin(store, journal)
        with repository.publication_transaction() as transaction:
            if prefix != "absent":
                transaction.ensure_create_tenant_namespace(plan.tenant_id)
            if prefix in {"desired", "complete"}:
                transaction.create_immutable(
                    StateRecordPath.tenant_desired(plan.tenant_id), plan.manifest
                )
            if prefix == "complete":
                transaction.create_immutable(
                    StateRecordPath.tenant_observed(plan.tenant_id), plan.observed_state
                )
            decision = reconcile_create(store, transaction, plan.intent_id, selected, CA)
            assert reconcile_create(store, transaction, plan.intent_id, selected, CA) == decision
            result = transaction.read(
                StateRecordPath.authorization_result(job.document["jobId"])
            ).document
            if choice == "source":
                assert result["status"] == "failed" and result["tenantId"] is None
                assert result["errorCode"] == "unavailable"
                assert plan.tenant_id not in transaction.measure_inventory().tenant_ids
            else:
                assert result == plan.result
                assert (
                    transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
                    == plan.manifest
                )
            assert transaction.inspect_audit().entry_count == 1
            assert not transaction.measure_intent_records().records


@pytest.mark.parametrize("boundary", list(CreateCommitBoundary))
def test_candidate_create_resumes_each_commit_boundary_with_original_identity(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    boundary: CreateCommitBoundary,
) -> None:
    repository, job, plan = prepare(tmp_path)
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        selected = evidence(plan, "candidate")
        begin(store, journal)

        def stop(step: CreateCommitBoundary) -> None:
            if step is boundary:
                raise RuntimeError("interrupted create restore")

        with (
            repository.publication_transaction() as transaction,
            pytest.raises(RuntimeError, match="interrupted create restore"),
        ):
            reconcile_create(store, transaction, plan.intent_id, selected, CA, failure_hook=stop)
        with repository.publication_transaction() as transaction:
            reconcile_create(store, transaction, plan.intent_id, selected, CA)
            assert (
                transaction.read(
                    StateRecordPath.authorization_result(job.document["jobId"])
                ).document
                == plan.result
            )
            assert transaction.inspect_audit().entry_count == 1
            assert not transaction.measure_intent_records().records


def test_source_selection_does_not_authorize_discarding_unrelated_tenant_records(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
) -> None:
    repository, _job, plan = prepare(tmp_path)
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        selected = evidence(plan, "source")
        begin(store, journal)
        with repository.publication_transaction() as transaction:
            transaction.ensure_create_tenant_state(
                plan.tenant_id, plan.manifest, plan.observed_state
            )
            path = StateRecordPath.tenant_desired(plan.tenant_id)
            current = transaction.read(path)
            document = current.document
            cast(dict[str, object], document["metadata"])["slug"] = "unrelated"
            transaction.compare_and_swap(path, current.revision, document)
            with pytest.raises(HostRestoreError, match="candidate_changed"):
                reconcile_create(store, transaction, plan.intent_id, selected, CA)
            assert transaction.read(path).document == document
            assert transaction.inspect_audit().entry_count == 0
