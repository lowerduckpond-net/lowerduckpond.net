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
from lowerduckpond_static_host_agent.deployment_commit import DeploymentCommitBoundary
from lowerduckpond_static_host_agent.host_restore_deployments import reconcile_deployment
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_deployment_commit import _capacity_isolated as _capacity_isolated  # noqa: PLC0414
from test_deployment_commit import _prepared, _write_correlation
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin


def evidence(
    repository: StateRepository, plan: DeploymentTransitionPlan, choice: str
) -> CaddyBackupEvidence:
    recorded = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    identifier = str(recorded[choice + "RuntimeGenerationId"])
    manifest = cast(dict[str, object], plan.intent[choice + "Manifest"])
    observed = cast(dict[str, object], recorded[choice + "ObservedState"])
    reference = cast(dict[str, object], manifest["spec"]).get("desiredDeployment")
    deployment = (
        plan.deployment
        if choice == "candidate"
        else None
        if reference is None
        else repository.read(
            StateRecordPath.tenant_deployment(
                plan.tenant_id, cast(dict[str, object], reference)["id"]
            )
        ).document
    )
    routes = build_tenant_caddy_routes(
        platform_namespace=repository.read(StateRecordPath.platform_namespace()).document,
        tenants=()
        if cast(dict[str, object], manifest["spec"])["desiredState"] == "archived"
        else (TenantRouteInput(manifest, observed, deployment),),
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


@pytest.mark.parametrize(
    "operation,state",
    [
        ("deploy", "active"),
        ("deploy", "suspended"),
        ("import", "undeployed"),
        ("rollback", "active"),
        ("rollback", "suspended"),
    ],
)
@pytest.mark.parametrize("choice", ["source", "candidate"])
def test_deployment_restore_uses_durable_release_and_preserves_suspension(  # noqa: PLR0913, PLR0917 - operation/state/selection matrix
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    operation: str,
    state: str,
    choice: str,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=0 if state == "undeployed" else 3,
        state=state,
    )
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(repository, plan, choice)
        begin(store, journal)
        with repository.publication_transaction() as transaction:
            decision = reconcile_deployment(
                store,
                transaction,
                cast(DeploymentReleaseStore, releases),
                plan.intent_id,
                selected,
                CA,
            )
            assert (
                reconcile_deployment(
                    store,
                    transaction,
                    cast(DeploymentReleaseStore, releases),
                    plan.intent_id,
                    selected,
                    CA,
                )
                == decision
            )
            result = transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
            assert result["status"] == ("succeeded" if choice == "candidate" else "failed")
            if choice == "source":
                assert result["errorCode"] == "unavailable"
                assert transaction.tenant_deployment_ids(plan.tenant_id) == tuple(
                    cast(list[str], job["dispatchDeploymentIds"])
                )
            assert (
                transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
                == plan.intent[choice + "Manifest"]
            )
            assert not transaction.measure_intent_records().records
            assert transaction.inspect_audit().entry_count == 1


@pytest.mark.parametrize("operation", ["deploy", "rollback"])
@pytest.mark.parametrize("boundary", list(DeploymentCommitBoundary))
def test_candidate_resumes_partial_record_release_retirement_and_result_commit(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    operation: str,
    boundary: DeploymentCommitBoundary,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path, operation=operation, deployment_count=3, state="active"
    )
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(repository, plan, "candidate")
        begin(store, journal)

        def stop(step: DeploymentCommitBoundary) -> None:
            if step is boundary:
                raise RuntimeError("interrupted deployment restore")

        with (
            repository.publication_transaction() as transaction,
            pytest.raises(RuntimeError, match="interrupted deployment restore"),
        ):
            reconcile_deployment(
                store,
                transaction,
                cast(DeploymentReleaseStore, releases),
                plan.intent_id,
                selected,
                CA,
                failure_hook=stop,
            )
        with repository.publication_transaction() as transaction:
            reconcile_deployment(
                store,
                transaction,
                cast(DeploymentReleaseStore, releases),
                plan.intent_id,
                selected,
                CA,
            )
            assert (
                transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
                == plan.result
            )
            assert not transaction.measure_intent_records().records
            assert transaction.inspect_audit().entry_count == 1


@pytest.mark.parametrize(
    "fault", ["candidate-release", "missing-candidate", "source-release", "retired-source-history"]
)
def test_selected_generation_cannot_replace_missing_or_corrupt_release_authority(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    fault: str,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path, operation="deploy", deployment_count=3, state="active"
    )
    choice = "candidate" if fault in {"candidate-release", "missing-candidate"} else "source"
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(repository, plan, choice)
        candidate_id = str(plan.deployment["id"])
        source_id = cast(list[str], job["dispatchDeploymentIds"])[0]
        if fault == "missing-candidate":
            del releases.releases[candidate_id]
        elif fault == "retired-source-history":
            with repository.publication_transaction() as transaction:
                record = transaction.read(
                    StateRecordPath.tenant_deployment(plan.tenant_id, source_id)
                )
                transaction.remove_exact_deployment(
                    record, transaction.deployment_removal_token(record)
                )
        else:
            identifier = candidate_id if fault == "candidate-release" else source_id
            releases.releases[identifier] = {**releases.releases[identifier], "value": "f" * 64}
        begin(store, journal)
        with repository.publication_transaction() as transaction:
            before = transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            with pytest.raises((HostRestoreError, FileNotFoundError)):
                reconcile_deployment(
                    store,
                    transaction,
                    cast(DeploymentReleaseStore, releases),
                    plan.intent_id,
                    selected,
                    CA,
                )
            assert (
                transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document == before
            )
            assert transaction.inspect_audit().entry_count == 0
            assert transaction.measure_intent_records().records
