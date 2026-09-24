"""Recover deploy/import/rollback from captured selection and durable releases."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

from lowerduckpond_static_contracts import platform_state_digest, validate_uuid7

from lowerduckpond_static_host_agent import deployment_recover as recovery
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.deployment_commit import (
    DeploymentCommitFailureHook,
    finalize_deployment_transition_outcome,
    validate_deployment_transition,
)
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore
from lowerduckpond_static_host_agent.host_restore_routes import (
    _original,
    _restore_source,
    _snapshot,
)
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.release_tree import ReleaseTreeError
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import snapshot_other_tenant_routes


def _selected_deployment(
    transaction: _StateTransaction, tenant_id: str, manifest: dict[str, object]
) -> dict[str, object] | None:
    desired = cast(dict[str, object], manifest["spec"]).get("desiredDeployment")
    if desired is None:
        return None
    if type(desired) is not dict:
        raise HostRestoreError("restore_deployment_source_invalid")
    return transaction.read(StateRecordPath.tenant_deployment(tenant_id, desired["id"])).document


def _source_history(
    transaction: _StateTransaction,
    releases: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
) -> None:
    history = job.document.get("dispatchDeploymentIds")
    if type(history) is not list or any(type(value) is not str for value in history):
        raise HostRestoreError("restore_deployment_history_unavailable")
    current = set(
        transaction.tenant_deployment_transition_ids(
            plan.tenant_id, candidate_id=plan.deployment["id"]
        )
        if plan.creates_deployment
        else transaction.tenant_deployment_ids(plan.tenant_id)
    )
    allowed = set(history) | ({str(plan.deployment["id"])} if plan.creates_deployment else set())
    if not set(history) <= current or not current <= allowed:
        raise HostRestoreError("restore_deployment_history_changed")
    for identifier in history:
        record = transaction.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, identifier)
        ).document
        measured = releases.measure(plan.tenant_id, identifier, publication_lock=transaction)
        if measured.digest.to_dict() != record["releaseTreeDigest"]:
            raise HostRestoreError("restore_deployment_source_release_changed")
    if plan.creates_deployment:
        path = StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"])
        if (
            str(plan.deployment["id"]) in current
            and transaction.read(path).document != plan.deployment
        ):
            raise HostRestoreError("restore_deployment_candidate_changed")
        try:
            measured = releases.measure(
                plan.tenant_id, plan.deployment["id"], publication_lock=transaction
            )
        except (FileNotFoundError, ReleaseTreeError) as error:
            if isinstance(error, FileNotFoundError) or isinstance(
                error.__cause__, FileNotFoundError
            ):
                return
            raise
        if measured.digest.to_dict() != plan.deployment["releaseTreeDigest"]:
            raise HostRestoreError("restore_deployment_candidate_release_changed")


def _discard_candidate(
    transaction: _StateTransaction, releases: DeploymentReleaseStore, plan: DeploymentTransitionPlan
) -> None:
    if not plan.creates_deployment:
        return
    path = StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"])
    try:
        stored = transaction.read(path)
    except FileNotFoundError:
        stored = None
    if stored is not None and stored.document != plan.deployment:
        raise HostRestoreError("restore_deployment_candidate_changed")
    token = None if stored is None else transaction.deployment_removal_token(stored)
    releases.remove_release(
        plan.tenant_id,
        plan.deployment["id"],
        expected_release_tree_digest=cast(dict[str, object], plan.deployment["releaseTreeDigest"]),
        publication_lock=transaction,
    )
    if stored is not None and token is not None:
        transaction.remove_exact_deployment(stored, token)


def reconcile_deployment(  # noqa: PLR0913, PLR0917 - selection, release and private transaction boundaries
    store: RestoreStore,
    transaction: _StateTransaction,
    releases: DeploymentReleaseStore,
    intent_id: str,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
    *,
    failure_hook: DeploymentCommitFailureHook | None = None,
) -> dict[str, object]:
    intent_id = validate_uuid7(intent_id)
    intent, job = _original(store, transaction, intent_id, family="deployment")
    source, source_observed, candidate, candidate_observed = recovery._intent_deployment_state(
        intent
    )
    tenant_id = validate_uuid7(intent["tenantId"])
    recorded = cast(dict[str, object], intent["lifecycleRecovery"])
    try:
        source_record = _selected_deployment(transaction, tenant_id, source)
    except FileNotFoundError:
        if evidence.selected_target.generation_id != recorded["candidateRuntimeGenerationId"]:
            raise
        # Ordinary rollback may already have retired its newer source. Its
        # exact candidate is independently proven below; no old state is rebuilt.
        source_record = None
    else:
        recovery._require_source_authority(transaction, job.document, source, source_record)
    namespace = transaction.read(StateRecordPath.platform_namespace()).document
    if (
        platform_state_digest(namespace).to_dict()
        != cast(dict[str, object], job.document["expectedSource"])["platformStateDigest"]
    ):
        raise HostRestoreError("restore_deployment_namespace_changed")
    recovery._require_bound_archive_history(transaction, job.document, tenant_id)
    deployment = recovery._candidate_deployment(transaction, job.document, intent, candidate)
    others = snapshot_other_tenant_routes(transaction, excluded_tenant_id=tenant_id)
    choice = require_captured_selection(
        evidence,
        {
            "source": (
                validate_uuid7(recorded["sourceRuntimeGenerationId"]),
                _snapshot(others, TenantRouteInput(source, source_observed, source_record)),
            ),
            "candidate": (
                validate_uuid7(recorded["candidateRuntimeGenerationId"]),
                _snapshot(others, TenantRouteInput(candidate, candidate_observed, deployment)),
            ),
        },
        original_origin_pull_ca_der,
    )
    result = recovery._deployment_result(job.document, candidate)
    audit = transaction.inspect_audit_correlation(intent["correlationId"])
    plan = DeploymentTransitionPlan(
        tenant_id,
        intent_id,
        candidate,
        candidate_observed,
        deployment,
        intent["operation"] in {"deploy", "import"},
        intent,
        result,
        recovery._recover_audit_entry(
            audit if choice == "candidate" else replace(audit, entry=None),
            job.document,
            intent,
            result,
        ),
    )
    validate_deployment_transition(job, plan)
    if choice == "source":
        _source_history(transaction, releases, job, plan)
    else:
        # Excluded staging/intake cannot manufacture a release. The selected
        # candidate must already exist durably and match its authorized digest.
        measured = releases.measure(tenant_id, deployment["id"], publication_lock=transaction)
        if measured.digest.to_dict() != deployment["releaseTreeDigest"]:
            raise HostRestoreError("restore_deployment_candidate_release_changed")
    decision = commit_decision(
        store,
        f"lifecycle-{intent_id}.json",
        {
            "kind": "deployment-lifecycle",
            "intent": intent,
            "job": job.document,
            "selection": choice,
        },
    )
    if choice == "candidate":
        current = transaction.read(StateRecordPath.authorization_job(job.document["jobId"]))
        finalize_deployment_transition_outcome(
            transaction, releases, current, plan, failure_hook=failure_hook
        )
    else:
        _restore_source(
            transaction, job, plan, cleanup=lambda: _discard_candidate(transaction, releases, plan)
        )
    return decision
