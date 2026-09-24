"""Captured source/candidate decisions use ordinary route transformations and results."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import cast

from lowerduckpond_static_contracts import decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent import create_recover, deployment_recover
from lowerduckpond_static_host_agent import route_recover as recovery
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.delete_plan import DeleteTransitionPlan
from lowerduckpond_static_host_agent.execution import (
    _failure_result,
    _publish_result,
    _repair_executor_failure_audit,
    _set_terminal_phase,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.lifecycle_plan import (
    DeploymentTransitionPlan,
    RouteTransitionPlan,
)
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_commit import (
    RouteCommitFailureHook,
    finalize_route_transition_outcome,
    validate_route_transition,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_other_tenant_routes,
)


def _original(
    store: RestoreStore, transaction: _StateTransaction, intent_id: str, *, family: str = "route"
) -> tuple[dict[str, object], StoredContract]:
    try:
        raw = store.read_bytes(f"lifecycle-{intent_id}.json")
    except FileNotFoundError:
        if family == "create":
            intent = create_recover._require_exact_create_intent(transaction, intent_id).document
            return intent, create_recover._require_bound_job(transaction, intent)
        if family == "deployment":
            intent = deployment_recover._require_exact_deployment_intent(
                transaction, intent_id
            ).document
            return intent, deployment_recover._require_bound_job(transaction, intent)
        if family == "route":
            intent = recovery._require_exact_route_intent(transaction, intent_id).document
            return intent, recovery._require_bound_job(transaction, intent)
        raise HostRestoreError("restore_lifecycle_family_invalid") from None
    receipt = decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES)
    payload = exact_object(receipt["payload"], {"kind", "intent", "job", "selection"})
    if payload["kind"] != f"{family}-lifecycle":
        raise HostRestoreError("restore_route_decision_changed")
    saved, expected = payload["intent"], payload["job"]
    if type(saved) is not dict or type(expected) is not dict or saved["intentId"] != intent_id:
        raise HostRestoreError("restore_route_decision_changed")
    current = transaction.read(StateRecordPath.authorization_job(expected["jobId"]))
    document = current.document
    comparable = {**document, "phase": expected["phase"]}
    if "executionValidated" in expected:
        comparable["executionValidated"] = expected["executionValidated"]
    if comparable != expected:
        raise HostRestoreError("restore_route_job_changed")
    identities = transaction.measure_intent_records().records
    if identities:
        if len(identities) != 1 or identities[0].intent_id != intent_id:
            raise HostRestoreError("restore_route_intent_changed")
        if transaction.read_intent(intent_id)[1].document != saved:
            raise HostRestoreError("restore_route_intent_changed")
    elif document["phase"] not in {"completed", "failed"}:
        raise HostRestoreError("restore_route_intent_missing")
    # commit_decision below revalidates this immutable receipt against this exact
    # validated journal before any mutation, including after interrupted cleanup.
    return saved, StoredContract(expected, current.revision)


def _snapshot(others: TenantRouteSnapshot, tenant: TenantRouteInput) -> TenantRouteSnapshot:
    if cast(dict[str, object], tenant.manifest["spec"])["desiredState"] == "archived":
        return others
    return TenantRouteSnapshot(others.platform_namespace, (*others.tenants, tenant))


def _restore_source(  # noqa: PLR0912 - explicit immutable result/audit/intent interruption cases
    transaction: _StateTransaction,
    original: StoredContract,
    plan: RouteTransitionPlan | DeploymentTransitionPlan | DeleteTransitionPlan,
    *,
    cleanup: Callable[[], None] | None = None,
    companion: StoredContract | None = None,
) -> None:
    intent = plan.intent
    selected = cast(dict[str, object], intent["lifecycleRecovery"])
    identities = {row.intent_id: row for row in transaction.measure_intent_records().records}
    companion_id = None if companion is None else str(companion.document["intentId"])
    allowed = {plan.intent_id} | (set() if companion_id is None else {companion_id})
    if not set(identities) <= allowed:
        raise HostRestoreError("restore_route_intent_changed")
    if companion is not None and (
        companion_id not in identities
        or transaction.read_intent(str(companion_id))[1].revision != companion.revision
    ):
        raise HostRestoreError("restore_route_companion_changed")
    if (
        plan.intent_id in identities
        and transaction.read_intent(plan.intent_id)[1].document != intent
    ):
        raise HostRestoreError("restore_route_intent_changed")
    current_job = transaction.read(StateRecordPath.authorization_job(original.document["jobId"]))
    try:
        result = transaction.read(
            StateRecordPath.authorization_result(current_job.document["jobId"])
        ).document
    except FileNotFoundError:
        result = None
    audit = transaction.inspect_audit_correlation(intent["correlationId"])
    if result is not None:
        _validate_result_binding(current_job.document, result)
        if (
            result.get("errorCode") != "unavailable"
            or result.get("failurePublisher") != "authorization-executor"
        ):
            raise HostRestoreError("restore_route_source_has_contradictory_result")
    elif audit.entry is not None or current_job.document["phase"] != "claimed":
        raise HostRestoreError("restore_route_source_has_contradictory_audit")
    updates = (
        (
            StateRecordPath.tenant_desired(plan.tenant_id),
            intent["sourceManifest"],
            intent["sourceManifest"]
            if intent["operation"] == "delete"
            else intent["candidateManifest"],
        ),
        (
            StateRecordPath.tenant_observed(plan.tenant_id),
            selected["sourceObservedState"],
            selected["sourceObservedState"]
            if intent["operation"] == "delete"
            else selected["candidateObservedState"],
        ),
    )
    # Prove the whole allowed pair before the first rollback write. Only this
    # intent's exact partial candidate can be restored to its authorized source.
    records = [transaction.read(path) for path, _source, _candidate in updates]
    if any(
        record.document not in (source, candidate)
        for record, (_path, source, candidate) in zip(records, updates, strict=True)
    ):
        raise HostRestoreError("restore_route_state_is_unrelated")
    for record, (path, source, _candidate) in zip(records, updates, strict=True):
        if record.document != source:
            transaction.compare_and_swap(path, record.revision, cast(dict[str, object], source))
    if cleanup is not None:
        cleanup()
    if result is None:
        _publish_result(
            transaction,
            current_job,
            _failure_result(current_job.document, "unavailable"),
            limits=DEFAULT_HOST_CAPACITY_LIMITS,
        )
    else:
        _repair_executor_failure_audit(
            transaction, current_job.document, result, limits=DEFAULT_HOST_CAPACITY_LIMITS
        )
        _set_terminal_phase(transaction, current_job, result, execution_validated=True)
    if plan.intent_id in identities:
        path, record = transaction.read_intent(plan.intent_id)
        transaction.remove_reconciled_intent(
            path,
            IntentRemovalToken(record.revision, identities[plan.intent_id].metadata_generation),
        )


def reconcile_route(  # noqa: PLR0913 - exact captured selection and private authority
    store: RestoreStore,
    transaction: _StateTransaction,
    intent_id: str,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
    *,
    failure_hook: RouteCommitFailureHook | None = None,
) -> dict[str, object]:
    intent_id = validate_uuid7(intent_id)
    intent, job = _original(store, transaction, intent_id)
    source, source_observed, candidate, candidate_observed = recovery._intent_route_state(intent)
    deployment = recovery._require_source_authority(transaction, job.document, source)
    tenant_id = validate_uuid7(intent["tenantId"])
    others = snapshot_other_tenant_routes(transaction, excluded_tenant_id=tenant_id)
    recorded = cast(dict[str, object], intent["lifecycleRecovery"])
    choice = require_captured_selection(
        evidence,
        {
            "source": (
                validate_uuid7(recorded["sourceRuntimeGenerationId"]),
                _snapshot(others, TenantRouteInput(source, source_observed, deployment)),
            ),
            "candidate": (
                validate_uuid7(recorded["candidateRuntimeGenerationId"]),
                _snapshot(others, TenantRouteInput(candidate, candidate_observed, deployment)),
            ),
        },
        original_origin_pull_ca_der,
    )
    result = recovery._route_result(job.document, candidate)
    audit = transaction.inspect_audit_correlation(intent["correlationId"])
    # Source rollback still validates the complete authorized candidate plan,
    # but never fabricates or publishes its hypothetical success audit entry.
    plan = RouteTransitionPlan(
        tenant_id,
        intent_id,
        candidate,
        candidate_observed,
        intent,
        result,
        recovery._recover_audit_entry(
            audit if choice == "candidate" else replace(audit, entry=None),
            job.document,
            intent,
            result,
        ),
    )
    validate_route_transition(job, plan)
    decision = commit_decision(
        store,
        f"lifecycle-{intent_id}.json",
        {"kind": "route-lifecycle", "intent": intent, "job": job.document, "selection": choice},
    )
    if choice == "candidate":
        current = transaction.read(StateRecordPath.authorization_job(job.document["jobId"]))
        finalize_route_transition_outcome(transaction, current, plan, failure_hook=failure_hook)
    else:
        _restore_source(transaction, job, plan)
    return decision
