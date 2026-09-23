"""Recover a captured create without inventing a replacement tenant or request."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import replace
from typing import cast

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent import create_recover as recovery
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.create_commit import (
    CreateCommitFailureHook,
    finalize_create_transition_outcome,
    validate_create_transition,
)
from lowerduckpond_static_host_agent.delete_state import _names
from lowerduckpond_static_host_agent.execution import (
    _failure_result,
    _publish_result,
    _repair_executor_failure_audit,
    _set_terminal_phase,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore
from lowerduckpond_static_host_agent.host_restore_routes import _original
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import CreateTransitionPlan
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_other_tenant_routes,
    snapshot_tenant_routes,
)


def _remove_uncommitted_create(transaction: _StateTransaction, plan: CreateTransitionPlan) -> None:
    """The original immutable backup retains every removed candidate record."""
    transaction._require_create_intent(plan.tenant_id)
    root = transaction._repository._durable
    try:
        tenant = root.open_descendant(("tenants", plan.tenant_id))
    except FileNotFoundError:
        transaction.remove_empty_create_tenant_namespace(plan.tenant_id)
        return
    with tenant:
        names = _names(tenant, {"desired.json", "observed.json", "deployments", "archives"})
        records = (
            (StateRecordPath.tenant_desired(plan.tenant_id), plan.manifest),
            (StateRecordPath.tenant_observed(plan.tenant_id), plan.observed_state),
        )
        for path, expected in records:
            if path.components[-1] in names and transaction.read(path).document != expected:
                raise HostRestoreError("restore_create_candidate_changed")
        for name in ("deployments", "archives"):
            if name in names:
                with tenant.open_descendant((name,)) as directory:
                    _names(directory, set())
        # Prove all remaining names and bytes before removing any. Each unlink
        # synchronizes its parent; the ordinary empty-namespace finalizer resumes
        # both partial directory creation and partial directory removal.
        for path, _expected in records:
            with suppress(FileNotFoundError):
                root.remove(path.components)
    transaction.remove_empty_create_tenant_namespace(plan.tenant_id)


def _restore_absence(
    transaction: _StateTransaction, plan: CreateTransitionPlan, job_id: object
) -> None:
    job = transaction.read(StateRecordPath.authorization_job(job_id))
    try:
        result = transaction.read(StateRecordPath.authorization_result(job_id)).document
    except FileNotFoundError:
        result = None
    audit = transaction.inspect_audit_correlation(plan.intent["correlationId"])
    if result is not None:
        _validate_result_binding(job.document, result)
        if (
            result.get("errorCode") != "unavailable"
            or result.get("failurePublisher") != "authorization-executor"
        ):
            raise HostRestoreError("restore_create_contradictory_result")
    elif audit.entry is not None or job.document["phase"] != "claimed":
        raise HostRestoreError("restore_create_contradictory_audit")
    identities = transaction.measure_intent_records().records
    if identities:
        _remove_uncommitted_create(transaction, plan)
    elif plan.tenant_id in transaction.measure_inventory().tenant_ids:
        raise HostRestoreError("restore_create_failed_result_retained_tenant")
    if result is None:
        _publish_result(
            transaction,
            job,
            _failure_result(job.document, "unavailable"),
            limits=DEFAULT_HOST_CAPACITY_LIMITS,
        )
    else:
        _repair_executor_failure_audit(
            transaction, job.document, result, limits=DEFAULT_HOST_CAPACITY_LIMITS
        )
        _set_terminal_phase(transaction, job, result, execution_validated=True)
    if identities:
        path, intent = transaction.read_intent(plan.intent_id)
        transaction.remove_reconciled_intent(
            path, IntentRemovalToken(intent.revision, identities[0].metadata_generation)
        )


def reconcile_create(  # noqa: PLR0913 - captured original inputs and private transaction
    store: RestoreStore,
    transaction: _StateTransaction,
    intent_id: str,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
    *,
    failure_hook: CreateCommitFailureHook | None = None,
) -> dict[str, object]:
    intent_id = validate_uuid7(intent_id)
    intent, job = _original(store, transaction, intent_id, family="create")
    tenant_id = validate_uuid7(intent["tenantId"])
    request = cast(dict[str, object], job.document["request"])
    if build_expected_source(transaction, request) != job.document["expectedSource"]:
        raise HostRestoreError("restore_create_namespace_changed")
    recorded = cast(dict[str, object], intent["lifecycleRecovery"])
    manifest, observed = recovery._require_candidate_tenant(
        (
            TenantRouteInput(
                cast(dict[str, object], intent["candidateManifest"]),
                cast(dict[str, object], recorded["candidateObservedState"]),
                None,
            ),
        ),
        intent,
    )
    others = (
        snapshot_other_tenant_routes(transaction, excluded_tenant_id=tenant_id)
        if tenant_id in transaction.measure_inventory().tenant_ids
        else snapshot_tenant_routes(transaction)
    )
    candidate = TenantRouteSnapshot(
        others.platform_namespace, (*others.tenants, TenantRouteInput(manifest, observed, None))
    )
    choice = require_captured_selection(
        evidence,
        {
            "source": (validate_uuid7(recorded["sourceRuntimeGenerationId"]), others),
            "candidate": (validate_uuid7(recorded["candidateRuntimeGenerationId"]), candidate),
        },
        original_origin_pull_ca_der,
    )
    result = recovery._create_result(job.document, manifest)
    audit = transaction.inspect_audit_correlation(intent["correlationId"])
    plan = CreateTransitionPlan(
        tenant_id,
        intent_id,
        manifest,
        observed,
        intent,
        result,
        recovery._recover_audit_entry(
            audit if choice == "candidate" else replace(audit, entry=None),
            job.document,
            intent,
            result,
        ),
    )
    validate_create_transition(job, plan)
    decision = commit_decision(
        store,
        f"lifecycle-{intent_id}.json",
        {"kind": "create-lifecycle", "intent": intent, "job": job.document, "selection": choice},
    )
    if choice == "candidate":
        current = transaction.read(StateRecordPath.authorization_job(job.document["jobId"]))
        finalize_create_transition_outcome(transaction, current, plan, failure_hook=failure_hook)
    else:
        _restore_absence(transaction, plan, job.document["jobId"])
    return decision
