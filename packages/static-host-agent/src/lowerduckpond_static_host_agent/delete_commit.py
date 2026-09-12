"""Commit a permanent tombstone before releasing a tenant's state, bytes, or slug."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from enum import StrEnum
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent.archive_commit import _missing_exact
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS, AuditState
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.delete_plan import DeleteTransitionPlan, plan_delete_transition
from lowerduckpond_static_host_agent.delete_state import (
    remove_deleted_state,
    validate_delete_namespace,
)
from lowerduckpond_static_host_agent.execution import ExecutionOutcome
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_commit import (
    _audit_needs_append,
    _ensure_audit,
    _ensure_completed_job,
    _ensure_result,
    _require_same_job,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class DeleteCommitError(RuntimeError):
    """Deletion cannot preserve the source authority and its permanent tombstone."""


class DeleteCommitBoundary(StrEnum):
    AUDIT_SYNC = "audit-sync"
    RELEASE_REMOVED = "release-removed"
    STATE_RECORD_REMOVED = "state-record-removed"
    STATE_DIRECTORY_REMOVED = "state-directory-removed"
    TENANT_REMOVED = "tenant-removed"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


def validate_delete_transition(  # noqa: PLR0913 - exact journals and partial-state validation
    transaction: _StateTransaction,
    spool: ExportSpool,
    job: StoredContract,
    plan: DeleteTransitionPlan,
    retirement: StoredContract | None,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    admit: bool = True,
) -> tuple[StoredContract, IntentRemovalToken, bool, bool]:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)
    current = _require_same_job(transaction, job)
    claimed = current.document
    claimed["phase"] = "claimed"
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    expected_ids = {plan.intent_id}
    if retirement is not None:
        expected_ids.add(str(retirement.document["intentId"]))
        if (
            transaction.read(
                StateRecordPath.archive_retirement_intent(retirement.document["intentId"])
            ).revision
            != retirement.revision
        ):
            raise DeleteCommitError("deletion retirement authority changed")
    records = transaction.measure_intent_records().records
    if {value.intent_id for value in records} != expected_ids:
        raise DeleteCommitError("deletion requires its exact exclusive journals")
    intent = transaction.read(StateRecordPath.transaction_intent(plan.intent_id))
    identity = next(value for value in records if value.intent_id == plan.intent_id)
    if intent.document != plan.intent or any(
        claimed.get("dispatch" + field[0].upper() + field[1:]) != recovery[field]
        for field in ("sourceObservedState", "sourceRuntimeGenerationId", "sourceRouteSet")
    ):
        raise DeleteCommitError("deletion transaction or source runtime changed")
    expected = plan_delete_transition(
        claimed,
        transaction.read(StateRecordPath.platform_namespace()).document,
        cast(dict[str, object], plan.intent["sourceManifest"]),
        cast(dict[str, object], recovery["sourceObservedState"]),
        None if retirement is None else retirement.document,
        source_runtime_generation_id=recovery["sourceRuntimeGenerationId"],
        candidate_runtime_generation_id=recovery["candidateRuntimeGenerationId"],
        audit_state=AuditState(
            cast(int, plan.audit_entry["sequence"]),
            0,
            0,
            cast(dict[str, str] | None, plan.audit_entry["previousEntryDigest"]),
        ),
        now=datetime.fromisoformat(cast(str, plan.intent["createdAt"])),
        clock=lambda: 0,
        entropy=lambda length: bytes(length),  # noqa: PLW0108 - entropy protocol
        intent_id=plan.intent_id,
    )
    if expected != plan:
        raise DeleteCommitError("deletion plan differs from independently reconstructed authority")
    audit_missing = _audit_needs_append(transaction.inspect_audit(), plan.audit_entry)
    result_missing = _missing_exact(
        transaction, StateRecordPath.authorization_result(current.document["jobId"]), plan.result
    )
    if audit_missing:
        request = cast(dict[str, object], current.document["request"])
        if (
            build_expected_source(transaction, request) != current.document["expectedSource"]
            or transaction.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
            != recovery["sourceObservedState"]
        ):
            raise DeleteCommitError("deletion source changed before its tombstone")
        if retirement is None and not transaction.tenant_has_creation_history(plan.tenant_id):
            raise DeleteCommitError("never-deployed deletion has no complete creation history")
        if transaction.tenant_deployment_ids(plan.tenant_id) != tuple(
            cast(list[str], current.document["dispatchDeploymentIds"])
        ) or transaction.tenant_archive_ids(plan.tenant_id) != tuple(
            cast(list[str], current.document["dispatchArchiveDeploymentIds"])
        ):
            raise DeleteCommitError("deletion source history changed")
    if (
        not result_missing
        and (audit_missing or plan.tenant_id in transaction.measure_inventory().tenant_ids)
    ) or (current.document["phase"] == "completed" and result_missing):
        raise DeleteCommitError("deletion terminal state violates its durable order")
    if admit:
        admit_delete_records(
            transaction,
            current,
            plan,
            capacity_limits=capacity_limits,
            audit_missing=audit_missing,
            result_missing=result_missing,
        )
    return (
        current,
        IntentRemovalToken(intent.revision, identity.metadata_generation),
        audit_missing,
        result_missing,
    )


def admit_delete_records(  # noqa: PLR0913 - exact remaining writes
    transaction: _StateTransaction,
    job: StoredContract,
    plan: DeleteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits,
    audit_missing: bool = True,
    result_missing: bool = True,
) -> None:
    if audit_missing:
        transaction.admit_audit_append(plan.audit_entry)
    if result_missing:
        transaction.admit_inventory(
            StateInventoryReservation(
                authorization_records=1,
                authorization_allocated_bytes=transaction.allocation_upper_bound(
                    len(canonical_json_bytes(plan.result))
                ),
            )
        )
    writes = ([] if not result_missing else [plan.result]) + (
        [] if job.document["phase"] == "completed" else [{**job.document, "phase": "completed"}]
    )
    allocated = sum(
        transaction.allocation_upper_bound(len(canonical_json_bytes(value))) for value in writes
    )
    if audit_missing:
        allocated += transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
    count = len(writes) + int(audit_missing)
    if count:
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                allocated + transaction.namespace_allocation_upper_bound(count), count
            ),
            transaction.measure_filesystem_capacity(),
            limits=capacity_limits,
        )


def finalize_delete_transition(  # noqa: PLR0913,PLR0917 - immutable authority and deletion primitives
    repository: StateRepository,
    transaction: _StateTransaction,
    spool: ExportSpool,
    store: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeleteTransitionPlan,
    retirement: StoredContract | None,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: Callable[[DeleteCommitBoundary], None] | None = None,
) -> ExecutionOutcome:
    plan = deepcopy(plan)
    current, removal, audit_missing, result_missing = validate_delete_transition(
        transaction, spool, job, plan, retirement, capacity_limits=capacity_limits
    )
    history = cast(list[str], current.document["dispatchDeploymentIds"])
    deployment_records: list[dict[str, object]] = []
    for identity in history:
        try:
            record = transaction.read(
                StateRecordPath.tenant_deployment(plan.tenant_id, identity)
            ).document
        except FileNotFoundError:
            if audit_missing:
                raise DeleteCommitError(
                    "deletion source deployment disappeared before commitment"
                ) from None
        else:
            deployment_records.append(record)
    actual = dict(store.published_inventory(publication_lock=transaction).tenant_releases).get(
        plan.tenant_id, ()
    )
    available = {str(value["id"]) for value in deployment_records}
    if not set(actual).issubset(available) or (audit_missing and actual != tuple(history)):
        raise DeleteCommitError("deletion release inventory exceeds its exact remaining history")
    for record in deployment_records:
        if record["id"] in actual and (
            store.measure(
                plan.tenant_id, record["id"], publication_lock=transaction
            ).digest.to_dict()
            != record["releaseTreeDigest"]
        ):
            raise DeleteCommitError("deletion release content changed before removal")

    def notify(value: DeleteCommitBoundary) -> None:
        if failure_hook is not None:
            failure_hook(value)

    if audit_missing:
        validate_delete_namespace(repository, transaction, current, plan.intent)
    _ensure_audit(transaction, plan.audit_entry)
    notify(DeleteCommitBoundary.AUDIT_SYNC)
    for record in deployment_records:
        store.remove_release(
            plan.tenant_id,
            record["id"],
            expected_release_tree_digest=cast(dict[str, object], record["releaseTreeDigest"]),
            publication_lock=transaction,
        )
        notify(DeleteCommitBoundary.RELEASE_REMOVED)
    if plan.tenant_id in dict(
        store.published_inventory(publication_lock=transaction).tenant_releases
    ):
        raise DeleteCommitError("deletion retained tenant release bytes")
    remove_deleted_state(
        repository,
        transaction,
        current,
        plan.intent,
        plan.audit_entry,
        hook=lambda value: notify(DeleteCommitBoundary(value)),
    )
    _ensure_result(transaction, current, plan.result, result_missing=result_missing)
    notify(DeleteCommitBoundary.RESULT_SYNC)
    _ensure_completed_job(transaction, current)
    notify(DeleteCommitBoundary.JOB_SYNC)
    transaction.remove_reconciled_intent(
        StateRecordPath.transaction_intent(plan.intent_id), removal
    )
    notify(DeleteCommitBoundary.INTENT_REMOVED)
    return ExecutionOutcome(plan.result, result_missing)
