"""Replayable restore commit while the exact remote object remains journal-protected."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import cast

from lowerduckpond_static_contracts import ContractKind, canonical_json_bytes, validate_contract

from lowerduckpond_static_host_agent.archive_commit import _missing_exact
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS, AuditState
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.execution import ExecutionOutcome
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.restore_plan import plan_restore_transition
from lowerduckpond_static_host_agent.route_commit import (
    _audit_needs_append,
    _ensure_audit,
    _ensure_completed_job,
    _ensure_result,
    _require_same_job,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class RestoreCommitError(RuntimeError):
    """The restore cannot preserve its exact source, candidate, and retirement evidence."""


class RestoreCommitBoundary(StrEnum):
    DEPLOYMENT_SYNC = "deployment-sync"
    DESIRED_STATE_SYNC = "desired-state-sync"
    OBSERVED_STATE_SYNC = "observed-state-sync"
    AUDIT_SYNC = "audit-sync"
    ARCHIVE_UNBOUND = "archive-unbound"
    RELEASE_REMOVED = "release-removed"
    DEPLOYMENT_REMOVED = "deployment-removed"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


@dataclass(frozen=True, slots=True)
class RestoreProgress:
    job: StoredContract
    retirement: StoredContract
    desired: StoredContract
    observed: StoredContract
    deployment_missing: bool
    result_missing: bool
    removal: IntentRemovalToken
    retired: tuple[StoredContract, ...]


def validate_restore_transition(  # noqa: PLR0913 - explicit replay evidence
    transaction: _StateTransaction,
    spool: ExportSpool,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    retirement: StoredContract,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    admit: bool = True,
) -> RestoreProgress:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)
    current = _require_same_job(transaction, job)
    _validate_plan(transaction, current, plan, retirement)
    records = transaction.measure_intent_records().records
    if {value.intent_id for value in records} != {plan.intent_id, retirement.document["intentId"]}:
        raise RestoreCommitError("restore requires its exact transaction and retirement")
    identity = next(value for value in records if value.intent_id == plan.intent_id)
    intent = transaction.read(StateRecordPath.transaction_intent(plan.intent_id))
    if intent.document != plan.intent:
        raise RestoreCommitError("restore intent changed before commitment")
    removal = IntentRemovalToken(intent.revision, identity.metadata_generation)
    desired = transaction.read(StateRecordPath.tenant_desired(plan.tenant_id))
    observed = transaction.read(StateRecordPath.tenant_observed(plan.tenant_id))
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    if desired.document not in (
        plan.intent["sourceManifest"],
        plan.manifest,
    ) or observed.document not in (
        recovery["sourceObservedState"],
        plan.observed_state,
    ):
        raise RestoreCommitError("restore local state escaped its exact transaction")
    deployment_missing = _missing_exact(
        transaction,
        StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"]),
        plan.deployment,
    )
    archive = cast(dict[str, object], retirement.document["archiveRecord"])
    archive_missing = _missing_exact(
        transaction,
        StateRecordPath.tenant_archive(plan.tenant_id, archive["deploymentId"]),
        archive,
    )
    if transaction.tenant_archive_ids(plan.tenant_id) != (
        () if archive_missing else (archive["deploymentId"],)
    ):
        raise RestoreCommitError("restore archive history exceeds its retirement authority")
    result_missing = _missing_exact(
        transaction,
        StateRecordPath.authorization_result(current.document["jobId"]),
        plan.result,
    )
    audit_missing = _audit_needs_append(transaction.inspect_audit(), plan.audit_entry)
    if (
        (desired.document == plan.manifest and deployment_missing)
        or (observed.document == plan.observed_state and desired.document != plan.manifest)
        or (not audit_missing and observed.document != plan.observed_state)
        or (archive_missing and audit_missing)
        or (not result_missing and (audit_missing or not archive_missing))
        or (current.document["phase"] == "completed" and result_missing)
    ):
        raise RestoreCommitError("restore durable steps disagree with their required order")
    history = cast(list[str], current.document["dispatchDeploymentIds"])
    candidate = cast(str, plan.deployment["id"])
    terminal = tuple((*history, candidate)[-3:])
    actual = transaction.tenant_deployment_transition_ids(plan.tenant_id, candidate_id=candidate)
    if not (
        (deployment_missing and actual == tuple(history))
        or (
            not deployment_missing
            and set(terminal).issubset(actual)
            and set(actual).issubset((*history, candidate))
        )
    ):
        raise RestoreCommitError("restore deployment history escaped its retention window")
    if (
        set(actual) != set(history) | ({candidate} if not deployment_missing else set())
        and audit_missing
    ):
        raise RestoreCommitError("restore history cleanup preceded commitment")
    retired = tuple(
        transaction.read(StateRecordPath.tenant_deployment(plan.tenant_id, value))
        for value in actual
        if value not in terminal
    )
    if admit:
        _admit(
            transaction,
            current,
            plan,
            deployment_missing,
            result_missing,
            audit_missing,
            capacity_limits,
        )
    return RestoreProgress(
        current, retirement, desired, observed, deployment_missing, result_missing, removal, retired
    )


def finalize_restore_transition(  # noqa: PLR0913,PLR0917 - trusted local boundaries and fault hook
    transaction: _StateTransaction,
    spool: ExportSpool,
    store: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    retirement: StoredContract,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: Callable[[RestoreCommitBoundary], None] | None = None,
) -> ExecutionOutcome:
    plan = deepcopy(plan)
    progress = validate_restore_transition(
        transaction, spool, job, plan, retirement, capacity_limits=capacity_limits
    )
    measured = store.measure(plan.tenant_id, plan.deployment["id"], publication_lock=transaction)
    if measured.digest.to_dict() != plan.deployment["releaseTreeDigest"]:
        raise RestoreCommitError("restored release disagrees with its archived bytes")

    def notify(boundary: RestoreCommitBoundary) -> None:
        if failure_hook is not None:
            failure_hook(boundary)

    if progress.deployment_missing:
        transaction.create_immutable(
            StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"]),
            plan.deployment,
        )
    notify(RestoreCommitBoundary.DEPLOYMENT_SYNC)
    if progress.desired.document != plan.manifest:
        transaction.compare_and_swap(
            StateRecordPath.tenant_desired(plan.tenant_id), progress.desired.revision, plan.manifest
        )
    notify(RestoreCommitBoundary.DESIRED_STATE_SYNC)
    if progress.observed.document != plan.observed_state:
        transaction.compare_and_swap(
            StateRecordPath.tenant_observed(plan.tenant_id),
            progress.observed.revision,
            plan.observed_state,
        )
    notify(RestoreCommitBoundary.OBSERVED_STATE_SYNC)
    _ensure_audit(transaction, plan.audit_entry)
    notify(RestoreCommitBoundary.AUDIT_SYNC)
    transaction.remove_restored_archive(retirement)
    notify(RestoreCommitBoundary.ARCHIVE_UNBOUND)
    for old in progress.retired:
        token = transaction.deployment_removal_token(old)
        store.remove_release(
            plan.tenant_id,
            old.document["id"],
            expected_release_tree_digest=cast(dict[str, object], old.document["releaseTreeDigest"]),
            publication_lock=transaction,
        )
        notify(RestoreCommitBoundary.RELEASE_REMOVED)
        transaction.remove_exact_deployment(old, token)
        notify(RestoreCommitBoundary.DEPLOYMENT_REMOVED)
    _ensure_result(transaction, progress.job, plan.result, result_missing=progress.result_missing)
    notify(RestoreCommitBoundary.RESULT_SYNC)
    _ensure_completed_job(transaction, progress.job)
    notify(RestoreCommitBoundary.JOB_SYNC)
    transaction.remove_reconciled_intent(
        StateRecordPath.transaction_intent(plan.intent_id), progress.removal
    )
    notify(RestoreCommitBoundary.INTENT_REMOVED)
    return ExecutionOutcome(plan.result, progress.result_missing)


def _validate_plan(
    transaction: _StateTransaction,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    retirement: StoredContract,
) -> None:
    validate_contract(plan.intent, expected_kind=ContractKind.TRANSACTION_INTENT)
    current = transaction.read(
        StateRecordPath.archive_retirement_intent(retirement.document["intentId"])
    )
    if current.revision != retirement.revision:
        raise RestoreCommitError("restore retirement journal changed")
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    claimed = job.document
    claimed["phase"] = "claimed"
    if any(
        claimed.get("dispatch" + field[0].upper() + field[1:]) != recovery[field]
        for field in ("sourceObservedState", "sourceRuntimeGenerationId", "sourceRouteSet")
    ):
        raise RestoreCommitError("restore source runtime is not durably bound")
    archive = cast(dict[str, object], retirement.document["archiveRecord"])
    expected = plan_restore_transition(
        claimed,
        transaction.read(StateRecordPath.platform_namespace()).document,
        cast(dict[str, object], plan.intent["sourceManifest"]),
        cast(dict[str, object], recovery["sourceObservedState"]),
        transaction.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, archive["deploymentId"])
        ).document,
        retirement.document,
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
        deployment_id=plan.deployment["id"],
        intent_id=plan.intent_id,
    )
    if expected != plan:
        raise RestoreCommitError("restore plan exceeds its independently reconstructed authority")


def _admit(  # noqa: PLR0913,PLR0917 - explicit bounded writes
    transaction: _StateTransaction,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    deployment_missing: bool,
    result_missing: bool,
    audit_missing: bool,
    limits: HostCapacityLimits,
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
    writes = [plan.manifest, plan.observed_state, {**job.document, "phase": "completed"}]
    if deployment_missing:
        writes.append(plan.deployment)
    if result_missing:
        writes.append(plan.result)
    allocated = sum(
        transaction.allocation_upper_bound(len(canonical_json_bytes(value))) for value in writes
    )
    if audit_missing:
        allocated += transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
    count = len(writes) + int(audit_missing)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(allocated + transaction.namespace_allocation_upper_bound(count), count),
        transaction.measure_filesystem_capacity(),
        limits=limits,
    )
