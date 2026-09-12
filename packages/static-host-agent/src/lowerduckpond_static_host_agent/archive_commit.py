"""Local archive commitment after verified no-route runtime activation.

The construction journal survives this transaction. A credential-bearing
service must independently verify the retained object before removing it.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    validate_contract,
)

from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS, AuditState
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.lifecycle_plan import (
    ArchiveTransitionPlan,
    plan_archive_transition,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateConflictError,
    StateRecordPath,
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


class ArchiveCommitError(RuntimeError):
    """Archive terminal mutation cannot preserve its exact prepared authority."""


class ArchiveCommitBoundary(StrEnum):
    ARCHIVE_RECORD_SYNC = "archive-record-sync"
    DESIRED_STATE_SYNC = "desired-state-sync"
    OBSERVED_STATE_SYNC = "observed-state-sync"
    RELEASE_VERIFIED = "release-verified"
    AUDIT_SYNC = "audit-sync"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


@dataclass(frozen=True, slots=True)
class ArchiveCommitOutcome:
    result: dict[str, object]
    created: bool


@dataclass(frozen=True, slots=True)
class _Progress:
    desired: StoredContract
    observed: StoredContract
    archive_missing: bool
    result_missing: bool
    removal: IntentRemovalToken | None
    deployments: tuple[dict[str, object], ...]


def admit_archive_transition(
    transaction: _StateTransaction,
    spool: ExportSpool,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> None:
    """Prove complete authority and capacity before selecting the candidate runtime."""
    _prepare_commit(transaction, spool, job, deepcopy(plan), capacity_limits=capacity_limits)


def validate_archive_transition(
    transaction: _StateTransaction,
    spool: ExportSpool,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
) -> None:
    """Validate recovery authority before activation decides how to handle capacity."""
    _prepare_commit(
        transaction,
        spool,
        job,
        deepcopy(plan),
        capacity_limits=DEFAULT_HOST_CAPACITY_LIMITS,
        admit=False,
    )


def finalize_archive_transition(  # noqa: PLR0913 - root-owned state and release boundaries
    transaction: _StateTransaction,
    spool: ExportSpool,
    release_store: DeploymentReleaseStore,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: Callable[[ArchiveCommitBoundary], None] | None = None,
) -> ArchiveCommitOutcome:
    """Commit archived state while preserving the bounded immutable release history."""
    frozen = deepcopy(plan)
    current, progress = _prepare_commit(
        transaction, spool, job, frozen, capacity_limits=capacity_limits
    )

    def notify(boundary: ArchiveCommitBoundary) -> None:
        if failure_hook is not None:
            failure_hook(boundary)

    if progress.archive_missing:
        transaction.create_immutable(
            StateRecordPath.tenant_archive(frozen.tenant_id, frozen.archive_record["deploymentId"]),
            frozen.archive_record,
        )
    notify(ArchiveCommitBoundary.ARCHIVE_RECORD_SYNC)
    if progress.desired.document != frozen.manifest:
        transaction.compare_and_swap(
            StateRecordPath.tenant_desired(frozen.tenant_id),
            progress.desired.revision,
            frozen.manifest,
        )
    notify(ArchiveCommitBoundary.DESIRED_STATE_SYNC)
    if progress.observed.document != frozen.observed_state:
        transaction.compare_and_swap(
            StateRecordPath.tenant_observed(frozen.tenant_id),
            progress.observed.revision,
            frozen.observed_state,
        )
    notify(ArchiveCommitBoundary.OBSERVED_STATE_SYNC)
    for deployment in progress.deployments:
        measured = release_store.measure(
            frozen.tenant_id,
            deployment["id"],
            publication_lock=transaction,
        )
        if measured.digest.to_dict() != deployment["releaseTreeDigest"]:
            raise ArchiveCommitError("archive retained release disagrees with its deployment")
        notify(ArchiveCommitBoundary.RELEASE_VERIFIED)
    history = dict(release_store.published_inventory(publication_lock=transaction).tenant_releases)
    if history.get(frozen.tenant_id) != tuple(str(value["id"]) for value in progress.deployments):
        raise ArchiveCommitError("archive local releases exceed retained deployment authority")
    _ensure_audit(transaction, frozen.audit_entry)
    notify(ArchiveCommitBoundary.AUDIT_SYNC)
    _ensure_result(transaction, current, frozen.result, result_missing=progress.result_missing)
    notify(ArchiveCommitBoundary.RESULT_SYNC)
    _ensure_completed_job(transaction, current)
    notify(ArchiveCommitBoundary.JOB_SYNC)
    if progress.removal is not None:
        transaction.remove_reconciled_intent(
            StateRecordPath.transaction_intent(frozen.intent_id),
            progress.removal,
        )
    notify(ArchiveCommitBoundary.INTENT_REMOVED)
    return ArchiveCommitOutcome(deepcopy(frozen.result), progress.result_missing)


def _prepare_commit(  # noqa: PLR0913 - explicit authority versus capacity admission
    transaction: _StateTransaction,
    spool: ExportSpool,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits,
    admit: bool = True,
) -> tuple[StoredContract, _Progress]:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)
    current = _require_same_job(transaction, job)
    _validate_plan(transaction, current, plan)
    removal = _intent_removal(transaction, current, plan)
    desired = transaction.read(StateRecordPath.tenant_desired(plan.tenant_id))
    observed = transaction.read(StateRecordPath.tenant_observed(plan.tenant_id))
    recovery = cast(dict[str, object], plan.intent["archiveRecovery"])
    if desired.document not in (recovery["sourceManifest"], plan.manifest):
        raise StateConflictError("archive desired state escaped its rollback and commit authority")
    if observed.document not in (recovery["sourceObservedState"], plan.observed_state):
        raise StateConflictError("archive observed state escaped its rollback and commit authority")
    archive_missing = _missing_exact(
        transaction,
        StateRecordPath.tenant_archive(plan.tenant_id, plan.archive_record["deploymentId"]),
        plan.archive_record,
    )
    result_missing = _missing_exact(
        transaction,
        StateRecordPath.authorization_result(current.document["jobId"]),
        plan.result,
    )
    audit_missing = _audit_needs_append(transaction.inspect_audit(), plan.audit_entry)
    if (
        (desired.document == plan.manifest and archive_missing)
        or (observed.document == plan.observed_state and desired.document != plan.manifest)
        or (not audit_missing and observed.document != plan.observed_state)
        or (not result_missing and audit_missing)
        or (current.document["phase"] == "completed" and result_missing)
        or (
            removal is None
            and (
                archive_missing
                or result_missing
                or audit_missing
                or desired.document != plan.manifest
                or observed.document != plan.observed_state
            )
        )
    ):
        raise ArchiveCommitError("archive terminal steps disagree with their durable order")
    deployment_ids = transaction.tenant_deployment_ids(plan.tenant_id)
    if current.document.get("dispatchDeploymentIds") != list(deployment_ids):
        raise ArchiveCommitError("archive release history exceeds its dispatch authority")
    if transaction.tenant_archive_ids(plan.tenant_id) != (
        () if archive_missing else (plan.archive_record["deploymentId"],)
    ):
        raise ArchiveCommitError("archive record history exceeds its construction authority")
    deployments = tuple(
        transaction.read(StateRecordPath.tenant_deployment(plan.tenant_id, identity)).document
        for identity in deployment_ids
    )
    if not admit:
        return current, _Progress(
            desired, observed, archive_missing, result_missing, removal, deployments
        )
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
    writes = [
        document
        for missing, document in (
            (archive_missing, plan.archive_record),
            (desired.document != plan.manifest, plan.manifest),
            (observed.document != plan.observed_state, plan.observed_state),
            (result_missing, plan.result),
            (current.document["phase"] != "completed", {**current.document, "phase": "completed"}),
        )
        if missing
    ]
    if writes or audit_missing:
        entries = len(writes) + int(audit_missing)
        allocated = sum(
            transaction.allocation_upper_bound(len(canonical_json_bytes(document)))
            for document in writes
        )
        if audit_missing:
            allocated += transaction.allocation_upper_bound(
                DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
            )
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                allocated + transaction.namespace_allocation_upper_bound(entries), entries
            ),
            transaction.measure_filesystem_capacity(),
            limits=capacity_limits,
        )
    return current, _Progress(
        desired, observed, archive_missing, result_missing, removal, deployments
    )


def _validate_plan(
    transaction: _StateTransaction, job: StoredContract, plan: ArchiveTransitionPlan
) -> None:
    if type(plan) is not ArchiveTransitionPlan:
        raise TypeError("archive commit requires one archive publication plan")
    validate_contract(plan.intent, expected_kind=ContractKind.TRANSACTION_INTENT)
    validate_contract(plan.audit_entry, expected_kind=ContractKind.AUDIT_ENTRY)
    recovery = cast(dict[str, object], plan.intent["archiveRecovery"])
    claimed = job.document
    claimed["phase"] = "claimed"
    if (
        claimed.get("dispatchSourceObservedState") != recovery["sourceObservedState"]
        or claimed.get("dispatchSourceRuntimeGenerationId") != recovery["sourceRuntimeGenerationId"]
        or claimed.get("dispatchSourceRouteSet") != recovery["sourceRouteSet"]
    ):
        raise ArchiveCommitError("archive runtime source is not durably job-bound")
    reconstructed = plan_archive_transition(
        claimed,
        transaction.read(StateRecordPath.platform_namespace()).document,
        cast(dict[str, object], recovery["sourceManifest"]),
        cast(dict[str, object], recovery["sourceObservedState"]),
        transaction.read(
            StateRecordPath.tenant_deployment(
                plan.tenant_id,
                plan.archive_record["deploymentId"],
            )
        ).document,
        transaction.read(
            StateRecordPath.archive_construction_intent(plan.construction_intent_id)
        ).document,
        plan.archive_record,
        source_runtime_generation_id=recovery["sourceRuntimeGenerationId"],
        candidate_runtime_generation_id=recovery["candidateRuntimeGenerationId"],
        source_route_set=recovery["sourceRouteSet"],
        audit_state=AuditState(
            cast(int, plan.audit_entry["sequence"]),
            0,
            0,
            cast(dict[str, str] | None, plan.audit_entry["previousEntryDigest"]),
        ),
        now=datetime.fromisoformat(cast(str, plan.intent["createdAt"])),
        clock=lambda: 0,
        entropy=lambda length: bytes(length),  # noqa: PLW0108 - named EntropySource parameter
        intent_id=plan.intent_id,
    )
    if reconstructed != plan:
        raise ArchiveCommitError("archive publication documents disagree with durable authority")


def _intent_removal(
    transaction: _StateTransaction,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
) -> IntentRemovalToken | None:
    inventory = transaction.measure_intent_records()
    identities = {item.intent_id for item in inventory.records}
    if identities == {plan.construction_intent_id} and job.document["phase"] == "completed":
        return None
    if identities != {plan.intent_id, plan.construction_intent_id}:
        raise ArchiveCommitError("archive commit requires exactly its construction and transaction")
    path, stored = transaction.read_intent(plan.intent_id)
    if path != StateRecordPath.transaction_intent(plan.intent_id) or stored.document != plan.intent:
        raise ArchiveCommitError("archive transaction changed before terminal mutation")
    identity = next(item for item in inventory.records if item.intent_id == plan.intent_id)
    return IntentRemovalToken(stored.revision, identity.metadata_generation)


def _missing_exact(
    transaction: _StateTransaction,
    path: StateRecordPath,
    document: dict[str, object],
) -> bool:
    try:
        current = transaction.read(path)
    except FileNotFoundError:
        return True
    if current.document != document:
        raise StateConflictError("archive terminal record disagrees with its exact plan")
    return False
