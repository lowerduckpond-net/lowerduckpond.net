"""Replay-safe terminal commitment for one route-only lifecycle intent."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    LIFECYCLE_MATRIX,
    ContractKind,
    LifecycleState,
    Operation,
    audit_entry_digest,
    canonical_json_bytes,
    manifest_digest,
    result_digest,
    validate_contract,
)

from lowerduckpond_static_host_agent.audit import (
    DEFAULT_AUDIT_LIMITS,
    AuditAppend,
    AuditState,
)
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    FilesystemCapacity,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.lifecycle_plan import RouteTransitionPlan
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateConflictError,
    StateRecordPath,
    StateRevision,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
    StateInventoryProjection,
    StateInventoryReservation,
)


class RouteCommitError(RuntimeError):
    """A prepared route transition cannot reach one exact terminal commit."""


class RouteCommitBoundary(StrEnum):
    """Replay boundaries after each durable route-transition step."""

    DESIRED_STATE_SYNC = "desired-state-sync"
    OBSERVED_STATE_SYNC = "observed-state-sync"
    AUDIT_SYNC = "audit-sync"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


RouteCommitFailureHook = Callable[[RouteCommitBoundary], None]


class RouteCommitTransaction(Protocol):
    """The held publication transaction surface used by route finalization."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract: ...

    def compare_and_swap(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
    ) -> StoredContract: ...

    def inspect_audit(self) -> AuditState: ...

    def append_audit(self, document: dict[str, object]) -> AuditAppend: ...

    def admit_audit_append(self, document: dict[str, object]) -> AuditState: ...

    def measure_inventory(self) -> StateInventory: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...

    def remove_reconciled_intent(
        self,
        path: StateRecordPath,
        expected: IntentRemovalToken,
    ) -> None: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def admit_inventory(
        self,
        reservation: StateInventoryReservation,
    ) -> StateInventoryProjection: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...


@dataclass(frozen=True, slots=True)
class RouteCommitOutcome:
    """One exact result and whether this finalizer published it."""

    result: dict[str, object]
    created: bool


@dataclass(frozen=True, slots=True)
class _RouteDocuments:
    tenant_id: str
    intent_id: str
    source_manifest: dict[str, object]
    source_observed_state: dict[str, object]
    manifest: dict[str, object]
    observed_state: dict[str, object]
    intent: dict[str, object]
    result: dict[str, object]
    audit_entry: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ExactIntent:
    path: StateRecordPath
    token: IntentRemovalToken


@dataclass(frozen=True, slots=True)
class _RouteProgress:
    desired: StoredContract
    observed: StoredContract
    write_desired: bool
    write_observed: bool
    result_missing: bool


def finalize_route_transition(
    transaction: RouteCommitTransaction,
    job: StoredContract,
    plan: RouteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: RouteCommitFailureHook | None = None,
) -> dict[str, object]:
    """Commit or replay one successful route-only lifecycle transition."""

    return finalize_route_transition_outcome(
        transaction,
        job,
        plan,
        capacity_limits=capacity_limits,
        failure_hook=failure_hook,
    ).result


def finalize_route_transition_outcome(
    transaction: RouteCommitTransaction,
    job: StoredContract,
    plan: RouteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: RouteCommitFailureHook | None = None,
) -> RouteCommitOutcome:
    """Commit or replay a route transition and report result ownership."""

    documents = _freeze_and_validate(job, plan)
    current_job = _require_same_job(transaction, job)
    terminal = _terminal_route_without_intent(transaction, current_job, documents)
    if terminal is not None:
        return RouteCommitOutcome(terminal, False)
    intent_removal = _require_exact_intent(transaction, documents)
    progress = _admit_transition(
        transaction,
        current_job,
        documents,
        capacity_limits=capacity_limits,
    )
    desired = progress.desired
    if progress.write_desired:
        desired = transaction.compare_and_swap(
            StateRecordPath.tenant_desired(documents.tenant_id),
            desired.revision,
            documents.manifest,
        )
    _notify(failure_hook, RouteCommitBoundary.DESIRED_STATE_SYNC)
    if progress.write_observed:
        transaction.compare_and_swap(
            StateRecordPath.tenant_observed(documents.tenant_id),
            progress.observed.revision,
            documents.observed_state,
        )
    _notify(failure_hook, RouteCommitBoundary.OBSERVED_STATE_SYNC)
    _ensure_audit(transaction, documents.audit_entry)
    _notify(failure_hook, RouteCommitBoundary.AUDIT_SYNC)
    _ensure_result(
        transaction,
        current_job,
        documents.result,
        result_missing=progress.result_missing,
    )
    _notify(failure_hook, RouteCommitBoundary.RESULT_SYNC)
    _ensure_completed_job(transaction, current_job)
    _notify(failure_hook, RouteCommitBoundary.JOB_SYNC)
    transaction.remove_reconciled_intent(intent_removal.path, intent_removal.token)
    _notify(failure_hook, RouteCommitBoundary.INTENT_REMOVED)
    return RouteCommitOutcome(deepcopy(documents.result), progress.result_missing)


def validate_route_transition(job: StoredContract, plan: RouteTransitionPlan) -> None:
    """Validate every route terminal-document relationship without mutation."""

    _freeze_and_validate(job, plan)


def admit_route_transition(
    transaction: RouteCommitTransaction,
    job: StoredContract,
    plan: RouteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> None:
    """Prove terminal route capacity before runtime mutation."""

    documents = _freeze_and_validate(job, plan)
    current_job = _require_same_job(transaction, job)
    _require_exact_intent(transaction, documents)
    _admit_transition(
        transaction,
        current_job,
        documents,
        capacity_limits=capacity_limits,
    )


def _freeze_and_validate(job: StoredContract, plan: RouteTransitionPlan) -> _RouteDocuments:
    if type(job) is not StoredContract or type(plan) is not RouteTransitionPlan:
        raise TypeError("route finalization requires one stored job and one route plan")
    intent = deepcopy(plan.intent)
    source_manifest = intent.get("sourceManifest")
    recovery = intent.get("lifecycleRecovery")
    if type(source_manifest) is not dict or type(recovery) is not dict:
        raise RouteCommitError("route recovery authority is malformed")
    source_observed_state = recovery.get("sourceObservedState")
    if type(source_observed_state) is not dict:
        raise RouteCommitError("route source observed-state authority is malformed")
    documents = _RouteDocuments(
        tenant_id=plan.tenant_id,
        intent_id=plan.intent_id,
        source_manifest=deepcopy(source_manifest),
        source_observed_state=deepcopy(source_observed_state),
        manifest=deepcopy(plan.manifest),
        observed_state=deepcopy(plan.observed_state),
        intent=intent,
        result=deepcopy(plan.result),
        audit_entry=deepcopy(plan.audit_entry),
    )
    for manifest in (documents.source_manifest, documents.manifest):
        validate_contract(manifest, expected_kind=ContractKind.SITE)
    for observed in (documents.source_observed_state, documents.observed_state):
        validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    validate_contract(documents.intent, expected_kind=ContractKind.TRANSACTION_INTENT)
    validate_contract(documents.result, expected_kind=ContractKind.OPERATION_RESULT)
    validate_contract(documents.audit_entry, expected_kind=ContractKind.AUDIT_ENTRY)
    _validate_document_relationships(job.document, documents)
    return documents


def _validate_document_relationships(
    job: dict[str, object],
    documents: _RouteDocuments,
) -> None:
    request = job["request"]
    expected_source = job["expectedSource"]
    provenance = documents.result["provenance"]
    recovery = documents.intent["lifecycleRecovery"]
    source_metadata = documents.source_manifest["metadata"]
    source_spec = documents.source_manifest["spec"]
    if not all(
        type(value) is dict
        for value in (
            request,
            expected_source,
            provenance,
            recovery,
            source_metadata,
            source_spec,
        )
    ):
        raise RouteCommitError("route terminal binding is malformed")
    request = cast(dict[str, object], request)
    expected_source = cast(dict[str, object], expected_source)
    provenance = cast(dict[str, object], provenance)
    recovery = cast(dict[str, object], recovery)
    source_metadata = cast(dict[str, object], source_metadata)
    source_spec = cast(dict[str, object], source_spec)
    operation = _route_operation(request.get("operation"))
    source_state = LifecycleState(cast(str, source_spec["desiredState"]))
    target_state = LIFECYCLE_MATRIX.get((operation, source_state))
    if target_state is None:
        raise RouteCommitError("route operation is not valid for its source lifecycle")
    expected_candidate = deepcopy(documents.source_manifest)
    if operation is Operation.RENAME:
        metadata = cast(dict[str, object], expected_candidate["metadata"])
        metadata["slug"] = request.get("slug")
    else:
        spec = cast(dict[str, object], expected_candidate["spec"])
        spec["desiredState"] = target_state.value
    source_digest = manifest_digest(documents.source_manifest).to_dict()
    candidate_digest = manifest_digest(documents.manifest).to_dict()
    expected_source_routes = "both" if source_state is LifecycleState.ACTIVE else "absent"
    candidate_routes = "both" if target_state is LifecycleState.ACTIVE else "absent"
    source_generation = recovery.get("sourceRuntimeGenerationId")
    candidate_generation = recovery.get("candidateRuntimeGenerationId")
    expected_candidate_runtime = candidate_generation if candidate_routes == "both" else None
    if (
        job["phase"] not in {"claimed", "completed"}
        or job.get("compatibilityVersion") != "static-job-v2"
        or documents.intent.get("compatibilityVersion") != "static-intent-v2"
        or documents.intent["operation"] != operation.value
        or documents.intent["phase"] != "prepared"
        or documents.intent.get("archiveRecovery") is not None
        or documents.intent.get("sourceManifest") != documents.source_manifest
        or documents.intent.get("candidateManifest") != documents.manifest
        or documents.intent["sourceManifestDigest"] != source_digest
        or documents.intent["candidateManifestDigest"] != candidate_digest
        or documents.manifest != expected_candidate
        or expected_source.get("expectsTenantAbsent") is not False
        or expected_source.get("lifecycle") != source_state.value
        or expected_source.get("manifestDigest") != source_digest
        or recovery.get("sourceObservedState") != documents.source_observed_state
        or recovery.get("candidateObservedState") != documents.observed_state
        or job.get("dispatchSourceObservedState") != recovery.get("sourceObservedState")
        or job.get("dispatchSourceRuntimeGenerationId") != recovery.get("sourceRuntimeGenerationId")
        or job.get("dispatchSourceRouteSet") != recovery.get("sourceRouteSet")
        or (
            operation is not Operation.RECONCILE
            and recovery.get("sourceRouteSet") != expected_source_routes
        )
        or recovery.get("candidateRouteSet") != candidate_routes
        or source_generation == candidate_generation
        or (
            operation is not Operation.RECONCILE
            and (
                documents.source_observed_state.get("desiredManifestDigest") != source_digest
                or documents.source_observed_state.get("observedState") != source_state.value
            )
        )
        or documents.observed_state.get("desiredManifestDigest") != candidate_digest
        or documents.observed_state.get("observedState") != target_state.value
        or documents.observed_state.get("runtimeGenerationId") != expected_candidate_runtime
        or provenance != {"kind": "authorization-job", "jobId": job["jobId"]}
        or documents.intent_id != documents.intent["intentId"]
        or documents.tenant_id
        != source_metadata["id"]
        != documents.source_observed_state["tenantId"]
        != documents.observed_state["tenantId"]
        != documents.intent["tenantId"]
        != documents.result["tenantId"]
        != documents.audit_entry["tenantId"]
        or request.get("tenantId") != documents.tenant_id
        or documents.result["correlationId"]
        != request.get("correlationId")
        != documents.intent["correlationId"]
        != documents.audit_entry["correlationId"]
        or documents.result.get("manifest") != documents.manifest
        or documents.result["canonicalOrigin"] != source_metadata["canonicalOrigin"]
        or documents.result["operation"] != operation.value
        or documents.result["status"] != "succeeded"
        or documents.audit_entry["operatorPrincipal"] != job["operatorPrincipal"]
        or documents.audit_entry["operation"] != operation.value
        or documents.audit_entry["resultStatus"] != "succeeded"
        or documents.audit_entry["timestamp"] != documents.intent["createdAt"]
        or documents.audit_entry["timestamp"] != documents.observed_state["reconciledAt"]
        or documents.audit_entry["resultDigest"] != result_digest(documents.result).to_dict()
    ):
        raise RouteCommitError("route terminal documents disagree")


def _route_operation(value: object) -> Operation:
    try:
        operation = Operation(cast(str, value))
    except (TypeError, ValueError) as error:
        raise RouteCommitError("route operation is malformed") from error
    if operation not in {
        Operation.SUSPEND,
        Operation.RESUME,
        Operation.RENAME,
        Operation.RECONCILE,
    }:
        raise RouteCommitError("route finalization received another operation")
    return operation


def _require_same_job(
    transaction: RouteCommitTransaction,
    expected: StoredContract,
) -> StoredContract:
    current = transaction.read(StateRecordPath.authorization_job(expected.document["jobId"]))
    first = expected.document
    second = current.document
    for field in (
        "phase",
        "dispatchArchiveDeploymentIds",
        "dispatchArtifactReleaseTreeDigest",
        "dispatchSourceReleaseTreeDigest",
        "dispatchDeploymentIds",
        "dispatchTenantIds",
        "dispatchTenantRecordHistories",
    ):
        first.pop(field, None)
        second.pop(field, None)
    if first != second or current.document["phase"] not in {"claimed", "completed"}:
        raise RouteCommitError("authorization job changed before route finalization")
    return current


def _require_exact_intent(
    transaction: RouteCommitTransaction,
    documents: _RouteDocuments,
) -> _ExactIntent:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != documents.intent_id:
        raise RouteCommitError("route finalization requires its sole exact intent")
    identity = inventory.records[0]
    path, record = transaction.read_intent(documents.intent_id)
    if (
        path != StateRecordPath.transaction_intent(documents.intent_id)
        or record.document != documents.intent
    ):
        raise RouteCommitError("route intent changed before terminal mutation")
    return _ExactIntent(
        path,
        IntentRemovalToken(record.revision, identity.metadata_generation),
    )


def _terminal_route_without_intent(
    transaction: RouteCommitTransaction,
    job: StoredContract,
    documents: _RouteDocuments,
) -> dict[str, object] | None:
    if transaction.measure_intent_records().records:
        return None
    if job.document["phase"] != "completed":
        raise RouteCommitError("nonterminal route transition lost its durable intent")
    expected = (
        (StateRecordPath.tenant_desired(documents.tenant_id), documents.manifest),
        (StateRecordPath.tenant_observed(documents.tenant_id), documents.observed_state),
        (StateRecordPath.authorization_result(job.document["jobId"]), documents.result),
    )
    try:
        if any(transaction.read(path).document != document for path, document in expected):
            raise RouteCommitError("terminal route state disagrees with its plan")
    except FileNotFoundError as error:
        raise RouteCommitError("terminal route state is incomplete") from error
    if _audit_needs_append(transaction.inspect_audit(), documents.audit_entry):
        raise RouteCommitError("terminal route audit entry is absent")
    return deepcopy(documents.result)


def _admit_transition(  # noqa: PLR0912 - each replay boundary is explicit
    transaction: RouteCommitTransaction,
    job: StoredContract,
    documents: _RouteDocuments,
    *,
    capacity_limits: HostCapacityLimits,
) -> _RouteProgress:
    desired = transaction.read(StateRecordPath.tenant_desired(documents.tenant_id))
    observed = transaction.read(StateRecordPath.tenant_observed(documents.tenant_id))
    if desired.document not in (documents.source_manifest, documents.manifest):
        raise StateConflictError("route desired state is outside recovery authority")
    if observed.document not in (
        documents.source_observed_state,
        documents.observed_state,
    ):
        raise StateConflictError("route observed state is outside recovery authority")
    write_desired = (
        desired.document == documents.source_manifest and desired.document != documents.manifest
    )
    write_observed = observed.document == documents.source_observed_state
    if observed.document == documents.observed_state and desired.document != documents.manifest:
        raise RouteCommitError("route observed state advanced before desired state")
    result_path = StateRecordPath.authorization_result(job.document["jobId"])
    try:
        existing_result = transaction.read(result_path)
    except FileNotFoundError:
        result_missing = True
    else:
        result_missing = False
        if existing_result.document != documents.result:
            raise StateConflictError("existing route result disagrees")
    audit_missing = _audit_needs_append(transaction.inspect_audit(), documents.audit_entry)
    if audit_missing:
        transaction.admit_audit_append(documents.audit_entry)
    job_transition = job.document["phase"] == "claimed"
    writes: list[dict[str, object]] = []
    if write_desired:
        writes.append(documents.manifest)
    if write_observed:
        writes.append(documents.observed_state)
    if result_missing:
        writes.append(documents.result)
    if audit_missing:
        writes.append(documents.audit_entry)
    if job_transition:
        completed = job.document
        completed["phase"] = "completed"
        writes.append(completed)
    if not writes:
        return _RouteProgress(
            desired,
            observed,
            write_desired,
            write_observed,
            result_missing,
        )
    if result_missing:
        allocation = transaction.allocation_upper_bound(len(canonical_json_bytes(documents.result)))
        transaction.admit_inventory(
            StateInventoryReservation(
                authorization_records=1,
                authorization_allocated_bytes=allocation,
            )
        )
    transient_allocations = [
        transaction.allocation_upper_bound(len(canonical_json_bytes(document)))
        for document in writes
        if document is not documents.audit_entry
    ]
    if audit_missing:
        transient_allocations.append(
            transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
        )
    entry_count = len(writes)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(
            allocated_bytes=(
                sum(transient_allocations)
                + transaction.namespace_allocation_upper_bound(entry_count)
            ),
            unique_inodes=entry_count,
        ),
        transaction.measure_filesystem_capacity(),
        limits=capacity_limits,
    )
    return _RouteProgress(
        desired,
        observed,
        write_desired,
        write_observed,
        result_missing,
    )


def _ensure_audit(
    transaction: RouteCommitTransaction,
    audit_entry: dict[str, object],
) -> None:
    if _audit_needs_append(transaction.inspect_audit(), audit_entry):
        transaction.append_audit(audit_entry)


def _audit_needs_append(state: AuditState, audit_entry: dict[str, object]) -> bool:
    sequence = audit_entry["sequence"]
    if type(sequence) is not int:  # pragma: no cover - schema validation proves this
        raise RouteCommitError("route audit sequence is malformed")
    expected_digest = audit_entry_digest(audit_entry).to_dict()
    if (
        state.entry_count == sequence
        and audit_entry["previousEntryDigest"] == state.terminal_digest
    ):
        return True
    if state.entry_count == sequence + 1 and state.terminal_digest == expected_digest:
        return False
    raise RouteCommitError("route audit no longer extends the exact chain")


def _ensure_result(
    transaction: RouteCommitTransaction,
    job: StoredContract,
    result: dict[str, object],
    *,
    result_missing: bool,
) -> None:
    path = StateRecordPath.authorization_result(job.document["jobId"])
    if result_missing:
        transaction.create_immutable(path, result)
        return
    if transaction.read(path).document != result:  # pragma: no cover - admission checks this
        raise StateConflictError("existing route result disagrees")


def _ensure_completed_job(
    transaction: RouteCommitTransaction,
    job: StoredContract,
) -> None:
    if job.document["phase"] == "completed":
        return
    completed = job.document
    completed["phase"] = "completed"
    transaction.compare_and_swap(
        StateRecordPath.authorization_job(completed["jobId"]),
        job.revision,
        completed,
    )


def _notify(
    hook: RouteCommitFailureHook | None,
    boundary: RouteCommitBoundary,
) -> None:
    if hook is not None:
        hook(boundary)
