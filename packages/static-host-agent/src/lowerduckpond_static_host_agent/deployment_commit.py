"""Replay-safe terminal commitment for deploy and rollback intents."""

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
    deployment_record_digest,
    manifest_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
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
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
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

_MAXIMUM_RETAINED_DEPLOYMENTS = 3


class DeploymentCommitError(RuntimeError):
    """A prepared deployment transition cannot reach one exact terminal commit."""


class DeploymentCommitBoundary(StrEnum):
    """Replay boundaries after each durable deployment-transition step."""

    RETIRED_RELEASE_REMOVED = "retired-release-removed"
    RETIRED_DEPLOYMENT_REMOVED = "retired-deployment-removed"
    DEPLOYMENT_SYNC = "deployment-sync"
    DESIRED_STATE_SYNC = "desired-state-sync"
    OBSERVED_STATE_SYNC = "observed-state-sync"
    AUDIT_SYNC = "audit-sync"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


DeploymentCommitFailureHook = Callable[[DeploymentCommitBoundary], None]


class DeploymentCommitTransaction(Protocol):
    """The held publication transaction surface used by deployment finalization."""

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

    def remove_exact_deployment(self, expected: StoredContract) -> None: ...

    def tenant_deployment_ids(self, tenant_id: object) -> tuple[str, ...]: ...

    def tenant_deployment_transition_ids(
        self,
        tenant_id: object,
        *,
        candidate_id: object,
    ) -> tuple[str, ...]: ...

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

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class DeploymentCommitOutcome:
    """One exact result and whether this finalizer published it."""

    result: dict[str, object]
    created: bool


@dataclass(frozen=True, slots=True)
class _DeploymentDocuments:
    tenant_id: str
    intent_id: str
    source_manifest: dict[str, object]
    source_observed_state: dict[str, object]
    manifest: dict[str, object]
    observed_state: dict[str, object]
    deployment: dict[str, object]
    creates_deployment: bool
    intent: dict[str, object]
    result: dict[str, object]
    audit_entry: dict[str, object]
    history: tuple[str, ...]
    source_deployment_digest: dict[str, object] | None
    source_release_tree_digest: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class _ExactIntent:
    path: StateRecordPath
    token: IntentRemovalToken


@dataclass(frozen=True, slots=True)
class _DeploymentProgress:
    desired: StoredContract
    observed: StoredContract
    retired: tuple[StoredContract, ...]
    write_deployment: bool
    write_desired: bool
    write_observed: bool
    result_missing: bool


def finalize_deployment_transition(  # noqa: PLR0913 - explicit authority surfaces
    transaction: DeploymentCommitTransaction,
    release_store: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: DeploymentCommitFailureHook | None = None,
) -> dict[str, object]:
    """Commit or replay one successful deploy or rollback transition."""

    return finalize_deployment_transition_outcome(
        transaction,
        release_store,
        job,
        plan,
        capacity_limits=capacity_limits,
        failure_hook=failure_hook,
    ).result


def finalize_deployment_transition_outcome(  # noqa: PLR0913 - explicit authority surfaces
    transaction: DeploymentCommitTransaction,
    release_store: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: DeploymentCommitFailureHook | None = None,
) -> DeploymentCommitOutcome:
    """Commit or replay a deployment transition and report result ownership."""

    documents = _freeze_and_validate(job, plan)
    current_job = _require_same_job(transaction, job)
    terminal = _terminal_transition_without_intent(
        transaction,
        release_store,
        current_job,
        documents,
    )
    if terminal is not None:
        return DeploymentCommitOutcome(terminal, False)
    intent_removal = _require_exact_intent(transaction, documents)
    progress = _admit_transition(
        transaction,
        current_job,
        documents,
        capacity_limits=capacity_limits,
    )
    _require_selected_release(transaction, release_store, documents)
    if progress.write_deployment:
        transaction.create_immutable(
            StateRecordPath.tenant_deployment(
                documents.tenant_id,
                documents.deployment["id"],
            ),
            documents.deployment,
        )
    _notify(failure_hook, DeploymentCommitBoundary.DEPLOYMENT_SYNC)
    desired = progress.desired
    if progress.write_desired:
        desired = transaction.compare_and_swap(
            StateRecordPath.tenant_desired(documents.tenant_id),
            desired.revision,
            documents.manifest,
        )
    _notify(failure_hook, DeploymentCommitBoundary.DESIRED_STATE_SYNC)
    if progress.write_observed:
        transaction.compare_and_swap(
            StateRecordPath.tenant_observed(documents.tenant_id),
            progress.observed.revision,
            documents.observed_state,
        )
    _notify(failure_hook, DeploymentCommitBoundary.OBSERVED_STATE_SYNC)
    for retired_record in progress.retired:
        retired = retired_record.document
        release_store.remove_release(
            documents.tenant_id,
            retired["id"],
            expected_release_tree_digest=cast(
                dict[str, object],
                retired["releaseTreeDigest"],
            ),
            publication_lock=transaction,
        )
        _notify(failure_hook, DeploymentCommitBoundary.RETIRED_RELEASE_REMOVED)
    for retired_record in progress.retired:
        transaction.remove_exact_deployment(retired_record)
        _notify(failure_hook, DeploymentCommitBoundary.RETIRED_DEPLOYMENT_REMOVED)
    _ensure_audit(transaction, documents.audit_entry)
    _notify(failure_hook, DeploymentCommitBoundary.AUDIT_SYNC)
    _ensure_result(
        transaction,
        current_job,
        documents.result,
        result_missing=progress.result_missing,
    )
    _notify(failure_hook, DeploymentCommitBoundary.RESULT_SYNC)
    _ensure_completed_job(transaction, current_job)
    _notify(failure_hook, DeploymentCommitBoundary.JOB_SYNC)
    transaction.remove_reconciled_intent(intent_removal.path, intent_removal.token)
    _notify(failure_hook, DeploymentCommitBoundary.INTENT_REMOVED)
    return DeploymentCommitOutcome(deepcopy(documents.result), progress.result_missing)


def validate_deployment_transition(
    job: StoredContract,
    plan: DeploymentTransitionPlan,
) -> None:
    """Validate every deployment terminal-document relationship without mutation."""

    _freeze_and_validate(job, plan)


def admit_deployment_transition(
    transaction: DeploymentCommitTransaction,
    job: StoredContract,
    plan: DeploymentTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> None:
    """Prove terminal deployment capacity before release or runtime mutation."""

    documents = _freeze_and_validate(job, plan)
    current_job = _require_same_job(transaction, job)
    _require_exact_intent(transaction, documents)
    _admit_transition(
        transaction,
        current_job,
        documents,
        capacity_limits=capacity_limits,
    )


def _freeze_and_validate(
    job: StoredContract,
    plan: DeploymentTransitionPlan,
) -> _DeploymentDocuments:
    if type(job) is not StoredContract or type(plan) is not DeploymentTransitionPlan:
        raise TypeError("deployment finalization requires one stored job and deployment plan")
    intent = deepcopy(plan.intent)
    source_manifest = intent.get("sourceManifest")
    recovery = intent.get("lifecycleRecovery")
    source_observed = recovery.get("sourceObservedState") if type(recovery) is dict else None
    history = job.document.get("dispatchDeploymentIds")
    expected_source = job.document.get("expectedSource")
    source_deployment_digest = (
        expected_source.get("deploymentDigest") if type(expected_source) is dict else None
    )
    source_release_tree_digest = job.document.get("dispatchSourceReleaseTreeDigest")
    if (
        type(source_manifest) is not dict
        or type(recovery) is not dict
        or type(source_observed) is not dict
        or type(history) is not list
        or any(type(value) is not str for value in history)
        or (source_deployment_digest is not None and type(source_deployment_digest) is not dict)
        or (source_release_tree_digest is not None and type(source_release_tree_digest) is not dict)
    ):
        raise DeploymentCommitError("deployment recovery authority is malformed")
    history_ids = tuple(validate_uuid7(value) for value in history)
    documents = _DeploymentDocuments(
        tenant_id=plan.tenant_id,
        intent_id=plan.intent_id,
        source_manifest=deepcopy(source_manifest),
        source_observed_state=deepcopy(source_observed),
        manifest=deepcopy(plan.manifest),
        observed_state=deepcopy(plan.observed_state),
        deployment=deepcopy(plan.deployment),
        creates_deployment=plan.creates_deployment,
        intent=intent,
        result=deepcopy(plan.result),
        audit_entry=deepcopy(plan.audit_entry),
        history=history_ids,
        source_deployment_digest=deepcopy(source_deployment_digest),
        source_release_tree_digest=deepcopy(source_release_tree_digest),
    )
    for manifest in (documents.source_manifest, documents.manifest):
        validate_contract(manifest, expected_kind=ContractKind.SITE)
    for observed in (documents.source_observed_state, documents.observed_state):
        validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    validate_contract(documents.deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    validate_contract(documents.intent, expected_kind=ContractKind.TRANSACTION_INTENT)
    validate_contract(documents.result, expected_kind=ContractKind.OPERATION_RESULT)
    validate_contract(documents.audit_entry, expected_kind=ContractKind.AUDIT_ENTRY)
    _validate_document_relationships(job.document, documents)
    return documents


def _validate_document_relationships(
    job: dict[str, object],
    documents: _DeploymentDocuments,
) -> None:
    request = job.get("request")
    expected_source = job.get("expectedSource")
    recovery = documents.intent.get("lifecycleRecovery")
    source_metadata = documents.source_manifest.get("metadata")
    source_spec = documents.source_manifest.get("spec")
    provenance = documents.result.get("provenance")
    if not all(
        type(value) is dict
        for value in (
            request,
            expected_source,
            recovery,
            source_metadata,
            source_spec,
            provenance,
        )
    ):
        raise DeploymentCommitError("deployment terminal binding is malformed")
    request = cast(dict[str, object], request)
    expected_source = cast(dict[str, object], expected_source)
    recovery = cast(dict[str, object], recovery)
    source_metadata = cast(dict[str, object], source_metadata)
    source_spec = cast(dict[str, object], source_spec)
    provenance = cast(dict[str, object], provenance)
    operation = _deployment_operation(request.get("operation"))
    source_state = LifecycleState(cast(str, source_spec["desiredState"]))
    target_state = LIFECYCLE_MATRIX.get((operation, source_state))
    if target_state is None:
        raise DeploymentCommitError("deployment operation is invalid for its source lifecycle")
    expected_candidate = deepcopy(documents.source_manifest)
    candidate_spec = cast(dict[str, object], expected_candidate["spec"])
    candidate_spec["desiredState"] = target_state.value
    candidate_spec["desiredDeployment"] = {
        "id": documents.deployment["id"],
        "archiveSha256": documents.deployment["archiveSha256"],
    }
    source_digest = manifest_digest(documents.source_manifest).to_dict()
    candidate_digest = manifest_digest(documents.manifest).to_dict()
    source_selected = source_spec.get("desiredDeployment")
    source_deployment_id = source_selected.get("id") if type(source_selected) is dict else None
    source_deployment_digest = expected_source.get("deploymentDigest")
    source_routes = "both" if source_state is LifecycleState.ACTIVE else "absent"
    candidate_routes = "both" if target_state is LifecycleState.ACTIVE else "absent"
    candidate_runtime = (
        recovery.get("candidateRuntimeGenerationId") if candidate_routes == "both" else None
    )
    history = documents.history
    target_id = cast(str, documents.deployment["id"])
    artifact = request.get("artifact")
    deploy_binding_valid = (
        operation is Operation.DEPLOY
        and documents.creates_deployment
        and type(artifact) is dict
        and job.get("artifact") == artifact
        and documents.deployment.get("archiveSha256") == artifact.get("sha256")
        and documents.deployment.get("releaseTreeDigest")
        == job.get("dispatchArtifactReleaseTreeDigest")
        and documents.deployment.get("correlationId") == request.get("correlationId")
        and target_id not in history
        and (not history or target_id > history[-1])
    )
    rollback_binding_valid = (
        operation is Operation.ROLLBACK
        and not documents.creates_deployment
        and artifact is None
        and job.get("artifact") is None
        and job.get("dispatchArtifactReleaseTreeDigest") is None
        and request.get("deploymentId") == target_id
        and target_id in history
        and target_id != source_deployment_id
    )
    if (
        job.get("phase") not in {"claimed", "completed"}
        or job.get("compatibilityVersion") != "static-job-v2"
        or documents.intent.get("compatibilityVersion") != "static-intent-v2"
        or documents.intent.get("operation") != operation.value
        or documents.intent.get("phase") != "prepared"
        or documents.intent.get("archiveRecovery") is not None
        or documents.intent.get("sourceManifest") != documents.source_manifest
        or documents.intent.get("candidateManifest") != documents.manifest
        or documents.intent.get("sourceManifestDigest") != source_digest
        or documents.intent.get("candidateManifestDigest") != candidate_digest
        or documents.manifest != expected_candidate
        or history != tuple(sorted(set(history)))
        or len(history) > _MAXIMUM_RETAINED_DEPLOYMENTS
        or job.get("dispatchArchiveDeploymentIds") != []
        or expected_source.get("expectsTenantAbsent") is not False
        or expected_source.get("lifecycle") != source_state.value
        or expected_source.get("manifestDigest") != source_digest
        or expected_source.get("archiveRecordDigest") is not None
        or documents.source_deployment_digest != source_deployment_digest
        or documents.source_release_tree_digest != job.get("dispatchSourceReleaseTreeDigest")
        or (
            source_state is LifecycleState.UNDEPLOYED
            and (
                history or source_deployment_id is not None or source_deployment_digest is not None
            )
        )
        or (
            source_state is not LifecycleState.UNDEPLOYED
            and (
                not history
                or source_deployment_id not in history
                or source_deployment_digest is None
            )
        )
        or recovery.get("sourceObservedState") != documents.source_observed_state
        or recovery.get("candidateObservedState") != documents.observed_state
        or job.get("dispatchSourceObservedState") != documents.source_observed_state
        or job.get("dispatchSourceRuntimeGenerationId") != recovery.get("sourceRuntimeGenerationId")
        or job.get("dispatchSourceRouteSet") != recovery.get("sourceRouteSet")
        or recovery.get("sourceRouteSet") != source_routes
        or recovery.get("candidateRouteSet") != candidate_routes
        or recovery.get("sourceRuntimeGenerationId") == recovery.get("candidateRuntimeGenerationId")
        or documents.source_observed_state.get("desiredManifestDigest") != source_digest
        or documents.source_observed_state.get("observedState") != source_state.value
        or documents.source_observed_state.get("activeDeploymentId") != source_deployment_id
        or documents.observed_state.get("desiredManifestDigest") != candidate_digest
        or documents.observed_state.get("observedState") != target_state.value
        or documents.observed_state.get("activeDeploymentId") != target_id
        or documents.observed_state.get("runtimeGenerationId") != candidate_runtime
        or not (deploy_binding_valid or rollback_binding_valid)
        or documents.deployment.get("tenantId") != documents.tenant_id
        or provenance != {"kind": "authorization-job", "jobId": job.get("jobId")}
        or documents.intent_id != documents.intent.get("intentId")
        or documents.tenant_id
        != source_metadata.get("id")
        != documents.source_observed_state.get("tenantId")
        != documents.observed_state.get("tenantId")
        != documents.intent.get("tenantId")
        != documents.result.get("tenantId")
        != documents.audit_entry.get("tenantId")
        or request.get("tenantId") != documents.tenant_id
        or documents.result.get("correlationId")
        != request.get("correlationId")
        != documents.intent.get("correlationId")
        != documents.audit_entry.get("correlationId")
        or documents.result.get("manifest") != documents.manifest
        or documents.result.get("canonicalOrigin") != source_metadata.get("canonicalOrigin")
        or documents.result.get("operation") != operation.value
        or documents.result.get("status") != "succeeded"
        or documents.audit_entry.get("operatorPrincipal") != job.get("operatorPrincipal")
        or documents.audit_entry.get("operation") != operation.value
        or documents.audit_entry.get("resultStatus") != "succeeded"
        or documents.audit_entry.get("timestamp") != documents.intent.get("createdAt")
        or documents.audit_entry.get("timestamp") != documents.observed_state.get("reconciledAt")
        or documents.audit_entry.get("resultDigest") != result_digest(documents.result).to_dict()
    ):
        raise DeploymentCommitError("deployment terminal documents disagree")


def _deployment_operation(value: object) -> Operation:
    try:
        operation = Operation(cast(str, value))
    except (TypeError, ValueError) as error:
        raise DeploymentCommitError("deployment operation is malformed") from error
    if operation not in {Operation.DEPLOY, Operation.ROLLBACK}:
        raise DeploymentCommitError("deployment finalization received another operation")
    return operation


def _require_same_job(
    transaction: DeploymentCommitTransaction,
    expected: StoredContract,
) -> StoredContract:
    current = transaction.read(StateRecordPath.authorization_job(expected.document["jobId"]))
    first = expected.document
    second = current.document
    first.pop("phase")
    second.pop("phase")
    if first != second or current.document["phase"] not in {"claimed", "completed"}:
        raise DeploymentCommitError("authorization job changed before deployment finalization")
    return current


def _require_exact_intent(
    transaction: DeploymentCommitTransaction,
    documents: _DeploymentDocuments,
) -> _ExactIntent:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != documents.intent_id:
        raise DeploymentCommitError("deployment finalization requires its sole exact intent")
    identity = inventory.records[0]
    path, record = transaction.read_intent(documents.intent_id)
    if (
        path != StateRecordPath.transaction_intent(documents.intent_id)
        or record.document != documents.intent
    ):
        raise DeploymentCommitError("deployment intent changed before terminal mutation")
    return _ExactIntent(
        path,
        IntentRemovalToken(record.revision, identity.metadata_generation),
    )


def _terminal_transition_without_intent(
    transaction: DeploymentCommitTransaction,
    release_store: DeploymentReleaseStore,
    job: StoredContract,
    documents: _DeploymentDocuments,
) -> dict[str, object] | None:
    if transaction.measure_intent_records().records:
        return None
    if job.document["phase"] != "completed":
        raise DeploymentCommitError("nonterminal deployment transition lost its durable intent")
    expected = (
        (StateRecordPath.tenant_desired(documents.tenant_id), documents.manifest),
        (
            StateRecordPath.tenant_observed(documents.tenant_id),
            documents.observed_state,
        ),
        (
            StateRecordPath.tenant_deployment(
                documents.tenant_id,
                documents.deployment["id"],
            ),
            documents.deployment,
        ),
        (StateRecordPath.authorization_result(job.document["jobId"]), documents.result),
    )
    try:
        if any(transaction.read(path).document != document for path, document in expected):
            raise DeploymentCommitError("terminal deployment state disagrees with its plan")
    except FileNotFoundError as error:
        raise DeploymentCommitError("terminal deployment state is incomplete") from error
    if transaction.tenant_deployment_ids(documents.tenant_id) != _terminal_history(documents):
        raise DeploymentCommitError("terminal deployment retention disagrees with its plan")
    _require_selected_release(transaction, release_store, documents)
    if _audit_needs_append(transaction.inspect_audit(), documents.audit_entry):
        raise DeploymentCommitError("terminal deployment audit entry is absent")
    return deepcopy(documents.result)


def _admit_transition(  # noqa: PLR0912,PLR0915 - each replay boundary is explicit
    transaction: DeploymentCommitTransaction,
    job: StoredContract,
    documents: _DeploymentDocuments,
    *,
    capacity_limits: HostCapacityLimits,
) -> _DeploymentProgress:
    desired = transaction.read(StateRecordPath.tenant_desired(documents.tenant_id))
    observed = transaction.read(StateRecordPath.tenant_observed(documents.tenant_id))
    if desired.document not in (documents.source_manifest, documents.manifest):
        raise StateConflictError("deployment desired state is outside recovery authority")
    if observed.document not in (
        documents.source_observed_state,
        documents.observed_state,
    ):
        raise StateConflictError("deployment observed state is outside recovery authority")
    write_desired = (
        desired.document == documents.source_manifest and desired.document != documents.manifest
    )
    write_observed = observed.document == documents.source_observed_state
    if observed.document == documents.observed_state and desired.document != documents.manifest:
        raise DeploymentCommitError("deployment observed state advanced before desired state")

    current_history = transaction.tenant_deployment_transition_ids(
        documents.tenant_id,
        candidate_id=documents.deployment["id"],
    )
    original = documents.history
    transition = _transition_history(documents)
    terminal = _terminal_history(documents)
    if not _history_is_replayable(
        current_history,
        original=original,
        transition=transition,
        terminal=terminal,
        creates_deployment=documents.creates_deployment,
    ):
        raise StateConflictError("deployment history is outside recovery authority")
    target_id = cast(str, documents.deployment["id"])
    write_deployment = documents.creates_deployment and target_id not in current_history
    if not write_deployment:
        _require_exact_deployment(transaction, documents.deployment)
    retired = tuple(
        _read_deployment(transaction, documents.tenant_id, deployment_id)
        for deployment_id in current_history
        if deployment_id not in terminal
    )
    _require_source_deployment(
        transaction,
        documents,
        current_history,
        transition_committed=not write_desired and not write_observed,
    )

    result_path = StateRecordPath.authorization_result(job.document["jobId"])
    try:
        existing_result = transaction.read(result_path)
    except FileNotFoundError:
        result_missing = True
    else:
        result_missing = False
        if existing_result.document != documents.result:
            raise StateConflictError("existing deployment result disagrees")
    audit_missing = _audit_needs_append(transaction.inspect_audit(), documents.audit_entry)
    if audit_missing:
        transaction.admit_audit_append(documents.audit_entry)
    job_transition = job.document["phase"] == "claimed"
    writes: list[dict[str, object]] = []
    if write_deployment:
        writes.append(documents.deployment)
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
    if result_missing:
        allocation = transaction.allocation_upper_bound(len(canonical_json_bytes(documents.result)))
        transaction.admit_inventory(
            StateInventoryReservation(
                authorization_records=1,
                authorization_allocated_bytes=allocation,
            )
        )
    if writes:
        allocations = [
            transaction.allocation_upper_bound(len(canonical_json_bytes(document)))
            for document in writes
            if document is not documents.audit_entry
        ]
        if audit_missing:
            allocations.append(
                transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
            )
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                allocated_bytes=(
                    sum(allocations) + transaction.namespace_allocation_upper_bound(len(writes))
                ),
                unique_inodes=len(writes),
            ),
            transaction.measure_filesystem_capacity(),
            limits=capacity_limits,
        )
    return _DeploymentProgress(
        desired,
        observed,
        retired,
        write_deployment,
        write_desired,
        write_observed,
        result_missing,
    )


def _transition_history(documents: _DeploymentDocuments) -> tuple[str, ...]:
    history = documents.history
    if documents.creates_deployment:
        history = (*history, cast(str, documents.deployment["id"]))
    return tuple(sorted(set(history)))


def _terminal_history(documents: _DeploymentDocuments) -> tuple[str, ...]:
    history = _transition_history(documents)
    target_id = cast(str, documents.deployment["id"])
    try:
        target_index = history.index(target_id)
    except ValueError as error:  # pragma: no cover - validated relationship proves membership
        raise DeploymentCommitError(
            "selected deployment is absent from transition history"
        ) from error
    first_retained = max(0, target_index - (_MAXIMUM_RETAINED_DEPLOYMENTS - 1))
    return history[first_retained : target_index + 1]


def _history_is_replayable(
    current: tuple[str, ...],
    *,
    original: tuple[str, ...],
    transition: tuple[str, ...],
    terminal: tuple[str, ...],
    creates_deployment: bool,
) -> bool:
    if current == original:
        return True
    if creates_deployment and transition[-1] not in current:
        return False
    return set(terminal).issubset(current) and set(current).issubset(transition)


def _read_deployment(
    transaction: DeploymentCommitTransaction,
    tenant_id: str,
    deployment_id: str,
) -> StoredContract:
    return transaction.read(StateRecordPath.tenant_deployment(tenant_id, deployment_id))


def _require_exact_deployment(
    transaction: DeploymentCommitTransaction,
    expected: dict[str, object],
) -> StoredContract:
    current = _read_deployment(
        transaction,
        cast(str, expected["tenantId"]),
        cast(str, expected["id"]),
    )
    if current.document != expected:
        raise StateConflictError("deployment record disagrees with transition authority")
    return current


def _require_source_deployment(
    transaction: DeploymentCommitTransaction,
    documents: _DeploymentDocuments,
    current_history: tuple[str, ...],
    *,
    transition_committed: bool,
) -> None:
    expected = cast(dict[str, object], documents.source_manifest["spec"]).get("desiredDeployment")
    if expected is None:
        return
    if type(expected) is not dict:
        raise StateConflictError("selected source deployment is absent")
    source_digest = documents.intent.get("sourceManifestDigest")
    expected_source = cast(dict[str, object], documents.intent["sourceManifest"])
    if source_digest != manifest_digest(expected_source).to_dict():
        raise DeploymentCommitError("source manifest digest drifted")
    source_id = expected.get("id")
    if source_id not in current_history:
        if source_id not in _terminal_history(documents) and transition_committed:
            return
        raise StateConflictError("selected source deployment is absent")
    source = _read_deployment(
        transaction,
        documents.tenant_id,
        cast(str, source_id),
    ).document
    expected_spec = cast(dict[str, object], expected_source["spec"])
    selected = cast(dict[str, object], expected_spec["desiredDeployment"])
    if (
        source.get("archiveSha256") != selected.get("archiveSha256")
        or source.get("releaseTreeDigest") != documents.source_release_tree_digest
        or deployment_record_digest(source).to_dict() != documents.source_deployment_digest
    ):
        raise StateConflictError("selected source deployment changed after dispatch")


def _require_selected_release(
    transaction: DeploymentCommitTransaction,
    release_store: DeploymentReleaseStore,
    documents: _DeploymentDocuments,
) -> None:
    measured = release_store.measure(
        documents.tenant_id,
        documents.deployment["id"],
        publication_lock=transaction,
    )
    if measured.digest.to_dict() != documents.deployment["releaseTreeDigest"]:
        raise StateConflictError("selected release disagrees with deployment authority")


def _ensure_audit(
    transaction: DeploymentCommitTransaction,
    audit_entry: dict[str, object],
) -> None:
    if _audit_needs_append(transaction.inspect_audit(), audit_entry):
        transaction.append_audit(audit_entry)


def _audit_needs_append(state: AuditState, audit_entry: dict[str, object]) -> bool:
    sequence = audit_entry["sequence"]
    if type(sequence) is not int:  # pragma: no cover - schema validation proves this
        raise DeploymentCommitError("deployment audit sequence is malformed")
    expected_digest = audit_entry_digest(audit_entry).to_dict()
    if (
        state.entry_count == sequence
        and audit_entry["previousEntryDigest"] == state.terminal_digest
    ):
        return True
    if state.entry_count == sequence + 1 and state.terminal_digest == expected_digest:
        return False
    raise DeploymentCommitError("deployment audit no longer extends the exact chain")


def _ensure_result(
    transaction: DeploymentCommitTransaction,
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
        raise StateConflictError("existing deployment result disagrees")


def _ensure_completed_job(
    transaction: DeploymentCommitTransaction,
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
    hook: DeploymentCommitFailureHook | None,
    boundary: DeploymentCommitBoundary,
) -> None:
    if hook is not None:
        hook(boundary)
