"""Replay-safe terminal commitment for one intent-authorized create."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
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
from lowerduckpond_static_host_agent.lifecycle_plan import CreateTransitionPlan
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

_CREATE_TENANT_DIRECTORY_COUNT: Final = 3


class CreateCommitError(RuntimeError):
    """A prepared create cannot reach one exact terminal commit."""


class CreateCommitBoundary(StrEnum):
    """Replay boundaries after each durable terminal-create step."""

    STATE_SYNC = "state-sync"
    AUDIT_SYNC = "audit-sync"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


CreateCommitFailureHook = Callable[[CreateCommitBoundary], None]


class CreateCommitTransaction(Protocol):
    """The held publication transaction surface used by create finalization."""

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

    def ensure_create_tenant_state(
        self,
        tenant_id: object,
        manifest: dict[str, object],
        observed_state: dict[str, object],
    ) -> None: ...

    def measure_create_tenant_namespace_growth(self, tenant_id: object) -> int: ...

    def inspect_audit(self) -> AuditState: ...

    def append_audit(self, document: dict[str, object]) -> AuditAppend: ...

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
class _CreateDocuments:
    tenant_id: str
    intent_id: str
    manifest: dict[str, object]
    observed_state: dict[str, object]
    intent: dict[str, object]
    result: dict[str, object]
    audit_entry: dict[str, object]


def finalize_create_transition(
    transaction: CreateCommitTransaction,
    job: StoredContract,
    plan: CreateTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: CreateCommitFailureHook | None = None,
) -> dict[str, object]:
    """Commit and replay one successful create after its runtime reload."""

    documents = _freeze_and_validate(job, plan)
    current_job = _require_same_job(transaction, job)
    terminal = _terminal_create_without_intent(transaction, current_job, documents)
    if terminal is not None:
        return terminal
    intent_removal = _require_exact_intent(transaction, documents)
    missing = _admit_missing_state(
        transaction,
        current_job,
        documents,
        capacity_limits=capacity_limits,
    )

    transaction.ensure_create_tenant_state(
        documents.tenant_id,
        documents.manifest,
        documents.observed_state,
    )
    _notify(failure_hook, CreateCommitBoundary.STATE_SYNC)
    _ensure_audit(transaction, documents.audit_entry)
    _notify(failure_hook, CreateCommitBoundary.AUDIT_SYNC)
    _ensure_result(transaction, current_job, documents.result, result_missing=missing.result)
    _notify(failure_hook, CreateCommitBoundary.RESULT_SYNC)
    _ensure_completed_job(transaction, current_job)
    _notify(failure_hook, CreateCommitBoundary.JOB_SYNC)
    transaction.remove_reconciled_intent(intent_removal.path, intent_removal.token)
    _notify(failure_hook, CreateCommitBoundary.INTENT_REMOVED)
    return deepcopy(documents.result)


def validate_create_transition(job: StoredContract, plan: CreateTransitionPlan) -> None:
    """Validate every create document relationship without mutating state."""

    _freeze_and_validate(job, plan)


def admit_create_transition(
    transaction: CreateCommitTransaction,
    job: StoredContract,
    plan: CreateTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> None:
    """Prove terminal create capacity and inventory before runtime mutation."""

    documents = _freeze_and_validate(job, plan)
    current_job = _require_same_job(transaction, job)
    _require_exact_intent(transaction, documents)
    _admit_missing_state(
        transaction,
        current_job,
        documents,
        capacity_limits=capacity_limits,
    )


@dataclass(frozen=True, slots=True)
class _MissingState:
    result: bool


@dataclass(frozen=True, slots=True)
class _ExactIntent:
    path: StateRecordPath
    token: IntentRemovalToken


def _require_exact_intent(
    transaction: CreateCommitTransaction,
    documents: _CreateDocuments,
) -> _ExactIntent:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != documents.intent_id:
        raise CreateCommitError("create finalization requires its sole exact intent")
    identity = inventory.records[0]
    path, record = transaction.read_intent(documents.intent_id)
    if (
        path != StateRecordPath.transaction_intent(documents.intent_id)
        or record.document != documents.intent
    ):
        raise CreateCommitError("create intent changed before terminal mutation")
    return _ExactIntent(
        path,
        IntentRemovalToken(record.revision, identity.metadata_generation),
    )


def _terminal_create_without_intent(
    transaction: CreateCommitTransaction,
    job: StoredContract,
    documents: _CreateDocuments,
) -> dict[str, object] | None:
    if transaction.measure_intent_records().records:
        return None
    if job.document["phase"] != "completed":
        raise CreateCommitError("nonterminal create lost its durable intent")
    expected = (
        (StateRecordPath.tenant_desired(documents.tenant_id), documents.manifest),
        (
            StateRecordPath.tenant_observed(documents.tenant_id),
            documents.observed_state,
        ),
        (
            StateRecordPath.authorization_result(job.document["jobId"]),
            documents.result,
        ),
    )
    try:
        if any(transaction.read(path).document != document for path, document in expected):
            raise CreateCommitError("terminal create state disagrees with its plan")
    except FileNotFoundError as error:
        raise CreateCommitError("terminal create state is incomplete") from error
    if _audit_needs_append(transaction.inspect_audit(), documents.audit_entry):
        raise CreateCommitError("terminal create audit entry is absent")
    return deepcopy(documents.result)


def _freeze_and_validate(job: StoredContract, plan: CreateTransitionPlan) -> _CreateDocuments:
    if type(job) is not StoredContract or type(plan) is not CreateTransitionPlan:
        raise TypeError("create finalization requires one stored job and one create plan")
    documents = _CreateDocuments(
        tenant_id=plan.tenant_id,
        intent_id=plan.intent_id,
        manifest=deepcopy(plan.manifest),
        observed_state=deepcopy(plan.observed_state),
        intent=deepcopy(plan.intent),
        result=deepcopy(plan.result),
        audit_entry=deepcopy(plan.audit_entry),
    )
    validate_contract(documents.manifest, expected_kind=ContractKind.SITE)
    validate_contract(
        documents.observed_state,
        expected_kind=ContractKind.TENANT_OBSERVED_STATE,
    )
    validate_contract(documents.intent, expected_kind=ContractKind.TRANSACTION_INTENT)
    validate_contract(documents.result, expected_kind=ContractKind.OPERATION_RESULT)
    validate_contract(documents.audit_entry, expected_kind=ContractKind.AUDIT_ENTRY)

    job_document = job.document
    request = job_document["request"]
    provenance = documents.result["provenance"]
    metadata = documents.manifest["metadata"]
    spec = documents.manifest["spec"]
    recovery = documents.intent["lifecycleRecovery"]
    if not all(type(value) is dict for value in (request, provenance, metadata, spec, recovery)):
        raise CreateCommitError("create terminal binding is malformed")
    request = cast(dict[str, object], request)
    provenance = cast(dict[str, object], provenance)
    metadata = cast(dict[str, object], metadata)
    spec = cast(dict[str, object], spec)
    recovery = cast(dict[str, object], recovery)
    desired_digest = manifest_digest(documents.manifest).to_dict()
    if (
        job_document["phase"] not in {"claimed", "completed"}
        or request["operation"] != "create"
        or metadata["slug"] != request["slug"]
        or spec
        != {
            "runtime": "static",
            "desiredState": "undeployed",
            "quotas": request["quotas"],
        }
        or documents.observed_state["desiredManifestDigest"] != desired_digest
        or documents.observed_state["observedState"] != "undeployed"
        or documents.observed_state["activeDeploymentId"] is not None
        or documents.observed_state["runtimeGenerationId"] is not None
        or documents.intent["operation"] != "create"
        or documents.intent["phase"] != "prepared"
        or documents.intent["sourceManifest"] is not None
        or documents.intent["sourceManifestDigest"] is not None
        or documents.intent["candidateManifestDigest"] != desired_digest
        or recovery["sourceObservedState"] is not None
        or recovery["sourceRouteSet"] != "absent"
        or recovery["candidateObservedState"] != documents.observed_state
        or recovery["candidateRouteSet"] != "absent"
        or recovery["sourceRuntimeGenerationId"] == recovery["candidateRuntimeGenerationId"]
        or provenance != {"kind": "authorization-job", "jobId": job_document["jobId"]}
        or documents.intent_id != documents.intent["intentId"]
        or documents.tenant_id
        != metadata["id"]
        != documents.observed_state["tenantId"]
        != documents.intent["tenantId"]
        != documents.result["tenantId"]
        != documents.audit_entry["tenantId"]
        or documents.result["correlationId"]
        != request["correlationId"]
        != documents.intent["correlationId"]
        != documents.audit_entry["correlationId"]
        or documents.result["manifest"] != documents.manifest
        or documents.result["operation"] != "create"
        or documents.result["status"] != "succeeded"
        or documents.audit_entry["operatorPrincipal"] != job_document["operatorPrincipal"]
        or documents.audit_entry["operation"] != "create"
        or documents.audit_entry["resultStatus"] != "succeeded"
        or documents.audit_entry["timestamp"] != documents.intent["createdAt"]
        or documents.audit_entry["timestamp"] != documents.observed_state["reconciledAt"]
        or documents.audit_entry["resultDigest"] != result_digest(documents.result).to_dict()
    ):
        raise CreateCommitError("create terminal documents disagree")
    return documents


def _require_same_job(
    transaction: CreateCommitTransaction,
    expected: StoredContract,
) -> StoredContract:
    job_id = expected.document["jobId"]
    current = transaction.read(StateRecordPath.authorization_job(job_id))
    first = expected.document
    second = current.document
    first.pop("phase", None)
    second.pop("phase", None)
    first.pop("dispatchArchiveDeploymentIds", None)
    second.pop("dispatchArchiveDeploymentIds", None)
    first.pop("dispatchArtifactReleaseTreeDigest", None)
    second.pop("dispatchArtifactReleaseTreeDigest", None)
    first.pop("dispatchDeploymentIds", None)
    second.pop("dispatchDeploymentIds", None)
    if first != second or current.document["phase"] not in {"claimed", "completed"}:
        raise CreateCommitError("authorization job changed before create finalization")
    return current


def _admit_missing_state(
    transaction: CreateCommitTransaction,
    job: StoredContract,
    documents: _CreateDocuments,
    *,
    capacity_limits: HostCapacityLimits,
) -> _MissingState:
    records = (
        (StateRecordPath.tenant_desired(documents.tenant_id), documents.manifest),
        (StateRecordPath.tenant_observed(documents.tenant_id), documents.observed_state),
        (
            StateRecordPath.authorization_result(
                cast(dict[str, object], documents.result["provenance"])["jobId"]
            ),
            documents.result,
        ),
    )
    missing: list[tuple[StateRecordPath, dict[str, object]]] = []
    for path, document in records:
        try:
            current = transaction.read(path)
        except FileNotFoundError:
            missing.append((path, document))
        else:
            if current.document != document:
                raise StateConflictError("existing create terminal state disagrees")

    result_path = records[-1][0]
    result_missing = any(path == result_path for path, _document in missing)
    audit_missing = _audit_needs_append(
        transaction.inspect_audit(),
        documents.audit_entry,
    )
    job_transition = job.document["phase"] == "claimed"
    inventory = transaction.measure_inventory()
    tenant_missing = documents.tenant_id not in inventory.tenant_ids
    directory_inodes = transaction.measure_create_tenant_namespace_growth(documents.tenant_id)
    if tenant_missing != (directory_inodes == _CREATE_TENANT_DIRECTORY_COUNT):
        raise CreateCommitError("create tenant inventory and namespace shape disagree")
    allocations = {
        path: transaction.allocation_upper_bound(len(canonical_json_bytes(document)))
        for path, document in missing
    }
    result_allocation = allocations.get(result_path, 0)
    transient_allocations = list(allocations.values())
    if audit_missing:
        transient_allocations.append(
            transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
        )
    if job_transition:
        completed = job.document
        completed["phase"] = "completed"
        transient_allocations.append(
            transaction.allocation_upper_bound(len(canonical_json_bytes(completed)))
        )
    entry_count = len(missing) + directory_inodes + int(audit_missing) + int(job_transition)
    if entry_count == 0:
        return _MissingState(result_missing)
    transaction.admit_inventory(
        StateInventoryReservation(
            tenants=int(tenant_missing),
            authorization_records=int(result_missing),
            authorization_allocated_bytes=result_allocation,
        )
    )
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
    return _MissingState(result_missing)


def _ensure_audit(
    transaction: CreateCommitTransaction,
    audit_entry: dict[str, object],
) -> None:
    state = transaction.inspect_audit()
    if not _audit_needs_append(state, audit_entry):
        return
    transaction.append_audit(audit_entry)


def _audit_needs_append(
    state: AuditState,
    audit_entry: dict[str, object],
) -> bool:
    sequence = audit_entry["sequence"]
    if type(sequence) is not int:  # pragma: no cover - schema validation proves this
        raise CreateCommitError("create audit sequence is malformed")
    expected_digest = audit_entry_digest(audit_entry).to_dict()
    if (
        state.entry_count == sequence
        and audit_entry["previousEntryDigest"] == state.terminal_digest
    ):
        return True
    if state.entry_count == sequence + 1 and state.terminal_digest == expected_digest:
        return False
    raise CreateCommitError("create audit no longer extends the exact chain")


def _ensure_result(
    transaction: CreateCommitTransaction,
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
        raise StateConflictError("existing create result disagrees")


def _ensure_completed_job(
    transaction: CreateCommitTransaction,
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
    hook: CreateCommitFailureHook | None,
    boundary: CreateCommitBoundary,
) -> None:
    if hook is not None:
        hook(boundary)
