"""Opaque authorization-job validation, claim, and terminal execution."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
from typing import Final, Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    manifest_digest,
    request_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    FilesystemCapacity,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.intake import (
    ArtifactClaim,
    ArtifactIntake,
    IntakeArtifactUnavailableError,
    IntakeError,
)
from lowerduckpond_static_host_agent.issuance import (
    SourceStateError,
    VerifiedArtifact,
    build_expected_source,
)
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordPath,
    StateRepository,
    StateRevision,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
    StateInventoryProjection,
    StateInventoryReservation,
)

_NOT_IMPLEMENTED: Final = "not_implemented"


class ExecutionError(RuntimeError):
    """An opaque authorized job could not reach one safe terminal result."""


class JobHandoff(Protocol):
    """Queue one validated opaque UUID without carrying operation authority."""

    def enqueue(self, job_id: str) -> None: ...


class ExecutionTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def compare_and_swap(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
    ) -> StoredContract: ...

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract: ...

    def measure_inventory(self) -> StateInventory: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...

    def tenant_has_identity_history(self, tenant_id: object) -> bool: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def admit_inventory(
        self,
        reservation: StateInventoryReservation,
    ) -> StateInventoryProjection: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """One immutable terminal result and whether this call published it."""

    result: dict[str, object]
    created: bool


class LifecycleJobHandler(Protocol):
    """Complete one validated root-owned lifecycle job and its durable result."""

    def execute(
        self,
        job_id: str,
        *,
        claim: ArtifactClaim | None,
        blocking: bool,
    ) -> ExecutionOutcome: ...


class AuthorizationExecutor:
    """Validate, claim, and dispatch only one root-owned authorization job."""

    def __init__(
        self,
        repository: StateRepository,
        intake: ArtifactIntake,
        *,
        handlers: Mapping[str, LifecycleJobHandler] | None = None,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> None:
        self._repository = repository
        self._intake = intake
        self._handlers = dict(handlers or {})
        self._capacity_limits = capacity_limits

    def execute(self, job_id: object, *, blocking: bool = False) -> ExecutionOutcome:
        """Execute exactly one canonical UUIDv7 job and no caller-selected fields."""

        canonical_id = validate_uuid7(job_id)
        path = StateRecordPath.authorization_job(canonical_id)
        initial = self._repository.read(path, blocking=blocking)
        handler = self._handler_for(initial.document)
        existing = self._read_result(canonical_id, blocking=blocking)
        if existing is not None:
            result: dict[str, object] | None = None
            with self._repository.transaction(
                mode=LockMode.EXCLUSIVE,
                blocking=blocking,
            ) as transaction:
                current = transaction.read(path)
                _require_same_authority(initial.document, current.document)
                durable = _read_result_transaction(transaction, canonical_id)
                if durable is None or durable.document != existing.document:
                    raise ExecutionError("terminal result changed during replay")
                _validate_result_binding(current.document, durable.document)
                dispatch = handler is not None and _has_bound_lifecycle_intent(
                    transaction,
                    current.document,
                    result=durable.document,
                )
                if not dispatch:
                    result = _repair_terminal_phase_transaction(
                        transaction,
                        current,
                        durable,
                    )
            if dispatch:
                if handler is None:  # pragma: no cover - dispatch proves a handler
                    raise ExecutionError("authorization handler selection was lost")
                artifact = _job_artifact(initial.document)
                if artifact is None:
                    return self._execute_handler(
                        canonical_id,
                        initial,
                        handler,
                        claim=None,
                        blocking=blocking,
                    )
                with ExitStack() as claim_stack:
                    try:
                        claim = claim_stack.enter_context(
                            self._intake.claim(
                                correlation_id=_correlation_id(initial.document),
                                declared=artifact,
                                blocking=blocking,
                            )
                        )
                    except IntakeArtifactUnavailableError as error:
                        raise ExecutionError("lifecycle replay artifact is unavailable") from error
                    except IntakeError as error:
                        raise ExecutionError(
                            "lifecycle replay artifact failed root-owned validation"
                        ) from error
                    outcome = self._execute_handler(
                        canonical_id,
                        initial,
                        handler,
                        claim=claim,
                        blocking=blocking,
                    )
                    claim.consume()
                    return outcome
            if result is None:  # pragma: no cover - direct replay assigns the result
                raise ExecutionError("terminal result selection was lost")
            self._consume_terminal_artifact(initial.document, blocking=blocking)
            return ExecutionOutcome(result, False)

        artifact = _job_artifact(initial.document)
        if artifact is None:
            return self._execute_with_claim(
                canonical_id,
                initial,
                claim=None,
                handler=handler,
                blocking=blocking,
            )
        with ExitStack() as claim_stack:
            try:
                claim = claim_stack.enter_context(
                    self._intake.claim(
                        correlation_id=_correlation_id(initial.document),
                        declared=artifact,
                        blocking=blocking,
                    )
                )
            except IntakeArtifactUnavailableError:
                return self._fail_without_claim(
                    canonical_id,
                    initial,
                    error_code="invalid_artifact",
                    blocking=blocking,
                )
            except IntakeError as error:
                raise ExecutionError(
                    "authorized artifact failed its root-owned validation"
                ) from error
            outcome = self._execute_with_claim(
                canonical_id,
                initial,
                claim=claim,
                handler=handler,
                blocking=blocking,
            )
            claim.consume()
            return outcome

    def _consume_terminal_artifact(
        self,
        job: dict[str, object],
        *,
        blocking: bool,
    ) -> None:
        artifact = _job_artifact(job)
        if artifact is None:
            return
        try:
            with self._intake.claim(
                correlation_id=_correlation_id(job),
                declared=artifact,
                blocking=blocking,
            ) as claim:
                claim.consume()
        except IntakeArtifactUnavailableError:
            return
        except IntakeError as error:
            raise ExecutionError("terminal artifact cleanup failed closed") from error

    def _execute_with_claim(
        self,
        job_id: str,
        initial: StoredContract,
        *,
        claim: ArtifactClaim | None,
        handler: LifecycleJobHandler | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        path = StateRecordPath.authorization_job(job_id)
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(path)
            _require_same_authority(initial.document, current.document)
            existing = _read_result_transaction(transaction, job_id)
            if existing is not None:
                _validate_result_binding(current.document, existing.document)
                if handler is None or not _has_bound_lifecycle_intent(
                    transaction,
                    current.document,
                    result=existing.document,
                ):
                    result = _repair_terminal_phase_transaction(transaction, current, existing)
                    return ExecutionOutcome(result, False)
            else:
                _validate_job_integrity(current.document, claim=claim)
                if current.document["phase"] == "pending":
                    error_code = _expected_source_error(transaction, current.document)
                    if error_code is not None:
                        result = _failure_result(current.document, error_code)
                        _publish_result(
                            transaction,
                            current,
                            result,
                            limits=self._capacity_limits,
                        )
                        return ExecutionOutcome(result, True)
                if current.document["phase"] == "claimed" and handler is None:
                    raise ExecutionError("claimed lifecycle job handler is unavailable")
                claimed = _claim_pending(transaction, current)
                if handler is None:
                    # Unsupported lifecycle operations remain mutation-free until
                    # their independently reviewed handlers become available.
                    result = _failure_result(claimed.document, _NOT_IMPLEMENTED)
                    _publish_result(transaction, claimed, result, limits=self._capacity_limits)
                    return ExecutionOutcome(result, True)
        if handler is None:  # pragma: no cover - every in-lock branch returns
            raise ExecutionError("authorization handler selection was lost")
        return self._execute_handler(
            job_id,
            initial,
            handler,
            claim=claim,
            blocking=blocking,
        )

    def _execute_handler(
        self,
        job_id: str,
        initial: StoredContract,
        handler: LifecycleJobHandler,
        *,
        claim: ArtifactClaim | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        returned = handler.execute(job_id, claim=claim, blocking=blocking)
        if type(returned) is not ExecutionOutcome:
            raise ExecutionError("lifecycle handler returned a malformed outcome")
        result = deepcopy(returned.result)
        validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            stored = _read_result_transaction(transaction, job_id)
            if stored is None or stored.document != result:
                raise ExecutionError("lifecycle handler result is not durably exact")
            _validate_result_binding(current.document, result)
            expected_phase = "completed" if result["status"] == "succeeded" else "failed"
            if current.document["phase"] != expected_phase:
                raise ExecutionError("lifecycle handler returned before terminal job commit")
        return ExecutionOutcome(result, returned.created)

    def _handler_for(self, job: dict[str, object]) -> LifecycleJobHandler | None:
        request = job["request"]
        if type(request) is not dict:  # pragma: no cover - validated reads prove this
            raise ExecutionError("authorization job request is not an object")
        operation = request["operation"]
        if type(operation) is not str:  # pragma: no cover - schema validation proves this
            raise ExecutionError("authorization operation is not a string")
        return self._handlers.get(operation)

    def _fail_without_claim(
        self,
        job_id: str,
        initial: StoredContract,
        *,
        error_code: str,
        blocking: bool,
    ) -> ExecutionOutcome:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            existing = _read_result_transaction(transaction, job_id)
            if existing is not None:
                return ExecutionOutcome(
                    _repair_terminal_phase_transaction(transaction, current, existing),
                    False,
                )
            result = _failure_result(current.document, error_code)
            _publish_result(transaction, current, result, limits=self._capacity_limits)
            return ExecutionOutcome(result, True)

    def _read_result(self, job_id: str, *, blocking: bool) -> StoredContract | None:
        try:
            return self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=blocking,
            )
        except FileNotFoundError:
            return None


def _job_artifact(job: dict[str, object]) -> VerifiedArtifact | None:
    declared = job["artifact"]
    if declared is None:
        return None
    if type(declared) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job artifact binding is not an object")
    return VerifiedArtifact(size=cast(int, declared["size"]), sha256=cast(str, declared["sha256"]))


def _correlation_id(job: dict[str, object]) -> str:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    return validate_uuid7(request["correlationId"])


def _require_same_authority(
    expected: dict[str, object],
    current: dict[str, object],
) -> None:
    first = deepcopy(expected)
    second = deepcopy(current)
    first.pop("phase", None)
    second.pop("phase", None)
    if first != second:
        raise ExecutionError("authorization job authority changed before execution")


def _validate_job_integrity(
    job: dict[str, object],
    *,
    claim: ArtifactClaim | None,
) -> None:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    if request_digest(request).to_dict() != job["requestDigest"]:
        raise ExecutionError("authorization request digest does not match its envelope")
    declared = _job_artifact(job)
    if (declared is None) != (claim is None):
        raise ExecutionError("authorization artifact presence does not match its envelope")
    if declared is not None and claim is not None and claim.artifact.verified != declared:
        raise ExecutionError("claimed artifact does not match its authorization envelope")


def _expected_source_error(
    transaction: ExecutionTransaction,
    job: dict[str, object],
) -> str | None:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    try:
        actual = build_expected_source(transaction, request)
    except FileNotFoundError, SourceStateError:
        return "state_drift"
    if actual != job["expectedSource"]:
        return "state_drift"
    if request["operation"] == "create":
        inventory = transaction.measure_inventory()
        slug = request["slug"]
        for tenant_id in inventory.tenant_ids:
            desired = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
            metadata = desired["metadata"]
            if type(metadata) is dict and metadata.get("slug") == slug:
                return "state_drift"
    return None


def _claim_pending(
    transaction: ExecutionTransaction,
    current: StoredContract,
) -> StoredContract:
    phase = current.document["phase"]
    if phase == "claimed":
        return current
    if phase != "pending":
        raise ExecutionError("authorization job has no result in a terminal phase")
    claimed = current.document
    claimed["phase"] = "claimed"
    return transaction.compare_and_swap(
        StateRecordPath.authorization_job(claimed["jobId"]),
        current.revision,
        claimed,
    )


def _failure_result(job: dict[str, object], error_code: str) -> dict[str, object]:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": request["operation"],
        "status": "failed",
        "errorCode": error_code,
        "tenantId": None if request["operation"] == "create" else request["tenantId"],
    }
    if request["operation"] == "archive":
        result["archiveRecord"] = None
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    return result


def _publish_result(
    transaction: ExecutionTransaction,
    job: StoredContract,
    result: dict[str, object],
    *,
    limits: HostCapacityLimits,
) -> None:
    canonical = canonical_json_bytes(result)
    allocation = transaction.allocation_upper_bound(len(canonical))
    reservation = StateInventoryReservation(
        authorization_records=1,
        authorization_allocated_bytes=allocation,
    )
    transaction.admit_inventory(reservation)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(
            allocated_bytes=(allocation + transaction.namespace_allocation_upper_bound(1)),
            unique_inodes=1,
        ),
        transaction.measure_filesystem_capacity(),
        limits=limits,
    )
    transaction.create_immutable(
        StateRecordPath.authorization_result(job.document["jobId"]),
        result,
    )
    _set_terminal_phase(transaction, job, result)


def _read_result_transaction(
    transaction: ExecutionTransaction,
    job_id: str,
) -> StoredContract | None:
    try:
        return transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        return None


def _has_bound_lifecycle_intent(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    *,
    result: dict[str, object],
) -> bool:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization job request is not an object")
    correlation_id = validate_uuid7(request["correlationId"])
    correlation = transaction.read(StateRecordPath.authorization_correlation(correlation_id))
    _require_same_authority(job, correlation.document)
    matching_kinds: set[str] = set()
    matching_intents: list[dict[str, object]] = []
    for identity in transaction.measure_intent_records().records:
        path, intent = transaction.read_intent(identity.intent_id)
        kind = cast(str, intent.document["kind"])
        expected_paths = {
            "TransactionIntent": StateRecordPath.transaction_intent,
            "ArchiveConstructionIntent": StateRecordPath.archive_construction_intent,
            "ArchiveRetirementIntent": StateRecordPath.archive_retirement_intent,
        }
        try:
            expected_path = expected_paths[kind](identity.intent_id)
        except KeyError as error:  # pragma: no cover - repository reads recognize intent kinds
            raise ExecutionError("lifecycle intent kind is not recognized") from error
        if path != expected_path:
            raise ExecutionError("lifecycle intent path disagrees with its identity")
        if not _intent_binds_job(intent.document, job, request):
            continue
        if kind in matching_kinds:
            raise ExecutionError("authorization job repeats one lifecycle intent kind")
        matching_kinds.add(kind)
        matching_intents.append(intent.document)
    if matching_intents:
        _validate_result_intent_binding(result, request, matching_intents)
    return bool(matching_kinds)


def _validate_result_intent_binding(
    result: dict[str, object],
    request: dict[str, object],
    intents: list[dict[str, object]],
) -> None:
    if result["status"] != "succeeded":
        return
    _validate_archive_result_intent_binding(result, request, intents)
    matching = [intent for intent in intents if intent["kind"] == "TransactionIntent"]
    if request["operation"] == "create" and len(matching) != 1:
        raise ExecutionError("successful create result has no exact lifecycle intent")
    if not matching:
        return
    if len(matching) != 1:  # pragma: no cover - duplicate kinds fail during collection
        raise ExecutionError("successful result has no exact lifecycle intent")
    intent = matching[0]
    manifest = result.get("manifest")
    if manifest is None:
        return
    if type(manifest) is not dict:
        raise ExecutionError("successful lifecycle result manifest is malformed")
    candidate_digest = manifest_digest(manifest).to_dict()
    if (
        result["tenantId"] != intent["tenantId"]
        or candidate_digest != intent["candidateManifestDigest"]
    ):
        raise ExecutionError("successful result disagrees with its lifecycle intent")
    if request["operation"] != "create":
        return
    recovery = intent["lifecycleRecovery"]
    if type(recovery) is not dict:
        raise ExecutionError("successful create recovery authority is malformed")
    metadata = manifest["metadata"]
    candidate_observed = recovery["candidateObservedState"]
    if type(metadata) is not dict or type(candidate_observed) is not dict:
        raise ExecutionError("successful create candidate authority is malformed")
    if (
        not result["tenantId"] == metadata["id"] == intent["tenantId"]
        or result["canonicalOrigin"] != metadata["canonicalOrigin"]
        or candidate_digest != intent["candidateManifestDigest"]
        or candidate_observed["tenantId"] != intent["tenantId"]
        or candidate_observed["desiredManifestDigest"] != candidate_digest
    ):
        raise ExecutionError("successful create result disagrees with its lifecycle intent")


def _validate_archive_result_intent_binding(
    result: dict[str, object],
    request: dict[str, object],
    intents: list[dict[str, object]],
) -> None:
    if request["operation"] != "archive":
        return
    matching = [intent for intent in intents if intent["kind"] == "ArchiveConstructionIntent"]
    if not matching:
        return
    if len(matching) != 1:  # pragma: no cover - duplicate kinds fail during collection
        raise ExecutionError("successful archive result has no exact construction intent")
    manifest = result.get("manifest")
    if type(manifest) is not dict:
        raise ExecutionError("successful archive result manifest is malformed")
    intent = matching[0]
    if (
        result["tenantId"] != intent["tenantId"]
        or manifest_digest(manifest).to_dict() != intent["candidateManifestDigest"]
    ):
        raise ExecutionError("successful archive result disagrees with its construction intent")


def _intent_binds_job(
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    kind = intent["kind"]
    if kind == "TransactionIntent":
        return _transaction_intent_binds_job(intent, job, request)
    if kind == "ArchiveConstructionIntent":
        return _archive_construction_intent_binds_job(intent, job, request)
    if kind == "ArchiveRetirementIntent":
        return _archive_retirement_intent_binds_job(intent, job, request)
    raise ExecutionError("lifecycle intent kind is not recognized")


def _transaction_intent_binds_job(
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    if intent["correlationId"] != request["correlationId"]:
        return False
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if (
        intent["operation"] != request["operation"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or (request["operation"] != "create" and intent["tenantId"] != request["tenantId"])
    ):
        raise ExecutionError("lifecycle intent authority does not match its job")
    return True


def _archive_construction_intent_binds_job(
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    overlaps = (
        intent["jobId"] == job["jobId"] or intent["correlationId"] == request["correlationId"]
    )
    if not overlaps:
        return False
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if (
        request["operation"] != "archive"
        or intent["jobId"] != job["jobId"]
        or intent["operatorPrincipal"] != job["operatorPrincipal"]
        or intent["tenantId"] != request["tenantId"]
        or intent["correlationId"] != request["correlationId"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or intent["deploymentRecordDigest"] != expected["deploymentDigest"]
    ):
        raise ExecutionError("archive construction authority does not match its job")
    return True


def _archive_retirement_intent_binds_job(
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    provenance = intent["provenance"]
    if type(provenance) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("archive retirement provenance is not an object")
    if provenance["kind"] == "emergency-administrator":
        if intent["correlationId"] == request["correlationId"]:
            raise ExecutionError("emergency intent collides with job authority")
        return False
    overlaps = (
        provenance["jobId"] == job["jobId"] or intent["correlationId"] == request["correlationId"]
    )
    if not overlaps:
        return False
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if (
        intent["transition"] != request["operation"]
        or provenance != {"kind": "authorization-job", "jobId": job["jobId"]}
        or intent["operatorPrincipal"] != job["operatorPrincipal"]
        or intent["tenantId"] != request["tenantId"]
        or intent["correlationId"] != request["correlationId"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or intent["archiveRecordDigest"] != expected["archiveRecordDigest"]
    ):
        raise ExecutionError("archive retirement authority does not match its job")
    return True


def _repair_terminal_phase_transaction(
    transaction: ExecutionTransaction,
    job: StoredContract,
    result: StoredContract,
) -> dict[str, object]:
    _validate_result_binding(job.document, result.document)
    expected_phase = "completed" if result.document["status"] == "succeeded" else "failed"
    if job.document["phase"] != expected_phase:
        _set_terminal_phase(transaction, job, result.document)
    return result.document


def _set_terminal_phase(
    transaction: ExecutionTransaction,
    job: StoredContract,
    result: dict[str, object],
) -> None:
    expected_phase = "completed" if result["status"] == "succeeded" else "failed"
    if job.document["phase"] == expected_phase:
        return
    terminal = job.document
    terminal["phase"] = expected_phase
    try:
        transaction.compare_and_swap(
            StateRecordPath.authorization_job(terminal["jobId"]),
            job.revision,
            terminal,
        )
    except StateConflictError as error:
        raise ExecutionError("authorization phase changed during terminal commit") from error


def _validate_result_binding(job: dict[str, object], result: dict[str, object]) -> None:
    request = job["request"]
    provenance = result["provenance"]
    if type(request) is not dict or type(provenance) is not dict:
        raise ExecutionError("terminal result binding is malformed")
    tenant_id = _expected_result_tenant(request, result)
    if (
        provenance != {"kind": "authorization-job", "jobId": job["jobId"]}
        or result["correlationId"] != request["correlationId"]
        or result["operation"] != request["operation"]
        or result["tenantId"] != tenant_id
    ):
        raise ExecutionError("terminal result does not match its authorization job")


def _expected_result_tenant(
    request: dict[str, object],
    result: dict[str, object],
) -> object:
    if request["operation"] != "create":
        return request["tenantId"]
    if result["status"] == "failed":
        return None
    try:
        return validate_uuid7(result["tenantId"])
    except (TypeError, ValueError) as error:
        raise ExecutionError("successful create result has no generated tenant") from error
