"""Opaque authorization-job validation, claim, and terminal execution."""

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from dataclasses import dataclass
from typing import Final, Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
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
from lowerduckpond_static_host_agent.issuance import VerifiedArtifact, build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordPath,
    StateRepository,
    StateRevision,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
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


class AuthorizationExecutor:
    """Validate only a root-owned job and produce a mutation-free M3.6 result."""

    def __init__(
        self,
        repository: StateRepository,
        intake: ArtifactIntake,
        *,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> None:
        self._repository = repository
        self._intake = intake
        self._capacity_limits = capacity_limits

    def execute(self, job_id: object, *, blocking: bool = False) -> ExecutionOutcome:
        """Execute exactly one canonical UUIDv7 job and no caller-selected fields."""

        canonical_id = validate_uuid7(job_id)
        path = StateRecordPath.authorization_job(canonical_id)
        initial = self._repository.read(path, blocking=blocking)
        existing = self._read_result(canonical_id, blocking=blocking)
        if existing is not None:
            result = self._repair_terminal_phase(initial, existing, blocking=blocking)
            self._consume_terminal_artifact(initial.document, blocking=blocking)
            return ExecutionOutcome(result, False)

        artifact = _job_artifact(initial.document)
        claim_context = (
            self._intake.claim(
                correlation_id=_correlation_id(initial.document),
                declared=artifact,
                blocking=blocking,
            )
            if artifact is not None
            else nullcontext(None)
        )
        try:
            with claim_context as claim:
                outcome = self._execute_with_claim(
                    canonical_id,
                    initial,
                    claim=claim,
                    blocking=blocking,
                )
                if claim is not None:
                    claim.consume()
                return outcome
        except IntakeArtifactUnavailableError:
            return self._fail_without_claim(
                canonical_id,
                initial,
                error_code="invalid_artifact",
                blocking=blocking,
            )
        except IntakeError as error:
            raise ExecutionError("authorized artifact failed its root-owned validation") from error

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
                result = _repair_terminal_phase_transaction(transaction, current, existing)
                return ExecutionOutcome(result, False)
            _validate_job_integrity(current.document, claim=claim)
            error_code = _expected_source_error(transaction, current.document)
            if error_code is not None:
                result = _failure_result(current.document, error_code)
                _publish_result(transaction, current, result, limits=self._capacity_limits)
                return ExecutionOutcome(result, True)
            claimed = _claim_pending(transaction, current)
            # Lifecycle handlers deliberately remain unavailable in M3.6. The
            # validated/claimed envelope is the compatibility boundary later
            # handlers consume; no tenant or publication state is mutated here.
            result = _failure_result(claimed.document, _NOT_IMPLEMENTED)
            _publish_result(transaction, claimed, result, limits=self._capacity_limits)
            return ExecutionOutcome(result, True)

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

    def _repair_terminal_phase(
        self,
        job: StoredContract,
        result: StoredContract,
        *,
        blocking: bool,
    ) -> dict[str, object]:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job.document["jobId"]))
            _require_same_authority(job.document, current.document)
            return _repair_terminal_phase_transaction(transaction, current, result)


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
    except FileNotFoundError:
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
