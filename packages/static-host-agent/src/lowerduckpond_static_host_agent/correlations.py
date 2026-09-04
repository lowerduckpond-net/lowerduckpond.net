"""Durable exact-retry binding and fail-closed correlation admission."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
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
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
    DEFAULT_STATE_INVENTORY_LIMITS,
    AuthorizationRecordInventory,
    StateInventoryLimits,
    StateInventoryReservation,
)

_RATE_WINDOW: Final = timedelta(hours=1)
_MAXIMUM_PER_WINDOW: Final = 60
_BURST_CAPACITY: Final = 5
_TOKEN_INTERVAL_MICROSECONDS: Final = 60 * 1_000_000
_TOKEN_CAPACITY_MICROSECONDS: Final = _BURST_CAPACITY * _TOKEN_INTERVAL_MICROSECONDS


class CorrelationError(RuntimeError):
    """Durable correlation state is invalid or cannot be admitted."""


class CorrelationConflictError(CorrelationError):
    """An established correlation ID was retried with another binding."""


class CorrelationRateLimitError(CorrelationError):
    """A new correlation ID crossed the rolling or burst admission limit."""


@dataclass(frozen=True, slots=True)
class CorrelationResolution:
    """The immutable job selected for one exact correlation binding."""

    job: StoredContract
    created: bool
    repaired_records: int


@dataclass(frozen=True, slots=True)
class CorrelationReconciliation:
    """The bounded, repaired authorization-job inventory at startup."""

    jobs: tuple[StoredContract, ...]
    repaired_records: int


class _CorrelationTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...

    def admit_inventory(
        self,
        reservation: StateInventoryReservation,
        *,
        limits: StateInventoryLimits,
    ) -> object: ...

    def measure_authorization_records(
        self,
        *,
        limits: StateInventoryLimits,
    ) -> AuthorizationRecordInventory: ...


class CorrelationAdmission:
    """Resolve exact retries and admit new immutable job/correlation pairs."""

    def __init__(
        self,
        repository: StateRepository,
        *,
        limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> None:
        self._repository = repository
        self._limits = limits
        self._capacity_limits = capacity_limits

    def resolve(
        self,
        candidate: dict[str, object],
        *,
        now: datetime,
        blocking: bool = False,
    ) -> CorrelationResolution:
        """Return an exact retry or durably admit one new pending job."""

        correlation_id, job_id, accepted_at, canonical = _validate_candidate(
            candidate,
            now=now,
        )
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            inventory = transaction.measure_authorization_records(limits=self._limits)
            correlations, repaired_records = _reconcile_pairs(
                transaction,
                inventory=inventory,
                limits=self._limits,
                capacity_limits=self._capacity_limits,
            )
            established = correlations.get(correlation_id)
            if established is not None:
                if _retry_binding(established) != _retry_binding(candidate):
                    raise CorrelationConflictError(
                        "correlation ID is already bound to another authorized request"
                    )
                established_job_id = _job_id(established)
                return CorrelationResolution(
                    job=transaction.read(StateRecordPath.authorization_job(established_job_id)),
                    created=False,
                    repaired_records=repaired_records,
                )

            established_job_ids = {_job_id(document) for document in correlations.values()}
            if job_id in established_job_ids:
                raise CorrelationConflictError(
                    "new correlation selected an established job identity"
                )

            _admit_rate(
                tuple(_accepted_at(document) for document in correlations.values()),
                accepted_at,
            )
            allocation = transaction.allocation_upper_bound(len(canonical))
            _admit_writes(
                transaction,
                StateInventoryReservation(
                    authorization_records=2,
                    authorization_allocated_bytes=2 * allocation,
                ),
                state_limits=self._limits,
                capacity_limits=self._capacity_limits,
            )
            correlation = transaction.create_immutable(
                StateRecordPath.authorization_correlation(correlation_id),
                candidate,
            )
            # If this second publication is interrupted, the correlation copy
            # contains the complete job needed by the next reconciliation.
            job = transaction.create_immutable(
                StateRecordPath.authorization_job(job_id),
                candidate,
            )
            if correlation.document != job.document:  # pragma: no cover - defensive
                raise CorrelationError("durable correlation and job copies diverged")
            return CorrelationResolution(
                job=job,
                created=True,
                repaired_records=repaired_records,
            )

    def reconcile(self, *, blocking: bool = False) -> CorrelationReconciliation:
        """Repair interrupted pairs and return each validated current job."""

        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            return self.reconcile_transaction(transaction)

    def reconcile_transaction(
        self,
        transaction: _CorrelationTransaction,
    ) -> CorrelationReconciliation:
        """Repair and snapshot pairs inside a caller-held state transaction."""

        inventory = transaction.measure_authorization_records(limits=self._limits)
        correlations, repaired_records = _reconcile_pairs(
            transaction,
            inventory=inventory,
            limits=self._limits,
            capacity_limits=self._capacity_limits,
        )
        jobs = tuple(
            transaction.read(StateRecordPath.authorization_job(_job_id(correlation)))
            for _correlation_id, correlation in sorted(correlations.items())
        )
        return CorrelationReconciliation(jobs=jobs, repaired_records=repaired_records)

    def find_retry(
        self,
        correlation_id: object,
        *,
        binding: dict[str, object],
        blocking: bool = False,
    ) -> CorrelationResolution | None:
        """Resolve one caller binding from durable authority without rebuilding it."""

        canonical_id = validate_uuid7(correlation_id)
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            inventory = transaction.measure_authorization_records(limits=self._limits)
            correlations, repaired_records = _reconcile_pairs(
                transaction,
                inventory=inventory,
                limits=self._limits,
                capacity_limits=self._capacity_limits,
            )
            established = correlations.get(canonical_id)
            if established is None:
                return None
            if _caller_retry_binding(established) != canonical_json_bytes(binding):
                raise CorrelationConflictError(
                    "correlation ID is already bound to another authorized request"
                )
            return CorrelationResolution(
                job=transaction.read(StateRecordPath.authorization_job(_job_id(established))),
                created=False,
                repaired_records=repaired_records,
            )


def _validate_candidate(
    candidate: dict[str, object],
    *,
    now: datetime,
) -> tuple[str, str, datetime, bytes]:
    if type(candidate) is not dict:
        raise TypeError("authorization job must be a contract object")
    validate_contract(candidate, expected_kind=ContractKind.AUTHORIZATION_JOB)
    if candidate["phase"] != "pending":
        raise CorrelationError("new correlation admission requires a pending job")
    request = candidate["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise CorrelationError("authorization job request is not an object")
    correlation_id = validate_uuid7(request["correlationId"])
    job_id = validate_uuid7(candidate["jobId"])
    accepted_at = _accepted_at(candidate)
    if now.tzinfo is None or now.utcoffset() is None:
        raise CorrelationError("correlation admission clock must be timezone-aware")
    if now.astimezone(UTC) != accepted_at:
        raise CorrelationError("job acceptance timestamp does not match the admission clock")
    StateRecordPath.authorization_correlation(correlation_id).validate_binding(candidate)
    StateRecordPath.authorization_job(job_id).validate_binding(candidate)
    return correlation_id, job_id, accepted_at, canonical_json_bytes(candidate)


def _reconcile_pairs(
    transaction: _CorrelationTransaction,
    *,
    inventory: AuthorizationRecordInventory,
    limits: StateInventoryLimits,
    capacity_limits: HostCapacityLimits,
) -> tuple[dict[str, dict[str, object]], int]:
    # These concrete attributes are provided by the repository transaction and
    # bounded AuthorizationRecordInventory. Keeping reconciliation here avoids
    # exposing mutable filesystem primitives as public API.
    correlation_ids = inventory.correlation_ids
    job_ids = inventory.job_ids
    correlations = {
        correlation_id: transaction.read(
            StateRecordPath.authorization_correlation(correlation_id)
        ).document
        for correlation_id in correlation_ids
    }
    jobs = {
        job_id: transaction.read(StateRecordPath.authorization_job(job_id)).document
        for job_id in job_ids
    }

    jobs_by_correlation: dict[str, dict[str, object]] = {}
    for job in jobs.values():
        correlation_id = _correlation_id(job)
        if correlation_id in jobs_by_correlation:
            raise CorrelationError("multiple jobs claim one correlation identity")
        jobs_by_correlation[correlation_id] = job

    correlations_by_job: dict[str, str] = {}
    for correlation_id, correlation in correlations.items():
        job_id = _job_id(correlation)
        established_correlation = correlations_by_job.setdefault(job_id, correlation_id)
        if established_correlation != correlation_id:
            raise CorrelationError("multiple correlations claim one job identity")

    repairs: list[tuple[StateRecordPath, dict[str, object]]] = []
    for correlation_id, correlation in correlations.items():
        job_id = _job_id(correlation)
        current_job = jobs.get(job_id)
        claimed = jobs_by_correlation.get(correlation_id)
        if claimed is not None and _job_id(claimed) != job_id:
            raise CorrelationError("correlation and job indexes disagree")
        if current_job is None:
            repairs.append((StateRecordPath.authorization_job(job_id), correlation))
        elif _durable_binding(current_job) != _durable_binding(correlation):
            raise CorrelationError("correlation and job bindings disagree")

    for correlation_id, job in jobs_by_correlation.items():
        if correlation_id not in correlations:
            repairs.append((StateRecordPath.authorization_correlation(correlation_id), job))
            correlations[correlation_id] = job

    if repairs:
        reservation_bytes = sum(
            transaction.allocation_upper_bound(len(canonical_json_bytes(document)))
            for _path, document in repairs
        )
        _admit_writes(
            transaction,
            StateInventoryReservation(
                authorization_records=len(repairs),
                authorization_allocated_bytes=reservation_bytes,
            ),
            state_limits=limits,
            capacity_limits=capacity_limits,
        )
        for path, document in repairs:
            transaction.create_immutable(path, document)
    return correlations, len(repairs)


def _admit_writes(
    transaction: _CorrelationTransaction,
    reservation: StateInventoryReservation,
    *,
    state_limits: StateInventoryLimits,
    capacity_limits: HostCapacityLimits,
) -> None:
    transaction.admit_inventory(reservation, limits=state_limits)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(
            allocated_bytes=(
                reservation.authorization_allocated_bytes
                + transaction.namespace_allocation_upper_bound(reservation.authorization_records)
            ),
            unique_inodes=reservation.authorization_records,
        ),
        transaction.measure_filesystem_capacity(),
        limits=capacity_limits,
    )


def _retry_binding(document: dict[str, object]) -> bytes:
    binding = deepcopy(document)
    for field in ("jobId", "acceptedAt", "phase"):
        del binding[field]
    binding.pop("executionValidated", None)
    binding.pop("dispatchArchiveDeploymentIds", None)
    binding.pop("dispatchArtifactReleaseTreeDigest", None)
    binding.pop("dispatchSourceReleaseTreeDigest", None)
    binding.pop("dispatchDeploymentIds", None)
    binding.pop("dispatchSourceRouteSet", None)
    binding.pop("dispatchSourceRuntimeGenerationId", None)
    binding.pop("dispatchTenantIds", None)
    binding.pop("dispatchTenantRecordHistories", None)
    return canonical_json_bytes(binding)


def _caller_retry_binding(document: dict[str, object]) -> bytes:
    return canonical_json_bytes(
        {
            "operatorPrincipal": document["operatorPrincipal"],
            "request": document["request"],
            "requestDigest": document["requestDigest"],
            "artifact": document["artifact"],
        }
    )


def _durable_binding(document: dict[str, object]) -> bytes:
    binding = deepcopy(document)
    del binding["phase"]
    binding.pop("executionValidated", None)
    binding.pop("dispatchArchiveDeploymentIds", None)
    binding.pop("dispatchArtifactReleaseTreeDigest", None)
    binding.pop("dispatchSourceReleaseTreeDigest", None)
    binding.pop("dispatchDeploymentIds", None)
    binding.pop("dispatchSourceRouteSet", None)
    binding.pop("dispatchSourceRuntimeGenerationId", None)
    binding.pop("dispatchTenantIds", None)
    binding.pop("dispatchTenantRecordHistories", None)
    return canonical_json_bytes(binding)


def _job_id(document: dict[str, object]) -> str:
    return validate_uuid7(document["jobId"])


def _correlation_id(document: dict[str, object]) -> str:
    request = document["request"]
    if type(request) is not dict:  # pragma: no cover - validated reads prove this
        raise CorrelationError("authorization request is not an object")
    return validate_uuid7(request["correlationId"])


def _accepted_at(document: dict[str, object]) -> datetime:
    value = document["acceptedAt"]
    if type(value) is not str:  # pragma: no cover - validated reads prove this
        raise CorrelationError("authorization acceptance time is not a string")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:  # pragma: no cover - schema validation proves this
        raise CorrelationError("authorization acceptance time is invalid") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise CorrelationError("authorization acceptance time has no timezone")
    return timestamp.astimezone(UTC)


def _admit_rate(history: tuple[datetime, ...], candidate: datetime) -> None:
    ordered = tuple(sorted(history))
    if ordered and candidate < ordered[-1]:
        raise CorrelationRateLimitError("wall-clock rollback closes new correlation admission")
    window_start = candidate - _RATE_WINDOW
    if sum(timestamp > window_start for timestamp in ordered) >= _MAXIMUM_PER_WINDOW:
        raise CorrelationRateLimitError("rolling-hour correlation limit is exhausted")

    credit = _TOKEN_CAPACITY_MICROSECONDS
    previous = ordered[0] if ordered else candidate
    for timestamp in (*ordered, candidate):
        elapsed = timestamp - previous
        elapsed_microseconds = (
            elapsed.days * 86_400_000_000 + elapsed.seconds * 1_000_000 + elapsed.microseconds
        )
        credit = min(_TOKEN_CAPACITY_MICROSECONDS, credit + elapsed_microseconds)
        if credit < _TOKEN_INTERVAL_MICROSECONDS:
            raise CorrelationRateLimitError("correlation burst limit is exhausted")
        credit -= _TOKEN_INTERVAL_MICROSECONDS
        previous = timestamp
