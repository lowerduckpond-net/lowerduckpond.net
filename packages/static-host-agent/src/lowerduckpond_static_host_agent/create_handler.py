"""Replay-safe dispatch of one claimed create authorization job."""

from __future__ import annotations

import secrets
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from lowerduckpond_static_contracts import ContractKind, validate_contract, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock

from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.create_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    activate_create_transition_outcome,
)
from lowerduckpond_static_host_agent.create_prepare import (
    CreateAuthorityDriftError,
    CreatePreparationError,
    prepare_create_transition,
)
from lowerduckpond_static_host_agent.create_recover import (
    CreateRecoveryError,
    recover_create_transition_outcome,
)
from lowerduckpond_static_host_agent.execution import (
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
)
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import IntentRecordInventory


class CreateLifecycleError(RuntimeError):
    """A claimed create job could not safely select its replay path."""


class UtcNow(Protocol):
    def __call__(self) -> datetime: ...


class CreateClassificationTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...


@dataclass(frozen=True, slots=True)
class _CreateReplay:
    result: dict[str, object] | None
    intent_id: str | None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _wall_clock_milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


class CreateLifecycleHandler:
    """Prepare, recover, or replay one exact create authorization job."""

    def __init__(  # noqa: PLR0913 - trusted lifecycle dependencies stay explicit
        self,
        repository: StateRepository,
        runtime: CaddyRuntime,
        gate: PublicationGate,
        *,
        now: UtcNow = _utc_now,
        clock: MillisecondClock = _wall_clock_milliseconds,
        entropy: EntropySource = _entropy,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
        reloader: GenerationReloader = reload_caddy_generation,
        restorer: GenerationRestorer = restore_caddy_generation,
        verifier: GenerationVerifier = verify_running_caddy,
    ) -> None:
        self._repository = repository
        self._runtime = runtime
        self._gate = gate
        self._now = now
        self._clock = clock
        self._entropy = entropy
        self._capacity_limits = capacity_limits
        self._reloader = reloader
        self._restorer = restorer
        self._verifier = verifier

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        """Complete one artifact-free create or replay its durable result."""

        canonical_job_id = validate_uuid7(job_id)
        if claim is not None:
            raise CreateLifecycleError("create authorization unexpectedly claimed an artifact")
        return self._execute_classified(
            canonical_job_id,
            blocking=blocking,
            retry_after_race=True,
        )

    def _execute_classified(
        self,
        job_id: str,
        *,
        blocking: bool,
        retry_after_race: bool,
    ) -> ExecutionOutcome:
        replay = self._classify(job_id, blocking=blocking)
        if replay.intent_id is not None:
            try:
                outcome = recover_create_transition_outcome(
                    self._repository,
                    self._runtime,
                    self._gate,
                    replay.intent_id,
                    capacity_limits=self._capacity_limits,
                    reloader=self._reloader,
                    restorer=self._restorer,
                    verifier=self._verifier,
                    blocking=blocking,
                )
            except CreateRecoveryError:
                if retry_after_race:
                    return self._execute_classified(
                        job_id,
                        blocking=blocking,
                        retry_after_race=False,
                    )
                raise
            return ExecutionOutcome(outcome.result, outcome.created)
        if replay.result is not None:
            result = deepcopy(replay.result)
            return ExecutionOutcome(
                result,
                False,
                replay_existing=(
                    result.get("status") == "failed"
                    and result.get("failurePublisher") == "authorization-executor"
                ),
            )
        try:
            prepared = prepare_create_transition(
                self._repository,
                self._runtime,
                self._gate,
                job_id,
                now=self._now(),
                clock=self._clock,
                entropy=self._entropy,
                capacity_limits=self._capacity_limits,
                blocking=blocking,
            )
        except CreateAuthorityDriftError as error:
            raise LifecycleJobRejectionError("state_drift") from error
        except CreatePreparationError:
            if retry_after_race:
                return self._execute_classified(
                    job_id,
                    blocking=blocking,
                    retry_after_race=False,
                )
            raise
        outcome = activate_create_transition_outcome(
            self._repository,
            self._runtime,
            self._gate,
            prepared,
            reloader=self._reloader,
            restorer=self._restorer,
            verifier=self._verifier,
            blocking=blocking,
        )
        return ExecutionOutcome(outcome.result, outcome.created)

    def _classify(self, job_id: str, *, blocking: bool) -> _CreateReplay:
        with self._repository.publication_transaction(blocking=blocking) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id))
            validate_contract(job.document, expected_kind=ContractKind.AUTHORIZATION_JOB)
            request = job.document["request"]
            if type(request) is not dict or request.get("operation") != "create":
                raise CreateLifecycleError("create handler received non-create authority")
            correlation_id = validate_uuid7(request["correlationId"])
            result = _read_result(transaction, job_id)
            if result is not None:
                _validate_create_result(job_id, request, result)
            inventory = transaction.measure_intent_records()
            matching: list[str] = []
            for identity in inventory.records:
                path, intent = transaction.read_intent(identity.intent_id)
                if (
                    path == StateRecordPath.transaction_intent(identity.intent_id)
                    and intent.document["operation"] == "create"
                    and intent.document["correlationId"] == correlation_id
                ):
                    matching.append(identity.intent_id)
            if len(matching) > 1:
                raise CreateLifecycleError("create job is bound to multiple active intents")
            if matching:
                if len(inventory.records) != 1:
                    raise CreateLifecycleError(
                        "create recovery authority is not globally exclusive"
                    )
                if result is not None and result["status"] != "succeeded":
                    raise CreateLifecycleError("failed create result retains an active intent")
                if job.document["phase"] not in {"claimed", "completed"}:
                    raise CreateLifecycleError("active create intent has an invalid job phase")
                return _CreateReplay(result, matching[0])
            if result is not None:
                return _CreateReplay(deepcopy(result), None)
            if inventory.records:
                raise CreateLifecycleError("another lifecycle intent is active")
            if job.document["phase"] != "claimed":
                raise CreateLifecycleError("fresh create job is not claimed")
            return _CreateReplay(None, None)


def _read_result(
    transaction: CreateClassificationTransaction,
    job_id: str,
) -> dict[str, object] | None:
    try:
        stored = transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        return None
    validate_contract(stored.document, expected_kind=ContractKind.OPERATION_RESULT)
    return stored.document


def _validate_create_result(
    job_id: str,
    request: dict[str, object],
    result: dict[str, object],
) -> None:
    provenance = result["provenance"]
    if (
        provenance != {"kind": "authorization-job", "jobId": job_id}
        or result["correlationId"] != request["correlationId"]
        or result["operation"] != "create"
    ):
        raise CreateLifecycleError("create result does not match its authorization job")
    if result["status"] != "succeeded":
        if result["tenantId"] is not None:
            raise CreateLifecycleError("failed create result names a tenant")
        return
    manifest = result["manifest"]
    if type(manifest) is not dict:  # pragma: no cover - schema validation proves this
        raise CreateLifecycleError("successful create result manifest is malformed")
    metadata = manifest["metadata"]
    if (
        type(metadata) is not dict
        or result["tenantId"] != metadata["id"]
        or result["canonicalOrigin"] != metadata["canonicalOrigin"]
    ):
        raise CreateLifecycleError("successful create result identity is inconsistent")
