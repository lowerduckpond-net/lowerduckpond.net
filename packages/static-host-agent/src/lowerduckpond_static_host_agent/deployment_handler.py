"""Replay-safe dispatch of one claimed deploy or rollback lifecycle job."""

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
from lowerduckpond_static_host_agent.deployment_activate import (
    DeploymentActivationError,
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    activate_deployment_transition_outcome,
)
from lowerduckpond_static_host_agent.deployment_commit import DeploymentCommitError
from lowerduckpond_static_host_agent.deployment_prepare import (
    DeploymentAuthorityDriftError,
    DeploymentPreparationError,
    prepare_deployment_transition,
)
from lowerduckpond_static_host_agent.deployment_recover import (
    DeploymentRecoveryError,
    recover_deployment_transition_outcome,
)
from lowerduckpond_static_host_agent.execution import (
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
)
from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.lifecycle_plan import LifecyclePlanError
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import IntentRecordInventory

_DEPLOYMENT_OPERATIONS = frozenset({"deploy", "rollback"})


class DeploymentLifecycleError(RuntimeError):
    """A deployment job could not safely select its exact execution path."""


class UtcNow(Protocol):
    def __call__(self) -> datetime: ...


class DeploymentClassificationTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...


@dataclass(frozen=True, slots=True)
class _DeploymentReplay:
    operation: str
    result: dict[str, object] | None
    intent_id: str | None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _wall_clock_milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


class DeploymentLifecycleHandler:
    """Prepare, recover, or replay one exact deploy or rollback job."""

    def __init__(  # noqa: PLR0913 - trusted lifecycle dependencies explicit
        self,
        repository: StateRepository,
        runtime: CaddyRuntime,
        intake: ArtifactIntake,
        release_store: DeploymentReleaseStore,
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
        self._intake = intake
        self._release_store = release_store
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
        """Complete one deployment transition or replay its durable result."""

        canonical_job_id = validate_uuid7(job_id)
        return self._execute_classified(
            canonical_job_id,
            claim=claim,
            blocking=blocking,
            retry_after_race=True,
        )

    def _execute_classified(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
        retry_after_race: bool,
    ) -> ExecutionOutcome:
        replay = self._classify(job_id, blocking=blocking)
        if replay.intent_id is not None:
            try:
                outcome = recover_deployment_transition_outcome(
                    self._repository,
                    self._runtime,
                    self._release_store,
                    self._gate,
                    replay.intent_id,
                    capacity_limits=self._capacity_limits,
                    reloader=self._reloader,
                    restorer=self._restorer,
                    verifier=self._verifier,
                    blocking=blocking,
                )
            except (
                DeploymentActivationError,
                DeploymentCommitError,
                DeploymentRecoveryError,
            ):
                if retry_after_race:
                    return self._execute_classified(
                        job_id,
                        claim=claim,
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
        artifact = None if claim is None else claim.artifact
        if (replay.operation == "deploy") != (artifact is not None):
            raise LifecycleJobRejectionError("invalid_artifact")
        try:
            prepared = prepare_deployment_transition(
                self._repository,
                self._runtime,
                self._intake,
                self._release_store,
                self._gate,
                job_id,
                artifact,
                now=self._now(),
                clock=self._clock,
                entropy=self._entropy,
                capacity_limits=self._capacity_limits,
                blocking=blocking,
            )
        except DeploymentAuthorityDriftError as error:
            raise LifecycleJobRejectionError("state_drift") from error
        except LifecyclePlanError as error:
            raise LifecycleJobRejectionError("invalid_request") from error
        except DeploymentPreparationError:
            if retry_after_race:
                return self._execute_classified(
                    job_id,
                    claim=claim,
                    blocking=blocking,
                    retry_after_race=False,
                )
            raise
        try:
            outcome = activate_deployment_transition_outcome(
                self._repository,
                self._runtime,
                self._release_store,
                self._gate,
                prepared,
                reloader=self._reloader,
                restorer=self._restorer,
                verifier=self._verifier,
                blocking=blocking,
            )
        except DeploymentActivationError, DeploymentCommitError:
            if retry_after_race:
                return self._execute_classified(
                    job_id,
                    claim=claim,
                    blocking=blocking,
                    retry_after_race=False,
                )
            raise
        return ExecutionOutcome(outcome.result, outcome.created)

    def _classify(  # noqa: PLR0912 - replay states remain explicit
        self,
        job_id: str,
        *,
        blocking: bool,
    ) -> _DeploymentReplay:
        with self._repository.publication_transaction(blocking=blocking) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id))
            validate_contract(job.document, expected_kind=ContractKind.AUTHORIZATION_JOB)
            request = job.document["request"]
            if type(request) is not dict or request.get("operation") not in (
                _DEPLOYMENT_OPERATIONS
            ):
                raise DeploymentLifecycleError("deployment handler received other authority")
            if job.document.get("compatibilityVersion") != "static-job-v2":
                raise LifecycleJobRejectionError("invalid_request")
            operation = str(request["operation"])
            correlation_id = validate_uuid7(request["correlationId"])
            tenant_id = validate_uuid7(request["tenantId"])
            result = _read_result(transaction, job_id)
            if result is not None:
                _validate_deployment_result(job_id, request, result)
            inventory = transaction.measure_intent_records()
            matching: list[str] = []
            for identity in inventory.records:
                path, intent = transaction.read_intent(identity.intent_id)
                if (
                    path == StateRecordPath.transaction_intent(identity.intent_id)
                    and intent.document["operation"] == operation
                    and intent.document["correlationId"] == correlation_id
                    and intent.document["tenantId"] == tenant_id
                ):
                    matching.append(identity.intent_id)
            if len(matching) > 1:
                raise DeploymentLifecycleError("deployment job is bound to multiple active intents")
            if matching:
                if len(inventory.records) != 1:
                    raise DeploymentLifecycleError(
                        "deployment recovery authority is not globally exclusive"
                    )
                if result is not None and result["status"] != "succeeded":
                    raise DeploymentLifecycleError(
                        "failed deployment result retains an active intent"
                    )
                if job.document["phase"] not in {"claimed", "completed"}:
                    raise DeploymentLifecycleError(
                        "active deployment intent has an invalid job phase"
                    )
                return _DeploymentReplay(operation, result, matching[0])
            if result is not None:
                return _DeploymentReplay(operation, deepcopy(result), None)
            if inventory.records:
                raise DeploymentLifecycleError("another lifecycle intent is active")
            if job.document["phase"] != "claimed":
                raise DeploymentLifecycleError("fresh deployment job is not claimed")
            return _DeploymentReplay(operation, None, None)


def _read_result(
    transaction: DeploymentClassificationTransaction,
    job_id: str,
) -> dict[str, object] | None:
    try:
        stored = transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        return None
    validate_contract(stored.document, expected_kind=ContractKind.OPERATION_RESULT)
    return stored.document


def _validate_deployment_result(
    job_id: str,
    request: dict[str, object],
    result: dict[str, object],
) -> None:
    provenance = result["provenance"]
    if (
        provenance != {"kind": "authorization-job", "jobId": job_id}
        or result["correlationId"] != request["correlationId"]
        or result["operation"] != request["operation"]
        or result["tenantId"] != request["tenantId"]
    ):
        raise DeploymentLifecycleError("deployment result does not match its authorization job")
    if result["status"] != "succeeded":
        return
    manifest = result["manifest"]
    if type(manifest) is not dict:  # pragma: no cover - schema validation proves this
        raise DeploymentLifecycleError("successful deployment result manifest is malformed")
    metadata = manifest["metadata"]
    if (
        type(metadata) is not dict
        or result["tenantId"] != metadata["id"]
        or result["canonicalOrigin"] != metadata["canonicalOrigin"]
    ):
        raise DeploymentLifecycleError("successful deployment result identity is inconsistent")
