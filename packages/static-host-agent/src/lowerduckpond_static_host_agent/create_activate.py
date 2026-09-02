"""Verified runtime activation and terminal commitment for prepared creates."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import NoReturn, Protocol

from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.create_commit import (
    CreateCommitFailureHook,
    finalize_create_transition,
    validate_create_transition,
)
from lowerduckpond_static_host_agent.create_prepare import PreparedCreateTransition
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import IntentRecordInventory

GenerationReloader = Callable[[PinnedCaddyGeneration, PinnedCaddyGeneration], None]
GenerationRestorer = Callable[[PinnedCaddyGeneration], None]
GenerationVerifier = Callable[[PinnedCaddyGeneration], None]


class CreateActivationError(RuntimeError):
    """A prepared create could not safely activate its exact candidate."""


class CreateActivationTransaction(Protocol):
    """The locked state surface required before runtime activation."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...


def activate_create_transition(  # noqa: PLR0913 - recovery mechanisms stay injectable
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    prepared: PreparedCreateTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: CreateCommitFailureHook | None = None,
    blocking: bool = False,
) -> dict[str, object]:
    """Activate or replay one candidate, then commit its exact create state."""

    if type(prepared) is not PreparedCreateTransition:
        raise TypeError("create activation requires one prepared transition")
    plan = deepcopy(prepared.plan)
    validate_create_transition(prepared.job, plan)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        current_job = _require_exact_job(transaction, prepared.job)
        if not transaction.measure_intent_records().records:
            return finalize_create_transition(
                transaction,
                current_job,
                plan,
                failure_hook=commit_failure_hook,
            )
        _require_exact_intent(transaction, plan.intent_id, plan.intent)
        recovery = plan.intent["lifecycleRecovery"]
        if type(recovery) is not dict:  # pragma: no cover - plan validation proves this
            raise CreateActivationError("create recovery authority is malformed")
        source_id = recovery["sourceRuntimeGenerationId"]
        candidate_id = recovery["candidateRuntimeGenerationId"]
        if prepared.candidate_manifest.generation_id != candidate_id:
            raise CreateActivationError("prepared candidate manifest identity disagrees")

        with (
            runtime.open_verified_generation(source_id) as source,
            runtime.open_verified_generation(candidate_id) as candidate,
        ):
            if candidate.manifest != prepared.candidate_manifest:
                raise CreateActivationError("prepared candidate manifest changed")
            _ensure_candidate_running(
                runtime,
                source,
                candidate,
                reloader=reloader,
                restorer=restorer,
                verifier=verifier,
            )
            return finalize_create_transition(
                transaction,
                current_job,
                plan,
                failure_hook=commit_failure_hook,
            )


def _require_exact_job(
    transaction: CreateActivationTransaction,
    prepared: StoredContract,
) -> StoredContract:
    current = transaction.read(StateRecordPath.authorization_job(prepared.document["jobId"]))
    expected_document = prepared.document
    current_document = current.document
    expected_document.pop("phase", None)
    current_phase = current_document.pop("phase", None)
    if expected_document != current_document or current_phase not in {"claimed", "completed"}:
        raise CreateActivationError("prepared create job changed before activation")
    return current


def _require_exact_intent(
    transaction: CreateActivationTransaction,
    intent_id: str,
    expected: dict[str, object],
) -> None:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != intent_id:
        raise CreateActivationError("create activation requires its sole exact intent")
    path, current = transaction.read_intent(intent_id)
    if path != StateRecordPath.transaction_intent(intent_id) or current.document != expected:
        raise CreateActivationError("create intent changed before runtime activation")


def _ensure_candidate_running(  # noqa: PLR0913 - keep recovery callbacks explicit
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    reloader: GenerationReloader,
    restorer: GenerationRestorer,
    verifier: GenerationVerifier,
) -> None:
    active_id = runtime.read_active()
    source_id = source.manifest.generation_id
    candidate_id = candidate.manifest.generation_id
    if active_id == source_id:
        try:
            runtime.select_active(candidate_id)
            reloader(source, candidate)
        except BaseException as error:
            _restore_source(runtime, source, restorer=restorer, error=error)
        return
    if active_id == candidate_id:
        try:
            verifier(candidate)
        except Exception:
            try:
                reloader(source, candidate)
            except BaseException as error:
                _restore_source(runtime, source, restorer=restorer, error=error)
        except BaseException as error:
            _restore_source(runtime, source, restorer=restorer, error=error)
        return
    raise CreateActivationError("active Caddy generation is outside create recovery authority")


def _restore_source(
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    *,
    restorer: GenerationRestorer,
    error: BaseException,
) -> NoReturn:
    try:
        runtime.select_active(source.manifest.generation_id)
        restorer(source)
    except BaseException as recovery_error:
        raise CreateActivationError("create runtime restoration failed closed") from recovery_error
    raise error from None
