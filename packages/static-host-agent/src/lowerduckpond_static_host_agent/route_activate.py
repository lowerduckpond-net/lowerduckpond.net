"""Verified runtime activation and terminal commit for route transitions."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import NoReturn, Protocol

from lowerduckpond_static_host_agent.audit import AuditCapacityError
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_commit import (
    RouteCommitFailureHook,
    RouteCommitOutcome,
    admit_route_transition,
    finalize_route_transition_outcome,
    validate_route_transition,
)
from lowerduckpond_static_host_agent.route_prepare import PreparedRouteTransition
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateAdmissionRejectedError,
)

GenerationReloader = Callable[[PinnedCaddyGeneration, PinnedCaddyGeneration], None]
GenerationRestorer = Callable[[PinnedCaddyGeneration], None]
GenerationVerifier = Callable[[PinnedCaddyGeneration], None]


class RouteActivationError(RuntimeError):
    """A prepared route transition could not safely activate its candidate."""


class RouteActivationTransaction(Protocol):
    """The locked state surface required before route activation."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...


def activate_route_transition(  # noqa: PLR0913 - recovery mechanisms stay injectable
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    prepared: PreparedRouteTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: RouteCommitFailureHook | None = None,
    blocking: bool = False,
) -> dict[str, object]:
    """Activate or replay one candidate, then commit its exact route state."""

    return activate_route_transition_outcome(
        repository,
        runtime,
        gate,
        prepared,
        reloader=reloader,
        restorer=restorer,
        verifier=verifier,
        commit_failure_hook=commit_failure_hook,
        blocking=blocking,
    ).result


def activate_route_transition_outcome(  # noqa: PLR0913
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    prepared: PreparedRouteTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: RouteCommitFailureHook | None = None,
    blocking: bool = False,
) -> RouteCommitOutcome:
    """Activate or replay a route candidate and report result ownership."""

    if type(prepared) is not PreparedRouteTransition:
        raise TypeError("route activation requires one prepared transition")
    plan = deepcopy(prepared.plan)
    validate_route_transition(prepared.job, plan)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        current_job = _require_exact_job(transaction, prepared.job)
        if not transaction.measure_intent_records().records:
            return finalize_route_transition_outcome(
                transaction,
                current_job,
                plan,
                capacity_limits=prepared.capacity_limits,
                failure_hook=commit_failure_hook,
            )
        _require_exact_intent(transaction, plan.intent_id, plan.intent)
        recovery = plan.intent["lifecycleRecovery"]
        if type(recovery) is not dict:  # pragma: no cover - plan validation proves this
            raise RouteActivationError("route recovery authority is malformed")
        source_id = recovery["sourceRuntimeGenerationId"]
        candidate_id = recovery["candidateRuntimeGenerationId"]
        if prepared.candidate_manifest.generation_id != candidate_id:
            raise RouteActivationError("prepared route candidate identity disagrees")

        with (
            runtime.open_verified_generation(source_id) as source,
            runtime.open_verified_generation(candidate_id) as candidate,
        ):
            if candidate.manifest != prepared.candidate_manifest:
                raise RouteActivationError("prepared route candidate manifest changed")
            runtime.remove_abandoned_reference_temporaries()
            try:
                admit_route_transition(
                    transaction,
                    current_job,
                    plan,
                    capacity_limits=prepared.capacity_limits,
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                _reject_capacity_before_activation(
                    runtime,
                    source,
                    candidate,
                    restorer=restorer,
                    verifier=verifier,
                    error=error,
                )
            _ensure_candidate_running(
                runtime,
                source,
                candidate,
                reloader=reloader,
                restorer=restorer,
                verifier=verifier,
                candidate_selection_is_durable=current_job.document["phase"] == "completed",
            )
            try:
                return finalize_route_transition_outcome(
                    transaction,
                    current_job,
                    plan,
                    capacity_limits=prepared.capacity_limits,
                    failure_hook=commit_failure_hook,
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                _restore_source(runtime, source, restorer=restorer, error=error)


def _require_exact_job(
    transaction: RouteActivationTransaction,
    prepared: StoredContract,
) -> StoredContract:
    current = transaction.read(StateRecordPath.authorization_job(prepared.document["jobId"]))
    expected_document = prepared.document
    current_document = current.document
    current_phase = current_document.get("phase")
    for field in (
        "phase",
        "dispatchArchiveDeploymentIds",
        "dispatchArtifactReleaseTreeDigest",
        "dispatchSourceReleaseTreeDigest",
        "dispatchDeploymentIds",
        "dispatchTenantIds",
        "dispatchTenantRecordHistories",
    ):
        expected_document.pop(field, None)
        current_document.pop(field, None)
    if expected_document != current_document or current_phase not in {"claimed", "completed"}:
        raise RouteActivationError("prepared route job changed before activation")
    return current


def _require_exact_intent(
    transaction: RouteActivationTransaction,
    intent_id: str,
    expected: dict[str, object],
) -> None:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != intent_id:
        raise RouteActivationError("route activation requires its sole exact intent")
    path, current = transaction.read_intent(intent_id)
    if path != StateRecordPath.transaction_intent(intent_id) or current.document != expected:
        raise RouteActivationError("route intent changed before runtime activation")


def _ensure_candidate_running(  # noqa: PLR0913 - keep recovery callbacks explicit
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    reloader: GenerationReloader,
    restorer: GenerationRestorer,
    verifier: GenerationVerifier,
    candidate_selection_is_durable: bool,
) -> None:
    active_id = runtime.read_active()
    source_id = source.manifest.generation_id
    candidate_id = candidate.manifest.generation_id
    if active_id == source_id:
        try:
            try:
                verifier(source)
            except Exception:
                restorer(source)
            runtime.select_active(candidate_id)
            reloader(source, candidate)
        except BaseException as error:
            _restore_source(runtime, source, restorer=restorer, error=error)
        return
    if active_id == candidate_id:
        if not candidate_selection_is_durable:
            try:
                runtime.select_active(candidate_id)
            except BaseException as error:
                _restore_source(runtime, source, restorer=restorer, error=error)
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
    raise RouteActivationError("active Caddy generation is outside route recovery authority")


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
        raise RouteActivationError("route runtime restoration failed closed") from recovery_error
    raise error from None


def _reject_capacity_before_activation(  # noqa: PLR0913 - callbacks stay injectable
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    restorer: GenerationRestorer,
    verifier: GenerationVerifier,
    error: BaseException,
) -> NoReturn:
    active_id = runtime.read_active()
    if active_id == source.manifest.generation_id:
        try:
            verifier(source)
        except Exception:
            _restore_source(runtime, source, restorer=restorer, error=error)
        except BaseException as control_error:
            _restore_source(runtime, source, restorer=restorer, error=control_error)
        raise error from None
    if active_id == candidate.manifest.generation_id:
        _restore_source(runtime, source, restorer=restorer, error=error)
    raise RouteActivationError("active Caddy generation is outside route recovery authority")
