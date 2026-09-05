"""Verified runtime activation and terminal commit for deployment transitions."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import NoReturn, Protocol, cast

from lowerduckpond_static_host_agent.audit import AuditCapacityError
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.deployment_commit import (
    DeploymentCommitFailureHook,
    DeploymentCommitOutcome,
    DeploymentCommitTransaction,
    admit_deployment_transition,
    finalize_deployment_transition_outcome,
    validate_deployment_transition,
)
from lowerduckpond_static_host_agent.deployment_prepare import (
    PreparedDeploymentTransition,
)
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateAdmissionRejectedError,
)

GenerationReloader = Callable[[PinnedCaddyGeneration, PinnedCaddyGeneration], None]
GenerationRestorer = Callable[[PinnedCaddyGeneration], None]
GenerationVerifier = Callable[[PinnedCaddyGeneration], None]


class DeploymentActivationError(RuntimeError):
    """A prepared deployment could not safely activate its exact candidate."""


class DeploymentActivationTransaction(Protocol):
    """The locked state surface required before deployment activation."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


def activate_deployment_transition(  # noqa: PLR0913 - recovery mechanisms explicit
    repository: StateRepository,
    runtime: CaddyRuntime,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    prepared: PreparedDeploymentTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: DeploymentCommitFailureHook | None = None,
    blocking: bool = False,
) -> dict[str, object]:
    """Activate or replay one deployment candidate, then commit its state."""

    return activate_deployment_transition_outcome(
        repository,
        runtime,
        release_store,
        gate,
        prepared,
        reloader=reloader,
        restorer=restorer,
        verifier=verifier,
        commit_failure_hook=commit_failure_hook,
        blocking=blocking,
    ).result


def activate_deployment_transition_outcome(  # noqa: PLR0913
    repository: StateRepository,
    runtime: CaddyRuntime,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    prepared: PreparedDeploymentTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: DeploymentCommitFailureHook | None = None,
    blocking: bool = False,
) -> DeploymentCommitOutcome:
    """Activate or replay a deployment candidate and report result ownership."""

    if type(prepared) is not PreparedDeploymentTransition:
        raise TypeError("deployment activation requires one prepared transition")
    plan = deepcopy(prepared.plan)
    validate_deployment_transition(prepared.job, plan)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        current_job = _require_exact_job(transaction, prepared.job)
        if not transaction.measure_intent_records().records:
            return finalize_deployment_transition_outcome(
                cast(DeploymentCommitTransaction, transaction),
                release_store,
                current_job,
                plan,
                capacity_limits=prepared.capacity_limits,
                failure_hook=commit_failure_hook,
            )
        _require_exact_intent(transaction, plan.intent_id, plan.intent)
        recovery = plan.intent["lifecycleRecovery"]
        if type(recovery) is not dict:  # pragma: no cover - plan validation proves this
            raise DeploymentActivationError("deployment recovery authority is malformed")
        source_id = recovery["sourceRuntimeGenerationId"]
        candidate_id = recovery["candidateRuntimeGenerationId"]
        if prepared.candidate_manifest.generation_id != candidate_id:
            raise DeploymentActivationError("prepared deployment candidate identity disagrees")

        with (
            runtime.open_verified_generation(source_id) as source,
            runtime.open_verified_generation(candidate_id) as candidate,
        ):
            if candidate.manifest != prepared.candidate_manifest:
                raise DeploymentActivationError("prepared deployment candidate manifest changed")
            _require_selected_release(transaction, release_store, plan)
            runtime.remove_abandoned_reference_temporaries()
            try:
                admit_deployment_transition(
                    cast(DeploymentCommitTransaction, transaction),
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
                    source_restoration_permitted=prepared.source_restoration_permitted,
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
                source_restoration_permitted=prepared.source_restoration_permitted,
            )
            try:
                return finalize_deployment_transition_outcome(
                    cast(DeploymentCommitTransaction, transaction),
                    release_store,
                    current_job,
                    plan,
                    capacity_limits=prepared.capacity_limits,
                    failure_hook=commit_failure_hook,
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                if prepared.source_restoration_permitted:
                    _restore_source(runtime, source, restorer=restorer, error=error)
                raise error from None


def _require_exact_job(
    transaction: DeploymentActivationTransaction,
    prepared: StoredContract,
) -> StoredContract:
    current = transaction.read(StateRecordPath.authorization_job(prepared.document["jobId"]))
    expected_document = prepared.document
    current_document = current.document
    current_phase = current_document.get("phase")
    for field in (
        "phase",
        "executionValidated",
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
        raise DeploymentActivationError("prepared deployment job changed before activation")
    return current


def _require_exact_intent(
    transaction: DeploymentActivationTransaction,
    intent_id: str,
    expected: dict[str, object],
) -> None:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != intent_id:
        raise DeploymentActivationError("deployment activation requires its sole exact intent")
    path, current = transaction.read_intent(intent_id)
    if path != StateRecordPath.transaction_intent(intent_id) or current.document != expected:
        raise DeploymentActivationError("deployment intent changed before runtime activation")


def _require_selected_release(
    transaction: DeploymentActivationTransaction,
    release_store: DeploymentReleaseStore,
    plan: DeploymentTransitionPlan,
) -> None:
    deployment = plan.deployment
    measured = release_store.measure(
        plan.tenant_id,
        deployment["id"],
        publication_lock=transaction,
    )
    if measured.digest.to_dict() != deployment["releaseTreeDigest"]:
        raise DeploymentActivationError("selected release disagrees with deployment authority")


def _ensure_candidate_running(  # noqa: PLR0913 - callbacks stay explicit
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    reloader: GenerationReloader,
    restorer: GenerationRestorer,
    verifier: GenerationVerifier,
    candidate_selection_is_durable: bool,
    source_restoration_permitted: bool,
) -> None:
    active_id = runtime.read_active()
    source_id = source.manifest.generation_id
    candidate_id = candidate.manifest.generation_id
    if active_id == source_id:
        if not source_restoration_permitted:
            raise DeploymentActivationError(
                "active source cannot be used after its release was retired"
            )
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
                _handle_candidate_failure(
                    runtime,
                    source,
                    restorer=restorer,
                    source_restoration_permitted=source_restoration_permitted,
                    error=error,
                )
        try:
            verifier(candidate)
        except Exception:
            try:
                reloader(source, candidate)
            except BaseException as error:
                _handle_candidate_failure(
                    runtime,
                    source,
                    restorer=restorer,
                    source_restoration_permitted=source_restoration_permitted,
                    error=error,
                )
        except BaseException as error:
            _handle_candidate_failure(
                runtime,
                source,
                restorer=restorer,
                source_restoration_permitted=source_restoration_permitted,
                error=error,
            )
        return
    raise DeploymentActivationError(
        "active Caddy generation is outside deployment recovery authority"
    )


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
        raise DeploymentActivationError(
            "deployment runtime restoration failed closed"
        ) from recovery_error
    raise error from None


def _handle_candidate_failure(
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    *,
    restorer: GenerationRestorer,
    source_restoration_permitted: bool,
    error: BaseException,
) -> NoReturn:
    if source_restoration_permitted:
        _restore_source(runtime, source, restorer=restorer, error=error)
    raise DeploymentActivationError(
        "deployment candidate failed after source release retirement"
    ) from error


def _reject_capacity_before_activation(  # noqa: PLR0913 - callbacks explicit
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    restorer: GenerationRestorer,
    verifier: GenerationVerifier,
    source_restoration_permitted: bool,
    error: BaseException,
) -> NoReturn:
    active_id = runtime.read_active()
    if active_id == source.manifest.generation_id:
        if not source_restoration_permitted:
            raise DeploymentActivationError(
                "active source cannot be used after its release was retired"
            )
        try:
            verifier(source)
        except Exception:
            _restore_source(runtime, source, restorer=restorer, error=error)
        except BaseException as control_error:
            _restore_source(runtime, source, restorer=restorer, error=control_error)
        raise error from None
    if active_id == candidate.manifest.generation_id:
        if source_restoration_permitted:
            _restore_source(runtime, source, restorer=restorer, error=error)
        raise error from None
    raise DeploymentActivationError(
        "active Caddy generation is outside deployment recovery authority"
    )
