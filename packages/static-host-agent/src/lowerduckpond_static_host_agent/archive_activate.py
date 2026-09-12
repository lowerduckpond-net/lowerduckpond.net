"""Select verified archived routes and complete local state under publication exclusion."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy

from lowerduckpond_static_host_agent.archive_commit import (
    ArchiveCommitBoundary,
    ArchiveCommitOutcome,
    admit_archive_transition,
    finalize_archive_transition,
)
from lowerduckpond_static_host_agent.archive_prepare import PreparedArchiveTransition
from lowerduckpond_static_host_agent.audit import AuditCapacityError
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_generation import PinnedCaddyGeneration
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    _ensure_candidate_running,
    _reject_capacity_before_activation,
    _restore_source,
)
from lowerduckpond_static_host_agent.route_commit import _require_same_job
from lowerduckpond_static_host_agent.state_inventory import StateAdmissionRejectedError


class ArchiveActivationError(RuntimeError):
    """Archive activation cannot prove its selected runtime or durable direction."""


def activate_archive_transition(  # noqa: PLR0913, PLR0917 - independent root boundaries
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    prepared: PreparedArchiveTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: Callable[[ArchiveCommitBoundary], None] | None = None,
    blocking: bool = False,
) -> ArchiveCommitOutcome:
    """Rollback before local commitment; recover forward after archive state is bound.

    Once the archive record is bound, recovery preserves the committed direction
    and does not reactivate the preceding routes.
    Remote construction evidence survives this function for independent cleanup.
    """
    if type(prepared) is not PreparedArchiveTransition:
        raise TypeError("archive activation requires one prepared archive transition")
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    plan = deepcopy(prepared.plan)
    recovery = plan.intent["archiveRecovery"]
    if type(recovery) is not dict:
        raise ArchiveActivationError("archive activation omitted runtime recovery evidence")
    source_id = recovery["sourceRuntimeGenerationId"]
    candidate_id = recovery["candidateRuntimeGenerationId"]
    if prepared.candidate_manifest.generation_id != candidate_id:
        raise ArchiveActivationError("archive candidate generation identity changed")
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = _require_same_job(transaction, prepared.job)
        with (
            runtime.open_verified_generation(source_id) as source,
            runtime.open_verified_generation(candidate_id) as candidate,
        ):
            if candidate.manifest != prepared.candidate_manifest:
                raise ArchiveActivationError("archive candidate files changed after preparation")
            started = _commit_started(transaction, prepared)
            try:
                admit_archive_transition(
                    transaction, spool, job, plan, capacity_limits=prepared.capacity_limits
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                if started:
                    _ensure_forward_candidate(
                        runtime,
                        source,
                        candidate,
                        reloader=reloader,
                        verifier=verifier,
                    )
                    raise
                _reject_capacity_before_activation(
                    runtime,
                    source,
                    candidate,
                    restorer=restorer,
                    verifier=verifier,
                    error=error,
                )
            runtime.remove_abandoned_reference_temporaries()
            if started:
                _ensure_forward_candidate(
                    runtime, source, candidate, reloader=reloader, verifier=verifier
                )
            else:
                _ensure_candidate_running(
                    runtime,
                    source,
                    candidate,
                    reloader=reloader,
                    restorer=restorer,
                    verifier=verifier,
                    candidate_selection_is_durable=False,
                )
            try:
                return finalize_archive_transition(
                    transaction,
                    spool,
                    release_store,
                    job,
                    plan,
                    capacity_limits=prepared.capacity_limits,
                    failure_hook=commit_failure_hook,
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                if _commit_started(transaction, prepared):
                    raise
                _restore_source(runtime, source, restorer=restorer, error=error)


def _commit_started(transaction: _StateTransaction, prepared: PreparedArchiveTransition) -> bool:
    plan = prepared.plan
    try:
        transaction.read(
            StateRecordPath.tenant_archive(plan.tenant_id, plan.archive_record["deploymentId"])
        )
    except FileNotFoundError:
        return False
    return True


def _ensure_forward_candidate(
    runtime: CaddyRuntime,
    source: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    reloader: GenerationReloader,
    verifier: GenerationVerifier,
) -> None:
    if runtime.read_active() not in {
        source.manifest.generation_id,
        candidate.manifest.generation_id,
    }:
        raise ArchiveActivationError("selected runtime escaped archive recovery authority")
    runtime.select_active(candidate.manifest.generation_id)
    try:
        verifier(candidate)
    except Exception:
        reloader(source, candidate)
        verifier(candidate)
