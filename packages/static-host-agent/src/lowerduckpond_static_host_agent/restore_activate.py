"""Activate exact restored routes and finish the journal-protected local commit."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent.archive_activate import _ensure_forward_candidate
from lowerduckpond_static_host_agent.audit import AuditCapacityError
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.execution import ExecutionOutcome
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.restore_commit import (
    RestoreCommitBoundary,
    RestoreCommitError,
    finalize_restore_transition,
    validate_restore_transition,
)
from lowerduckpond_static_host_agent.restore_prepare import PreparedRestoreTransition
from lowerduckpond_static_host_agent.route_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    _ensure_candidate_running,
    _reject_capacity_before_activation,
    _restore_source,
)
from lowerduckpond_static_host_agent.state_inventory import StateAdmissionRejectedError


def activate_restore_transition(  # noqa: PLR0913,PLR0917 - independent activation mechanisms
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    store: DeploymentReleaseStore,
    gate: PublicationGate,
    prepared: PreparedRestoreTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    failure_hook: Callable[[RestoreCommitBoundary], None] | None = None,
    blocking: bool = False,
) -> ExecutionOutcome:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    plan = prepared.plan
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        progress = validate_restore_transition(
            transaction, spool, prepared.job, plan, prepared.retirement, admit=False
        )
        started = progress.desired.document == plan.manifest
        source_id = validate_uuid7(recovery["sourceRuntimeGenerationId"])
        candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
        with (
            runtime.open_verified_generation(source_id) as source,
            runtime.open_verified_generation(candidate_id) as candidate,
        ):
            if candidate.manifest != prepared.candidate_manifest:
                raise RestoreCommitError("restore candidate generation changed before activation")
            measured = store.measure(
                plan.tenant_id, plan.deployment["id"], publication_lock=transaction
            )
            if measured.digest.to_dict() != plan.deployment["releaseTreeDigest"]:
                raise RestoreCommitError("restored release changed before activation")
            try:
                validate_restore_transition(
                    transaction,
                    spool,
                    prepared.job,
                    plan,
                    prepared.retirement,
                    capacity_limits=prepared.capacity_limits,
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                if started:
                    _ensure_forward_candidate(
                        runtime, source, candidate, reloader=reloader, verifier=verifier
                    )
                    raise
                _reject_capacity_before_activation(
                    runtime, source, candidate, restorer=restorer, verifier=verifier, error=error
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
                return finalize_restore_transition(
                    transaction,
                    spool,
                    store,
                    prepared.job,
                    plan,
                    prepared.retirement,
                    capacity_limits=prepared.capacity_limits,
                    failure_hook=failure_hook,
                )
            except (AuditCapacityError, CapacityError, StateAdmissionRejectedError) as error:
                if (
                    transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
                    == plan.manifest
                ):
                    raise
                _restore_source(runtime, source, restorer=restorer, error=error)
