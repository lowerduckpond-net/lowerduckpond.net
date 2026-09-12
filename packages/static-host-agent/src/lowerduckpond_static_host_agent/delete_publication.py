"""Exact no-tenant runtime preparation and recovery for ordinary deletion."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.archive_activate import _ensure_forward_candidate
from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_generation import CaddyGenerationManifest
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.delete_commit import (
    DeleteCommitBoundary,
    DeleteCommitError,
    admit_delete_records,
    finalize_delete_transition,
    validate_delete_transition,
)
from lowerduckpond_static_host_agent.delete_plan import DeleteTransitionPlan, plan_delete_transition
from lowerduckpond_static_host_agent.execution import ExecutionOutcome
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    _ensure_candidate_running,
)
from lowerduckpond_static_host_agent.route_prepare import _bind_source_runtime_authority
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    snapshot_other_tenant_routes,
    snapshot_tenant_routes,
)


class DeletePreparationError(RuntimeError):
    """Deletion cannot prove its exact source and complete no-tenant generation."""


@dataclass(frozen=True, slots=True)
class PreparedDeleteTransition:
    job: StoredContract
    plan: DeleteTransitionPlan
    retirement: StoredContract | None
    candidate_manifest: CaddyGenerationManifest
    capacity_limits: HostCapacityLimits


def prepare_delete_transition(  # noqa: PLR0913, PLR0917 - immutable deletion authority
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    job_id: str,
    retirement: StoredContract | None,
    *,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedDeleteTransition:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        request = cast(dict[str, object], job.document["request"])
        tenant = validate_uuid7(request["tenantId"])
        if build_expected_source(transaction, request) != job.document["expectedSource"]:
            raise DeletePreparationError("deletion source changed before preparation")
        records = transaction.measure_intent_records().records
        if {value.intent_id for value in records} != (
            set() if retirement is None else {retirement.document["intentId"]}
        ):
            raise DeletePreparationError("deletion preparation has other active authority")
        if retirement is None and not transaction.tenant_has_creation_history(tenant):
            raise DeletePreparationError("never-deployed deletion lacks complete creation evidence")
        source = transaction.read(StateRecordPath.tenant_desired(tenant)).document
        observed = transaction.read(StateRecordPath.tenant_observed(tenant)).document
        spec = cast(dict[str, object], source["spec"])
        desired = spec.get("desiredDeployment")
        previous = (
            None
            if desired is None
            else transaction.read(
                StateRecordPath.tenant_deployment(tenant, cast(dict[str, object], desired)["id"])
            ).document
        )
        active = runtime.open_active_verified()
        try:
            source_id = active.generation_id
        finally:
            active.generation.close()
        if runtime.read_generation_route_snapshot(source_id) != snapshot_tenant_routes(transaction):
            raise DeletePreparationError(
                "deletion source disagrees with the complete selected runtime"
            )
        job = _bind_source_runtime_authority(
            transaction,
            job,
            source_observed_state=observed,
            source_runtime_generation_id=source_id,
            source_route_set="absent",
            allow_reconcile_source_advance=False,
            capacity_limits=capacity_limits,
        )
        candidate_id = generate_uuid7(clock=clock, entropy=entropy)
        plan = plan_delete_transition(
            job.document,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source,
            observed,
            None if retirement is None else retirement.document,
            source_runtime_generation_id=source_id,
            candidate_runtime_generation_id=candidate_id,
            audit_state=transaction.inspect_audit(),
            now=now,
            clock=clock,
            entropy=entropy,
        )
        admit_delete_records(transaction, job, plan, capacity_limits=capacity_limits)
        allocation = transaction.allocation_upper_bound(len(canonical_json_bytes(plan.intent)))
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(allocation + transaction.namespace_allocation_upper_bound(1), 1),
            transaction.measure_filesystem_capacity(),
            limits=capacity_limits,
        )
        runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
        target = TenantRouteInput(source, observed, previous)
        candidate = runtime.publish_candidate(
            candidate_id,
            transaction=transaction,
            overlay=TenantRouteOverlay(RouteOverlayMode.REMOVE, target, target),
            gate=gate,
        )
        try:
            transaction.create_immutable(
                StateRecordPath.transaction_intent(plan.intent_id), plan.intent
            )
        except BaseException:
            try:
                stored = transaction.read(StateRecordPath.transaction_intent(plan.intent_id))
            except FileNotFoundError:
                runtime.discard_unselected_candidate(candidate_id, candidate)
            else:
                if stored.document != plan.intent:
                    raise DeletePreparationError(
                        "delete intent publication has conflicting authority"
                    ) from None
            raise
        return PreparedDeleteTransition(job, plan, retirement, candidate, capacity_limits)


def reconstruct_delete_transition(  # noqa: PLR0913 - exact durable reconstruction
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    job_id: str,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedDeleteTransition:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        records = [
            transaction.read_intent(value.intent_id)[1]
            for value in transaction.measure_intent_records().records
        ]
        intents = [value for value in records if value.document["kind"] == "TransactionIntent"]
        retirements = [
            value for value in records if value.document["kind"] == "ArchiveRetirementIntent"
        ]
        if (
            len(intents) != 1
            or len(retirements) > 1
            or len(records) != len(intents) + len(retirements)
        ):
            raise DeletePreparationError("delete recovery cannot select exact journals")
        intent = intents[0].document
        retirement = next(iter(retirements), None)
        if intent["operation"] != "delete":
            raise DeletePreparationError("delete recovery selected another operation")
        source = cast(dict[str, object], intent["sourceManifest"])
        recovery = cast(dict[str, object], intent["lifecycleRecovery"])
        observed = cast(dict[str, object], recovery["sourceObservedState"])
        audit = transaction.inspect_audit_correlation(intent["correlationId"])
        prefix = (
            audit.state
            if audit.entry is None
            else AuditState(
                cast(int, audit.entry["sequence"]),
                0,
                0,
                cast(dict[str, str] | None, audit.entry["previousEntryDigest"]),
            )
        )
        claimed = job.document
        claimed["phase"] = "claimed"
        plan = plan_delete_transition(
            claimed,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source,
            observed,
            None if retirement is None else retirement.document,
            source_runtime_generation_id=recovery["sourceRuntimeGenerationId"],
            candidate_runtime_generation_id=recovery["candidateRuntimeGenerationId"],
            audit_state=prefix,
            now=datetime.fromisoformat(cast(str, intent["createdAt"])),
            clock=lambda: 0,
            entropy=lambda length: bytes(length),  # noqa: PLW0108 - entropy protocol
            intent_id=intent["intentId"],
        )
        if plan.intent != intent or (audit.entry is not None and audit.entry != plan.audit_entry):
            raise DeletePreparationError("delete recovery changed durable authority")
        validate_delete_transition(transaction, spool, job, plan, retirement, admit=False)
        others = (
            snapshot_other_tenant_routes(transaction, excluded_tenant_id=plan.tenant_id)
            if plan.tenant_id in transaction.measure_inventory().tenant_ids
            else snapshot_tenant_routes(transaction)
        )
        source_snapshot = others
        if cast(dict[str, object], source["spec"])["desiredState"] == "undeployed":
            target = TenantRouteInput(source, observed, None)
            source_snapshot = TenantRouteSnapshot(
                others.platform_namespace,
                tuple(
                    sorted(
                        (*others.tenants, target),
                        key=lambda value: str(
                            cast(dict[str, object], value.manifest["metadata"])["id"]
                        ),
                    )
                ),
            )
        source_id = validate_uuid7(recovery["sourceRuntimeGenerationId"])
        candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
        if (
            runtime.read_generation_route_snapshot(source_id) != source_snapshot
            or runtime.read_generation_route_snapshot(candidate_id) != others
        ):
            raise DeletePreparationError(
                "delete recovery runtime changed complete tenant authority"
            )
        with runtime.open_verified_generation(candidate_id) as candidate:
            return PreparedDeleteTransition(
                job, plan, retirement, candidate.manifest, capacity_limits
            )


def activate_delete_transition(  # noqa: PLR0913,PLR0917 - independent runtime and durable commit
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    store: DeploymentReleaseStore,
    gate: PublicationGate,
    prepared: PreparedDeleteTransition,
    *,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    failure_hook: Callable[[DeleteCommitBoundary], None] | None = None,
    blocking: bool = False,
) -> ExecutionOutcome:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        _job, _removal, audit_missing, _result_missing = validate_delete_transition(
            transaction,
            spool,
            prepared.job,
            prepared.plan,
            prepared.retirement,
            capacity_limits=prepared.capacity_limits,
        )
        recovery = cast(dict[str, object], prepared.plan.intent["lifecycleRecovery"])
        with (
            runtime.open_verified_generation(
                validate_uuid7(recovery["sourceRuntimeGenerationId"])
            ) as source,
            runtime.open_verified_generation(
                validate_uuid7(recovery["candidateRuntimeGenerationId"])
            ) as candidate,
        ):
            if candidate.manifest != prepared.candidate_manifest:
                raise DeleteCommitError("delete candidate generation changed")
            runtime.remove_abandoned_reference_temporaries()
            if audit_missing:
                _ensure_candidate_running(
                    runtime,
                    source,
                    candidate,
                    reloader=reloader,
                    restorer=restorer,
                    verifier=verifier,
                    candidate_selection_is_durable=False,
                )
            else:
                _ensure_forward_candidate(
                    runtime, source, candidate, reloader=reloader, verifier=verifier
                )
            return finalize_delete_transition(
                repository,
                transaction,
                spool,
                store,
                prepared.job,
                prepared.plan,
                prepared.retirement,
                capacity_limits=prepared.capacity_limits,
                failure_hook=failure_hook,
            )
