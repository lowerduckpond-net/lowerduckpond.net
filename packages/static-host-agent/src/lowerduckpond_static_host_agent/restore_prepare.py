"""Prepare and reconstruct exact restore publication from two durable journals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import ContractKind, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.caddy_generation import CaddyGenerationManifest
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.deployment_prepare import (
    DeploymentQuotaExceededError,
    _admit_and_create_intent,
    _measure_retained_releases,
    _recover_failed_intent_creation,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.restore_commit import validate_restore_transition
from lowerduckpond_static_host_agent.restore_plan import plan_restore_transition
from lowerduckpond_static_host_agent.route_prepare import _bind_source_runtime_authority
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    snapshot_other_tenant_routes,
    snapshot_tenant_routes,
)


class RestorePreparationError(RuntimeError):
    """Restore publication cannot preserve exact source and staged content authority."""


@dataclass(frozen=True, slots=True)
class PreparedRestoreTransition:
    job: StoredContract
    plan: DeploymentTransitionPlan
    retirement: StoredContract
    candidate_manifest: CaddyGenerationManifest
    capacity_limits: HostCapacityLimits


def prepare_restore_transition(  # noqa: PLR0913,PLR0917 - complete trust inputs
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    store: DeploymentReleaseStore,
    gate: PublicationGate,
    job_id: str,
    retirement_id: str,
    *,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedRestoreTransition:
    spool.locks.require_held(LockName.INTAKE, mode=LockMode.EXCLUSIVE)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        request = cast(dict[str, object], job.document["request"])
        if build_expected_source(transaction, request) != job.document["expectedSource"]:
            raise RestorePreparationError("restore source changed before preparation")
        records = transaction.measure_intent_records().records
        if len(records) != 1 or records[0].intent_id != retirement_id:
            raise RestorePreparationError(
                "restore preparation requires its sole retirement journal"
            )
        retirement = transaction.read(StateRecordPath.archive_retirement_intent(retirement_id))
        tenant = validate_uuid7(request["tenantId"])
        source = transaction.read(StateRecordPath.tenant_desired(tenant)).document
        observed = transaction.read(StateRecordPath.tenant_observed(tenant)).document
        archive = cast(dict[str, object], retirement.document["archiveRecord"])
        previous = transaction.read(
            StateRecordPath.tenant_deployment(tenant, archive["deploymentId"])
        ).document
        active = runtime.open_active_verified()
        try:
            source_id = active.generation_id
        finally:
            active.generation.close()
        if runtime.read_generation_route_snapshot(source_id) != snapshot_tenant_routes(transaction):
            raise RestorePreparationError(
                "restore source disagrees with the complete selected runtime"
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
        plan = plan_restore_transition(
            job.document,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source,
            observed,
            previous,
            retirement.document,
            source_runtime_generation_id=source_id,
            candidate_runtime_generation_id=generate_uuid7(clock=clock, entropy=entropy),
            audit_state=transaction.inspect_audit(),
            now=now,
            clock=clock,
            entropy=entropy,
        )
        store.reconcile_staging({}, publication_lock=transaction)
        usage = _measure_retained_releases(store, transaction, job.document)
        staged = store.stage_archive(
            spool,
            archive,
            source,
            tenant_id=tenant,
            deployment_id=plan.deployment["id"],
            retained_usage=usage,
            publication_lock=transaction,
            capacity_limits=capacity_limits,
        )
        quotas = cast(dict[str, int], cast(dict[str, object], source["spec"])["quotas"])
        if (
            staged.measurement.logical_content_bytes > quotas["storageMiB"] * 1024 * 1024
            or staged.measurement.entry_count > quotas["entries"]
        ):
            store.discard_staged(staged, publication_lock=transaction)
            raise DeploymentQuotaExceededError("restored content exceeds current tenant quotas")
        try:
            _admit_and_create_intent(transaction, plan, capacity_limits=capacity_limits)
        except BaseException as error:
            _recover_failed_intent_creation(transaction, store, plan, staged, error)
        validate_restore_transition(
            transaction, spool, job, plan, retirement, capacity_limits=capacity_limits
        )
        store.publish(staged, publication_lock=transaction)
        candidate = _publish_candidate(transaction, runtime, gate, plan, previous)
        return PreparedRestoreTransition(job, plan, retirement, candidate, capacity_limits)


def reconstruct_restore_transition(  # noqa: PLR0913, PLR0917 - exact journals and source
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    store: DeploymentReleaseStore,
    gate: PublicationGate,
    job_id: str,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedRestoreTransition:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        values = [
            transaction.read_intent(value.intent_id)[1]
            for value in transaction.measure_intent_records().records
        ]
        by_kind = {value.revision.contract_kind: value for value in values}
        if len(values) != 2 or set(by_kind) != {  # noqa: PLR2004 - exact two journals
            ContractKind.TRANSACTION_INTENT,
            ContractKind.ARCHIVE_RETIREMENT_INTENT,
        }:
            raise RestorePreparationError("restore recovery requires both exact journals")
        intent = by_kind[ContractKind.TRANSACTION_INTENT].document
        retirement = by_kind[ContractKind.ARCHIVE_RETIREMENT_INTENT]
        if intent["operation"] != "restore":
            raise RestorePreparationError("restore recovery selected another operation")
        source = cast(dict[str, object], intent["sourceManifest"])
        recovery = cast(dict[str, object], intent["lifecycleRecovery"])
        archive = cast(dict[str, object], retirement.document["archiveRecord"])
        previous = transaction.read(
            StateRecordPath.tenant_deployment(intent["tenantId"], archive["deploymentId"])
        ).document
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
        candidate = cast(dict[str, object], intent["candidateManifest"])
        selected = cast(
            dict[str, object], cast(dict[str, object], candidate["spec"])["desiredDeployment"]
        )
        plan = plan_restore_transition(
            claimed,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source,
            cast(dict[str, object], recovery["sourceObservedState"]),
            previous,
            retirement.document,
            source_runtime_generation_id=recovery["sourceRuntimeGenerationId"],
            candidate_runtime_generation_id=recovery["candidateRuntimeGenerationId"],
            audit_state=prefix,
            now=datetime.fromisoformat(cast(str, intent["createdAt"])),
            clock=lambda: 0,
            entropy=lambda length: bytes(length),  # noqa: PLW0108 - entropy protocol
            deployment_id=selected["id"],
            intent_id=intent["intentId"],
        )
        if plan.intent != intent or (audit.entry is not None and audit.entry != plan.audit_entry):
            raise RestorePreparationError("restore recovery changed prepared documents")
        validate_restore_transition(transaction, spool, job, plan, retirement, admit=False)
        others = snapshot_other_tenant_routes(transaction, excluded_tenant_id=plan.tenant_id)
        source_id = validate_uuid7(recovery["sourceRuntimeGenerationId"])
        candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
        if runtime.read_generation_route_snapshot(source_id) != others:
            raise RestorePreparationError(
                "restore preceding runtime changed other tenant authority"
            )
        store.resume_publication(
            plan.tenant_id,
            plan.deployment["id"],
            expected_release_tree_digest=cast(dict[str, object], archive["releaseTreeDigest"]),
            publication_lock=transaction,
        )
        try:
            with runtime.open_verified_generation(candidate_id) as generation:
                candidate_manifest = generation.manifest
        except FileNotFoundError:
            if (
                transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document != source
                or transaction.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
                != recovery["sourceObservedState"]
            ):
                raise RestorePreparationError(
                    "committing restore lost its durable runtime generation"
                ) from None
            candidate_manifest = _publish_candidate(transaction, runtime, gate, plan, previous)
        tenant = TenantRouteInput(plan.manifest, plan.observed_state, plan.deployment)
        expected = TenantRouteSnapshot(
            others.platform_namespace,
            tuple(
                sorted(
                    (*others.tenants, tenant),
                    key=lambda value: str(
                        cast(dict[str, object], value.manifest["metadata"])["id"]
                    ),
                )
            ),
        )
        if runtime.read_generation_route_snapshot(candidate_id) != expected:
            raise RestorePreparationError(
                "restore candidate changed complete tenant routing authority"
            )
        return PreparedRestoreTransition(job, plan, retirement, candidate_manifest, capacity_limits)


def _publish_candidate(
    transaction: _StateTransaction,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    plan: DeploymentTransitionPlan,
    previous: dict[str, object],
) -> CaddyGenerationManifest:
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    source = TenantRouteInput(
        cast(dict[str, object], plan.intent["sourceManifest"]),
        cast(dict[str, object], recovery["sourceObservedState"]),
        previous,
    )
    candidate = TenantRouteInput(plan.manifest, plan.observed_state, plan.deployment)
    runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
    return runtime.publish_candidate(
        validate_uuid7(recovery["candidateRuntimeGenerationId"]),
        transaction=transaction,
        overlay=TenantRouteOverlay(RouteOverlayMode.REPLACE, candidate, source),
        gate=gate,
        deployment_transition_tenant_id=plan.tenant_id,
    )
