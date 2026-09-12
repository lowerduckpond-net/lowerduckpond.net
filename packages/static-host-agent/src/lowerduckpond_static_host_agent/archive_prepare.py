"""Prepare a complete unselected no-route generation from one verified upload."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, cast

from lowerduckpond_static_contracts import canonical_json_bytes, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.archive_journal import _archive_record
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
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import (
    ArchiveTransitionPlan,
    plan_archive_transition,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_prepare import _bind_source_runtime_authority
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
    snapshot_tenant_routes,
)


class ArchivePreparationError(RuntimeError):
    """Archive preparation could not retain its exact source and candidate evidence."""


class ArchiveAuthorityDriftError(ArchivePreparationError):
    """Archive source state or selected runtime changed before local publication."""


@dataclass(frozen=True, slots=True)
class PreparedArchiveTransition:
    job: StoredContract
    plan: ArchiveTransitionPlan
    candidate_manifest: CaddyGenerationManifest
    capacity_limits: HostCapacityLimits


def prepare_archive_transition(  # noqa: PLR0913, PLR0917 - explicit root-owned dependencies
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    job_id: object,
    construction_intent_id: object,
    *,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedArchiveTransition:
    """Sync a source-bound transaction after publishing its unselected candidate."""
    canonical_job = validate_uuid7(job_id)
    construction_id = validate_uuid7(construction_intent_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(canonical_job))
        document = job.document
        request = cast(dict[str, object], document["request"])
        expected = cast(dict[str, object], document["expectedSource"])
        if (
            document["compatibilityVersion"] != "static-job-v2"
            or document["phase"] != "claimed"
            or document["artifact"] is not None
            or request["operation"] != "archive"
            or expected["lifecycle"] not in {"active", "suspended"}
            or build_expected_source(transaction, request) != expected
        ):
            raise ArchiveAuthorityDriftError("archive preparation has no current claimed source")
        try:
            transaction.read(StateRecordPath.authorization_result(canonical_job))
        except FileNotFoundError:
            pass
        else:
            raise ArchivePreparationError("archive preparation already has a terminal result")
        identities = transaction.measure_intent_records().records
        if len(identities) != 1 or identities[0].intent_id != construction_id:
            raise ArchivePreparationError("archive preparation requires its sole construction")
        construction = transaction.read(
            StateRecordPath.archive_construction_intent(construction_id)
        )
        tenant_id = validate_uuid7(request["tenantId"])
        source = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
        observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
        desired = cast(
            dict[str, object], cast(dict[str, object], source["spec"])["desiredDeployment"]
        )
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, desired["id"])
        ).document
        active = runtime.open_active_verified()
        try:
            source_generation = active.generation_id
        finally:
            active.generation.close()
        selected = runtime.read_generation_route_snapshot(source_generation)
        if selected != snapshot_tenant_routes(transaction):
            raise ArchiveAuthorityDriftError(
                "archive source routes do not match the selected generation"
            )
        source_routes = "both" if expected["lifecycle"] == "active" else "absent"
        job = _bind_source_runtime_authority(
            transaction,
            job,
            source_observed_state=observed,
            source_runtime_generation_id=source_generation,
            source_route_set=source_routes,
            allow_reconcile_source_advance=False,
            capacity_limits=capacity_limits,
        )
        candidate_id = generate_uuid7(clock=clock, entropy=entropy)
        plan = plan_archive_transition(
            job.document,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source,
            observed,
            deployment,
            construction.document,
            _archive_record(construction.document, deployment),
            source_runtime_generation_id=source_generation,
            candidate_runtime_generation_id=candidate_id,
            source_route_set=source_routes,
            audit_state=transaction.inspect_audit(),
            now=now,
            clock=clock,
            entropy=entropy,
        )
        overlay = TenantRouteOverlay(
            RouteOverlayMode.REPLACE,
            TenantRouteInput(plan.manifest, plan.observed_state, deployment),
            TenantRouteInput(source, observed, deployment),
            archive_record=plan.archive_record,
        )
        runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
        candidate = runtime.publish_candidate(
            candidate_id, transaction=transaction, overlay=overlay, gate=gate
        )
        try:
            _publish_intent(transaction, plan, capacity_limits=capacity_limits)
        except BaseException as error:
            _recover_intent_publication(transaction, runtime, plan, candidate, error)
        return PreparedArchiveTransition(job, plan, candidate, capacity_limits)


def _publish_intent(
    transaction: _StateTransaction,
    plan: ArchiveTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits,
) -> None:
    allocation = transaction.allocation_upper_bound(len(canonical_json_bytes(plan.intent)))
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(allocation + transaction.namespace_allocation_upper_bound(1), 1),
        transaction.measure_filesystem_capacity(),
        limits=capacity_limits,
    )
    transaction.create_immutable(StateRecordPath.transaction_intent(plan.intent_id), plan.intent)


def _recover_intent_publication(
    transaction: _StateTransaction,
    runtime: CaddyRuntime,
    plan: ArchiveTransitionPlan,
    candidate: CaddyGenerationManifest,
    error: BaseException,
) -> NoReturn:
    try:
        stored = transaction.read(StateRecordPath.transaction_intent(plan.intent_id))
    except FileNotFoundError:
        runtime.discard_unselected_candidate(candidate.generation_id, candidate)
        raise error from None
    if stored.document == plan.intent:
        raise ArchivePreparationError(
            "archive intent publication has ambiguous completion"
        ) from error
    raise ArchivePreparationError(
        "archive transaction path contains conflicting authority"
    ) from error
