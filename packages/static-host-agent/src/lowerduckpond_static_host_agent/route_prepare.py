"""Locked preparation of one route-only lifecycle transition."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.caddy_generation import CaddyGenerationManifest
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    FilesystemCapacity,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.issuance import (
    PublicationGate,
    build_expected_source,
)
from lowerduckpond_static_host_agent.lifecycle_plan import (
    RouteTransitionPlan,
    plan_route_transition,
)
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordPath,
    StateRepository,
    StateRevision,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    RouteSnapshotError,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
)


class RoutePreparationError(RuntimeError):
    """A claimed route operation could not establish one exact intent."""


class RouteAuthorityDriftError(RoutePreparationError):
    """A claimed route operation no longer matches authoritative state."""


@dataclass(frozen=True, slots=True)
class PreparedRouteTransition:
    """The exact job, plan, and published candidate bound by one intent."""

    job: StoredContract
    plan: RouteTransitionPlan
    candidate_manifest: CaddyGenerationManifest
    capacity_limits: HostCapacityLimits


class RoutePreparationTransaction(Protocol):
    """The locked state surface needed before a route transition executes."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def deployment_history_tenant_ids(
        self,
        tenant_ids: tuple[str, ...],
    ) -> frozenset[str]: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract: ...

    def bind_dispatch_authority(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
        *,
        capacity_limits: HostCapacityLimits,
    ) -> StoredContract: ...

    def measure_inventory(self) -> StateInventory: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def inspect_audit(self) -> AuditState: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...


def prepare_route_transition(  # noqa: PLR0913 - authority sources stay explicit
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    job_id: object,
    *,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedRouteTransition:
    """Publish one unselected route candidate, then bind its durable intent."""

    canonical_job_id = validate_uuid7(job_id)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(canonical_job_id))
        request = _require_current_route_authority(transaction, job)
        if transaction.measure_intent_records().records:
            raise RoutePreparationError("route preparation requires an empty intent store")

        source = _read_route_source(transaction, request)
        active = runtime.open_active_verified()
        try:
            source_generation_id = active.generation_id
        finally:
            active.generation.close()
        selected_snapshot = runtime.read_generation_route_snapshot(source_generation_id)
        source_route_set = _selected_tenant_route_set(
            selected_snapshot,
            validate_uuid7(request["tenantId"]),
        )
        tenant_id = validate_uuid7(request["tenantId"])
        try:
            expected_snapshot = snapshot_tenant_routes(
                transaction,
                observed_drift_tenant_id=(
                    tenant_id if request["operation"] == "reconcile" else None
                ),
            )
        except (FileNotFoundError, RouteSnapshotError) as error:
            raise RouteAuthorityDriftError(
                "authoritative tenant routes cannot produce a complete snapshot"
            ) from error
        if selected_snapshot != expected_snapshot and (
            request["operation"] != "reconcile"
            or not _snapshots_match_except_tenant(
                selected_snapshot,
                expected_snapshot,
                tenant_id=tenant_id,
            )
        ):
            raise RouteAuthorityDriftError(
                "selected runtime generation disagrees with authoritative tenant routes"
            )
        job = _bind_source_runtime_authority(
            transaction,
            job,
            source_runtime_generation_id=source_generation_id,
            source_route_set=source_route_set,
            capacity_limits=capacity_limits,
        )
        candidate_generation_id = generate_uuid7(clock=clock, entropy=entropy)
        plan = plan_route_transition(
            job.document,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source.manifest,
            source.observed_state,
            source.deployment,
            source.archive_record,
            source_route_set=source_route_set,
            source_runtime_generation_id=source_generation_id,
            candidate_runtime_generation_id=candidate_generation_id,
            audit_state=transaction.inspect_audit(),
            now=now,
            clock=clock,
            entropy=entropy,
        )
        _require_slug_available(transaction, plan)
        overlay = TenantRouteOverlay(
            RouteOverlayMode.REPLACE,
            TenantRouteInput(plan.manifest, plan.observed_state, source.deployment),
            TenantRouteInput(source.manifest, source.observed_state, source.deployment),
        )
        runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
        candidate_manifest = runtime.publish_candidate(
            candidate_generation_id,
            transaction=transaction,
            overlay=overlay,
            gate=gate,
        )
        try:
            _admit_and_create_intent(
                transaction,
                plan,
                capacity_limits=capacity_limits,
            )
        except BaseException as error:
            _recover_failed_intent_publication(
                transaction,
                runtime,
                plan,
                candidate_manifest,
                error,
            )
        return PreparedRouteTransition(job, plan, candidate_manifest, capacity_limits)


def _bind_source_runtime_authority(
    transaction: RoutePreparationTransaction,
    job: StoredContract,
    *,
    source_runtime_generation_id: str,
    source_route_set: str,
    capacity_limits: HostCapacityLimits,
) -> StoredContract:
    """Persist the selected source needed after terminal intent cleanup."""

    document = job.document
    if document["compatibilityVersion"] != "static-job-v2":
        return job
    existing_generation = document.get("dispatchSourceRuntimeGenerationId")
    existing_route_set = document.get("dispatchSourceRouteSet")
    if existing_generation is not None or existing_route_set is not None:
        if (
            existing_generation != source_runtime_generation_id
            or existing_route_set != source_route_set
        ):
            raise RouteAuthorityDriftError("route source runtime authority changed")
        return job
    if "dispatchSourceRuntimeGenerationId" in document or "dispatchSourceRouteSet" in document:
        raise RouteAuthorityDriftError("route source runtime authority is partially bound")
    document["dispatchSourceRuntimeGenerationId"] = source_runtime_generation_id
    document["dispatchSourceRouteSet"] = source_route_set
    try:
        return transaction.bind_dispatch_authority(
            StateRecordPath.authorization_job(document["jobId"]),
            job.revision,
            document,
            capacity_limits=capacity_limits,
        )
    except StateConflictError as error:
        raise RouteAuthorityDriftError("route source runtime authority changed") from error


@dataclass(frozen=True, slots=True)
class _RouteSource:
    manifest: dict[str, object]
    observed_state: dict[str, object]
    deployment: dict[str, object] | None
    archive_record: dict[str, object] | None


def _selected_tenant_route_set(
    snapshot: TenantRouteSnapshot,
    tenant_id: str,
) -> str:
    matching = []
    for tenant in snapshot.tenants:
        metadata = tenant.manifest.get("metadata")
        if type(metadata) is dict and metadata.get("id") == tenant_id:
            matching.append(tenant)
    if len(matching) > 1:
        raise RouteSnapshotError("selected generation repeats the route source tenant")
    if not matching:
        return "absent"
    spec = matching[0].manifest.get("spec")
    if type(spec) is not dict:
        raise RouteSnapshotError("selected route source manifest is malformed")
    return "both" if spec.get("desiredState") == "active" else "absent"


def _snapshots_match_except_tenant(
    selected: TenantRouteSnapshot,
    expected: TenantRouteSnapshot,
    *,
    tenant_id: str,
) -> bool:
    """Admit reconcile drift only within its one authorized target tenant."""

    if selected.platform_namespace != expected.platform_namespace:
        return False

    def without_target(snapshot: TenantRouteSnapshot) -> tuple[TenantRouteInput, ...]:
        others: list[TenantRouteInput] = []
        for tenant in snapshot.tenants:
            metadata = tenant.manifest.get("metadata")
            if type(metadata) is not dict:
                raise RouteSnapshotError("selected route metadata is malformed")
            if metadata.get("id") != tenant_id:
                others.append(tenant)
        return tuple(others)

    return without_target(selected) == without_target(expected)


def _require_current_route_authority(
    transaction: RoutePreparationTransaction,
    job: StoredContract,
) -> dict[str, object]:
    document = job.document
    validate_contract(document, expected_kind=ContractKind.AUTHORIZATION_JOB)
    request = document["request"]
    if type(request) is not dict:
        raise RoutePreparationError("route authorization request is malformed")
    request = cast(dict[str, object], request)
    if document["phase"] != "claimed" or request["operation"] not in {
        "suspend",
        "resume",
        "rename",
        "reconcile",
    }:
        raise RoutePreparationError("route preparation requires one claimed route job")
    try:
        current_source = build_expected_source(transaction, request)
    except FileNotFoundError as error:
        raise RouteAuthorityDriftError("route authorization source state disappeared") from error
    if current_source != document["expectedSource"]:
        raise RouteAuthorityDriftError("route authorization source state drifted")
    return request


def _read_route_source(
    transaction: RoutePreparationTransaction,
    request: dict[str, object],
) -> _RouteSource:
    tenant_id = validate_uuid7(request["tenantId"])
    manifest = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
    observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    spec = cast(dict[str, object], manifest["spec"])
    if spec["desiredState"] == "undeployed":
        if tenant_id in transaction.deployment_history_tenant_ids((tenant_id,)):
            raise RouteAuthorityDriftError("undeployed route source retains deployment history")
        return _RouteSource(manifest, observed, None, None)
    reference = cast(dict[str, object], spec["desiredDeployment"])
    deployment_id = validate_uuid7(reference["id"])
    deployment = transaction.read(
        StateRecordPath.tenant_deployment(tenant_id, deployment_id)
    ).document
    archive_path = StateRecordPath.tenant_archive(tenant_id, deployment_id)
    if spec["desiredState"] == "archived":
        archive = transaction.read(archive_path).document
    else:
        try:
            transaction.read(archive_path)
        except FileNotFoundError:
            archive = None
        else:
            raise RouteAuthorityDriftError("live route source retained an archive record")
    return _RouteSource(manifest, observed, deployment, archive)


def _require_slug_available(
    transaction: RoutePreparationTransaction,
    plan: RouteTransitionPlan,
) -> None:
    metadata = cast(dict[str, object], plan.manifest["metadata"])
    candidate_slug = metadata["slug"]
    for tenant_id in transaction.measure_inventory().tenant_ids:
        if tenant_id == plan.tenant_id:
            continue
        desired = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
        current_metadata = desired["metadata"]
        if type(current_metadata) is dict and current_metadata.get("slug") == candidate_slug:
            raise RouteAuthorityDriftError("route candidate slug became unavailable")


def _admit_and_create_intent(
    transaction: RoutePreparationTransaction,
    plan: RouteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits,
) -> None:
    canonical = canonical_json_bytes(plan.intent)
    allocation = transaction.allocation_upper_bound(len(canonical))
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(
            allocated_bytes=(allocation + transaction.namespace_allocation_upper_bound(1)),
            unique_inodes=1,
        ),
        transaction.measure_filesystem_capacity(),
        limits=capacity_limits,
    )
    transaction.create_immutable(
        StateRecordPath.transaction_intent(plan.intent_id),
        plan.intent,
    )


def _recover_failed_intent_publication(
    transaction: RoutePreparationTransaction,
    runtime: CaddyRuntime,
    plan: RouteTransitionPlan,
    candidate_manifest: CaddyGenerationManifest,
    error: BaseException,
) -> NoReturn:
    path = StateRecordPath.transaction_intent(plan.intent_id)
    try:
        stored = transaction.read(path)
    except FileNotFoundError:
        runtime.discard_unselected_candidate(
            candidate_manifest.generation_id,
            candidate_manifest,
        )
        raise error from None
    if stored.document == plan.intent:
        raise RoutePreparationError(
            "route intent commit reported an ambiguous durable completion"
        ) from error
    raise RoutePreparationError("route intent path contains conflicting authority") from error
