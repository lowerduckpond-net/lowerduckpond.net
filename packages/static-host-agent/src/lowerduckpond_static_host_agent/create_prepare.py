"""Locked, capacity-admitted preparation of one durable create intent."""

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
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import (
    CreateTransitionPlan,
    plan_create_transition,
)
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
)


class CreatePreparationError(RuntimeError):
    """A claimed create could not establish one exact durable intent."""


class CreateAuthorityDriftError(CreatePreparationError):
    """A claimed create no longer matches authoritative source state."""


@dataclass(frozen=True, slots=True)
class PreparedCreateTransition:
    """The exact job, plan, and published candidate bound by one intent."""

    job: StoredContract
    plan: CreateTransitionPlan
    candidate_manifest: CaddyGenerationManifest
    capacity_limits: HostCapacityLimits


class CreatePreparationTransaction(Protocol):
    """The locked state surface needed before a create becomes executable."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...

    def tenant_has_identity_history(self, tenant_id: object) -> bool: ...

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract: ...

    def measure_inventory(self) -> StateInventory: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def inspect_audit(self) -> AuditState: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...


def prepare_create_transition(  # noqa: PLR0913 - authority sources stay explicit
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
) -> PreparedCreateTransition:
    """Publish one unselected candidate, then durably bind its create intent."""

    canonical_job_id = validate_uuid7(job_id)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(canonical_job_id))
        request = _require_current_create_authority(transaction, job)
        if transaction.measure_intent_records().records:
            raise CreatePreparationError("create preparation requires an empty intent store")

        active = runtime.open_active_verified()
        try:
            source_generation_id = active.generation_id
        finally:
            active.generation.close()
        candidate_generation_id = generate_uuid7(clock=clock, entropy=entropy)
        plan = plan_create_transition(
            job.document,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source_runtime_generation_id=source_generation_id,
            candidate_runtime_generation_id=candidate_generation_id,
            audit_state=transaction.inspect_audit(),
            now=now,
            clock=clock,
            entropy=entropy,
        )
        _require_create_target_still_available(transaction, request, plan.tenant_id)
        overlay = TenantRouteOverlay(
            RouteOverlayMode.ADD,
            TenantRouteInput(plan.manifest, plan.observed_state, None),
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
        return PreparedCreateTransition(job, plan, candidate_manifest, capacity_limits)


def _require_current_create_authority(
    transaction: CreatePreparationTransaction,
    job: StoredContract,
) -> dict[str, object]:
    document = job.document
    validate_contract(document, expected_kind=ContractKind.AUTHORIZATION_JOB)
    request = document["request"]
    if type(request) is not dict:
        raise CreatePreparationError("create authorization request is malformed")
    request = cast(dict[str, object], request)
    if document["phase"] != "claimed" or request["operation"] != "create":
        raise CreatePreparationError("create preparation requires one claimed create job")
    if build_expected_source(transaction, request) != document["expectedSource"]:
        raise CreateAuthorityDriftError("create authorization source state drifted")
    return request


def _require_create_target_still_available(
    transaction: CreatePreparationTransaction,
    request: dict[str, object],
    tenant_id: str,
) -> None:
    slug = request["slug"]
    inventory = transaction.measure_inventory()
    if tenant_id in inventory.tenant_ids or transaction.tenant_has_identity_history(tenant_id):
        raise CreatePreparationError("generated create tenant identity is unavailable")
    for existing_tenant_id in inventory.tenant_ids:
        desired = transaction.read(StateRecordPath.tenant_desired(existing_tenant_id)).document
        metadata = desired["metadata"]
        if type(metadata) is dict and metadata.get("slug") == slug:
            raise CreateAuthorityDriftError("create slug became unavailable")


def _admit_and_create_intent(
    transaction: CreatePreparationTransaction,
    plan: CreateTransitionPlan,
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
    transaction: CreatePreparationTransaction,
    runtime: CaddyRuntime,
    plan: CreateTransitionPlan,
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
        raise CreatePreparationError(
            "create intent commit reported an ambiguous durable completion"
        ) from error
    raise CreatePreparationError("create intent path contains conflicting authority") from error
