"""Locked preparation of one deploy or rollback transition."""

from __future__ import annotations

from copy import deepcopy
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
    aggregate_release_usage,
)
from lowerduckpond_static_host_agent.deployment_commit import (
    DeploymentCommitTransaction,
    admit_deployment_transition,
)
from lowerduckpond_static_host_agent.intake import AdmittedArtifact, ArtifactIntake
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import (
    DeploymentTransitionPlan,
    plan_deployment_transition,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import (
    DeploymentReleaseStore,
    StagedDeploymentRelease,
)
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordError,
    StateRecordPath,
    StateRepository,
    StateRevision,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    RouteSnapshotError,
    TenantRouteOverlay,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
)

_DEPLOYMENT_OPERATIONS = frozenset({"deploy", "rollback"})


class DeploymentPreparationError(RuntimeError):
    """A claimed deployment operation could not establish one exact intent."""


class DeploymentAuthorityDriftError(DeploymentPreparationError):
    """A claimed deployment operation no longer matches authoritative state."""


@dataclass(frozen=True, slots=True)
class PreparedDeploymentTransition:
    """The exact job, plan, release, and Caddy candidate bound by one intent."""

    job: StoredContract
    plan: DeploymentTransitionPlan
    candidate_manifest: CaddyGenerationManifest
    capacity_limits: HostCapacityLimits


class DeploymentPreparationTransaction(Protocol):
    """The locked state surface required before deployment activation."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def deployment_history_tenant_ids(
        self,
        tenant_ids: tuple[str, ...],
    ) -> frozenset[str]: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...

    def tenant_deployment_ids(self, tenant_id: object) -> tuple[str, ...]: ...

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

    def rebind_route_source_authority(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
        *,
        allow_reconcile_source_advance: bool,
        capacity_limits: HostCapacityLimits,
    ) -> StoredContract: ...

    def measure_inventory(self) -> StateInventory: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def inspect_audit(self) -> AuditState: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _DeploymentSource:
    manifest: dict[str, object]
    observed_state: dict[str, object]
    deployment: dict[str, object] | None
    rollback_deployment: dict[str, object] | None


def prepare_deployment_transition(  # noqa: PLR0913,PLR0917 - authority tuple
    repository: StateRepository,
    runtime: CaddyRuntime,
    intake: ArtifactIntake,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    job_id: object,
    artifact: AdmittedArtifact | None,
    *,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedDeploymentTransition:
    """Protect staging with an intent before publishing release or Caddy state."""

    canonical_job_id = validate_uuid7(job_id)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(canonical_job_id))
        request = _require_current_deployment_authority(transaction, job, artifact)
        if transaction.measure_intent_records().records:
            raise DeploymentPreparationError(
                "deployment preparation requires an empty intent store"
            )
        release_store.reconcile_staging({}, publication_lock=transaction)

        source = _read_deployment_source(transaction, request, job.document)
        active = runtime.open_active_verified()
        try:
            source_generation_id = active.generation_id
        finally:
            active.generation.close()
        selected_snapshot = runtime.read_generation_route_snapshot(source_generation_id)
        try:
            expected_snapshot = snapshot_tenant_routes(transaction)
        except (FileNotFoundError, RouteSnapshotError) as error:
            raise DeploymentAuthorityDriftError(
                "authoritative tenant routes cannot produce a complete snapshot"
            ) from error
        if selected_snapshot != expected_snapshot:
            raise DeploymentAuthorityDriftError(
                "selected runtime generation disagrees with authoritative tenant routes"
            )
        source_route_set = _source_route_set(source.manifest)
        job = _bind_source_runtime_authority(
            transaction,
            job,
            source_observed_state=source.observed_state,
            source_runtime_generation_id=source_generation_id,
            source_route_set=source_route_set,
            capacity_limits=capacity_limits,
        )

        candidate_generation_id = generate_uuid7(clock=clock, entropy=entropy)
        release_digest = _artifact_release_digest(job.document, artifact)
        plan = plan_deployment_transition(
            job.document,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source.manifest,
            source.observed_state,
            source.deployment,
            source.rollback_deployment,
            artifact_release_tree_digest=release_digest,
            source_runtime_generation_id=source_generation_id,
            candidate_runtime_generation_id=candidate_generation_id,
            audit_state=transaction.inspect_audit(),
            now=now,
            clock=clock,
            entropy=entropy,
        )
        retained_usage = _measure_retained_releases(
            release_store,
            transaction,
        )
        staged = _stage_candidate_release(
            intake,
            release_store,
            transaction,
            plan,
            artifact,
            retained_usage=retained_usage,
            capacity_limits=capacity_limits,
        )
        try:
            _admit_and_create_intent(
                transaction,
                plan,
                capacity_limits=capacity_limits,
            )
        except BaseException as error:
            _recover_failed_intent_creation(
                transaction,
                release_store,
                plan,
                staged,
                error,
            )

        admit_deployment_transition(
            cast(DeploymentCommitTransaction, transaction),
            job,
            plan,
            capacity_limits=capacity_limits,
        )

        if staged is not None:
            release_store.publish(staged, publication_lock=transaction)
        else:
            selected = release_store.measure(
                plan.tenant_id,
                plan.deployment["id"],
                publication_lock=transaction,
            )
            if selected.digest.to_dict() != plan.deployment["releaseTreeDigest"]:
                raise DeploymentAuthorityDriftError(
                    "rollback release disagrees with retained deployment authority"
                )

        overlay = TenantRouteOverlay(
            RouteOverlayMode.REPLACE,
            TenantRouteInput(plan.manifest, plan.observed_state, plan.deployment),
            TenantRouteInput(
                source.manifest,
                source.observed_state,
                source.deployment,
            ),
        )
        runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
        candidate_manifest = runtime.publish_candidate(
            candidate_generation_id,
            transaction=transaction,
            overlay=overlay,
            gate=gate,
        )
        return PreparedDeploymentTransition(
            job,
            plan,
            candidate_manifest,
            capacity_limits,
        )


def _require_current_deployment_authority(
    transaction: DeploymentPreparationTransaction,
    job: StoredContract,
    artifact: AdmittedArtifact | None,
) -> dict[str, object]:
    document = job.document
    validate_contract(document, expected_kind=ContractKind.AUTHORIZATION_JOB)
    request = document["request"]
    if type(request) is not dict:
        raise DeploymentPreparationError("deployment authorization request is malformed")
    request = cast(dict[str, object], request)
    operation = request.get("operation")
    if document["phase"] != "claimed" or operation not in _DEPLOYMENT_OPERATIONS:
        raise DeploymentPreparationError(
            "deployment preparation requires one claimed deploy or rollback job"
        )
    if (operation == "deploy") != (artifact is not None):
        raise DeploymentPreparationError(
            "deployment artifact presence disagrees with the authorized operation"
        )
    if build_expected_source(transaction, request) != document["expectedSource"]:
        raise DeploymentAuthorityDriftError("deployment authorization source state drifted")
    return request


def _read_deployment_source(
    transaction: DeploymentPreparationTransaction,
    request: dict[str, object],
    job: dict[str, object],
) -> _DeploymentSource:
    tenant_id = validate_uuid7(request["tenantId"])
    try:
        manifest = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
        observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
    except FileNotFoundError as error:
        raise DeploymentAuthorityDriftError("deployment source state disappeared") from error
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    spec = cast(dict[str, object], manifest["spec"])
    selected = spec.get("desiredDeployment")
    deployment: dict[str, object] | None = None
    if selected is not None:
        if type(selected) is not dict:
            raise DeploymentAuthorityDriftError("selected deployment reference is malformed")
        try:
            deployment = transaction.read(
                StateRecordPath.tenant_deployment(tenant_id, selected["id"])
            ).document
        except FileNotFoundError as error:
            raise DeploymentAuthorityDriftError("selected deployment record disappeared") from error
        validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)

    current_ids = transaction.tenant_deployment_ids(tenant_id)
    bound_ids = job.get("dispatchDeploymentIds")
    if type(bound_ids) is not list or any(type(value) is not str for value in bound_ids):
        raise DeploymentPreparationError("deployment history authority is unavailable")
    canonical_bound = tuple(validate_uuid7(value) for value in bound_ids)
    if canonical_bound != current_ids:
        raise DeploymentAuthorityDriftError("retained deployment history changed")
    history: list[dict[str, object]] = []
    try:
        for deployment_id in current_ids:
            record = transaction.read(
                StateRecordPath.tenant_deployment(tenant_id, deployment_id)
            ).document
            validate_contract(record, expected_kind=ContractKind.DEPLOYMENT_RECORD)
            history.append(record)
    except FileNotFoundError as error:
        raise DeploymentAuthorityDriftError("retained deployment history changed") from error

    rollback: dict[str, object] | None = None
    if request["operation"] == "rollback":
        target_id = validate_uuid7(request["deploymentId"])
        matching = [record for record in history if record["id"] == target_id]
        if len(matching) != 1:
            raise DeploymentAuthorityDriftError("rollback target left retained deployment history")
        rollback = matching[0]
    bound_source_digest = job.get("dispatchSourceReleaseTreeDigest")
    expected_source_digest = None if deployment is None else deployment["releaseTreeDigest"]
    if bound_source_digest != expected_source_digest:
        raise DeploymentAuthorityDriftError("selected source release authority changed")
    return _DeploymentSource(manifest, observed, deployment, rollback)


def _source_route_set(manifest: dict[str, object]) -> str:
    spec = cast(dict[str, object], manifest["spec"])
    return "both" if spec["desiredState"] == "active" else "absent"


def _bind_source_runtime_authority(  # noqa: PLR0913 - authority tuple stays explicit
    transaction: DeploymentPreparationTransaction,
    job: StoredContract,
    *,
    source_observed_state: dict[str, object],
    source_runtime_generation_id: str,
    source_route_set: str,
    capacity_limits: HostCapacityLimits,
) -> StoredContract:
    document = job.document
    existing_observed = document.get("dispatchSourceObservedState")
    existing_generation = document.get("dispatchSourceRuntimeGenerationId")
    existing_route_set = document.get("dispatchSourceRouteSet")
    if any(
        value is not None for value in (existing_observed, existing_generation, existing_route_set)
    ):
        if (
            type(existing_observed) is not dict
            or existing_generation is None
            or existing_route_set not in {"absent", "both"}
            or existing_observed != source_observed_state
            or existing_route_set != source_route_set
        ):
            raise DeploymentAuthorityDriftError("deployment source runtime authority changed")
        if existing_generation == source_runtime_generation_id:
            return job
        rebound = deepcopy(document)
        rebound["dispatchSourceRuntimeGenerationId"] = source_runtime_generation_id
        try:
            return transaction.rebind_route_source_authority(
                StateRecordPath.authorization_job(document["jobId"]),
                job.revision,
                rebound,
                allow_reconcile_source_advance=False,
                capacity_limits=capacity_limits,
            )
        except (StateConflictError, StateRecordError) as error:
            raise DeploymentAuthorityDriftError(
                "deployment source runtime authority changed"
            ) from error
    bound = deepcopy(document)
    bound["dispatchSourceObservedState"] = deepcopy(source_observed_state)
    bound["dispatchSourceRuntimeGenerationId"] = source_runtime_generation_id
    bound["dispatchSourceRouteSet"] = source_route_set
    try:
        return transaction.bind_dispatch_authority(
            StateRecordPath.authorization_job(document["jobId"]),
            job.revision,
            bound,
            capacity_limits=capacity_limits,
        )
    except StateConflictError as error:
        raise DeploymentAuthorityDriftError(
            "deployment source runtime authority changed"
        ) from error


def _artifact_release_digest(
    job: dict[str, object],
    artifact: AdmittedArtifact | None,
) -> dict[str, object] | None:
    raw = job.get("dispatchArtifactReleaseTreeDigest")
    if artifact is None:
        if raw is not None:
            raise DeploymentPreparationError("rollback retained artifact release authority")
        return None
    declared = job.get("artifact")
    if type(declared) is not dict or (
        artifact.verified.size != declared.get("size")
        or artifact.verified.sha256 != declared.get("sha256")
    ):
        raise DeploymentPreparationError("claimed deployment artifact changed")
    if type(raw) is not dict:
        raise DeploymentPreparationError("deploy release authority is unavailable")
    return deepcopy(raw)


def _measure_retained_releases(
    release_store: DeploymentReleaseStore,
    transaction: DeploymentPreparationTransaction,
) -> ReleaseCapacityUsage:
    measurements = []
    for tenant_id in transaction.measure_inventory().tenant_ids:
        for deployment_id in transaction.tenant_deployment_ids(tenant_id):
            try:
                deployment = transaction.read(
                    StateRecordPath.tenant_deployment(tenant_id, deployment_id)
                ).document
            except FileNotFoundError as error:
                raise DeploymentAuthorityDriftError(
                    "retained deployment history changed"
                ) from error
            validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
            measured = release_store.measure(
                tenant_id,
                deployment_id,
                publication_lock=transaction,
            )
            if measured.digest.to_dict() != deployment["releaseTreeDigest"]:
                raise DeploymentAuthorityDriftError(
                    "retained release disagrees with deployment authority"
                )
            measurements.append(measured)
    return aggregate_release_usage(measurements)


def _stage_candidate_release(  # noqa: PLR0913 - extraction authorities stay explicit
    intake: ArtifactIntake,
    release_store: DeploymentReleaseStore,
    transaction: DeploymentPreparationTransaction,
    plan: DeploymentTransitionPlan,
    artifact: AdmittedArtifact | None,
    *,
    retained_usage: ReleaseCapacityUsage,
    capacity_limits: HostCapacityLimits,
) -> StagedDeploymentRelease | None:
    if not plan.creates_deployment:
        if artifact is not None:
            raise DeploymentPreparationError("rollback unexpectedly retained an artifact")
        return None
    if artifact is None:
        raise DeploymentPreparationError("deploy artifact disappeared before staging")
    return release_store.stage(
        intake,
        artifact,
        tenant_id=plan.tenant_id,
        deployment_id=plan.deployment["id"],
        expected_release_tree_digest=cast(dict[str, object], plan.deployment["releaseTreeDigest"]),
        retained_usage=retained_usage,
        publication_lock=transaction,
        capacity_limits=capacity_limits,
    )


def _admit_and_create_intent(
    transaction: DeploymentPreparationTransaction,
    plan: DeploymentTransitionPlan,
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


def _recover_failed_intent_creation(
    transaction: DeploymentPreparationTransaction,
    release_store: DeploymentReleaseStore,
    plan: DeploymentTransitionPlan,
    staged: StagedDeploymentRelease | None,
    error: BaseException,
) -> NoReturn:
    try:
        stored = transaction.read(StateRecordPath.transaction_intent(plan.intent_id))
    except FileNotFoundError:
        if staged is not None:
            release_store.discard_staged(staged, publication_lock=transaction)
        raise error from None
    if stored.document == plan.intent:
        raise DeploymentPreparationError(
            "deployment intent commit reported an ambiguous durable completion"
        ) from error
    if staged is not None:
        release_store.discard_staged(staged, publication_lock=transaction)
    raise DeploymentPreparationError(
        "deployment intent path contains conflicting authority"
    ) from error
