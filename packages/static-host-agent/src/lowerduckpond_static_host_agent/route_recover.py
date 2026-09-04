"""Exact reconstruction and activation of one durable route transition."""

from __future__ import annotations

from copy import deepcopy
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.audit import AuditCorrelationSnapshot
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.lifecycle_plan import RouteTransitionPlan
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    activate_route_transition_outcome,
)
from lowerduckpond_static_host_agent.route_commit import (
    RouteCommitFailureHook,
    RouteCommitOutcome,
    RouteCommitTransaction,
    admit_route_transition,
)
from lowerduckpond_static_host_agent.route_prepare import PreparedRouteTransition
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
)

_ROUTE_OPERATIONS = frozenset({"suspend", "resume", "rename", "reconcile"})


class RouteRecoveryError(RuntimeError):
    """Durable route evidence cannot reconstruct one exact transition."""


class RouteRecoveryTransaction(Protocol):
    """The locked state surface needed to reconstruct a route transition."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...

    def deployment_history_tenant_ids(
        self,
        tenant_ids: tuple[str, ...],
    ) -> frozenset[str]: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def measure_inventory(self) -> StateInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...

    def inspect_audit_correlation(
        self,
        correlation_id: object,
    ) -> AuditCorrelationSnapshot: ...


def recover_route_transition(  # noqa: PLR0913 - recovery mechanisms stay injectable
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    intent_id: object,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: RouteCommitFailureHook | None = None,
    blocking: bool = False,
) -> dict[str, object]:
    """Reconstruct one prepared route transition and activate it."""

    return recover_route_transition_outcome(
        repository,
        runtime,
        gate,
        intent_id,
        capacity_limits=capacity_limits,
        reloader=reloader,
        restorer=restorer,
        verifier=verifier,
        commit_failure_hook=commit_failure_hook,
        blocking=blocking,
    ).result


def recover_route_transition_outcome(  # noqa: PLR0913
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    intent_id: object,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: RouteCommitFailureHook | None = None,
    blocking: bool = False,
) -> RouteCommitOutcome:
    """Recover a prepared route transition and report result ownership."""

    canonical_intent_id = validate_uuid7(intent_id)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        prepared = _reconstruct_route(
            transaction,
            runtime,
            canonical_intent_id,
            capacity_limits=capacity_limits,
        )
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
    )


def _reconstruct_route(
    transaction: RouteRecoveryTransaction,
    runtime: CaddyRuntime,
    intent_id: str,
    *,
    capacity_limits: HostCapacityLimits,
) -> PreparedRouteTransition:
    intent = _require_exact_route_intent(transaction, intent_id)
    job = _require_bound_job(transaction, intent.document)
    source_manifest, source_observed, candidate_manifest, candidate_observed = _intent_route_state(
        intent.document
    )
    deployment = _require_source_authority(transaction, job.document, source_manifest)
    source_tenant = TenantRouteInput(source_manifest, source_observed, deployment)
    candidate_tenant = TenantRouteInput(candidate_manifest, candidate_observed, deployment)

    recovery = cast(dict[str, object], intent.document["lifecycleRecovery"])
    source_id = validate_uuid7(recovery["sourceRuntimeGenerationId"])
    candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
    tenant_id = validate_uuid7(intent.document["tenantId"])
    operation = cast(str, intent.document["operation"])
    current_snapshot = snapshot_tenant_routes(
        transaction,
        observed_drift_tenant_id=(tenant_id if operation == "reconcile" else None),
    )
    source_snapshot = runtime.read_generation_route_snapshot(source_id)
    candidate_snapshot = runtime.read_generation_route_snapshot(candidate_id)
    _require_generation_snapshots(
        current_snapshot,
        source_snapshot,
        candidate_snapshot,
        operation=operation,
        source_route_set=cast(str, recovery["sourceRouteSet"]),
        source_tenant=source_tenant,
        candidate_tenant=candidate_tenant,
    )
    with runtime.open_verified_generation(candidate_id) as candidate:
        candidate_generation_manifest = candidate.manifest

    result = _route_result(job.document, candidate_manifest)
    audit_entry = _recover_audit_entry(
        transaction.inspect_audit_correlation(intent.document["correlationId"]),
        job.document,
        intent.document,
        result,
    )
    plan = RouteTransitionPlan(
        tenant_id=tenant_id,
        intent_id=intent_id,
        manifest=candidate_manifest,
        observed_state=candidate_observed,
        intent=intent.document,
        result=result,
        audit_entry=audit_entry,
    )
    admit_route_transition(
        cast(RouteCommitTransaction, transaction),
        job,
        plan,
        capacity_limits=capacity_limits,
    )
    return PreparedRouteTransition(job, plan, candidate_generation_manifest, capacity_limits)


def _require_exact_route_intent(
    transaction: RouteRecoveryTransaction,
    intent_id: str,
) -> StoredContract:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != intent_id:
        raise RouteRecoveryError("route recovery requires its sole exact intent")
    path, intent = transaction.read_intent(intent_id)
    document = intent.document
    if (
        path != StateRecordPath.transaction_intent(intent_id)
        or document.get("compatibilityVersion") != "static-intent-v2"
        or document["operation"] not in _ROUTE_OPERATIONS
        or document["phase"] != "prepared"
        or document["archiveRecovery"] is not None
        or document["restartFence"] is not None
    ):
        raise RouteRecoveryError("intent is not one recoverable prepared route transition")
    return intent


def _require_bound_job(
    transaction: RouteRecoveryTransaction,
    intent: dict[str, object],
) -> StoredContract:
    correlation_id = validate_uuid7(intent["correlationId"])
    correlation = transaction.read(
        StateRecordPath.authorization_correlation(correlation_id)
    ).document
    job_id = validate_uuid7(correlation["jobId"])
    job = transaction.read(StateRecordPath.authorization_job(job_id))
    job_document = job.document
    immutable_correlation = deepcopy(correlation)
    immutable_job = deepcopy(job_document)
    for field in (
        "phase",
        "executionValidated",
        "dispatchArchiveDeploymentIds",
        "dispatchArtifactReleaseTreeDigest",
        "dispatchSourceReleaseTreeDigest",
        "dispatchDeploymentIds",
        "dispatchTenantIds",
        "dispatchTenantRecordHistories",
        "dispatchSourceObservedState",
        "dispatchSourceRuntimeGenerationId",
        "dispatchSourceRouteSet",
    ):
        immutable_correlation.pop(field, None)
        immutable_job.pop(field, None)
    request = job_document["request"]
    recovery = intent.get("lifecycleRecovery")
    if (
        immutable_correlation != immutable_job
        or job_document["phase"] not in {"claimed", "completed"}
        or type(request) is not dict
        or type(recovery) is not dict
        or request.get("operation") != intent["operation"]
        or request.get("correlationId") != correlation_id
        or request.get("tenantId") != intent["tenantId"]
        or job_document.get("dispatchSourceObservedState") != recovery.get("sourceObservedState")
        or job_document.get("dispatchSourceRuntimeGenerationId")
        != recovery.get("sourceRuntimeGenerationId")
        or job_document.get("dispatchSourceRouteSet") != recovery.get("sourceRouteSet")
    ):
        raise RouteRecoveryError("route intent has no exact durable job binding")
    return job


def _intent_route_state(
    intent: dict[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    recovery = intent["lifecycleRecovery"]
    source = intent["sourceManifest"]
    candidate = intent["candidateManifest"]
    if type(recovery) is not dict or type(source) is not dict or type(candidate) is not dict:
        raise RouteRecoveryError("route intent state authority is malformed")
    source_observed = recovery["sourceObservedState"]
    candidate_observed = recovery["candidateObservedState"]
    if type(source_observed) is not dict or type(candidate_observed) is not dict:
        raise RouteRecoveryError("route intent observed-state authority is malformed")
    return source, source_observed, candidate, candidate_observed


def _require_source_authority(
    transaction: RouteRecoveryTransaction,
    job: dict[str, object],
    source_manifest: dict[str, object],
) -> dict[str, object] | None:
    expected = job["expectedSource"]
    metadata = source_manifest["metadata"]
    spec = source_manifest["spec"]
    if type(expected) is not dict or type(metadata) is not dict or type(spec) is not dict:
        raise RouteRecoveryError("route source authority is malformed")
    tenant_id = validate_uuid7(metadata["id"])
    namespace = transaction.read(StateRecordPath.platform_namespace()).document
    desired = spec.get("desiredDeployment")
    deployment: dict[str, object] | None = None
    archive_digest: dict[str, str] | None = None
    if desired is not None:
        if type(desired) is not dict:  # pragma: no cover - schema validation proves this
            raise RouteRecoveryError("route source deployment reference is malformed")
        deployment_id = validate_uuid7(desired["id"])
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, deployment_id)
        ).document
        validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
        if spec["desiredState"] == "archived":
            archive = transaction.read(
                StateRecordPath.tenant_archive(tenant_id, deployment_id)
            ).document
            validate_contract(archive, expected_kind=ContractKind.ARCHIVE_RECORD)
            archive_digest = archive_record_digest(archive).to_dict()
    actual = {
        "expectsTenantAbsent": False,
        "lifecycle": spec["desiredState"],
        "manifestDigest": manifest_digest(source_manifest).to_dict(),
        "deploymentDigest": (
            deployment_record_digest(deployment).to_dict() if deployment is not None else None
        ),
        "archiveRecordDigest": archive_digest,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
    }
    if actual != expected:
        raise RouteRecoveryError("route recovery source authority drifted")
    return deployment


def _require_generation_snapshots(  # noqa: PLR0913 - exact snapshots and authority
    current: TenantRouteSnapshot,
    source: TenantRouteSnapshot,
    candidate: TenantRouteSnapshot,
    *,
    operation: str,
    source_route_set: str,
    source_tenant: TenantRouteInput,
    candidate_tenant: TenantRouteInput,
) -> None:
    expected_candidate = _replace_snapshot_tenant(current, candidate_tenant)
    if candidate != expected_candidate:
        raise RouteRecoveryError("route generation snapshots disagree with durable authority")
    if operation == "reconcile":
        _require_reconcile_source_snapshot(
            current,
            source,
            tenant_id=_route_tenant_id(source_tenant),
            route_set=source_route_set,
        )
        return
    expected_source = _replace_snapshot_tenant(current, source_tenant)
    if source != expected_source:
        raise RouteRecoveryError("route generation snapshots disagree with durable authority")


def _require_reconcile_source_snapshot(
    current: TenantRouteSnapshot,
    source: TenantRouteSnapshot,
    *,
    tenant_id: str,
    route_set: str,
) -> None:
    if current.platform_namespace != source.platform_namespace:
        raise RouteRecoveryError("reconcile source namespace drifted")
    current_others = tuple(
        tenant for tenant in current.tenants if _route_tenant_id(tenant) != tenant_id
    )
    source_others = tuple(
        tenant for tenant in source.tenants if _route_tenant_id(tenant) != tenant_id
    )
    matching = tuple(tenant for tenant in source.tenants if _route_tenant_id(tenant) == tenant_id)
    if current_others != source_others or len(matching) > 1:
        raise RouteRecoveryError("reconcile source snapshot changed unrelated tenants")
    actual_route_set = "absent"
    if matching and _route_tenant_is_active(matching[0]):
        actual_route_set = "both"
    if actual_route_set != route_set:
        raise RouteRecoveryError("reconcile source route evidence drifted")


def _replace_snapshot_tenant(
    snapshot: TenantRouteSnapshot,
    replacement: TenantRouteInput,
) -> TenantRouteSnapshot:
    replacement_id = _route_tenant_id(replacement)
    others = [tenant for tenant in snapshot.tenants if _route_tenant_id(tenant) != replacement_id]
    if _route_tenant_is_archived(replacement):
        if len(others) != len(snapshot.tenants):
            raise RouteRecoveryError("archived route snapshot unexpectedly contains its tenant")
        return TenantRouteSnapshot(deepcopy(snapshot.platform_namespace), tuple(others))
    if len(others) + 1 != len(snapshot.tenants):
        raise RouteRecoveryError("route snapshot does not contain its exact tenant")
    tenants = [*others, deepcopy(replacement)]
    tenants.sort(key=_route_tenant_id)
    return TenantRouteSnapshot(deepcopy(snapshot.platform_namespace), tuple(tenants))


def _route_tenant_id(tenant: TenantRouteInput) -> str:
    metadata = tenant.manifest.get("metadata")
    if type(metadata) is not dict:
        raise RouteRecoveryError("route snapshot tenant identity is malformed")
    return validate_uuid7(metadata.get("id"))


def _route_tenant_is_archived(tenant: TenantRouteInput) -> bool:
    spec = tenant.manifest.get("spec")
    if type(spec) is not dict:
        raise RouteRecoveryError("route snapshot tenant lifecycle is malformed")
    return spec.get("desiredState") == "archived"


def _route_tenant_is_active(tenant: TenantRouteInput) -> bool:
    spec = tenant.manifest.get("spec")
    if type(spec) is not dict:
        raise RouteRecoveryError("route snapshot tenant lifecycle is malformed")
    return (
        spec.get("desiredState") == "active"
        and tenant.observed_state.get("observedState") == "active"
    )


def _route_result(
    job: dict[str, object],
    manifest: dict[str, object],
) -> dict[str, object]:
    request = cast(dict[str, object], job["request"])
    metadata = cast(dict[str, object], manifest["metadata"])
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": request["operation"],
        "status": "succeeded",
        "tenantId": metadata["id"],
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": deepcopy(manifest),
    }
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    return result


def _recover_audit_entry(
    snapshot: AuditCorrelationSnapshot,
    job: dict[str, object],
    intent: dict[str, object],
    result: dict[str, object],
) -> dict[str, object]:
    if snapshot.entry is not None:
        sequence = snapshot.entry["sequence"]
        predecessor = snapshot.entry["previousEntryDigest"]
    else:
        sequence = snapshot.state.entry_count
        predecessor = snapshot.state.terminal_digest
    candidate: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": sequence,
        "previousEntryDigest": predecessor,
        "timestamp": intent["createdAt"],
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": intent["operation"],
        "tenantId": intent["tenantId"],
        "correlationId": intent["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
    }
    validate_contract(candidate, expected_kind=ContractKind.AUDIT_ENTRY)
    if snapshot.entry is not None and snapshot.entry != candidate:
        raise RouteRecoveryError("existing route audit entry disagrees with durable evidence")
    return candidate
