"""Exact reconstruction and activation of one durable prepared create."""

from __future__ import annotations

from copy import deepcopy
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    manifest_digest,
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
from lowerduckpond_static_host_agent.create_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    activate_create_transition,
)
from lowerduckpond_static_host_agent.create_commit import CreateCommitFailureHook
from lowerduckpond_static_host_agent.create_prepare import PreparedCreateTransition
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import CreateTransitionPlan
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
)


class CreateRecoveryError(RuntimeError):
    """Durable create evidence cannot reconstruct one exact transition."""


class CreateRecoveryTransaction(Protocol):
    """The locked state surface needed to reconstruct a prepared create."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def measure_inventory(self) -> StateInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...

    def inspect_audit_correlation(
        self,
        correlation_id: object,
    ) -> AuditCorrelationSnapshot: ...


def recover_create_transition(  # noqa: PLR0913 - recovery mechanisms stay injectable
    repository: StateRepository,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    intent_id: object,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: CreateCommitFailureHook | None = None,
    blocking: bool = False,
) -> dict[str, object]:
    """Reconstruct one prepared create from durable evidence and activate it."""

    canonical_intent_id = validate_uuid7(intent_id)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        prepared = _reconstruct_create(
            transaction,
            runtime,
            canonical_intent_id,
            capacity_limits=capacity_limits,
        )
    return activate_create_transition(
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


def _reconstruct_create(
    transaction: CreateRecoveryTransaction,
    runtime: CaddyRuntime,
    intent_id: str,
    *,
    capacity_limits: HostCapacityLimits,
) -> PreparedCreateTransition:
    intent = _require_exact_create_intent(transaction, intent_id)
    job = _require_bound_job(transaction, intent.document)
    request = job.document["request"]
    if type(request) is not dict:  # pragma: no cover - validated reads prove this
        raise CreateRecoveryError("create recovery job request is malformed")
    request = cast(dict[str, object], request)
    if build_expected_source(transaction, request) != job.document["expectedSource"]:
        raise CreateRecoveryError("create recovery authority disagrees with the namespace")

    recovery = intent.document["lifecycleRecovery"]
    if type(recovery) is not dict:  # pragma: no cover - schema validation proves this
        raise CreateRecoveryError("create recovery authority is malformed")
    candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
    route_snapshot = runtime.read_generation_route_snapshot(candidate_id)
    namespace = transaction.read(StateRecordPath.platform_namespace()).document
    if route_snapshot.platform_namespace != namespace:
        raise CreateRecoveryError("create candidate namespace disagrees with authority")
    candidate_manifest, candidate_observed = _require_candidate_tenant(
        route_snapshot.tenants,
        intent.document,
    )
    candidate_tenant = TenantRouteInput(
        candidate_manifest,
        candidate_observed,
        None,
    )
    tenant_id = validate_uuid7(intent.document["tenantId"])
    overlay = (
        None
        if tenant_id in transaction.measure_inventory().tenant_ids
        else TenantRouteOverlay(RouteOverlayMode.ADD, candidate_tenant)
    )
    if route_snapshot != snapshot_tenant_routes(transaction, overlay=overlay):
        raise CreateRecoveryError("create candidate route snapshot disagrees with authority")
    with runtime.open_verified_generation(candidate_id) as generation:
        generation_manifest = generation.manifest

    result = _create_result(job.document, candidate_manifest)
    audit_entry = _recover_audit_entry(
        transaction.inspect_audit_correlation(intent.document["correlationId"]),
        job.document,
        intent.document,
        result,
    )
    plan = CreateTransitionPlan(
        tenant_id=validate_uuid7(intent.document["tenantId"]),
        intent_id=intent_id,
        manifest=candidate_manifest,
        observed_state=candidate_observed,
        intent=intent.document,
        result=result,
        audit_entry=audit_entry,
    )
    return PreparedCreateTransition(job, plan, generation_manifest, capacity_limits)


def _require_exact_create_intent(
    transaction: CreateRecoveryTransaction,
    intent_id: str,
) -> StoredContract:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != intent_id:
        raise CreateRecoveryError("create recovery requires its sole exact intent")
    path, intent = transaction.read_intent(intent_id)
    document = intent.document
    if (
        path != StateRecordPath.transaction_intent(intent_id)
        or document["operation"] != "create"
        or document["phase"] != "prepared"
        or document["archiveRecovery"] is not None
        or document["restartFence"] is not None
    ):
        raise CreateRecoveryError("intent is not one recoverable prepared create")
    return intent


def _require_bound_job(
    transaction: CreateRecoveryTransaction,
    intent: dict[str, object],
) -> StoredContract:
    correlation_id = validate_uuid7(intent["correlationId"])
    correlation = transaction.read(
        StateRecordPath.authorization_correlation(correlation_id)
    ).document
    job_id = validate_uuid7(correlation["jobId"])
    job = transaction.read(StateRecordPath.authorization_job(job_id))
    immutable_correlation = deepcopy(correlation)
    immutable_job = job.document
    immutable_correlation.pop("phase", None)
    immutable_job.pop("phase", None)
    request = job.document["request"]
    if (
        immutable_correlation != immutable_job
        or job.document["phase"] not in {"claimed", "completed"}
        or type(request) is not dict
        or request.get("operation") != "create"
        or request.get("correlationId") != correlation_id
    ):
        raise CreateRecoveryError("create intent has no exact durable job binding")
    return job


def _require_candidate_tenant(
    tenants: tuple[TenantRouteInput, ...],
    intent: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    tenant_id = validate_uuid7(intent["tenantId"])
    matching = []
    for tenant in tenants:
        manifest = tenant.manifest
        metadata = manifest.get("metadata")
        if type(metadata) is dict and metadata.get("id") == tenant_id:
            matching.append(tenant)
    if len(matching) != 1:
        raise CreateRecoveryError("create candidate does not contain its exact tenant")
    candidate = matching[0]
    manifest = deepcopy(candidate.manifest)
    observed = deepcopy(candidate.observed_state)
    if candidate.deployment is not None:
        raise CreateRecoveryError("create candidate unexpectedly contains a deployment")
    recovery = intent["lifecycleRecovery"]
    if type(recovery) is not dict:  # pragma: no cover - schema validation proves this
        raise CreateRecoveryError("create recovery authority is malformed")
    if (
        manifest_digest(manifest).to_dict() != intent["candidateManifestDigest"]
        or observed != recovery["candidateObservedState"]
    ):
        raise CreateRecoveryError("create candidate tenant disagrees with its intent")
    return manifest, observed


def _create_result(
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
        "operation": "create",
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
    correlation_id = intent["correlationId"]
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
        "operation": "create",
        "tenantId": intent["tenantId"],
        "correlationId": correlation_id,
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
    }
    validate_contract(candidate, expected_kind=ContractKind.AUDIT_ENTRY)
    if snapshot.entry is not None and snapshot.entry != candidate:
        raise CreateRecoveryError("existing create audit entry disagrees with durable evidence")
    return candidate
