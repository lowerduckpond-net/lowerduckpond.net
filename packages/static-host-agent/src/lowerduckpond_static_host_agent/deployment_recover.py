"""Exact reconstruction and activation of one durable deployment transition."""

from __future__ import annotations

from copy import deepcopy
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
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
from lowerduckpond_static_host_agent.caddy_generation import CaddyGenerationManifest
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.deployment_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    activate_deployment_transition_outcome,
)
from lowerduckpond_static_host_agent.deployment_commit import (
    DeploymentCommitFailureHook,
    DeploymentCommitOutcome,
    DeploymentCommitTransaction,
    admit_deployment_transition,
)
from lowerduckpond_static_host_agent.deployment_prepare import (
    PreparedDeploymentTransition,
)
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.release_store import (
    DeploymentReleaseStore,
    PublicationLockProof,
    ReleaseStoreError,
)
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
)

_DEPLOYMENT_OPERATIONS = frozenset({"deploy", "rollback"})


class DeploymentRecoveryError(RuntimeError):
    """Durable deployment evidence cannot reconstruct one exact transition."""


class DeploymentRecoveryTransaction(PublicationLockProof, Protocol):
    """The locked state surface needed to reconstruct a deployment transition."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

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


def recover_deployment_transition(  # noqa: PLR0913 - recovery mechanisms explicit
    repository: StateRepository,
    runtime: CaddyRuntime,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    intent_id: object,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: DeploymentCommitFailureHook | None = None,
    blocking: bool = False,
) -> dict[str, object]:
    """Reconstruct one prepared deployment transition and activate it."""

    return recover_deployment_transition_outcome(
        repository,
        runtime,
        release_store,
        gate,
        intent_id,
        capacity_limits=capacity_limits,
        reloader=reloader,
        restorer=restorer,
        verifier=verifier,
        commit_failure_hook=commit_failure_hook,
        blocking=blocking,
    ).result


def recover_deployment_transition_outcome(  # noqa: PLR0913
    repository: StateRepository,
    runtime: CaddyRuntime,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    intent_id: object,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    reloader: GenerationReloader = reload_caddy_generation,
    restorer: GenerationRestorer = restore_caddy_generation,
    verifier: GenerationVerifier = verify_running_caddy,
    commit_failure_hook: DeploymentCommitFailureHook | None = None,
    blocking: bool = False,
) -> DeploymentCommitOutcome:
    """Recover a prepared deployment transition and report result ownership."""

    canonical_intent_id = validate_uuid7(intent_id)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        prepared = _reconstruct_deployment(
            transaction,
            runtime,
            release_store,
            gate,
            canonical_intent_id,
            capacity_limits=capacity_limits,
        )
    return activate_deployment_transition_outcome(
        repository,
        runtime,
        release_store,
        gate,
        prepared,
        reloader=reloader,
        restorer=restorer,
        verifier=verifier,
        commit_failure_hook=commit_failure_hook,
        blocking=blocking,
    )


def _reconstruct_deployment(  # noqa: PLR0913 - recovery authority stays explicit
    transaction: DeploymentRecoveryTransaction,
    runtime: CaddyRuntime,
    release_store: DeploymentReleaseStore,
    gate: PublicationGate,
    intent_id: str,
    *,
    capacity_limits: HostCapacityLimits,
) -> PreparedDeploymentTransition:
    intent = _require_exact_deployment_intent(transaction, intent_id)
    job = _require_bound_job(transaction, intent.document)
    source_manifest, source_observed, candidate_manifest, candidate_observed = (
        _intent_deployment_state(intent.document)
    )
    recovery = cast(dict[str, object], intent.document["lifecycleRecovery"])
    source_id = validate_uuid7(recovery["sourceRuntimeGenerationId"])
    candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
    tenant_id = validate_uuid7(intent.document["tenantId"])
    current_snapshot = snapshot_tenant_routes(
        transaction,
        deployment_transition_tenant_id=tenant_id,
    )
    source_snapshot = runtime.read_generation_route_snapshot(source_id)
    source_deployment = _require_source_authority(
        transaction,
        job.document,
        source_manifest,
    )
    deployment = _candidate_deployment(
        transaction,
        job.document,
        intent.document,
        candidate_manifest,
    )
    source_tenant = TenantRouteInput(
        source_manifest,
        source_observed,
        source_deployment,
    )
    candidate_tenant = TenantRouteInput(
        candidate_manifest,
        candidate_observed,
        deployment,
    )

    result = _deployment_result(job.document, candidate_manifest)
    audit_entry = _recover_audit_entry(
        transaction.inspect_audit_correlation(intent.document["correlationId"]),
        job.document,
        intent.document,
        result,
    )
    plan = DeploymentTransitionPlan(
        tenant_id=tenant_id,
        intent_id=intent_id,
        manifest=candidate_manifest,
        observed_state=candidate_observed,
        deployment=deployment,
        creates_deployment=intent.document["operation"] == "deploy",
        intent=intent.document,
        result=result,
        audit_entry=audit_entry,
    )
    admit_deployment_transition(
        cast(DeploymentCommitTransaction, transaction),
        job,
        plan,
        capacity_limits=capacity_limits,
    )
    _resume_release_publication(
        transaction,
        release_store,
        plan,
    )
    candidate_generation_manifest = _resume_candidate_publication(
        transaction,
        runtime,
        gate,
        source_tenant,
        candidate_tenant,
        candidate_id=candidate_id,
        tenant_id=tenant_id,
    )
    candidate_snapshot = runtime.read_generation_route_snapshot(candidate_id)
    _require_generation_snapshots(
        current_snapshot,
        source_snapshot,
        candidate_snapshot,
        tenant_id=tenant_id,
        source_manifest=source_manifest,
        source_observed=source_observed,
        candidate_manifest=candidate_manifest,
        candidate_observed=candidate_observed,
    )
    return PreparedDeploymentTransition(
        job,
        plan,
        candidate_generation_manifest,
        capacity_limits,
    )


def _require_exact_deployment_intent(
    transaction: DeploymentRecoveryTransaction,
    intent_id: str,
) -> StoredContract:
    inventory = transaction.measure_intent_records()
    if len(inventory.records) != 1 or inventory.records[0].intent_id != intent_id:
        raise DeploymentRecoveryError("deployment recovery requires its sole exact intent")
    path, intent = transaction.read_intent(intent_id)
    document = intent.document
    if (
        path != StateRecordPath.transaction_intent(intent_id)
        or document.get("compatibilityVersion") != "static-intent-v2"
        or document["operation"] not in _DEPLOYMENT_OPERATIONS
        or document["phase"] != "prepared"
        or document["archiveRecovery"] is not None
        or document["restartFence"] is not None
    ):
        raise DeploymentRecoveryError(
            "intent is not one recoverable prepared deployment transition"
        )
    return intent


def _require_bound_job(
    transaction: DeploymentRecoveryTransaction,
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
        raise DeploymentRecoveryError("deployment intent has no exact durable job binding")
    return job


def _intent_deployment_state(
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
        raise DeploymentRecoveryError("deployment intent state authority is malformed")
    source_observed = recovery["sourceObservedState"]
    candidate_observed = recovery["candidateObservedState"]
    if type(source_observed) is not dict or type(candidate_observed) is not dict:
        raise DeploymentRecoveryError("deployment intent observed-state authority is malformed")
    return source, source_observed, candidate, candidate_observed


def _require_source_authority(
    transaction: DeploymentRecoveryTransaction,
    job: dict[str, object],
    source_manifest: dict[str, object],
) -> dict[str, object] | None:
    expected = job["expectedSource"]
    metadata = source_manifest["metadata"]
    spec = source_manifest["spec"]
    if type(expected) is not dict or type(metadata) is not dict or type(spec) is not dict:
        raise DeploymentRecoveryError("deployment source authority is malformed")
    tenant_id = validate_uuid7(metadata["id"])
    namespace = transaction.read(StateRecordPath.platform_namespace()).document
    desired = spec.get("desiredDeployment")
    source_deployment: dict[str, object] | None = None
    if desired is not None:
        if type(desired) is not dict:  # pragma: no cover - schema validation proves this
            raise DeploymentRecoveryError("deployment source reference is malformed")
        source_deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, desired["id"])
        ).document
    if source_deployment is not None:
        validate_contract(source_deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    actual = {
        "expectsTenantAbsent": False,
        "lifecycle": spec["desiredState"],
        "manifestDigest": manifest_digest(source_manifest).to_dict(),
        "deploymentDigest": (
            deployment_record_digest(source_deployment).to_dict()
            if source_deployment is not None
            else None
        ),
        "archiveRecordDigest": None,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
    }
    if actual != expected or (
        source_deployment is not None and source_deployment["tenantId"] != tenant_id
    ):
        raise DeploymentRecoveryError("deployment recovery source authority drifted")
    return source_deployment


def _candidate_deployment(
    transaction: DeploymentRecoveryTransaction,
    job: dict[str, object],
    intent: dict[str, object],
    candidate_manifest: dict[str, object],
) -> dict[str, object]:
    request = job.get("request")
    metadata = candidate_manifest.get("metadata")
    spec = candidate_manifest.get("spec")
    if type(request) is not dict or type(metadata) is not dict or type(spec) is not dict:
        raise DeploymentRecoveryError("deployment candidate authority is malformed")
    selected = spec.get("desiredDeployment")
    if type(selected) is not dict:
        raise DeploymentRecoveryError("deployment candidate omitted its selected release")
    tenant_id = validate_uuid7(metadata["id"])
    deployment_id = validate_uuid7(selected["id"])
    if intent["operation"] == "rollback":
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, deployment_id)
        ).document
    else:
        release_digest = job.get("dispatchArtifactReleaseTreeDigest")
        if type(release_digest) is not dict:
            raise DeploymentRecoveryError("deployment release authority is malformed")
        deployment = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "DeploymentRecord",
            "id": deployment_id,
            "tenantId": tenant_id,
            "archiveSha256": selected["archiveSha256"],
            "releaseTreeDigest": deepcopy(release_digest),
            "createdAt": intent["createdAt"],
            "correlationId": intent["correlationId"],
        }
    validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    return deployment


def _resume_release_publication(
    transaction: DeploymentRecoveryTransaction,
    release_store: DeploymentReleaseStore,
    plan: DeploymentTransitionPlan,
) -> None:
    deployment = plan.deployment
    try:
        if plan.creates_deployment:
            release_store.resume_publication(
                plan.tenant_id,
                deployment["id"],
                expected_release_tree_digest=cast(
                    dict[str, object],
                    deployment["releaseTreeDigest"],
                ),
                publication_lock=transaction,
            )
            return
        measured = release_store.measure(
            plan.tenant_id,
            deployment["id"],
            publication_lock=transaction,
        )
    except (FileNotFoundError, ReleaseStoreError) as error:
        raise DeploymentRecoveryError(
            "deployment release publication cannot be recovered"
        ) from error
    if measured.digest.to_dict() != deployment["releaseTreeDigest"]:
        raise DeploymentRecoveryError("rollback release disagrees with recovery authority")


def _resume_candidate_publication(  # noqa: PLR0913 - publication authority explicit
    transaction: DeploymentRecoveryTransaction,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    source_tenant: TenantRouteInput,
    candidate_tenant: TenantRouteInput,
    *,
    candidate_id: str,
    tenant_id: str,
) -> CaddyGenerationManifest:
    try:
        candidate = runtime.open_verified_generation(candidate_id)
    except FileNotFoundError:
        runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
        return runtime.publish_candidate(
            candidate_id,
            transaction=transaction,
            overlay=TenantRouteOverlay(
                RouteOverlayMode.REPLACE,
                candidate_tenant,
                source_tenant,
            ),
            gate=gate,
            deployment_transition_tenant_id=tenant_id,
        )
    with candidate:
        return candidate.manifest


def _require_generation_snapshots(  # noqa: PLR0913 - exact authority tuple
    current: TenantRouteSnapshot,
    source: TenantRouteSnapshot,
    candidate: TenantRouteSnapshot,
    *,
    tenant_id: str,
    source_manifest: dict[str, object],
    source_observed: dict[str, object],
    candidate_manifest: dict[str, object],
    candidate_observed: dict[str, object],
) -> tuple[TenantRouteInput, TenantRouteInput]:
    source_tenant = _snapshot_tenant(source, tenant_id)
    candidate_tenant = _snapshot_tenant(candidate, tenant_id)
    if (
        source_tenant.manifest != source_manifest
        or source_tenant.observed_state != source_observed
        or candidate_tenant.manifest != candidate_manifest
        or candidate_tenant.observed_state != candidate_observed
    ):
        raise DeploymentRecoveryError("deployment generation state disagrees with intent")
    if source != _replace_snapshot_tenant(current, source_tenant) or candidate != (
        _replace_snapshot_tenant(current, candidate_tenant)
    ):
        raise DeploymentRecoveryError(
            "deployment generation snapshots changed unrelated tenant authority"
        )
    return source_tenant, candidate_tenant


def _snapshot_tenant(snapshot: TenantRouteSnapshot, tenant_id: str) -> TenantRouteInput:
    matches = tuple(tenant for tenant in snapshot.tenants if _route_tenant_id(tenant) == tenant_id)
    if len(matches) != 1:
        raise DeploymentRecoveryError("deployment generation omitted its exact tenant")
    return matches[0]


def _replace_snapshot_tenant(
    snapshot: TenantRouteSnapshot,
    replacement: TenantRouteInput,
) -> TenantRouteSnapshot:
    replacement_id = _route_tenant_id(replacement)
    others = [tenant for tenant in snapshot.tenants if _route_tenant_id(tenant) != replacement_id]
    if len(others) + 1 != len(snapshot.tenants):
        raise DeploymentRecoveryError("deployment snapshot does not contain its exact tenant")
    tenants = [*others, deepcopy(replacement)]
    tenants.sort(key=_route_tenant_id)
    return TenantRouteSnapshot(deepcopy(snapshot.platform_namespace), tuple(tenants))


def _route_tenant_id(tenant: TenantRouteInput) -> str:
    metadata = tenant.manifest.get("metadata")
    if type(metadata) is not dict:
        raise DeploymentRecoveryError("deployment snapshot tenant identity is malformed")
    return validate_uuid7(metadata.get("id"))


def _deployment_result(
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
        raise DeploymentRecoveryError(
            "existing deployment audit entry disagrees with durable evidence"
        )
    return candidate
