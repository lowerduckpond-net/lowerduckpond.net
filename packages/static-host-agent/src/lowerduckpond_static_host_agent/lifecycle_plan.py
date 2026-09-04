"""Pure, contract-validated plans for authoritative lifecycle transactions."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from lowerduckpond_static_contracts import (
    LIFECYCLE_MATRIX,
    ContractKind,
    LifecycleState,
    Operation,
    archive_record_digest,
    deployment_record_digest,
    manifest_digest,
    materialize_create_request,
    materialize_platform_namespace,
    platform_state_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import (
    EntropySource,
    MillisecondClock,
    construct_create_manifest,
    generate_uuid7,
)

from lowerduckpond_static_host_agent.audit import AuditState


class LifecyclePlanError(RuntimeError):
    """Trusted lifecycle inputs cannot describe one accepted transition."""


@dataclass(frozen=True, slots=True)
class CreateTransitionPlan:
    """Every contract needed to commit one absent-to-undeployed transition."""

    tenant_id: str
    intent_id: str
    manifest: dict[str, object]
    observed_state: dict[str, object]
    intent: dict[str, object]
    result: dict[str, object]
    audit_entry: dict[str, object]


@dataclass(frozen=True, slots=True)
class RouteTransitionPlan:
    """Every contract needed for one route-only desired-state transition."""

    tenant_id: str
    intent_id: str
    manifest: dict[str, object]
    observed_state: dict[str, object]
    intent: dict[str, object]
    result: dict[str, object]
    audit_entry: dict[str, object]


def plan_create_transition(  # noqa: PLR0913 - each authority input is explicit
    authorization_job: dict[str, object],
    platform_namespace: dict[str, object],
    *,
    source_runtime_generation_id: object,
    candidate_runtime_generation_id: object,
    audit_state: AuditState,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
) -> CreateTransitionPlan:
    """Derive one complete create transition without reading or mutating host state."""

    job = deepcopy(authorization_job)
    namespace = deepcopy(platform_namespace)
    validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
    if job["phase"] != "claimed":
        raise LifecyclePlanError("create planning requires one claimed authorization job")
    request = cast(dict[str, object], job["request"])
    create_request = materialize_create_request(request)
    validated_namespace = materialize_platform_namespace(namespace)
    expected_source = cast(dict[str, object], job["expectedSource"])
    if expected_source != {
        "expectsTenantAbsent": True,
        "lifecycle": None,
        "manifestDigest": None,
        "deploymentDigest": None,
        "archiveRecordDigest": None,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
    }:
        raise LifecyclePlanError("create authority is not bound to the supplied namespace")

    source_generation = validate_uuid7(source_runtime_generation_id)
    candidate_generation = validate_uuid7(candidate_runtime_generation_id)
    if source_generation == candidate_generation:
        raise LifecyclePlanError("create must select a distinct complete runtime generation")
    timestamp = _canonical_timestamp(now)

    created = construct_create_manifest(
        create_request,
        validated_namespace,
        clock=clock,
        entropy=entropy,
    )
    desired_digest = manifest_digest(created.manifest).to_dict()
    observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": created.tenant_id,
        "desiredManifestDigest": desired_digest,
        "observedState": "undeployed",
        "activeDeploymentId": None,
        "runtimeGenerationId": None,
        "reconciledAt": timestamp,
    }
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)

    # The intent is separate root-generated authority, not a caller field.
    intent_id = generate_uuid7(clock=clock, entropy=entropy)
    if intent_id == created.tenant_id:
        raise LifecyclePlanError("create tenant and transaction identities collided")
    intent: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TransactionIntent",
        "compatibilityVersion": "static-intent-v2",
        "intentId": intent_id,
        "tenantId": created.tenant_id,
        "correlationId": request["correlationId"],
        "operation": "create",
        "archiveRecovery": None,
        "lifecycleRecovery": {
            "sourceObservedState": None,
            "sourceRuntimeGenerationId": source_generation,
            "sourceRouteSet": "absent",
            "candidateObservedState": observed,
            "candidateRuntimeGenerationId": candidate_generation,
            "candidateRouteSet": "absent",
        },
        "sourceManifest": None,
        "sourceManifestDigest": None,
        "candidateManifest": created.manifest,
        "candidateManifestDigest": desired_digest,
        "phase": "prepared",
        "restartFence": None,
        "createdAt": timestamp,
    }
    validate_contract(intent, expected_kind=ContractKind.TRANSACTION_INTENT)

    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "create",
        "status": "succeeded",
        "tenantId": created.tenant_id,
        "canonicalOrigin": created.canonical_origin,
        "manifest": created.manifest,
    }
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)

    audit_entry: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": audit_state.entry_count,
        "previousEntryDigest": audit_state.terminal_digest,
        "timestamp": timestamp,
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": "create",
        "tenantId": created.tenant_id,
        "correlationId": request["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
    }
    validate_contract(audit_entry, expected_kind=ContractKind.AUDIT_ENTRY)

    return CreateTransitionPlan(
        tenant_id=created.tenant_id,
        intent_id=intent_id,
        manifest=deepcopy(created.manifest),
        observed_state=deepcopy(observed),
        intent=deepcopy(intent),
        result=deepcopy(result),
        audit_entry=deepcopy(audit_entry),
    )


def plan_route_transition(  # noqa: PLR0912, PLR0913, PLR0915, PLR0917 - authority tuple
    authorization_job: dict[str, object],
    platform_namespace: dict[str, object],
    source_manifest: dict[str, object],
    source_observed_state: dict[str, object],
    source_deployment: dict[str, object] | None,
    source_archive_record: dict[str, object] | None,
    *,
    source_route_set: object,
    source_runtime_generation_id: object,
    candidate_runtime_generation_id: object,
    audit_state: AuditState,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
) -> RouteTransitionPlan:
    """Derive suspend, resume, rename, or reconcile without mutating host state."""

    job = deepcopy(authorization_job)
    namespace = deepcopy(platform_namespace)
    source = deepcopy(source_manifest)
    observed = deepcopy(source_observed_state)
    deployment = deepcopy(source_deployment)
    archive = deepcopy(source_archive_record)
    validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
    validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    validate_contract(source, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    if deployment is not None:
        validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    if archive is not None:
        validate_contract(archive, expected_kind=ContractKind.ARCHIVE_RECORD)
    if job["phase"] != "claimed":
        raise LifecyclePlanError("route planning requires one claimed authorization job")

    request = cast(dict[str, object], job["request"])
    try:
        operation = Operation(cast(str, request["operation"]))
    except ValueError as error:
        raise LifecyclePlanError("route planning received an unsupported operation") from error
    if operation not in {
        Operation.SUSPEND,
        Operation.RESUME,
        Operation.RENAME,
        Operation.RECONCILE,
    }:
        raise LifecyclePlanError("route planning received an unsupported operation")

    metadata = cast(dict[str, object], source["metadata"])
    spec = cast(dict[str, object], source["spec"])
    tenant_id = cast(str, metadata["id"])
    if request["tenantId"] != tenant_id:
        raise LifecyclePlanError("route authority selected a different tenant")
    source_digest = manifest_digest(source).to_dict()
    source_state = LifecycleState(cast(str, spec["desiredState"]))
    if source_state not in {
        LifecycleState.UNDEPLOYED,
        LifecycleState.ACTIVE,
        LifecycleState.SUSPENDED,
        LifecycleState.ARCHIVED,
    }:
        raise LifecyclePlanError("route planning does not accept this lifecycle state")
    target_state = LIFECYCLE_MATRIX.get((operation, source_state))
    if target_state is None:
        raise LifecyclePlanError("route operation is not valid for the source lifecycle")

    deployment_digest: dict[str, str] | None = None
    archive_digest: dict[str, str] | None = None
    active_deployment_id: str | None = None
    if source_state is LifecycleState.UNDEPLOYED:
        if deployment is not None or archive is not None:
            raise LifecyclePlanError("undeployed route source retained deployment evidence")
    else:
        if deployment is None:
            raise LifecyclePlanError("deployed route source omitted its deployment")
        desired_deployment = cast(dict[str, object], spec["desiredDeployment"])
        desired_deployment_id = cast(str, desired_deployment["id"])
        if (
            deployment["tenantId"] != tenant_id
            or deployment["id"] != desired_deployment_id
            or deployment["archiveSha256"] != desired_deployment["archiveSha256"]
        ):
            raise LifecyclePlanError("route source deployment binding drifted")
        deployment_digest = deployment_record_digest(deployment).to_dict()
        if source_state is LifecycleState.ARCHIVED:
            if archive is None:
                raise LifecyclePlanError("archived route source omitted its archive record")
            if (
                archive["tenantId"] != tenant_id
                or archive["deploymentId"] != desired_deployment_id
                or archive["releaseTreeDigest"] != deployment["releaseTreeDigest"]
                or archive["manifestDigest"] != source_digest
            ):
                raise LifecyclePlanError("route source archive binding drifted")
            archive_digest = archive_record_digest(archive).to_dict()
        else:
            if archive is not None:
                raise LifecyclePlanError("live route source retained an archive record")
            active_deployment_id = desired_deployment_id

    expected_source = cast(dict[str, object], job["expectedSource"])
    if expected_source != {
        "expectsTenantAbsent": False,
        "lifecycle": source_state.value,
        "manifestDigest": source_digest,
        "deploymentDigest": deployment_digest,
        "archiveRecordDigest": archive_digest,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
    }:
        raise LifecyclePlanError("route authority is not bound to the supplied source")

    source_generation = validate_uuid7(source_runtime_generation_id)
    candidate_generation = validate_uuid7(candidate_runtime_generation_id)
    if source_generation == candidate_generation:
        raise LifecyclePlanError("route transition must select a distinct runtime generation")
    if source_route_set not in {"absent", "both"}:
        raise LifecyclePlanError("route source has an invalid selected route set")
    expected_source_routes = "both" if source_state is LifecycleState.ACTIVE else "absent"
    if operation is Operation.RECONCILE:
        if observed["tenantId"] != tenant_id:
            raise LifecyclePlanError("route source observed-state tenant drifted")
    else:
        _validate_route_source_observed(
            observed,
            tenant_id=tenant_id,
            source_digest=source_digest,
            source_state=source_state,
            active_deployment_id=active_deployment_id,
        )
        if source_route_set != expected_source_routes:
            raise LifecyclePlanError("route source selected routes disagree with authority")

    candidate = deepcopy(source)
    candidate_metadata = cast(dict[str, object], candidate["metadata"])
    candidate_spec = cast(dict[str, object], candidate["spec"])
    if operation is Operation.RENAME:
        candidate_metadata["slug"] = request["slug"]
    else:
        candidate_spec["desiredState"] = target_state.value
    validate_contract(candidate, expected_kind=ContractKind.SITE)
    candidate_digest = manifest_digest(candidate).to_dict()
    if operation is Operation.RENAME and candidate_digest == source_digest:
        raise LifecyclePlanError("rename must select a different slug")

    timestamp = _canonical_timestamp(now)
    candidate_observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": tenant_id,
        "desiredManifestDigest": candidate_digest,
        "observedState": target_state.value,
        "activeDeploymentId": active_deployment_id,
        "runtimeGenerationId": (
            candidate_generation if target_state is LifecycleState.ACTIVE else None
        ),
        "reconciledAt": timestamp,
    }
    validate_contract(candidate_observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)

    intent_id = generate_uuid7(clock=clock, entropy=entropy)
    if intent_id == tenant_id:
        raise LifecyclePlanError("tenant and transaction identities collided")
    intent: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TransactionIntent",
        "compatibilityVersion": "static-intent-v2",
        "intentId": intent_id,
        "tenantId": tenant_id,
        "correlationId": request["correlationId"],
        "operation": operation.value,
        "archiveRecovery": None,
        "lifecycleRecovery": {
            "sourceObservedState": observed,
            "sourceRuntimeGenerationId": source_generation,
            "sourceRouteSet": source_route_set,
            "candidateObservedState": candidate_observed,
            "candidateRuntimeGenerationId": candidate_generation,
            "candidateRouteSet": ("both" if target_state is LifecycleState.ACTIVE else "absent"),
        },
        "sourceManifest": source,
        "sourceManifestDigest": source_digest,
        "candidateManifest": candidate,
        "candidateManifestDigest": candidate_digest,
        "phase": "prepared",
        "restartFence": None,
        "createdAt": timestamp,
    }
    validate_contract(intent, expected_kind=ContractKind.TRANSACTION_INTENT)

    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": operation.value,
        "status": "succeeded",
        "tenantId": tenant_id,
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": candidate,
    }
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    audit_entry = _successful_audit_entry(
        job,
        operation=operation.value,
        tenant_id=tenant_id,
        result=result,
        audit_state=audit_state,
        timestamp=timestamp,
    )

    return RouteTransitionPlan(
        tenant_id=tenant_id,
        intent_id=intent_id,
        manifest=deepcopy(candidate),
        observed_state=deepcopy(candidate_observed),
        intent=deepcopy(intent),
        result=deepcopy(result),
        audit_entry=deepcopy(audit_entry),
    )


def _validate_route_source_observed(
    observed: dict[str, object],
    *,
    tenant_id: str,
    source_digest: dict[str, str],
    source_state: LifecycleState,
    active_deployment_id: str | None,
) -> None:
    if (
        observed["tenantId"] != tenant_id
        or observed["desiredManifestDigest"] != source_digest
        or observed["observedState"] != source_state.value
        or observed["activeDeploymentId"] != active_deployment_id
    ):
        raise LifecyclePlanError("route source observed-state binding drifted")


def _successful_audit_entry(  # noqa: PLR0913 - exact audit authority tuple
    job: dict[str, object],
    *,
    operation: str,
    tenant_id: str,
    result: dict[str, object],
    audit_state: AuditState,
    timestamp: str,
) -> dict[str, object]:
    request = cast(dict[str, object], job["request"])
    audit_entry: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": audit_state.entry_count,
        "previousEntryDigest": audit_state.terminal_digest,
        "timestamp": timestamp,
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": operation,
        "tenantId": tenant_id,
        "correlationId": request["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
    }
    validate_contract(audit_entry, expected_kind=ContractKind.AUDIT_ENTRY)
    return audit_entry


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LifecyclePlanError("lifecycle clock must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
