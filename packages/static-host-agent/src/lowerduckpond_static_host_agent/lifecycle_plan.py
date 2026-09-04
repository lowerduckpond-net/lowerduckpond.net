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


@dataclass(frozen=True, slots=True)
class DeploymentTransitionPlan:
    """Every contract needed for one deploy or rollback selection."""

    tenant_id: str
    intent_id: str
    manifest: dict[str, object]
    observed_state: dict[str, object]
    deployment: dict[str, object]
    creates_deployment: bool
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


def plan_deployment_transition(  # noqa: PLR0913,PLR0915,PLR0917 - authority tuple
    authorization_job: dict[str, object],
    platform_namespace: dict[str, object],
    source_manifest: dict[str, object],
    source_observed_state: dict[str, object],
    source_deployment: dict[str, object] | None,
    rollback_deployment: dict[str, object] | None,
    *,
    artifact_release_tree_digest: dict[str, object] | None,
    source_runtime_generation_id: object,
    candidate_runtime_generation_id: object,
    audit_state: AuditState,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
) -> DeploymentTransitionPlan:
    """Derive one complete deploy or rollback without mutating host state."""

    job = deepcopy(authorization_job)
    namespace = deepcopy(platform_namespace)
    source = deepcopy(source_manifest)
    observed = deepcopy(source_observed_state)
    selected_source = deepcopy(source_deployment)
    rollback_target = deepcopy(rollback_deployment)
    validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
    validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    validate_contract(source, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    if selected_source is not None:
        validate_contract(selected_source, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    if rollback_target is not None:
        validate_contract(rollback_target, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    if job["phase"] != "claimed":
        raise LifecyclePlanError("deployment planning requires one claimed authorization job")

    request = cast(dict[str, object], job["request"])
    try:
        operation = Operation(cast(str, request["operation"]))
    except ValueError as error:
        raise LifecyclePlanError("deployment planning received an unsupported operation") from error
    if operation not in {Operation.DEPLOY, Operation.ROLLBACK}:
        raise LifecyclePlanError("deployment planning received an unsupported operation")

    metadata = cast(dict[str, object], source["metadata"])
    spec = cast(dict[str, object], source["spec"])
    tenant_id = validate_uuid7(metadata["id"])
    if request["tenantId"] != tenant_id:
        raise LifecyclePlanError("deployment authority selected a different tenant")
    source_state = LifecycleState(cast(str, spec["desiredState"]))
    target_state = LIFECYCLE_MATRIX.get((operation, source_state))
    if target_state is None:
        raise LifecyclePlanError("deployment operation is not valid for the source lifecycle")

    source_digest = manifest_digest(source).to_dict()
    source_deployment_digest = _validate_deployment_source(
        source,
        observed,
        selected_source,
        tenant_id=tenant_id,
        source_state=source_state,
        source_digest=source_digest,
    )
    expected_source = cast(dict[str, object], job["expectedSource"])
    if expected_source != {
        "expectsTenantAbsent": False,
        "lifecycle": source_state.value,
        "manifestDigest": source_digest,
        "deploymentDigest": source_deployment_digest,
        "archiveRecordDigest": None,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
    }:
        raise LifecyclePlanError("deployment authority is not bound to the supplied source")

    source_generation = validate_uuid7(source_runtime_generation_id)
    candidate_generation = validate_uuid7(candidate_runtime_generation_id)
    if source_generation == candidate_generation:
        raise LifecyclePlanError("deployment must select a distinct runtime generation")
    timestamp = _canonical_timestamp(now)
    deployment, creates_deployment = _select_deployment(
        job,
        request,
        selected_source,
        rollback_target,
        artifact_release_tree_digest,
        tenant_id=tenant_id,
        timestamp=timestamp,
        clock=clock,
        entropy=entropy,
    )

    candidate = deepcopy(source)
    candidate_spec = cast(dict[str, object], candidate["spec"])
    candidate_spec["desiredState"] = target_state.value
    candidate_spec["desiredDeployment"] = {
        "id": deployment["id"],
        "archiveSha256": deployment["archiveSha256"],
    }
    validate_contract(candidate, expected_kind=ContractKind.SITE)
    candidate_digest = manifest_digest(candidate).to_dict()
    candidate_observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": tenant_id,
        "desiredManifestDigest": candidate_digest,
        "observedState": target_state.value,
        "activeDeploymentId": deployment["id"],
        "runtimeGenerationId": (
            candidate_generation if target_state is LifecycleState.ACTIVE else None
        ),
        "reconciledAt": timestamp,
    }
    validate_contract(candidate_observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)

    intent_id = generate_uuid7(clock=clock, entropy=entropy)
    if intent_id in {tenant_id, deployment["id"]}:
        raise LifecyclePlanError("deployment and transaction identities collided")
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
            "sourceRouteSet": ("both" if source_state is LifecycleState.ACTIVE else "absent"),
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
    return DeploymentTransitionPlan(
        tenant_id=tenant_id,
        intent_id=intent_id,
        manifest=deepcopy(candidate),
        observed_state=deepcopy(candidate_observed),
        deployment=deepcopy(deployment),
        creates_deployment=creates_deployment,
        intent=deepcopy(intent),
        result=deepcopy(result),
        audit_entry=deepcopy(audit_entry),
    )


def _validate_deployment_source(  # noqa: PLR0913 - exact source tuple
    manifest: dict[str, object],
    observed: dict[str, object],
    deployment: dict[str, object] | None,
    *,
    tenant_id: str,
    source_state: LifecycleState,
    source_digest: dict[str, str],
) -> dict[str, str] | None:
    if source_state is LifecycleState.UNDEPLOYED:
        source_spec = cast(dict[str, object], manifest["spec"])
        if deployment is not None or "desiredDeployment" in source_spec:
            raise LifecyclePlanError("undeployed source retained deployment evidence")
        active_deployment_id = None
        deployment_digest = None
    elif source_state in {LifecycleState.ACTIVE, LifecycleState.SUSPENDED}:
        if deployment is None:
            raise LifecyclePlanError("deployed source omitted its deployment")
        source_spec = cast(dict[str, object], manifest["spec"])
        selected = cast(dict[str, object], source_spec["desiredDeployment"])
        if (
            deployment["tenantId"] != tenant_id
            or deployment["id"] != selected["id"]
            or deployment["archiveSha256"] != selected["archiveSha256"]
        ):
            raise LifecyclePlanError("source deployment binding drifted")
        active_deployment_id = deployment["id"]
        deployment_digest = deployment_record_digest(deployment).to_dict()
    else:
        raise LifecyclePlanError("deployment planning does not accept this lifecycle state")
    if (
        observed["tenantId"] != tenant_id
        or observed["desiredManifestDigest"] != source_digest
        or observed["observedState"] != source_state.value
        or observed["activeDeploymentId"] != active_deployment_id
    ):
        raise LifecyclePlanError("deployment source observed-state binding drifted")
    return deployment_digest


def _select_deployment(  # noqa: PLR0913 - exact selection inputs stay explicit
    job: dict[str, object],
    request: dict[str, object],
    source: dict[str, object] | None,
    rollback: dict[str, object] | None,
    release_tree_digest: dict[str, object] | None,
    *,
    tenant_id: str,
    timestamp: str,
    clock: MillisecondClock,
    entropy: EntropySource,
) -> tuple[dict[str, object], bool]:
    history = job.get("dispatchDeploymentIds")
    if type(history) is not list or any(type(value) is not str for value in history):
        raise LifecyclePlanError("deployment history authority is unavailable")
    history_ids = tuple(validate_uuid7(value) for value in history)
    if history_ids != tuple(sorted(set(history_ids))):
        raise LifecyclePlanError("deployment history authority is not canonical")
    if source is None:
        if history_ids:
            raise LifecyclePlanError("undeployed source retained deployment history")
    elif not history_ids or source["id"] != history_ids[-1]:
        raise LifecyclePlanError("selected source does not terminate retained deployment history")
    operation = request["operation"]
    if operation == "rollback":
        if release_tree_digest is not None or rollback is None:
            raise LifecyclePlanError("rollback selection authority is malformed")
        target_id = validate_uuid7(request["deploymentId"])
        if source is not None and target_id == source["id"]:
            raise LifecyclePlanError("rollback target is already selected")
        if (
            target_id not in history_ids
            or rollback["id"] != target_id
            or rollback["tenantId"] != tenant_id
        ):
            raise LifecyclePlanError("rollback target is outside retained history")
        return rollback, False
    if operation != "deploy" or rollback is not None:
        raise LifecyclePlanError("deploy selection authority is malformed")
    bound_digest = job.get("dispatchArtifactReleaseTreeDigest")
    if release_tree_digest is None or bound_digest != release_tree_digest:
        raise LifecyclePlanError("deploy release content exceeds dispatch authority")
    artifact = cast(dict[str, object], request["artifact"])
    deployment_id = generate_uuid7(clock=clock, entropy=entropy)
    if history_ids and deployment_id <= history_ids[-1]:
        raise LifecyclePlanError("deploy identity does not follow retained deployment history")
    deployment: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "DeploymentRecord",
        "id": deployment_id,
        "tenantId": tenant_id,
        "archiveSha256": artifact["sha256"],
        "releaseTreeDigest": release_tree_digest,
        "createdAt": timestamp,
        "correlationId": request["correlationId"],
    }
    validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    return deployment, True


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
