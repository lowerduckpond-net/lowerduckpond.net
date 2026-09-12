"""Pure restore planning from an exact archived source and retirement journal."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.lifecycle_plan import (
    DeploymentTransitionPlan,
    LifecyclePlanError,
    _canonical_timestamp,
    _successful_audit_entry,
)


def plan_restore_transition(  # noqa: PLR0913, PLR0917 - complete authority tuple
    authorization_job: dict[str, object],
    platform_namespace: dict[str, object],
    source_manifest: dict[str, object],
    source_observed: dict[str, object],
    source_deployment: dict[str, object],
    retirement_intent: dict[str, object],
    *,
    source_runtime_generation_id: object,
    candidate_runtime_generation_id: object,
    audit_state: AuditState,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    deployment_id: object | None = None,
    intent_id: object | None = None,
) -> DeploymentTransitionPlan:
    """Preserve tenant identity and policy while selecting a new verified deployment."""
    job, namespace, source, observed, previous, retirement = deepcopy(
        (
            authorization_job,
            platform_namespace,
            source_manifest,
            source_observed,
            source_deployment,
            retirement_intent,
        )
    )
    for document, kind in (
        (job, ContractKind.AUTHORIZATION_JOB),
        (namespace, ContractKind.PLATFORM_NAMESPACE),
        (source, ContractKind.SITE),
        (observed, ContractKind.TENANT_OBSERVED_STATE),
        (previous, ContractKind.DEPLOYMENT_RECORD),
        (retirement, ContractKind.ARCHIVE_RETIREMENT_INTENT),
    ):
        validate_contract(document, expected_kind=kind)
    archive = cast(dict[str, object], retirement["archiveRecord"])
    metadata = cast(dict[str, object], source["metadata"])
    spec = cast(dict[str, object], source["spec"])
    request = cast(dict[str, object], job["request"])
    tenant = validate_uuid7(metadata["id"])
    source_digest = manifest_digest(source).to_dict()
    archive_digest = archive_record_digest(archive).to_dict()
    history = job.get("dispatchDeploymentIds")
    if (
        job["compatibilityVersion"] != "static-job-v2"
        or job["phase"] != "claimed"
        or request["operation"] != "restore"
        or request["tenantId"] != tenant
        or job["artifact"] is not None
        or spec["desiredState"] != "archived"
        or spec.get("desiredDeployment")
        != {"id": previous["id"], "archiveSha256": previous["archiveSha256"]}
        or previous["tenantId"] != tenant
        or job["sourceAuthority"] != {"manifest": source, "archiveRecord": archive}
        or job["expectedSource"]
        != {
            "expectsTenantAbsent": False,
            "lifecycle": "archived",
            "manifestDigest": source_digest,
            "deploymentDigest": deployment_record_digest(previous).to_dict(),
            "archiveRecordDigest": archive_digest,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
        or archive["manifestDigest"] != source_digest
        or archive["tenantId"] != tenant
        or archive["deploymentId"] != previous["id"]
        or archive["releaseTreeDigest"] != previous["releaseTreeDigest"]
        or retirement["compatibilityVersion"] != "static-retirement-v2"
        or retirement["provenance"] != {"kind": "authorization-job", "jobId": job["jobId"]}
        or retirement["operatorPrincipal"] != job["operatorPrincipal"]
        or retirement["transition"] != "restore"
        or retirement["phase"] != "prepared"
        or retirement["tenantId"] != tenant
        or retirement["correlationId"] != request["correlationId"]
        or retirement["sourceManifestDigest"] != source_digest
        or retirement["archiveRecordDigest"] != archive_digest
        or observed["tenantId"] != tenant
        or observed["desiredManifestDigest"] != source_digest
        or observed["observedState"] != "archived"
        or observed["activeDeploymentId"] is not None
        or observed["runtimeGenerationId"] is not None
        or type(history) is not list
        or not history
        or history != sorted(set(history))
        or history[-1] != previous["id"]
        or job.get("dispatchArchiveDeploymentIds") != [previous["id"]]
        or job.get("dispatchSourceReleaseTreeDigest") != previous["releaseTreeDigest"]
    ):
        raise LifecyclePlanError("restore source exceeds its exact retirement authority")
    source_generation = validate_uuid7(source_runtime_generation_id)
    candidate_generation = validate_uuid7(candidate_runtime_generation_id)
    selected = validate_uuid7(
        deployment_id if deployment_id is not None else generate_uuid7(clock=clock, entropy=entropy)
    )
    intent_identity = validate_uuid7(
        intent_id if intent_id is not None else generate_uuid7(clock=clock, entropy=entropy)
    )
    if (
        selected <= str(history[-1])
        or source_generation == candidate_generation
        or len({tenant, selected, intent_identity, str(retirement["intentId"])}) != 4  # noqa: PLR2004 - four distinct authorities
    ):
        raise LifecyclePlanError(
            "restore requires distinct new deployment and transaction identities"
        )
    timestamp = _canonical_timestamp(now)
    deployment: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "DeploymentRecord",
        "tenantId": tenant,
        "id": selected,
        "archiveSha256": cast(dict[str, object], archive["bundleDigest"])["value"],
        "releaseTreeDigest": archive["releaseTreeDigest"],
        "createdAt": timestamp,
        "correlationId": request["correlationId"],
    }
    candidate = deepcopy(source)
    cast(dict[str, object], candidate["spec"]).update(
        desiredState="active",
        desiredDeployment={"id": selected, "archiveSha256": deployment["archiveSha256"]},
    )
    candidate_digest = manifest_digest(candidate).to_dict()
    candidate_observed: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "TenantObservedState",
        "tenantId": tenant,
        "desiredManifestDigest": candidate_digest,
        "observedState": "active",
        "activeDeploymentId": selected,
        "runtimeGenerationId": candidate_generation,
        "reconciledAt": timestamp,
    }
    intent: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "TransactionIntent",
        "compatibilityVersion": "static-intent-v2",
        "intentId": intent_identity,
        "tenantId": tenant,
        "correlationId": request["correlationId"],
        "operation": "restore",
        "archiveRecovery": None,
        "lifecycleRecovery": {
            "sourceObservedState": observed,
            "sourceRuntimeGenerationId": source_generation,
            "sourceRouteSet": "absent",
            "candidateObservedState": candidate_observed,
            "candidateRuntimeGenerationId": candidate_generation,
            "candidateRouteSet": "both",
        },
        "sourceManifest": source,
        "sourceManifestDigest": source_digest,
        "candidateManifest": candidate,
        "candidateManifestDigest": candidate_digest,
        "phase": "prepared",
        "restartFence": None,
        "createdAt": timestamp,
    }
    result: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "restore",
        "status": "succeeded",
        "tenantId": tenant,
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": candidate,
    }
    for document, kind in (
        (deployment, ContractKind.DEPLOYMENT_RECORD),
        (candidate, ContractKind.SITE),
        (candidate_observed, ContractKind.TENANT_OBSERVED_STATE),
        (intent, ContractKind.TRANSACTION_INTENT),
        (result, ContractKind.OPERATION_RESULT),
    ):
        validate_contract(document, expected_kind=kind)
    audit_entry = _successful_audit_entry(
        job,
        operation="restore",
        tenant_id=tenant,
        result=result,
        audit_state=audit_state,
        timestamp=timestamp,
    )
    return deepcopy(
        DeploymentTransitionPlan(
            tenant,
            intent_identity,
            candidate,
            candidate_observed,
            deployment,
            True,
            intent,
            result,
            audit_entry,
        )
    )
