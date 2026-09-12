"""Pure ordinary deletion plans bound to current archive or never-deployed evidence."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    canonical_json_bytes,
    manifest_digest,
    platform_state_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.lifecycle_plan import (
    LifecyclePlanError,
    _canonical_timestamp,
)


@dataclass(frozen=True, slots=True)
class DeleteTransitionPlan:
    tenant_id: str
    intent_id: str
    intent: dict[str, object]
    result: dict[str, object]
    audit_entry: dict[str, object]


def plan_delete_transition(  # noqa: PLR0913 - full deletion authority
    job: dict[str, object],
    namespace: dict[str, object],
    source: dict[str, object],
    observed: dict[str, object],
    retirement: dict[str, object] | None,
    *,
    source_runtime_generation_id: object,
    candidate_runtime_generation_id: object,
    audit_state: AuditState,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    intent_id: object | None = None,
) -> DeleteTransitionPlan:
    job, namespace, source, observed, retirement = deepcopy(
        (job, namespace, source, observed, retirement)
    )
    for value, kind in (
        (job, ContractKind.AUTHORIZATION_JOB),
        (namespace, ContractKind.PLATFORM_NAMESPACE),
        (source, ContractKind.SITE),
        (observed, ContractKind.TENANT_OBSERVED_STATE),
    ):
        validate_contract(value, expected_kind=kind)
    metadata = cast(dict[str, object], source["metadata"])
    spec = cast(dict[str, object], source["spec"])
    request = cast(dict[str, object], job["request"])
    expected = cast(dict[str, object], job["expectedSource"])
    authority = cast(dict[str, object], job["sourceAuthority"])
    evidence = expected.get("deletionEvidence")
    tenant = validate_uuid7(metadata["id"])
    digest = manifest_digest(source).to_dict()
    if (
        job["phase"] != "claimed"
        or job["compatibilityVersion"] != "static-job-v2"
        or request["operation"] != "delete"
        or request["tenantId"] != tenant
        or job["artifact"] is not None
        or spec["desiredState"] not in {"undeployed", "archived"}
        or authority["manifest"] != source
        or expected["expectsTenantAbsent"] is not False
        or expected["lifecycle"] != spec["desiredState"]
        or expected["manifestDigest"] != digest
        or expected["platformStateDigest"] != platform_state_digest(namespace).to_dict()
        or type(evidence) is not dict
        or evidence["releasedSlugs"] != [metadata["slug"]]
        or observed["tenantId"] != tenant
        or observed["desiredManifestDigest"] != digest
        or observed["observedState"] != spec["desiredState"]
        or observed["activeDeploymentId"] is not None
        or observed["runtimeGenerationId"] is not None
    ):
        raise LifecyclePlanError("delete source exceeds its ordinary authorization")
    if spec["desiredState"] == "undeployed":
        if (
            retirement is not None
            or authority["archiveRecord"] is not None
            or expected["deploymentDigest"] is not None
            or expected["archiveRecordDigest"] is not None
            or job.get("dispatchDeploymentIds") != []
            or job.get("dispatchArchiveDeploymentIds") != []
        ):
            raise LifecyclePlanError("never-deployed deletion carries deployment history")
    else:
        if retirement is None:
            raise LifecyclePlanError("archived deletion omitted its retirement journal")
        validate_contract(retirement, expected_kind=ContractKind.ARCHIVE_RETIREMENT_INTENT)
        archive = cast(dict[str, object], authority["archiveRecord"])
        selected = cast(dict[str, object], spec["desiredDeployment"])
        if (
            retirement["compatibilityVersion"] != "static-retirement-v2"
            or retirement["provenance"] != {"kind": "authorization-job", "jobId": job["jobId"]}
            or retirement["transition"] != "delete"
            or retirement["phase"] != "prepared"
            or retirement["operatorPrincipal"] != job["operatorPrincipal"]
            or retirement["tenantId"] != tenant
            or retirement["correlationId"] != request["correlationId"]
            or retirement["sourceManifestDigest"] != digest
            or retirement["archiveRecord"] != archive
            or retirement["archiveRecordDigest"] != expected["archiveRecordDigest"]
            or archive_record_digest(archive).to_dict() != expected["archiveRecordDigest"]
            or archive["manifestDigest"] != digest
            or archive["tenantId"] != tenant
            or archive["deploymentId"] != selected["id"]
            or job.get("dispatchArchiveDeploymentIds") != [selected["id"]]
            or type(job.get("dispatchDeploymentIds")) is not list
            or selected["id"] not in cast(list[object], job["dispatchDeploymentIds"])
        ):
            raise LifecyclePlanError("delete retirement journal exceeds current archive authority")
    source_id = validate_uuid7(source_runtime_generation_id)
    candidate_id = validate_uuid7(candidate_runtime_generation_id)
    identity = validate_uuid7(
        intent_id if intent_id is not None else generate_uuid7(clock=clock, entropy=entropy)
    )
    if (
        source_id == candidate_id
        or identity == tenant
        or (retirement is not None and identity == retirement["intentId"])
    ):
        raise LifecyclePlanError("delete requires distinct transaction and runtime identities")
    timestamp = _canonical_timestamp(now)
    intent: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "TransactionIntent",
        "compatibilityVersion": "static-intent-v2",
        "intentId": identity,
        "tenantId": tenant,
        "correlationId": request["correlationId"],
        "operation": "delete",
        "archiveRecovery": None,
        "lifecycleRecovery": {
            "sourceObservedState": observed,
            "sourceRuntimeGenerationId": source_id,
            "sourceRouteSet": "absent",
            "candidateObservedState": None,
            "candidateRuntimeGenerationId": candidate_id,
            "candidateRouteSet": "absent",
        },
        "sourceManifest": source,
        "sourceManifestDigest": digest,
        "candidateManifest": None,
        "candidateManifestDigest": None,
        "phase": "prepared",
        "restartFence": None,
        "createdAt": timestamp,
    }
    result: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "delete",
        "status": "succeeded",
        "tenantId": tenant,
        "canonicalOrigin": metadata["canonicalOrigin"],
    }
    audit: dict[str, object] = {
        "apiVersion": source["apiVersion"],
        "kind": "AuditEntry",
        "sequence": audit_state.entry_count,
        "previousEntryDigest": audit_state.terminal_digest,
        "timestamp": timestamp,
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": "delete",
        "tenantId": tenant,
        "correlationId": request["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
    }
    audit["deletionEvidence"] = deepcopy(evidence)
    for value, kind in (
        (intent, ContractKind.TRANSACTION_INTENT),
        (result, ContractKind.OPERATION_RESULT),
        (audit, ContractKind.AUDIT_ENTRY),
    ):
        validate_contract(value, expected_kind=kind)
        canonical_json_bytes(value)
    return deepcopy(DeleteTransitionPlan(tenant, identity, intent, result, audit))
