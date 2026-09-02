"""Pure, contract-validated plans for authoritative lifecycle transactions."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
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


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LifecyclePlanError("lifecycle clock must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
