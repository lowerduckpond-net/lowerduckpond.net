"""Prepare durable administrator authority without an ordinary authorization job."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    manifest_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.lifecycle_plan import _canonical_timestamp


def plan_emergency_deletion(  # noqa: PLR0913 - complete separately authenticated root authority
    source: dict[str, object],
    observed: dict[str, object],
    deployments: list[dict[str, object]],
    archive: dict[str, object] | None,
    *,
    operator_principal: str,
    reason: str,
    correlation_id: str,
    source_runtime_generation_id: str,
    candidate_runtime_generation_id: str,
    retirement_intent_id: str,
    audit_state: AuditState,
    now: datetime,
) -> dict[str, object]:
    source, observed, deployments, archive = deepcopy((source, observed, deployments, archive))
    metadata = source["metadata"]
    if type(metadata) is not dict:
        raise ValueError("emergency source metadata is malformed")
    correlation = validate_uuid7(correlation_id)
    timestamp = _canonical_timestamp(now)
    provenance = {
        "kind": "emergency-administrator",
        "operatorPrincipal": operator_principal,
        "reason": reason,
    }
    result = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": provenance,
        "correlationId": correlation,
        "operation": "delete",
        "status": "succeeded",
        "tenantId": metadata["id"],
        "canonicalOrigin": metadata["canonicalOrigin"],
    }
    audit = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": audit_state.entry_count,
        "previousEntryDigest": audit_state.terminal_digest,
        "timestamp": timestamp,
        "operatorPrincipal": operator_principal,
        "operation": "delete",
        "tenantId": metadata["id"],
        "correlationId": correlation,
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
        "deletionEvidence": {
            "mode": "emergency" if archive is None else "emergency-archived",
            "releasedSlugs": [metadata["slug"]],
            "archiveRecordDigest": None
            if archive is None
            else archive_record_digest(archive).to_dict(),
            "bucket": None if archive is None else archive["bucket"],
            "key": None if archive is None else archive["key"],
            "versionId": None if archive is None else archive["versionId"],
            "emergencyReason": reason,
        },
    }
    retirement = (
        None
        if archive is None
        else {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "ArchiveRetirementIntent",
            "compatibilityVersion": "static-retirement-v2",
            "intentId": validate_uuid7(retirement_intent_id),
            "provenance": {"kind": "emergency-administrator", "reason": reason},
            "operatorPrincipal": operator_principal,
            "tenantId": metadata["id"],
            "correlationId": correlation,
            "transition": "delete",
            "sourceManifestDigest": manifest_digest(source).to_dict(),
            "archiveRecord": archive,
            "archiveRecordDigest": archive_record_digest(archive).to_dict(),
            "phase": "prepared",
            "createdAt": timestamp,
            **{
                key: archive[key]
                for key in ("bucket", "key", "versionId", "bundleDigest", "bundleSize")
            },
        }
    )
    intent: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "EmergencyDeletionIntent",
        "compatibilityVersion": "static-emergency-deletion-v1",
        "intentId": correlation,
        "correlationId": correlation,
        "operatorPrincipal": operator_principal,
        "reason": reason,
        "createdAt": timestamp,
        "tenantId": metadata["id"],
        "sourceManifest": source,
        "sourceObservedState": observed,
        "deploymentRecords": deployments,
        "archiveRecord": archive,
        "sourceRuntimeGenerationId": source_runtime_generation_id,
        "candidateRuntimeGenerationId": candidate_runtime_generation_id,
        "retirementIntent": retirement,
        "result": result,
        "auditEntry": audit,
    }
    validate_contract(intent, expected_kind=ContractKind.EMERGENCY_DELETION_INTENT)
    return intent
