"""Durable failure of an unpublished construction, preserving its exact source."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from enum import StrEnum
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    manifest_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.archive_journal import _archive_record
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.execution import ExecutionOutcome
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.route_commit import _ensure_audit, _ensure_result
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class ArchiveAbortError(RuntimeError):
    """Unpublished archive failure cannot preserve its exact durable authority."""


class ArchiveAbortBoundary(StrEnum):
    AUDIT_SYNC = "audit-sync"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"


def finalize_failed_construction(  # noqa: PLR0912, PLR0913, PLR0915 - explicit replay boundaries
    repository: StateRepository,
    spool: ExportSpool,
    job_id: str,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: Callable[[ArchiveAbortBoundary], None] | None = None,
    blocking: bool = False,
) -> ExecutionOutcome:
    """Publish failure while retaining the construction for independent remote cleanup.

    No local transaction may exist and the complete authorized source must
    remain current. The result stays behind the intent barrier until the
    network service proves permanent remote absence and removes that journal.
    """
    canonical_job = validate_uuid7(job_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with repository.publication_transaction(blocking=blocking) as transaction:
        path = StateRecordPath.authorization_job(canonical_job)
        job = transaction.read(path)
        request = cast(dict[str, object], job.document["request"])
        expected = cast(dict[str, object], job.document["expectedSource"])
        identities = transaction.measure_intent_records().records
        if (
            job.document["compatibilityVersion"] != "static-job-v2"
            or job.document["phase"] not in {"claimed", "failed"}
            or request["operation"] != "archive"
            or expected["lifecycle"] not in {"active", "suspended"}
            or build_expected_source(transaction, request) != expected
            or len(identities) != 1
        ):
            raise ArchiveAbortError("construction failure has no unchanged exclusive source")
        _intent_path, stored = transaction.read_intent(identities[0].intent_id)
        intent = stored.document
        if (
            intent["kind"] != "ArchiveConstructionIntent"
            or intent["jobId"] != canonical_job
            or intent["tenantId"] != request["tenantId"]
            or intent["correlationId"] != request["correlationId"]
            or intent["operatorPrincipal"] != job.document["operatorPrincipal"]
            or intent["sourceManifestDigest"] != expected["manifestDigest"]
            or intent["deploymentRecordDigest"] != expected["deploymentDigest"]
        ):
            raise ArchiveAbortError("construction failure exceeds its job authority")
        source = transaction.read(StateRecordPath.tenant_desired(request["tenantId"])).document
        if job.document["sourceAuthority"] != {"manifest": source, "archiveRecord": None}:
            raise ArchiveAbortError("construction failure lost its exact source manifest")
        desired = cast(
            dict[str, object], cast(dict[str, object], source["spec"])["desiredDeployment"]
        )
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(request["tenantId"], desired["id"])
        ).document
        candidate = deepcopy(source)
        cast(dict[str, object], candidate["spec"])["desiredState"] = "archived"
        if (
            intent["candidateManifestDigest"] != manifest_digest(candidate).to_dict()
            or intent["releaseTreeDigest"] != deployment["releaseTreeDigest"]
        ):
            raise ArchiveAbortError("construction failure lost its exact candidate binding")
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": canonical_job},
            "operation": "archive",
            "status": "failed",
            "tenantId": request["tenantId"],
            "correlationId": request["correlationId"],
            "errorCode": "archive_unavailable",
            "archiveRecord": None
            if intent["phase"] == "prepared"
            else _archive_record(intent, deployment),
        }
        validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
        result_path = StateRecordPath.authorization_result(canonical_job)
        try:
            existing = transaction.read(result_path)
        except FileNotFoundError:
            result_missing = True
        else:
            result_missing = False
            if existing.document != result:
                raise ArchiveAbortError("construction failure result changed")
        if job.document["phase"] == "failed" and result_missing:
            raise ArchiveAbortError("failed construction job has no durable result")
        audit = transaction.inspect_audit_correlation(request["correlationId"])
        entry: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "AuditEntry",
            "sequence": audit.state.entry_count if audit.entry is None else audit.entry["sequence"],
            "previousEntryDigest": audit.state.terminal_digest
            if audit.entry is None
            else audit.entry["previousEntryDigest"],
            "timestamp": intent["createdAt"],
            "operatorPrincipal": job.document["operatorPrincipal"],
            "operation": "archive",
            "tenantId": request["tenantId"],
            "correlationId": request["correlationId"],
            "resultDigest": result_digest(result).to_dict(),
            "resultStatus": "failed",
        }
        validate_contract(entry, expected_kind=ContractKind.AUDIT_ENTRY)
        if audit.entry is not None and audit.entry != entry:
            raise ArchiveAbortError("construction failure audit changed")
        if audit.entry is None:
            transaction.admit_audit_append(entry)
        if result_missing:
            transaction.admit_inventory(
                StateInventoryReservation(
                    authorization_records=1,
                    authorization_allocated_bytes=transaction.allocation_upper_bound(
                        len(canonical_json_bytes(result))
                    ),
                )
            )
        failed = deepcopy(job.document)
        failed["phase"] = "failed"
        writes = [result, failed]
        allocation = sum(
            transaction.allocation_upper_bound(len(canonical_json_bytes(value))) for value in writes
        )
        if audit.entry is None:
            allocation += transaction.allocation_upper_bound(
                DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
            )
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(allocation + transaction.namespace_allocation_upper_bound(3), 3),
            transaction.measure_filesystem_capacity(),
            limits=capacity_limits,
        )
        _ensure_audit(transaction, entry)
        if failure_hook is not None:
            failure_hook(ArchiveAbortBoundary.AUDIT_SYNC)
        _ensure_result(transaction, job, result, result_missing=result_missing)
        if failure_hook is not None:
            failure_hook(ArchiveAbortBoundary.RESULT_SYNC)
        if job.document != failed:
            transaction.compare_and_swap(path, job.revision, failed)
        if failure_hook is not None:
            failure_hook(ArchiveAbortBoundary.JOB_SYNC)
        return ExecutionOutcome(result, result_missing)
