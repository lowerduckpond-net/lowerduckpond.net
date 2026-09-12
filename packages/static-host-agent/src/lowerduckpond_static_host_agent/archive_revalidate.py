"""Replay-safe revalidation of an unchanged authoritative archive."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    manifest_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.caddy_admin import verify_running_caddy
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.execution import ExecutionOutcome
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.lifecycle_plan import _canonical_timestamp
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StateRepository,
)
from lowerduckpond_static_host_agent.route_activate import GenerationVerifier
from lowerduckpond_static_host_agent.route_commit import (
    _ensure_audit,
    _ensure_completed_job,
    _ensure_result,
)
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class ArchiveRevalidationError(RuntimeError):
    """A repeated archive cannot preserve its complete authorized source."""


def revalidate_archive(  # noqa: PLR0912, PLR0913, PLR0915, PLR0917 - explicit no-op transaction
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    client: ArchiveCleanupClient,
    job_id: str,
    *,
    now: datetime,
    clock: MillisecondClock,
    entropy: EntropySource,
    verifier: GenerationVerifier = verify_running_caddy,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    failure_hook: Callable[[str], None] | None = None,
    blocking: bool = False,
) -> ExecutionOutcome:
    canonical_job = validate_uuid7(job_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
        job = transaction.read(StateRecordPath.authorization_job(canonical_job))
        authority = cast(dict[str, object], job.document["sourceAuthority"])
        archive = cast(dict[str, object], authority["archiveRecord"])
        fresh = not transaction.measure_intent_records().records
    if fresh:
        client.verify_source(canonical_job, archive)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(canonical_job))
        request = cast(dict[str, object], job.document["request"])
        expected = cast(dict[str, object], job.document["expectedSource"])
        if (
            job.document["compatibilityVersion"] != "static-job-v2"
            or job.document["phase"] not in {"claimed", "completed"}
            or request["operation"] != "archive"
            or expected["lifecycle"] != "archived"
            or build_expected_source(transaction, request) != expected
        ):
            raise ArchiveRevalidationError("archive revalidation has no current claimed source")
        tenant_id = validate_uuid7(request["tenantId"])
        source = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
        observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
        desired = cast(
            dict[str, object], cast(dict[str, object], source["spec"])["desiredDeployment"]
        )
        current_archive = transaction.read(
            StateRecordPath.tenant_archive(tenant_id, desired["id"])
        ).document
        if current_archive != archive or job.document["sourceAuthority"] != {
            "manifest": source,
            "archiveRecord": archive,
        }:
            raise ArchiveRevalidationError("archive revalidation source changed")
        active = runtime.open_active_verified()
        try:
            generation_id = active.generation_id
            verifier(active.generation)
        finally:
            active.generation.close()
        if runtime.read_generation_route_snapshot(generation_id) != snapshot_tenant_routes(
            transaction
        ):
            raise ArchiveRevalidationError("archive revalidation found incomplete current routes")
        identities = transaction.measure_intent_records().records
        if len(identities) > 1:
            raise ArchiveRevalidationError("archive revalidation requires exclusive recovery")
        prior = None
        if identities:
            _path, prior = transaction.read_intent(identities[0].intent_id)
        elif not fresh:
            raise ArchiveRevalidationError("archive revalidation lost its durable intent")
        timestamp = _canonical_timestamp(now) if prior is None else prior.document["createdAt"]
        intent_id = (
            generate_uuid7(clock=clock, entropy=entropy)
            if prior is None
            else validate_uuid7(prior.document["intentId"])
        )
        digest = manifest_digest(source).to_dict()
        intent: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "TransactionIntent",
            "compatibilityVersion": "static-intent-v2",
            "intentId": intent_id,
            "tenantId": tenant_id,
            "correlationId": request["correlationId"],
            "operation": "archive",
            "archiveRecovery": {
                "sourceManifest": source,
                "sourceObservedState": observed,
                "sourceRuntimeGenerationId": generation_id,
                "sourceRouteSet": "absent",
                "candidateManifest": source,
                "candidateArchiveRecord": archive,
                "candidateRuntimeGenerationId": generation_id,
                "candidateRouteSet": "absent",
            },
            "lifecycleRecovery": None,
            "sourceManifest": source,
            "sourceManifestDigest": digest,
            "candidateManifest": source,
            "candidateManifestDigest": digest,
            "phase": "prepared",
            "restartFence": None,
            "createdAt": timestamp,
        }
        validate_contract(intent, expected_kind=ContractKind.TRANSACTION_INTENT)
        if prior is not None and prior.document != intent:
            raise ArchiveRevalidationError(
                "archive revalidation intent no longer matches its source"
            )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": canonical_job},
            "operation": "archive",
            "status": "succeeded",
            "correlationId": request["correlationId"],
            "tenantId": tenant_id,
            "canonicalOrigin": cast(dict[str, object], source["metadata"])["canonicalOrigin"],
            "manifest": source,
            "archiveRecord": archive,
        }
        validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
        try:
            existing = transaction.read(StateRecordPath.authorization_result(canonical_job))
        except FileNotFoundError:
            missing = True
        else:
            missing = False
            if existing.document != result:
                raise ArchiveRevalidationError("archive revalidation result changed")
        audit = transaction.inspect_audit_correlation(request["correlationId"])
        entry: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "AuditEntry",
            "sequence": audit.state.entry_count if audit.entry is None else audit.entry["sequence"],
            "previousEntryDigest": audit.state.terminal_digest
            if audit.entry is None
            else audit.entry["previousEntryDigest"],
            "timestamp": timestamp,
            "operatorPrincipal": job.document["operatorPrincipal"],
            "operation": "archive",
            "tenantId": tenant_id,
            "correlationId": request["correlationId"],
            "resultDigest": result_digest(result).to_dict(),
            "resultStatus": "succeeded",
        }
        validate_contract(entry, expected_kind=ContractKind.AUDIT_ENTRY)
        if audit.entry is not None and audit.entry != entry:
            raise ArchiveRevalidationError("archive revalidation audit changed")
        if audit.entry is None:
            transaction.admit_audit_append(entry)
        if missing:
            transaction.admit_inventory(
                StateInventoryReservation(
                    authorization_records=1,
                    authorization_allocated_bytes=transaction.allocation_upper_bound(
                        len(canonical_json_bytes(result))
                    ),
                )
            )
        allocation = sum(
            transaction.allocation_upper_bound(len(canonical_json_bytes(value)))
            for value in (job.document, intent, result)
        )
        if audit.entry is None:
            allocation += transaction.allocation_upper_bound(
                DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
            )
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(allocation + transaction.namespace_allocation_upper_bound(4), 4),
            transaction.measure_filesystem_capacity(),
            limits=capacity_limits,
        )
        if prior is None:
            prior = transaction.create_immutable(
                StateRecordPath.transaction_intent(intent_id), intent
            )
        if failure_hook is not None:
            failure_hook("intent-sync")
        _ensure_audit(transaction, entry)
        if failure_hook is not None:
            failure_hook("audit-sync")
        _ensure_result(transaction, job, result, result_missing=missing)
        if failure_hook is not None:
            failure_hook("result-sync")
        _ensure_completed_job(transaction, job)
        if failure_hook is not None:
            failure_hook("job-sync")
        identity = transaction.measure_intent_records().records[0]
        transaction.remove_reconciled_intent(
            StateRecordPath.transaction_intent(intent_id),
            IntentRemovalToken(prior.revision, identity.metadata_generation),
        )
        return ExecutionOutcome(deepcopy(result), missing)
