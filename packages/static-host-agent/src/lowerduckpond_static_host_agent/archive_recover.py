"""Reconstruct archive activation from exact durable journals and complete generations."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import ContractKind, validate_uuid7

from lowerduckpond_static_host_agent.archive_commit import validate_archive_transition
from lowerduckpond_static_host_agent.archive_prepare import PreparedArchiveTransition
from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.lifecycle_plan import plan_archive_transition
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_other_tenant_routes,
)


class ArchiveRecoveryError(RuntimeError):
    """Archive journal state cannot reconstruct one exact authorized publication."""


def reconstruct_archive_transition(  # noqa: PLR0913 - complete recovery proof
    repository: StateRepository,
    spool: ExportSpool,
    runtime: CaddyRuntime,
    gate: PublicationGate,
    job_id: object,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    blocking: bool = False,
) -> PreparedArchiveTransition:
    """Rebuild a prepared transition without trusting caller-held plan objects."""
    canonical = validate_uuid7(job_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with (
        repository.publication_transaction(blocking=blocking) as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        gate.require_enabled()
        job = transaction.read(StateRecordPath.authorization_job(canonical))
        claimed = job.document
        if claimed["phase"] not in {"claimed", "completed"}:
            raise ArchiveRecoveryError("archive recovery requires a claimed or committing job")
        claimed["phase"] = "claimed"
        request = cast(dict[str, object], claimed["request"])
        tenant_id = validate_uuid7(request["tenantId"])
        identities = transaction.measure_intent_records().records
        records = [transaction.read_intent(identity.intent_id)[1] for identity in identities]
        by_kind = {record.revision.contract_kind: record for record in records}
        if len(records) != 2 or set(by_kind) != {  # noqa: PLR2004 - exactly both archive journals
            ContractKind.TRANSACTION_INTENT,
            ContractKind.ARCHIVE_CONSTRUCTION_INTENT,
        }:
            raise ArchiveRecoveryError("archive recovery requires its transaction and construction")
        intent = by_kind[ContractKind.TRANSACTION_INTENT].document
        construction = by_kind[ContractKind.ARCHIVE_CONSTRUCTION_INTENT].document
        if intent["operation"] != "archive" or intent["tenantId"] != tenant_id:
            raise ArchiveRecoveryError("archive recovery selected another tenant or operation")
        recovery = cast(dict[str, object], intent["archiveRecovery"])
        source = cast(dict[str, object], intent["sourceManifest"])
        observed = cast(dict[str, object], recovery["sourceObservedState"])
        archive = cast(dict[str, object], recovery["candidateArchiveRecord"])
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, archive["deploymentId"])
        ).document
        audit = transaction.inspect_audit_correlation(request["correlationId"])
        prefix = (
            audit.state
            if audit.entry is None
            else AuditState(
                cast(int, audit.entry["sequence"]),
                0,
                0,
                cast(dict[str, str] | None, audit.entry["previousEntryDigest"]),
            )
        )
        plan = plan_archive_transition(
            claimed,
            transaction.read(StateRecordPath.platform_namespace()).document,
            source,
            observed,
            deployment,
            construction,
            archive,
            source_runtime_generation_id=recovery["sourceRuntimeGenerationId"],
            candidate_runtime_generation_id=recovery["candidateRuntimeGenerationId"],
            source_route_set=recovery["sourceRouteSet"],
            audit_state=prefix,
            now=datetime.fromisoformat(cast(str, intent["createdAt"])),
            clock=lambda: 0,
            entropy=lambda length: bytes(length),  # noqa: PLW0108 - named EntropySource parameter
            intent_id=intent["intentId"],
        )
        if plan.intent != intent or (audit.entry is not None and audit.entry != plan.audit_entry):
            raise ArchiveRecoveryError("archive recovery documents disagree with durable evidence")
        others = snapshot_other_tenant_routes(transaction, excluded_tenant_id=tenant_id)
        source_tenant = TenantRouteInput(deepcopy(source), deepcopy(observed), deepcopy(deployment))
        expected_source = TenantRouteSnapshot(
            others.platform_namespace,
            tuple(sorted((*others.tenants, source_tenant), key=_tenant_id)),
        )
        source_id = validate_uuid7(recovery["sourceRuntimeGenerationId"])
        candidate_id = validate_uuid7(recovery["candidateRuntimeGenerationId"])
        if (
            runtime.read_generation_route_snapshot(source_id) != expected_source
            or runtime.read_generation_route_snapshot(candidate_id) != others
        ):
            raise ArchiveRecoveryError("archive generation snapshots changed tenant authority")
        with runtime.open_verified_generation(candidate_id) as candidate:
            candidate_manifest = candidate.manifest
        # Validate exact partial-state order and durable dispatch authority here.
        # Activation handles capacity failures while preserving the no-route
        # candidate once local commitment has started.
        validate_archive_transition(transaction, spool, job, plan)
        return PreparedArchiveTransition(job, plan, candidate_manifest, capacity_limits)


def _tenant_id(tenant: TenantRouteInput) -> str:
    return cast(str, cast(dict[str, object], tenant.manifest["metadata"])["id"])
