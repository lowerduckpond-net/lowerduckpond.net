"""Recover tenant archive restoration from its captured source or candidate."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.execution import _validate_result_audit
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_archives import require_verified_archive
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_deployments import (
    _discard_candidate,
    _source_history,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_lifecycle_pair import original_pair
from lowerduckpond_static_host_agent.host_restore_routes import _restore_source, _snapshot
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.lifecycle_plan import DeploymentTransitionPlan
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.restore_commit import (
    finalize_restore_transition,
    validate_restore_transition,
)
from lowerduckpond_static_host_agent.restore_plan import plan_restore_transition
from lowerduckpond_static_host_agent.route_snapshot import snapshot_other_tenant_routes


def _plan(
    transaction: _StateTransaction,
    intent: dict[str, object],
    job: StoredContract,
    retirement: StoredContract,
) -> DeploymentTransitionPlan:
    recorded = cast(dict[str, object], intent["lifecycleRecovery"])
    candidate = cast(dict[str, object], intent["candidateManifest"])
    selected = cast(
        dict[str, object], cast(dict[str, object], candidate["spec"])["desiredDeployment"]
    )
    archive = cast(dict[str, object], retirement.document["archiveRecord"])
    audit = transaction.inspect_audit_correlation(intent["correlationId"])
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
    claimed = deepcopy(job.document)
    claimed["phase"] = "claimed"
    if any(
        claimed.get("dispatch" + field[0].upper() + field[1:]) != recorded[field]
        for field in ("sourceObservedState", "sourceRuntimeGenerationId", "sourceRouteSet")
    ):
        raise HostRestoreError("restore_tenant_dispatch_changed")
    plan = plan_restore_transition(
        claimed,
        transaction.read(StateRecordPath.platform_namespace()).document,
        cast(dict[str, object], intent["sourceManifest"]),
        cast(dict[str, object], recorded["sourceObservedState"]),
        transaction.read(
            StateRecordPath.tenant_deployment(intent["tenantId"], archive["deploymentId"])
        ).document,
        retirement.document,
        source_runtime_generation_id=recorded["sourceRuntimeGenerationId"],
        candidate_runtime_generation_id=recorded["candidateRuntimeGenerationId"],
        audit_state=prefix,
        now=datetime.fromisoformat(cast(str, intent["createdAt"])),
        clock=lambda: 0,
        entropy=lambda length: bytes(length),  # noqa: PLW0108
        deployment_id=selected["id"],
        intent_id=intent["intentId"],
    )
    if plan.intent != intent:
        raise HostRestoreError("restore_tenant_plan_changed")
    return plan


def _finished(
    transaction: _StateTransaction, job: StoredContract, plan: DeploymentTransitionPlan
) -> None:
    current = transaction.read(StateRecordPath.authorization_job(job.document["jobId"])).document
    if (
        current["phase"] != "completed"
        or transaction.read(StateRecordPath.authorization_result(current["jobId"])).document
        != plan.result
    ):
        raise HostRestoreError("restore_tenant_incomplete_result")
    _validate_result_audit(transaction, current, plan.result)
    if (
        transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document != plan.manifest
        or transaction.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
        != plan.observed_state
        or transaction.tenant_archive_ids(plan.tenant_id)
    ):
        raise HostRestoreError("restore_tenant_terminal_state_changed")
    expected = (*cast(list[str], current["dispatchDeploymentIds"]), str(plan.deployment["id"]))[-3:]
    if (
        transaction.tenant_deployment_ids(plan.tenant_id) != expected
        or transaction.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"])
        ).document
        != plan.deployment
    ):
        raise HostRestoreError("restore_tenant_terminal_history_changed")


def reconcile_tenant_restore(  # noqa: PLR0913, PLR0917 - complete trusted selection and version proof
    store: RestoreStore,
    transaction: _StateTransaction,
    spool: ExportSpool,
    releases: DeploymentReleaseStore,
    intent_id: str,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
    archive_proof: dict[str, object],
    *,
    failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Preserve retirement until the credential helper verifies its terminal choice."""
    intent_id = validate_uuid7(intent_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    intent, job, retirement, resuming = original_pair(
        store, transaction, intent_id, family="tenant-restore"
    )
    if retirement is None:
        raise HostRestoreError("restore_tenant_retirement_unavailable")
    plan = _plan(transaction, intent, job, retirement)
    choice = restore_selection(transaction, plan, evidence, original_origin_pull_ca_der)
    archive = cast(dict[str, object], retirement.document["archiveRecord"])
    require_verified_archive(archive_proof, archive, required=choice == "source")
    local_present = any(
        row.intent_id == intent_id for row in transaction.measure_intent_records().records
    )
    if (not resuming or choice == "candidate") and local_present:
        validate_restore_transition(transaction, spool, job, plan, retirement, admit=False)
    if choice == "source":
        if (
            transaction.read(
                StateRecordPath.tenant_archive(plan.tenant_id, archive["deploymentId"])
            ).document
            != archive
        ):
            raise HostRestoreError("restore_tenant_source_archive_changed")
        _source_history(transaction, releases, job, plan)
    else:
        measured = releases.measure(
            plan.tenant_id, plan.deployment["id"], publication_lock=transaction
        )
        if measured.digest.to_dict() != plan.deployment["releaseTreeDigest"]:
            raise HostRestoreError("restore_tenant_candidate_release_changed")
        if not local_present:
            _finished(transaction, job, plan)
    decision = commit_decision(
        store,
        f"lifecycle-{intent_id}.json",
        {
            "kind": "tenant-restore-lifecycle",
            "intent": intent,
            "job": job.document,
            "retirement": retirement.document,
            "selection": choice,
        },
    )
    if choice == "candidate" and local_present:
        finalize_restore_transition(
            transaction, spool, releases, job, plan, retirement, failure_hook=failure_hook
        )
    elif choice == "source":
        _restore_source(
            transaction,
            job,
            plan,
            cleanup=lambda: _discard_candidate(transaction, releases, plan),
            companion=retirement,
        )
    return decision


def restore_selection(
    transaction: _StateTransaction,
    plan: DeploymentTransitionPlan,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
) -> str:
    recorded = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    others = snapshot_other_tenant_routes(transaction, excluded_tenant_id=plan.tenant_id)
    return require_captured_selection(
        evidence,
        {
            "source": (validate_uuid7(recorded["sourceRuntimeGenerationId"]), others),
            "candidate": (
                validate_uuid7(recorded["candidateRuntimeGenerationId"]),
                _snapshot(
                    others, TenantRouteInput(plan.manifest, plan.observed_state, plan.deployment)
                ),
            ),
        },
        original_origin_pull_ca_der,
    )
