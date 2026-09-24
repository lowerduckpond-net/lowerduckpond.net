"""Reconcile ordinary deletion while preserving permanent tombstone authority."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.delete_commit import (
    finalize_delete_transition,
    validate_delete_transition,
)
from lowerduckpond_static_host_agent.delete_plan import DeleteTransitionPlan, plan_delete_transition
from lowerduckpond_static_host_agent.execution import _expected_source_error
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_archives import require_verified_archive
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore
from lowerduckpond_static_host_agent.host_restore_lifecycle_pair import original_pair
from lowerduckpond_static_host_agent.host_restore_routes import _restore_source, _snapshot
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    snapshot_other_tenant_routes,
    snapshot_tenant_routes,
)


def _plan(
    transaction: _StateTransaction,
    intent: dict[str, object],
    job: StoredContract,
    retirement: StoredContract | None,
) -> DeleteTransitionPlan:
    recorded = cast(dict[str, object], intent["lifecycleRecovery"])
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
        raise HostRestoreError("restore_delete_dispatch_changed")
    plan = plan_delete_transition(
        claimed,
        transaction.read(StateRecordPath.platform_namespace()).document,
        cast(dict[str, object], intent["sourceManifest"]),
        cast(dict[str, object], recorded["sourceObservedState"]),
        None if retirement is None else retirement.document,
        source_runtime_generation_id=recorded["sourceRuntimeGenerationId"],
        candidate_runtime_generation_id=recorded["candidateRuntimeGenerationId"],
        audit_state=prefix,
        now=datetime.fromisoformat(cast(str, intent["createdAt"])),
        clock=lambda: 0,
        entropy=lambda length: bytes(length),  # noqa: PLW0108
        intent_id=intent["intentId"],
    )
    if plan.intent != intent:
        raise HostRestoreError("restore_delete_plan_changed")
    return plan


def _source_history(
    transaction: _StateTransaction,
    releases: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeleteTransitionPlan,
) -> None:
    if _expected_source_error(transaction, job.document) is not None:
        raise HostRestoreError("restore_delete_source_unavailable")
    history = transaction.tenant_deployment_ids(plan.tenant_id)
    if list(history) != job.document.get("dispatchDeploymentIds") or list(
        transaction.tenant_archive_ids(plan.tenant_id)
    ) != job.document.get("dispatchArchiveDeploymentIds"):
        raise HostRestoreError("restore_delete_source_history_changed")
    for identity in history:
        record = transaction.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, identity)
        ).document
        if (
            releases.measure(
                plan.tenant_id, identity, publication_lock=transaction
            ).digest.to_dict()
            != record["releaseTreeDigest"]
        ):
            raise HostRestoreError("restore_delete_source_release_changed")
    published = dict(releases.published_inventory(publication_lock=transaction).tenant_releases)
    if published.get(plan.tenant_id, ()) != history:
        raise HostRestoreError("restore_delete_source_releases_changed")


def _finished(
    transaction: _StateTransaction,
    releases: DeploymentReleaseStore,
    job: StoredContract,
    plan: DeleteTransitionPlan,
) -> None:
    current = transaction.read(StateRecordPath.authorization_job(job.document["jobId"])).document
    if (
        current["phase"] != "completed"
        or transaction.read(StateRecordPath.authorization_result(current["jobId"])).document
        != plan.result
        or transaction.inspect_audit_correlation(plan.intent["correlationId"]).entry
        != plan.audit_entry
        or plan.tenant_id in transaction.measure_inventory().tenant_ids
        or plan.tenant_id
        in dict(releases.published_inventory(publication_lock=transaction).tenant_releases)
    ):
        raise HostRestoreError("restore_delete_tombstone_incomplete")


def reconcile_delete(  # noqa: PLR0913, PLR0917 - complete captured authority and separate archive proof
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
    intent_id = validate_uuid7(intent_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    intent, job, retirement, resuming = original_pair(
        store, transaction, intent_id, family="delete"
    )
    plan = _plan(transaction, intent, job, retirement)
    choice = delete_selection(transaction, plan, evidence, original_origin_pull_ca_der)
    if retirement is not None:
        require_verified_archive(
            archive_proof,
            cast(dict[str, object], retirement.document["archiveRecord"]),
            required=choice == "source",
        )
    local_present = any(
        row.intent_id == intent_id for row in transaction.measure_intent_records().records
    )
    if (not resuming or choice == "candidate") and local_present:
        validate_delete_transition(transaction, spool, job, plan, retirement, admit=False)
    if choice == "source":
        _source_history(transaction, releases, job, plan)
    elif not local_present:
        _finished(transaction, releases, job, plan)
    decision = commit_decision(
        store,
        f"lifecycle-{intent_id}.json",
        {
            "kind": "delete-lifecycle",
            "intent": intent,
            "job": job.document,
            "retirement": None if retirement is None else retirement.document,
            "selection": choice,
        },
    )
    if choice == "candidate" and local_present:
        finalize_delete_transition(
            transaction._repository,
            transaction,
            spool,
            releases,
            job,
            plan,
            retirement,
            failure_hook=failure_hook,
        )
    elif choice == "source":
        _restore_source(transaction, job, plan, companion=retirement)
    return decision


def delete_selection(
    transaction: _StateTransaction,
    plan: DeleteTransitionPlan,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
) -> str:
    recorded = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    source = cast(dict[str, object], plan.intent["sourceManifest"])
    others = (
        snapshot_other_tenant_routes(transaction, excluded_tenant_id=plan.tenant_id)
        if plan.tenant_id in transaction.measure_inventory().tenant_ids
        else snapshot_tenant_routes(transaction)
    )
    return require_captured_selection(
        evidence,
        {
            "source": (
                validate_uuid7(recorded["sourceRuntimeGenerationId"]),
                _snapshot(
                    others,
                    TenantRouteInput(
                        source, cast(dict[str, object], recorded["sourceObservedState"]), None
                    ),
                ),
            ),
            "candidate": (validate_uuid7(recorded["candidateRuntimeGenerationId"]), others),
        },
        original_origin_pull_ca_der,
    )
