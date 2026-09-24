"""Reconcile archive activation without uploading or retiring remote bytes."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import ContractKind, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.archive_abort import finalize_failed_construction
from lowerduckpond_static_host_agent.archive_commit import (
    _validate_plan,
    finalize_archive_transition,
    validate_archive_transition,
)
from lowerduckpond_static_host_agent.archive_journal import failed_construction_result
from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.execution import (
    _require_same_authority,
    _validate_request_integrity,
    _validate_result_audit,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_archives import require_verified_archive
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.host_restore_routes import _snapshot
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.lifecycle_plan import (
    ArchiveTransitionPlan,
    plan_archive_transition,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import snapshot_other_tenant_routes


def _original(
    store: RestoreStore, transaction: _StateTransaction, intent_id: str
) -> tuple[dict[str, object], StoredContract, bool]:
    try:
        raw = store.read_bytes(f"lifecycle-{intent_id}.json")
    except FileNotFoundError:
        path, stored = transaction.read_intent(intent_id)
        intent = stored.document
        if (
            path != StateRecordPath.transaction_intent(intent_id)
            or intent["operation"] != "archive"
        ):
            raise HostRestoreError("restore_archive_intent_invalid") from None
        correlation = transaction.read(
            StateRecordPath.authorization_correlation(intent["correlationId"])
        ).document
        job = transaction.read(StateRecordPath.authorization_job(correlation["jobId"]))
        _validate_request_integrity(job.document)
        _require_same_authority(job.document, correlation)
        return intent, job, False
    receipt = decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES)
    payload = exact_object(receipt["payload"], {"kind", "intent", "job", "selection"})
    if payload["kind"] != "archive-lifecycle":
        raise HostRestoreError("restore_archive_decision_changed")
    saved, expected = payload["intent"], payload["job"]
    if type(saved) is not dict or type(expected) is not dict or saved["intentId"] != intent_id:
        raise HostRestoreError("restore_archive_decision_changed")
    job = transaction.read(StateRecordPath.authorization_job(expected["jobId"]))
    comparable = {**job.document, "phase": expected["phase"]}
    if comparable != expected:
        raise HostRestoreError("restore_archive_job_changed")
    return saved, StoredContract(expected, job.revision), True


def _plan(
    transaction: _StateTransaction, intent: dict[str, object], job: StoredContract
) -> ArchiveTransitionPlan:
    recorded = cast(dict[str, object], intent["archiveRecovery"])
    archive = cast(dict[str, object], recorded["candidateArchiveRecord"])
    constructions = [
        stored.document
        for row in transaction.measure_intent_records().records
        for path, stored in (transaction.read_intent(row.intent_id),)
        if path.contract_kind is ContractKind.ARCHIVE_CONSTRUCTION_INTENT
    ]
    if len(constructions) != 1:
        raise HostRestoreError("restore_archive_construction_changed")
    construction = constructions[0]
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
    plan = plan_archive_transition(
        claimed,
        transaction.read(StateRecordPath.platform_namespace()).document,
        cast(dict[str, object], intent["sourceManifest"]),
        cast(dict[str, object], recorded["sourceObservedState"]),
        transaction.read(
            StateRecordPath.tenant_deployment(intent["tenantId"], archive["deploymentId"])
        ).document,
        construction,
        archive,
        source_runtime_generation_id=recorded["sourceRuntimeGenerationId"],
        candidate_runtime_generation_id=recorded["candidateRuntimeGenerationId"],
        source_route_set=recorded["sourceRouteSet"],
        audit_state=prefix,
        now=datetime.fromisoformat(cast(str, intent["createdAt"])),
        clock=lambda: 0,
        entropy=lambda length: bytes(length),  # noqa: PLW0108
        intent_id=intent["intentId"],
    )
    if plan.intent != intent:
        raise HostRestoreError("restore_archive_plan_changed")
    _validate_plan(transaction, job, plan)
    return plan


def _source(  # noqa: PLR0912 - exact partial source and terminal evidence
    transaction: _StateTransaction,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
    notify: Callable[[str], None],
) -> None:
    recorded = cast(dict[str, object], plan.intent["archiveRecovery"])
    construction = transaction.read(
        StateRecordPath.archive_construction_intent(plan.construction_intent_id)
    ).document
    try:
        result = transaction.read(StateRecordPath.authorization_result(job.document["jobId"]))
    except FileNotFoundError:
        result = None
    audit = transaction.inspect_audit_correlation(plan.intent["correlationId"])
    if (
        result is not None
        and result.document != failed_construction_result(job.document, construction)
    ) or (audit.entry is not None and audit.entry["resultStatus"] != "failed"):
        raise HostRestoreError("restore_archive_source_has_committed_success")
    if audit.entry is not None:
        _validate_result_audit(
            transaction, job.document, failed_construction_result(job.document, construction)
        )
        if audit.entry["timestamp"] != construction["createdAt"]:
            raise HostRestoreError("restore_archive_failure_time_changed")
    paths = (
        (
            StateRecordPath.tenant_observed(plan.tenant_id),
            recorded["sourceObservedState"],
            plan.observed_state,
        ),
        (
            StateRecordPath.tenant_desired(plan.tenant_id),
            plan.intent["sourceManifest"],
            plan.manifest,
        ),
    )
    for path, source, candidate in paths:
        if transaction.read(path).document not in (source, candidate):
            raise HostRestoreError("restore_archive_source_changed")
    archive_path = StateRecordPath.tenant_archive(
        plan.tenant_id, plan.archive_record["deploymentId"]
    )
    try:
        archive = transaction.read(archive_path)
    except FileNotFoundError:
        archive = None
    if archive is not None and archive.document != plan.archive_record:
        raise HostRestoreError("restore_archive_record_changed")
    if transaction.tenant_archive_ids(plan.tenant_id) != (
        () if archive is None else (str(plan.archive_record["deploymentId"]),)
    ):
        raise HostRestoreError("restore_archive_history_changed")
    identities = {row.intent_id: row for row in transaction.measure_intent_records().records}
    if set(identities) not in (
        {plan.construction_intent_id},
        {plan.intent_id, plan.construction_intent_id},
    ):
        raise HostRestoreError("restore_archive_journals_changed")
    if (
        plan.intent_id in identities
        and transaction.read_intent(plan.intent_id)[1].document != plan.intent
    ):
        raise HostRestoreError("restore_archive_intent_changed")
    for path, source, _candidate in paths:
        current = transaction.read(path)
        if current.document != source:
            transaction.compare_and_swap(path, current.revision, cast(dict[str, object], source))
        notify(path.components[-1])
    if archive is not None:
        transaction._repository._durable.remove(archive_path.components)
    notify("archive-unbound")
    if plan.intent_id in identities:
        path, stored = transaction.read_intent(plan.intent_id)
        transaction.remove_reconciled_intent(
            path,
            IntentRemovalToken(stored.revision, identities[plan.intent_id].metadata_generation),
        )
    notify("intent-removed")


def reconcile_archive(  # noqa: PLR0913, PLR0917 - independent authority and credential proof
    store: RestoreStore,
    repository: StateRepository,
    spool: ExportSpool,
    releases: DeploymentReleaseStore,
    intent_id: str,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
    archive_proof: dict[str, object],
    *,
    failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Keep the construction journal for independently verified remote finalization."""
    intent_id = validate_uuid7(intent_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)

    def notify(step: str) -> None:
        if failure_hook is not None:
            failure_hook(step)

    with repository.publication_transaction() as transaction:
        intent, job, resuming = _original(store, transaction, intent_id)
        plan = _plan(transaction, intent, job)
        choice = archive_selection(transaction, plan, evidence, original_origin_pull_ca_der)
        require_verified_archive(archive_proof, plan.archive_record, required=choice == "candidate")
        if not resuming or choice == "candidate":
            validate_archive_transition(transaction, spool, job, plan)
        # Both decisions preserve every original release. Validate before the
        # first local mutation, including when source rollback is being resumed.
        history = transaction.tenant_deployment_ids(plan.tenant_id)
        if list(history) != job.document.get("dispatchDeploymentIds"):
            raise HostRestoreError("restore_archive_history_changed")
        for identity in history:
            deployment = transaction.read(
                StateRecordPath.tenant_deployment(plan.tenant_id, identity)
            ).document
            if (
                releases.measure(
                    plan.tenant_id, identity, publication_lock=transaction
                ).digest.to_dict()
                != deployment["releaseTreeDigest"]
            ):
                raise HostRestoreError("restore_archive_release_changed")
        published = dict(releases.published_inventory(publication_lock=transaction).tenant_releases)
        if published.get(plan.tenant_id) != history:
            raise HostRestoreError("restore_archive_release_history_changed")
        decision = commit_decision(
            store,
            f"lifecycle-{intent_id}.json",
            {
                "kind": "archive-lifecycle",
                "intent": intent,
                "job": job.document,
                "selection": choice,
            },
        )
        if choice == "candidate":
            finalize_archive_transition(
                transaction, spool, releases, job, plan, failure_hook=notify
            )
        else:
            _source(transaction, job, plan, notify)
    if choice == "source":
        finalize_failed_construction(
            repository, spool, str(job.document["jobId"]), failure_hook=notify
        )
    return decision


def archive_selection(
    transaction: _StateTransaction,
    plan: ArchiveTransitionPlan,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
) -> str:
    recorded = cast(dict[str, object], plan.intent["archiveRecovery"])
    others = snapshot_other_tenant_routes(transaction, excluded_tenant_id=plan.tenant_id)
    source = TenantRouteInput(
        cast(dict[str, object], plan.intent["sourceManifest"]),
        cast(dict[str, object], recorded["sourceObservedState"]),
        transaction.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, plan.archive_record["deploymentId"])
        ).document,
    )
    return require_captured_selection(
        evidence,
        {
            "source": (
                validate_uuid7(recorded["sourceRuntimeGenerationId"]),
                _snapshot(others, source),
            ),
            "candidate": (validate_uuid7(recorded["candidateRuntimeGenerationId"]), others),
        },
        original_origin_pull_ca_der,
    )
