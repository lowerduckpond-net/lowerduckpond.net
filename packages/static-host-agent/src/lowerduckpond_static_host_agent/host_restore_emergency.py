"""Resume only a captured, separately authorized emergency deletion candidate."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    decode_json_object,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.emergency_commit import (
    finalize_emergency_transition,
    verify_emergency_releases,
)
from lowerduckpond_static_host_agent.emergency_delete import EmergencyDeletion
from lowerduckpond_static_host_agent.emergency_plan import plan_emergency_deletion
from lowerduckpond_static_host_agent.emergency_state import verify_emergency_state
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
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_commit import _audit_needs_append
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes


def _original(
    store: RestoreStore, transaction: _StateTransaction, intent_id: str
) -> tuple[dict[str, object], StoredContract | None]:
    try:
        raw = store.read_bytes(f"lifecycle-{intent_id}.json")
    except FileNotFoundError:
        stored = transaction.read(StateRecordPath.emergency_deletion_intent(intent_id))
        return stored.document, stored
    receipt = decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES)
    payload = exact_object(receipt["payload"], {"kind", "intent", "selection"})
    intent = payload["intent"]
    if (
        payload["kind"] != "emergency-deletion"
        or type(intent) is not dict
        or intent["intentId"] != intent_id
    ):
        raise HostRestoreError("restore_emergency_decision_changed")
    try:
        current = transaction.read(StateRecordPath.emergency_deletion_intent(intent_id))
    except FileNotFoundError:
        return intent, None
    if current.document != intent:
        raise HostRestoreError("restore_emergency_intent_changed")
    return intent, current


def _validate_plan(intent: dict[str, object]) -> None:
    validate_contract(intent, expected_kind=ContractKind.EMERGENCY_DELETION_INTENT)
    audit = cast(dict[str, object], intent["auditEntry"])
    retirement = cast(dict[str, object] | None, intent["retirementIntent"])
    expected = plan_emergency_deletion(
        cast(dict[str, object], intent["sourceManifest"]),
        cast(dict[str, object], intent["sourceObservedState"]),
        cast(list[dict[str, object]], intent["deploymentRecords"]),
        cast(dict[str, object] | None, intent["archiveRecord"]),
        operator_principal=str(intent["operatorPrincipal"]),
        reason=str(intent["reason"]),
        correlation_id=str(intent["correlationId"]),
        source_runtime_generation_id=str(intent["sourceRuntimeGenerationId"]),
        candidate_runtime_generation_id=str(intent["candidateRuntimeGenerationId"]),
        retirement_intent_id=str(
            intent["intentId"] if retirement is None else retirement["intentId"]
        ),
        audit_state=AuditState(
            cast(int, audit["sequence"]),
            0,
            0,
            cast(dict[str, str] | None, audit["previousEntryDigest"]),
        ),
        now=datetime.fromisoformat(str(intent["createdAt"])),
    )
    if expected != intent:
        raise HostRestoreError("restore_emergency_plan_changed")


def reconcile_emergency(  # noqa: PLR0913, PLR0917 - distinct administrator and archive proofs
    store: RestoreStore,
    transaction: _StateTransaction,
    spool: ExportSpool,
    releases: DeploymentReleaseStore,
    intent_id: str,
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
    archive_proof: dict[str, object],
    *,
    failure_hook: Callable[[str], None] = lambda _step: None,
) -> dict[str, object]:
    intent_id = validate_uuid7(intent_id)
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    intent, prepared = _original(store, transaction, intent_id)
    _validate_plan(intent)
    tenant = str(intent["tenantId"])
    others = EmergencyDeletion._others(transaction, tenant)
    choice = emergency_selection(transaction, intent, evidence, original_origin_pull_ca_der)
    if choice == "source":
        # The emergency contract authorizes only an administrator success and
        # tombstone. Recovery cannot invent a failed ordinary job or activate an
        # unselected deletion. Preserve the original authority and close the gate.
        raise HostRestoreError("restore_emergency_source_has_no_authorized_failure")
    retirement = cast(dict[str, object] | None, intent["retirementIntent"])
    allowed = {intent_id} | (set() if retirement is None else {str(retirement["intentId"])})
    identities = {row.intent_id for row in transaction.measure_intent_records().records}
    if not identities <= allowed:
        raise HostRestoreError("restore_emergency_unrelated_journals")
    if retirement is not None:
        require_verified_archive(
            archive_proof, cast(dict[str, object], intent["archiveRecord"]), required=False
        )
        if (
            str(retirement["intentId"]) in identities
            and transaction.read(
                StateRecordPath.archive_retirement_intent(retirement["intentId"])
            ).document
            != retirement
        ):
            raise HostRestoreError("restore_emergency_retirement_changed")
    audit = cast(dict[str, object], intent["auditEntry"])
    if prepared is not None:
        committed = not _audit_needs_append(transaction.inspect_audit(), audit)
        verify_emergency_state(transaction._repository, transaction, intent, committed=committed)
        verify_emergency_releases(releases, transaction, intent, committed=committed)
    elif (
        transaction.read(StateRecordPath.emergency_result(intent_id)).document != intent["result"]
        or transaction.inspect_audit_correlation(intent_id).entry != audit
        or tenant in transaction.measure_inventory().tenant_ids
        or tenant
        in dict(releases.published_inventory(publication_lock=transaction).tenant_releases)
        or (retirement is not None and str(retirement["intentId"]) not in identities)
    ):
        raise HostRestoreError("restore_emergency_terminal_state_changed")
    decision = commit_decision(
        store,
        f"lifecycle-{intent_id}.json",
        {"kind": "emergency-deletion", "intent": intent, "selection": choice},
    )

    def verify_routes() -> None:
        if snapshot_tenant_routes(transaction) != others:
            raise HostRestoreError("restore_emergency_changed_other_routes")

    if prepared is not None:
        finalize_emergency_transition(
            transaction._repository,
            transaction,
            spool,
            releases,
            prepared,
            limits=DEFAULT_HOST_CAPACITY_LIMITS,
            verify_absence=verify_routes,
            hook=failure_hook,
        )
    return decision


def emergency_selection(
    transaction: _StateTransaction,
    intent: dict[str, object],
    evidence: CaddyBackupEvidence,
    original_origin_pull_ca_der: tuple[bytes, ...],
) -> str:
    _validate_plan(intent)
    others = EmergencyDeletion._others(transaction, str(intent["tenantId"]))
    return require_captured_selection(
        evidence,
        {
            "source": (
                str(intent["sourceRuntimeGenerationId"]),
                _snapshot(others, EmergencyDeletion._source(intent)),
            ),
            "candidate": (str(intent["candidateRuntimeGenerationId"]), others),
        },
        original_origin_pull_ca_der,
    )
