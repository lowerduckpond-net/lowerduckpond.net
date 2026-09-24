"""Retire excluded deliveries without rewriting immutable export results."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from lowerduckpond_static_contracts import (
    ContractKind,
    audit_entry_digest,
    canonical_json_bytes,
    decode_json_object,
    result_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreStore,
    exact_object,
)

if TYPE_CHECKING:
    from lowerduckpond_static_host_agent.execution import ExecutionTransaction
    from lowerduckpond_static_host_agent.repository import _StateTransaction


def export_decision_name(job_id: object) -> str:
    return f"export-retirement-{validate_uuid7(job_id)}.json"


def _completed_job(job: dict[str, object]) -> dict[str, object]:
    # These two fields are the ordinary executor's only permitted terminal
    # advancement after a durable result/audit pair. Request and source bindings
    # remain exact, including acceptedAt; recovery cannot extend delivery life.
    completed = {**job, "phase": "completed"}
    if job.get("compatibilityVersion") == "static-job-v2":
        completed["executionValidated"] = True
    return completed


def _authority(
    transaction: ExecutionTransaction, job: dict[str, object], result: dict[str, object]
) -> dict[str, object]:
    # Local imports avoid the repository/executor dependency cycle. The same
    # operation-specific request, result and audit rules govern normal replay.
    from lowerduckpond_static_host_agent.execution import (  # noqa: PLC0415
        _validate_request_integrity,
        _validate_result_audit,
        _validate_result_binding,
    )

    validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    _validate_request_integrity(job)
    _validate_result_binding(job, result)
    if (
        result["operation"] != "export"
        or result["status"] != "succeeded"
        or job["phase"] not in {"claimed", "completed"}
        or job.get("exportDelivery") in {"expired", "acknowledged"}
    ):
        raise HostRestoreError("restore_export_not_committed")
    _validate_result_audit(transaction, job, result)
    audit = transaction.inspect_audit_correlation(result["correlationId"]).entry
    if audit is None:
        raise HostRestoreError("restore_export_missing_audit")
    return {
        "kind": "export-retirement",
        "job": _completed_job(job),
        "resultDigest": result_digest(result).to_dict(),
        "auditDigest": audit_entry_digest(audit).to_dict(),
    }


def retire_restored_export(
    store: RestoreStore,
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
) -> dict[str, object]:
    """Caller has validated the capture and proved its excluded delivery absent.

    This creates administrator provenance only. The ordinary executor still
    validates source, manifest, observed runtime and history before terminal
    completion; this decision exempts only the already excluded delivery bytes.
    """
    return commit_decision(
        store, export_decision_name(job["jobId"]), _authority(transaction, job, result)
    )


def require_export_retirement(
    payload: dict[str, object],
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
) -> None:
    exact_object(payload, {"kind", "job", "resultDigest", "auditDigest"})
    if canonical_json_bytes(payload) != canonical_json_bytes(_authority(transaction, job, result)):
        raise HostRestoreError("restore_export_retirement_changed")


def finish_export_intent(transaction: _StateTransaction, job_id: str) -> None:
    """Complete only an existing export's result/audit pair on private authority.

    Receipt validation exempts missing delivery bytes, while the ordinary
    executor independently proves source state and retained history. Runtime
    validation remains outstanding until the reconstructed generation starts.
    """
    from lowerduckpond_static_host_agent.execution import (  # noqa: PLC0415
        _capture_authorized_lifecycle_authority,
        _repair_terminal_phase_transaction,
        _validate_handler_result_state,
        _validate_result_audit,
        _validate_result_intent_binding,
    )
    from lowerduckpond_static_host_agent.export_handler import (  # noqa: PLC0415
        _find_intent,
        _read_job,
    )
    from lowerduckpond_static_host_agent.repository import StateRecordPath  # noqa: PLC0415

    job = _read_job(transaction, validate_uuid7(job_id))
    intent = _find_intent(transaction, job)
    if intent is None:
        return
    result = transaction.read(StateRecordPath.authorization_result(job_id))
    if not transaction.restored_export_retired(job.document, result.document):
        raise HostRestoreError("restore_export_intent_has_no_retirement")
    request = job.document["request"]
    if type(request) is not dict:
        raise HostRestoreError("restore_export_request_invalid")
    _validate_result_intent_binding(result.document, request, [intent.record.document])
    latest = _validate_result_audit(transaction, job.document, result.document)
    if not latest:
        raise HostRestoreError("restore_export_intent_superseded")
    authority = _capture_authorized_lifecycle_authority(transaction, job.document)
    _validate_handler_result_state(
        transaction,
        job.document,
        result.document,
        authority=authority,
        audit_is_latest_for_tenant=latest,
    )
    _repair_terminal_phase_transaction(transaction, job, result)
    transaction.remove_reconciled_intent(intent.path, intent.token)


def abandon_uncommitted_export(
    store: RestoreStore,
    transaction: _StateTransaction,
    job_id: str,
    intent_id: str,
    *,
    failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Discard only a read-only intent, allowing ordinary export recapture later.

    Excluded delivery bytes cannot establish an audit-only success. Neither a
    terminal result nor an audit may exist here; committed exports require the
    separate immutable-result retirement path. The restore's complete original
    authority proof and export EX lease precede this private reconciliation.
    """
    from lowerduckpond_static_host_agent.execution import (  # noqa: PLC0415
        _validate_request_integrity,
    )
    from lowerduckpond_static_host_agent.export_handler import (  # noqa: PLC0415
        _find_intent,
        _read_job,
    )
    from lowerduckpond_static_host_agent.issuance import build_expected_source  # noqa: PLC0415
    from lowerduckpond_static_host_agent.repository import StateRecordPath  # noqa: PLC0415

    job = _read_job(transaction, validate_uuid7(job_id))
    _validate_request_integrity(job.document)
    request = job.document["request"]
    if (
        type(request) is not dict
        or job.document["phase"] != "claimed"
        or build_expected_source(transaction, request) != job.document["expectedSource"]
        or transaction.inspect_audit_correlation(request["correlationId"]).entry is not None
    ):
        raise HostRestoreError("restore_export_uncommitted_source_changed")
    try:
        transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        pass
    else:
        raise HostRestoreError("restore_export_already_has_result")
    intent_id = validate_uuid7(intent_id)
    name = f"lifecycle-{intent_id}.json"
    intent = _find_intent(transaction, job)
    if intent is not None:
        if intent.record.document["intentId"] != intent_id:
            raise HostRestoreError("restore_export_intent_changed")
        original = intent.record.document
    else:
        saved = decode_json_object(store.read_bytes(name))
        payload = exact_object(saved["payload"], {"kind", "job", "intent"})
        saved_intent = payload["intent"]
        if type(saved_intent) is not dict or saved_intent.get("intentId") != intent_id:
            raise HostRestoreError("restore_export_intent_changed")
        original = saved_intent
    decision = commit_decision(
        store,
        name,
        {"kind": "uncommitted-export", "job": job.document, "intent": original},
    )
    if failure_hook is not None:
        failure_hook("decision")
    if intent is not None:
        transaction.remove_reconciled_intent(intent.path, intent.token)
    if failure_hook is not None:
        failure_hook("removed")
    return decision
