"""Explicit missing-input failures preserve the ordinary result-first audit protocol."""

from __future__ import annotations

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.execution import (
    ExecutionTransaction,
    _expected_source_error,
    _failure_result,
    _has_bound_lifecycle_intent,
    _publish_result,
    _repair_executor_failure_audit,
    _set_terminal_phase,
    _validate_request_integrity,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.repository import StateRecordPath


def finish_missing_input(
    transaction: ExecutionTransaction, job_id: str
) -> dict[str, object] | None:
    """Called only on a verified private restore while intake/export are excluded.

    Existing successful or unrelated terminal results remain immutable. Durable
    lifecycle intents own their consumed artifacts and must be reconciled first.
    A lost result/audit reply resumes the same executor failure publication.
    """
    job_id = validate_uuid7(job_id)
    job = transaction.read(StateRecordPath.authorization_job(job_id))
    document = job.document
    _validate_request_integrity(document)
    request = document["request"]
    if type(request) is not dict or request["operation"] not in {"deploy", "import"}:
        return None
    if _has_bound_lifecycle_intent(transaction, document):
        return None
    try:
        existing = transaction.read(StateRecordPath.authorization_result(job_id)).document
    except FileNotFoundError:
        existing = None
    if existing is not None:
        _validate_result_binding(document, existing)
        if existing.get("errorCode") != "restore_input_unavailable":
            return None
        _repair_executor_failure_audit(
            transaction, document, existing, limits=DEFAULT_HOST_CAPACITY_LIMITS
        )
        _set_terminal_phase(
            transaction,
            job,
            existing,
            execution_validated=True,
            capacity_limits=DEFAULT_HOST_CAPACITY_LIMITS,
        )
        return existing
    if document["phase"] not in {"pending", "claimed"} or document["artifact"] is None:
        raise HostRestoreError("restore_pending_input_authority_incomplete")
    error = _expected_source_error(transaction, document)
    if error is not None:
        # The pre-existing stale request has its ordinary authorized failure;
        # missing intake is not permission to restore its superseded source.
        result = _failure_result(document, error)
    else:
        result = _failure_result(document, "restore_input_unavailable")
    _publish_result(transaction, job, result, limits=DEFAULT_HOST_CAPACITY_LIMITS)
    return result
