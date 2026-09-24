"""Cancel an unstarted retirement without consuming its required archive version."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from lowerduckpond_static_contracts import decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.archive_journal import ArchiveRetirementJournal
from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.execution import (
    _failure_result,
    _publish_result,
    _repair_executor_failure_audit,
    _set_terminal_phase,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.host_restore_archive_authority import unstarted_retirement
from lowerduckpond_static_host_agent.host_restore_archives import require_verified_archive
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.repository import StateRecordPath


def reconcile_unstarted_retirement(  # noqa: PLR0912, PLR0915 - exact decision/removal/result retry cases
    store: RestoreStore,
    retirement: ArchiveRetirementJournal,
    intent_id: str,
    archive_proof: dict[str, object],
    *,
    failure_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Use ordinary cancellation then the executor's result-first failure protocol.

    The immutable decision precedes cancellation so a crash in the interval
    before result publication cannot redispatch the old captured authorization.
    Remote bytes remain required and this function has no storage credentials.
    """
    intent_id = validate_uuid7(intent_id)
    retirement._require_lock()
    name = f"lifecycle-{intent_id}.json"
    with retirement.repository.publication_transaction() as transaction:
        try:
            saved = decode_json_object(store.read_bytes(name))
        except FileNotFoundError:
            identities = transaction.measure_intent_records().records
            if len(identities) != 1 or identities[0].intent_id != intent_id:
                raise HostRestoreError("restore_retirement_preparation_missing") from None
            _, current = transaction.read_intent(intent_id)
            document = current.document
            unstarted_retirement(transaction, document, bucket=retirement.bucket)
            provenance = cast(dict[str, object], document["provenance"])
            original = transaction.read(
                StateRecordPath.authorization_job(provenance["jobId"])
            ).document
            payload: dict[str, object] = {
                "kind": "unstarted-retirement",
                "intent": document,
                "job": original,
            }
        else:
            payload = exact_object(saved["payload"], {"kind", "intent", "job"})
            if payload["kind"] != "unstarted-retirement":
                raise HostRestoreError("restore_retirement_decision_changed")
            document = cast(dict[str, object], payload["intent"])
            original = cast(dict[str, object], payload["job"])
        job_id = validate_uuid7(original["jobId"])
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        comparable = {**job.document, "phase": original["phase"]}
        if "executionValidated" in original:
            comparable["executionValidated"] = original["executionValidated"]
        request = cast(dict[str, object], original["request"])
        if (
            document["intentId"] != intent_id
            or comparable != original
            or build_expected_source(transaction, request) != original["expectedSource"]
        ):
            raise HostRestoreError("restore_retirement_preparation_source_changed")
        require_verified_archive(
            archive_proof, cast(dict[str, object], document["archiveRecord"]), required=True
        )
        identities = transaction.measure_intent_records().records
        current_retirement = None
        if identities:
            if len(identities) != 1 or identities[0].intent_id != intent_id:
                raise HostRestoreError("restore_retirement_preparation_changed")
            _, current_retirement = transaction.read_intent(intent_id)
            if current_retirement.document != document:
                raise HostRestoreError("restore_retirement_preparation_changed")
            unstarted_retirement(transaction, document, bucket=retirement.bucket)
        decision = commit_decision(store, name, payload)
    if failure_hook is not None:
        failure_hook("decision")
    if current_retirement is not None and not retirement.cancel_unstarted_retirement(
        job_id, current_retirement
    ):
        raise HostRestoreError("restore_retirement_preparation_not_cancelled")
    if failure_hook is not None:
        failure_hook("removed")
    with retirement.repository.publication_transaction() as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        try:
            result = transaction.read(StateRecordPath.authorization_result(job_id)).document
        except FileNotFoundError:
            if transaction.inspect_audit_correlation(request["correlationId"]).entry is not None:
                raise HostRestoreError("restore_retirement_preparation_audit_conflicts") from None
            _publish_result(
                transaction,
                job,
                _failure_result(job.document, "unavailable"),
                limits=DEFAULT_HOST_CAPACITY_LIMITS,
            )
        else:
            _validate_result_binding(job.document, result)
            unpositioned = {
                key: value
                for key, value in result.items()
                if key not in {"failureAuditSequence", "failureAuditPredecessorDigest"}
            }
            if unpositioned != _failure_result(job.document, "unavailable"):
                raise HostRestoreError("restore_retirement_preparation_result_conflicts")
            _repair_executor_failure_audit(
                transaction, job.document, result, limits=DEFAULT_HOST_CAPACITY_LIMITS
            )
            _set_terminal_phase(transaction, job, result, execution_validated=True)
    if failure_hook is not None:
        failure_hook("result")
    return decision
