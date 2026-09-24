"""Preserve the original authorization and paired retirement across local recovery."""

from __future__ import annotations

from lowerduckpond_static_contracts import ContractKind, decode_json_object

from lowerduckpond_static_host_agent.execution import (
    _require_same_authority,
    _validate_request_integrity,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StoredContract,
    _StateTransaction,
)


def original_pair(
    store: RestoreStore, transaction: _StateTransaction, intent_id: str, *, family: str
) -> tuple[dict[str, object], StoredContract, StoredContract | None, bool]:
    records = [
        transaction.read_intent(row.intent_id)[1]
        for row in transaction.measure_intent_records().records
    ]
    retirement_records = [
        row
        for row in records
        if row.revision.contract_kind is ContractKind.ARCHIVE_RETIREMENT_INTENT
    ]
    if len(retirement_records) > 1:
        raise HostRestoreError("restore_tenant_retirement_unavailable")
    retirement = next(iter(retirement_records), None)
    allowed = {intent_id} | (
        set() if retirement is None else {str(retirement.document["intentId"])}
    )
    if any(str(row.document["intentId"]) not in allowed for row in records):
        raise HostRestoreError("restore_tenant_journals_changed")
    try:
        raw = store.read_bytes(f"lifecycle-{intent_id}.json")
    except FileNotFoundError:
        intent = transaction.read(StateRecordPath.transaction_intent(intent_id)).document
        correlation = transaction.read(
            StateRecordPath.authorization_correlation(intent["correlationId"])
        ).document
        job = transaction.read(StateRecordPath.authorization_job(correlation["jobId"]))
        _require_same_authority(job.document, correlation)
        _validate_request_integrity(job.document)
        return intent, job, retirement, False
    receipt = decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES)
    payload = exact_object(receipt["payload"], {"kind", "intent", "job", "retirement", "selection"})
    saved, expected = payload["intent"], payload["job"]
    if (
        payload["kind"] != family + "-lifecycle"
        or type(saved) is not dict
        or type(expected) is not dict
        or saved["intentId"] != intent_id
        or payload["retirement"] != (None if retirement is None else retirement.document)
    ):
        raise HostRestoreError("restore_tenant_decision_changed")
    current = transaction.read(StateRecordPath.authorization_job(expected["jobId"]))
    comparable = {
        **current.document,
        "phase": expected["phase"],
        "executionValidated": expected["executionValidated"],
    }
    if comparable != expected:
        raise HostRestoreError("restore_tenant_job_changed")
    for row in records:
        if row.document["intentId"] == intent_id and row.document != saved:
            raise HostRestoreError("restore_tenant_intent_changed")
    return saved, StoredContract(expected, current.revision), retirement, True
