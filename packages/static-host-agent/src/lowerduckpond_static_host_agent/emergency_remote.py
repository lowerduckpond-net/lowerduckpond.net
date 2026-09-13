"""Administrative archive retirement, unreachable through the ordinary worker RPC."""

from __future__ import annotations

from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    result_digest,
    validate_contract,
)

from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.emergency_delete import EmergencyDeletionError
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository


def finish_emergency_retirement(
    journal: ArchiveJournal,
    retirement: dict[str, object] | None,
    audit: dict[str, object],
) -> None:
    """Purge only the exact emergency retirement after its audited local deletion.

    The administrative caller separately verifies release and running-route absence
    while holding the same export exclusion. No worker socket exposes this function.
    """
    journal.spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    verify_emergency_terminal(journal.repository, audit)
    evidence = cast(dict[str, object], audit["deletionEvidence"])
    if retirement is not None:
        validate_contract(retirement, expected_kind=ContractKind.ARCHIVE_RETIREMENT_INTENT)
        intent = journal._remote_intent(str(retirement["intentId"]))
        archive = cast(dict[str, object], retirement.get("archiveRecord"))
        if (
            intent.record.document != retirement
            or evidence["mode"] != "emergency-archived"
            or retirement.get("compatibilityVersion") != "static-retirement-v2"
            or retirement["operatorPrincipal"] != audit["operatorPrincipal"]
            or retirement["tenantId"] != audit["tenantId"]
            or retirement["correlationId"] != audit["correlationId"]
            or retirement["provenance"]
            != {"kind": "emergency-administrator", "reason": evidence["emergencyReason"]}
            or retirement["transition"] != "delete"
            or evidence["archiveRecordDigest"] != archive_record_digest(archive).to_dict()
            or any(evidence[field] != archive[field] for field in ("bucket", "key", "versionId"))
        ):
            raise EmergencyDeletionError("emergency retirement differs from its permanent evidence")
        journal._purge(retirement)
        journal.repository.remove_reconciled_intent(intent.path, intent.removal_token)
    if evidence["mode"] == "emergency-archived":
        if evidence["bucket"] != journal.remote.bucket:
            raise EmergencyDeletionError("emergency cleanup selected another bucket")
        try:
            journal.remote.require_absent(str(evidence["key"]))
        except Exception:
            journal.quarantine(None)
            raise
    elif evidence["mode"] != "emergency" or retirement is not None:
        raise EmergencyDeletionError("emergency cleanup received ordinary deletion evidence")


def verify_emergency_terminal(repository: StateRepository, audit: dict[str, object]) -> None:
    validate_contract(audit, expected_kind=ContractKind.AUDIT_ENTRY)
    evidence = cast(dict[str, object], audit.get("deletionEvidence"))
    with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        result = transaction.read(StateRecordPath.emergency_result(audit["correlationId"])).document
        if (
            result["operation"] != "delete"
            or result["status"] != "succeeded"
            or result["tenantId"] != audit["tenantId"]
            or result["correlationId"] != audit["correlationId"]
            or result["provenance"]
            != {
                "kind": "emergency-administrator",
                "operatorPrincipal": audit["operatorPrincipal"],
                "reason": evidence["emergencyReason"],
            }
            or audit["resultDigest"] != result_digest(result).to_dict()
            or audit["resultStatus"] != "succeeded"
            or audit["operation"] != "delete"
            or transaction.inspect_audit_correlation(audit["correlationId"]).entry != audit
            or audit["tenantId"] in transaction.measure_inventory().tenant_ids
        ):
            raise EmergencyDeletionError("emergency cleanup has no exact audited deletion")
