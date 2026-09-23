"""Exact-version retirement after complete independent restored-state verification."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    canonical_json_bytes,
    decode_json_object,
    result_digest,
    validate_contract,
)

from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
)
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.emergency_remote import verify_emergency_terminal
from lowerduckpond_static_host_agent.host_restore_archives import (
    RestoreArchive,
    _inventory_document,
    verify_restore_archives,
)
from lowerduckpond_static_host_agent.host_restore_construction import classify_unbound_construction
from lowerduckpond_static_host_agent.host_restore_decisions import commit_decision
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath


def _bound(journal: ArchiveJournal) -> list[RestoreArchive]:
    with journal.repository.publication_transaction() as transaction:
        return [
            RestoreArchive(
                transaction.read(StateRecordPath.tenant_archive(tenant, deployment)).document,
                transaction.read(StateRecordPath.tenant_desired(tenant)).document,
            )
            for tenant in transaction.measure_inventory().tenant_ids
            for deployment in transaction.tenant_archive_ids(tenant)
        ]


def _terminal(
    journal: ArchiveJournal, document: dict[str, object]
) -> tuple[dict[str, object], bool]:
    provenance = document.get("provenance")
    if type(provenance) is not dict or provenance["kind"] != "emergency-administrator":
        result = journal._terminal_result(document)
        preserve = result["status"] == (
            "succeeded" if document["kind"] == "ArchiveConstructionIntent" else "failed"
        )
        return result, preserve
    with journal.repository.publication_transaction() as transaction:
        audit = transaction.inspect_audit_correlation(document["correlationId"]).entry
        result = transaction.read(
            StateRecordPath.emergency_result(document["correlationId"])
        ).document
    if audit is None:
        raise HostRestoreError("restore_remote_emergency_audit_missing")
    verify_emergency_terminal(journal.repository, audit)
    evidence = cast(dict[str, object], audit["deletionEvidence"])
    archive = cast(dict[str, object], document["archiveRecord"])
    if (
        evidence["mode"] != "emergency-archived"
        or document["transition"] != "delete"
        or document["operatorPrincipal"] != audit["operatorPrincipal"]
        or document["tenantId"] != audit["tenantId"]
        or provenance != {"kind": "emergency-administrator", "reason": evidence["emergencyReason"]}
        or evidence["archiveRecordDigest"] != archive_record_digest(archive).to_dict()
        or any(evidence[field] != archive[field] for field in ("bucket", "key", "versionId"))
    ):
        raise HostRestoreError("restore_remote_emergency_authority_changed")
    return result, False


def _digest(inventory: RemoteInventory) -> dict[str, str]:
    return framed_digest(
        "lowerduckpond-host-restore-remote-v1",
        canonical_json_bytes(_inventory_document(inventory), maximum_bytes=MAX_RESTORE_BYTES),
    )


def _delete_exact(remote: ArchiveRemoteStore, version: RemoteVersion) -> None:
    # No mutable-key deletion, list-and-purge loop, marker removal or re-upload.
    response = remote.client.delete_object(
        Bucket=remote.bucket, Key=version.key, VersionId=version.version_id
    )
    if (
        response.get("VersionId") != version.version_id
        or response.get("DeleteMarker", False) is not False
    ):
        raise HostRestoreError("restore_remote_delete_response_ambiguous")


def _completed_cleanup(
    store: RestoreStore, journal: ArchiveJournal, intent_id: str, workspace: Path
) -> dict[str, object]:
    name = f"remote-cleanup-{intent_id}.json"
    receipt = decode_json_object(store.read_bytes(name), maximum_bytes=MAX_RESTORE_BYTES)
    payload = exact_object(
        receipt["payload"], {"kind", "intent", "resultDigest", "preserve", "archiveRecord"}
    )
    document = payload["intent"]
    if payload["kind"] != "archive-cleanup" or type(document) is not dict:
        raise HostRestoreError("restore_remote_cleanup_authority_changed")
    validate_contract(
        document,
        expected_kind=ContractKind.ARCHIVE_CONSTRUCTION_INTENT
        if document["kind"] == "ArchiveConstructionIntent"
        else ContractKind.ARCHIVE_RETIREMENT_INTENT,
    )
    if document["intentId"] != intent_id or document["bucket"] != journal.remote.bucket:
        raise HostRestoreError("restore_remote_cleanup_authority_changed")
    result, preserve = _terminal(journal, document)
    if (
        payload["resultDigest"] != result_digest(result).to_dict()
        or payload["preserve"] is not preserve
    ):
        raise HostRestoreError("restore_remote_terminal_state_changed")
    authority = _bound(journal)
    target = next((item for item in authority if item.record["key"] == document["key"]), None)
    if (preserve and (target is None or target.record != payload["archiveRecord"])) or (
        not preserve and target is not None
    ):
        raise HostRestoreError("restore_remote_completed_binding_changed")
    # Unknown resurrected retired bytes cannot be admitted into a completed
    # cleanup receipt. The complete listing must now equal only bound archives.
    verify_restore_archives(journal.remote, authority, workspace, owner=journal.owner)
    return commit_decision(store, name, payload)


def finish_restore_remote(  # noqa: PLR0912, PLR0915 - every mutation follows exact proof and interruption checks
    store: RestoreStore,
    journal: ArchiveJournal,
    intent_id: str,
    workspace: Path,
) -> dict[str, object]:
    """Run in the archive credential helper after local lifecycle reconciliation.

    Every invocation independently proves all bound archives and the sole
    optional retirement. A lost delete reply preserves the journal; retry can
    accept exact absence but never adopt another version or delete an unknown.
    The root restore journal and its source-fence binding must already be
    validated by the helper entrypoint before constructing this context.
    """
    if not journal.repository.measure_intent_records().records:
        return _completed_cleanup(store, journal, intent_id, workspace)
    intent = journal._remote_intent(intent_id)
    document = intent.record.document
    result, preserve = _terminal(journal, document)
    authority = _bound(journal)
    target = next((item for item in authority if item.record["key"] == document["key"]), None)
    if preserve:
        expected = (
            result.get("archiveRecord")
            if document["kind"] == "ArchiveConstructionIntent"
            else document["archiveRecord"]
        )
        if target is None or target.record != expected:
            raise HostRestoreError("restore_remote_retained_archive_changed")
    else:
        if target is not None:
            raise HostRestoreError("restore_remote_version_remains_bound")
        if intent.kind is ContractKind.ARCHIVE_CONSTRUCTION_INTENT:
            discovered = journal.remote.inventory()
            with journal.repository.publication_transaction() as transaction:
                target = classify_unbound_construction(
                    transaction, intent_id, discovered, bucket=journal.remote.bucket
                )
        else:
            target = RestoreArchive(
                cast(dict[str, object], document["archiveRecord"]), None, required=False
            )
        if target is not None:
            authority.append(target)
    proof = verify_restore_archives(journal.remote, authority, workspace, owner=journal.owner)
    current = journal.remote.inventory()
    if _digest(current) != proof["inventoryDigest"]:
        raise HostRestoreError("restore_remote_inventory_changed")
    version = None if target is None else target.version(journal.remote.bucket)
    payload = {
        "kind": "archive-cleanup",
        "intent": document,
        "resultDigest": result_digest(result).to_dict(),
        "preserve": preserve,
        "archiveRecord": None if target is None else target.record,
    }
    # A prepared upload whose response was lost may be absent after our own
    # interrupted deletion. Recover its original exact optional projection from
    # this immutable receipt, never from a newly appearing remote version.
    name = f"remote-cleanup-{intent_id}.json"
    try:
        previous = decode_json_object(store.read_bytes(name), maximum_bytes=MAX_RESTORE_BYTES)
    except FileNotFoundError:
        pass
    else:
        saved = exact_object(previous["payload"], set(payload))
        if target is None and document["kind"] == "ArchiveConstructionIntent" and not preserve:
            payload["archiveRecord"] = saved["archiveRecord"]
        if saved != payload:
            raise HostRestoreError("restore_remote_cleanup_authority_changed")
    receipt = commit_decision(store, name, payload)
    if not preserve and version is not None and version in current.versions:
        if any(bound.key == version.key for bound in journal.bound_versions()):
            raise HostRestoreError("restore_remote_version_remains_bound")
        before = journal.remote.inventory()
        if _inventory_document(before) != _inventory_document(current):
            raise HostRestoreError("restore_remote_inventory_changed")
        _delete_exact(journal.remote, version)
        current = RemoteInventory(tuple(row for row in current.versions if row != version), ())
    after = journal.remote.inventory()
    if _inventory_document(after) != _inventory_document(current):
        raise HostRestoreError("restore_remote_inventory_changed")
    if not preserve and any(row.key == document["key"] for row in after.versions):
        raise HostRestoreError("restore_remote_version_still_present")
    if _terminal(journal, document) != (result, preserve):
        raise HostRestoreError("restore_remote_terminal_state_changed")
    journal.repository.remove_reconciled_intent(intent.path, intent.removal_token)
    return receipt
