"""Read-only archive obligations from independently proved lifecycle choices."""

from __future__ import annotations

from typing import cast

from lowerduckpond_static_contracts import ContractKind

from lowerduckpond_static_host_agent import (
    host_restore_archive,
    host_restore_delete,
    host_restore_emergency,
    host_restore_tenant_restore,
)
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_remote import RemoteInventory
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.execution import (
    _require_same_authority,
    _validate_request_integrity,
)
from lowerduckpond_static_host_agent.host_restore_archives import RestoreArchive
from lowerduckpond_static_host_agent.host_restore_construction import classify_unbound_construction
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_lifecycle_pair import original_pair
from lowerduckpond_static_host_agent.host_restore_remote import _terminal
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.repository import StateRecordPath, _StateTransaction


def unstarted_retirement(
    transaction: _StateTransaction, document: dict[str, object], *, bucket: str
) -> RestoreArchive:
    """Same unchanged-source predicate as ordinary preparation cancellation.

    No remote absence is excused: without a selected lifecycle candidate the
    archived source version remains required. This function makes no changes.
    """
    provenance = document.get("provenance")
    if type(provenance) is not dict or provenance.get("kind") != "authorization-job":
        raise HostRestoreError("restore_retirement_preparation_unbound")
    job_id = provenance["jobId"]
    job = transaction.read(StateRecordPath.authorization_job(job_id)).document
    _validate_request_integrity(job)
    correlation = transaction.read(
        StateRecordPath.authorization_correlation(document["correlationId"])
    ).document
    _require_same_authority(job, correlation)
    request = cast(dict[str, object], job["request"])
    source = cast(dict[str, object], job["sourceAuthority"])
    if (
        job["phase"] != "claimed"
        or request["operation"] not in {"restore", "delete"}
        or document["kind"] != "ArchiveRetirementIntent"
        or document["transition"] != request["operation"]
        or document["correlationId"] != request["correlationId"]
        or document["tenantId"] != request["tenantId"]
        or document["bucket"] != bucket
        or document["operatorPrincipal"] != job["operatorPrincipal"]
        or build_expected_source(transaction, request) != job["expectedSource"]
        or source["archiveRecord"] != document["archiveRecord"]
        or transaction.inspect_audit_correlation(request["correlationId"]).entry is not None
    ):
        raise HostRestoreError("restore_retirement_preparation_source_changed")
    try:
        transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        pass
    else:
        raise HostRestoreError("restore_retirement_preparation_has_result")
    return RestoreArchive(
        cast(dict[str, object], document["archiveRecord"]),
        cast(dict[str, object], source["manifest"]),
    )


def _lifecycle_archive(
    store: RestoreStore,
    transaction: _StateTransaction,
    intent: dict[str, object],
    evidence: CaddyBackupEvidence,
    original_ca: tuple[bytes, ...],
) -> RestoreArchive | None:
    identity = str(intent["intentId"])
    if intent["kind"] == "EmergencyDeletionIntent":
        original, _ = host_restore_emergency._original(store, transaction, identity)
        choice = host_restore_emergency.emergency_selection(
            transaction, original, evidence, original_ca
        )
        if choice != "candidate":
            raise HostRestoreError("restore_emergency_source_has_no_authorized_failure")
        archive = cast(dict[str, object] | None, original["archiveRecord"])
        return (
            None
            if archive is None
            else RestoreArchive(
                archive, cast(dict[str, object], original["sourceManifest"]), required=False
            )
        )
    operation = intent["operation"]
    if operation == "archive":
        original, job, _ = host_restore_archive._original(store, transaction, identity)
        archive_plan = host_restore_archive._plan(transaction, original, job)
        choice = host_restore_archive.archive_selection(
            transaction, archive_plan, evidence, original_ca
        )
        return RestoreArchive(
            archive_plan.archive_record, archive_plan.manifest, required=choice == "candidate"
        )
    if operation not in {"restore", "delete"}:
        return None
    original, job, retirement, _ = original_pair(
        store,
        transaction,
        identity,
        family="tenant-restore" if operation == "restore" else "delete",
    )
    if operation == "restore":
        if retirement is None:
            raise HostRestoreError("restore_tenant_retirement_unavailable")
        restore_plan = host_restore_tenant_restore._plan(transaction, original, job, retirement)
        choice = host_restore_tenant_restore.restore_selection(
            transaction, restore_plan, evidence, original_ca
        )
    else:
        delete_plan = host_restore_delete._plan(transaction, original, job, retirement)
        choice = host_restore_delete.delete_selection(
            transaction, delete_plan, evidence, original_ca
        )
    return (
        None
        if retirement is None
        else RestoreArchive(
            cast(dict[str, object], retirement.document["archiveRecord"]),
            cast(dict[str, object], original["sourceManifest"]),
            required=choice == "source",
        )
    )


def collect_restore_archives(  # noqa: PLR0912 - lifecycle, unstarted, and terminal remote authority
    store: RestoreStore,
    journal: ArchiveJournal,
    evidence: CaddyBackupEvidence,
    original_ca: tuple[bytes, ...],
    inventory: RemoteInventory,
) -> tuple[RestoreArchive, ...]:
    """Derive the whole set before verification; never delete or invent versions.

    The credential helper holds export EX and the coordinator has quiesced all
    other writers. The state leases remain short; no network happens under them.
    Complete inventory plus actual bundle verification remains mandatory after
    this classification, and local finalizers independently recheck each choice.
    """
    current = store.read()
    if current is None or current.phase is not RestorePhase.VALIDATED:
        raise HostRestoreError("restore_archive_classification_requires_validated")
    journal._require_lock()
    with journal.repository.publication_transaction() as transaction:
        records = [
            transaction.read_intent(row.intent_id)[1]
            for row in transaction.measure_intent_records().records
        ]
        local = [
            record
            for record in records
            if record.revision.contract_kind
            in {ContractKind.TRANSACTION_INTENT, ContractKind.EMERGENCY_DELETION_INTENT}
        ]
        if len(local) > 1:
            raise HostRestoreError("restore_archive_local_intents_ambiguous")
        override = (
            None
            if not local
            else _lifecycle_archive(store, transaction, local[0].document, evidence, original_ca)
        )
    if not local and records:
        if len(records) != 1:
            raise HostRestoreError("restore_archive_remote_intents_ambiguous")
        record = records[0]
        if record.revision.contract_kind is ContractKind.ARCHIVE_RETIREMENT_INTENT:
            try:
                _, preserve = _terminal(journal, record.document)
            except FileNotFoundError:
                with journal.repository.publication_transaction() as transaction:
                    override = unstarted_retirement(
                        transaction, record.document, bucket=journal.remote.bucket
                    )
            else:
                with journal.repository.publication_transaction() as transaction:
                    source = (
                        transaction.read(
                            StateRecordPath.tenant_desired(record.document["tenantId"])
                        ).document
                        if preserve
                        else None
                    )
                override = RestoreArchive(
                    cast(dict[str, object], record.document["archiveRecord"]),
                    source,
                    required=preserve,
                )
        elif record.revision.contract_kind is ContractKind.ARCHIVE_CONSTRUCTION_INTENT:
            with journal.repository.publication_transaction() as transaction:
                bound = any(
                    transaction.read(StateRecordPath.tenant_archive(tenant, deployment)).document[
                        "key"
                    ]
                    == record.document["key"]
                    for tenant in transaction.measure_inventory().tenant_ids
                    for deployment in transaction.tenant_archive_ids(tenant)
                )
                if not bound:
                    # Includes a source failure interrupted between immutable
                    # result and audit/job repair. Classification is read-only;
                    # cleanup still requires the complete terminal proof.
                    override = classify_unbound_construction(
                        transaction,
                        str(record.document["intentId"]),
                        inventory,
                        bucket=journal.remote.bucket,
                    )
            if bound:
                _, preserve = _terminal(journal, record.document)
                if not preserve:
                    raise HostRestoreError("restore_construction_failed_but_bound")
        # Other local journals have no archive effect; ordinary strict state
        # validation and their operation-specific finalizer still govern them.
    with journal.repository.publication_transaction() as transaction:
        authority = []
        for tenant in transaction.measure_inventory().tenant_ids:
            for deployment in transaction.tenant_archive_ids(tenant):
                archive = transaction.read(
                    StateRecordPath.tenant_archive(tenant, deployment)
                ).document
                if override is not None and archive == override.record:
                    continue
                authority.append(
                    RestoreArchive(
                        archive, transaction.read(StateRecordPath.tenant_desired(tenant)).document
                    )
                )
        if override is not None:
            authority.append(override)
        for item in authority:
            item.version(journal.remote.bucket)
        return tuple(authority)
