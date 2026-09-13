"""Independent remote evidence derived from durable source or terminal jobs."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    manifest_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, RemoteVersion
from lowerduckpond_static_host_agent.archive_service import _read_authority
from lowerduckpond_static_host_agent.execution import (
    _validate_request_integrity,
    _validate_result_audit,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath


def verify_archive_source(journal: ArchiveJournal, job_id: str) -> dict[str, object]:
    journal.spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    record = _read_authority(
        journal.repository,
        validate_uuid7(job_id),
        bucket=journal.remote.bucket,
        operations=frozenset({"archive", "restore", "delete"}),
        allow_retirement=True,
    )
    journal.verify_retained(record)
    return {"status": "verified", "mode": "retained", "archiveRecord": record}


def verify_archive_terminal(journal: ArchiveJournal, job_id: str) -> dict[str, object]:
    """Recheck provider bytes or key absence even after a journal has been removed.

    A lost upload response has no version ID to put in an ArchiveRecord. For
    that failure, complete inventory must exactly match all retained bindings;
    the absence of a fabricated record is never treated as remote evidence.
    """
    journal.spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    mode, archive = _terminal_authority(journal, validate_uuid7(job_id))
    bound = journal.bound_versions()
    if archive is None:
        inventory = journal.remote.inventory()
        if inventory.multipart_uploads or frozenset(inventory.versions) != bound:
            journal.quarantine(inventory)
            raise ArchiveRemoteError("failed archive retains unaccounted remote evidence")
    else:
        if archive["bucket"] != journal.remote.bucket:
            raise ArchiveRemoteError("terminal archive belongs to another bucket")
        key = cast(str, archive["key"])
        bindings = frozenset(value for value in bound if value.key == key)
        if mode == "retained":
            if bindings != frozenset(
                {
                    RemoteVersion(
                        key,
                        cast(str, archive["versionId"]),
                        cast(int, archive["bundleSize"]),
                        False,
                    )
                }
            ):
                raise ArchiveRemoteError("terminal archive has no exact retained binding")
            journal.verify_retained(archive)
        else:
            if bindings:
                raise ArchiveRemoteError("terminal retired key still has an authoritative binding")
            journal.remote.require_absent(key)
    return {"status": "verified", "mode": mode, "archiveRecord": archive}


def _terminal_authority(
    journal: ArchiveJournal, job_id: str
) -> tuple[str, dict[str, object] | None]:
    with journal.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id)).document
        result = transaction.read(StateRecordPath.authorization_result(job_id)).document
        request = cast(dict[str, object], job["request"])
        if (
            job["compatibilityVersion"] != "static-job-v2"
            or job["phase"] != ("completed" if result["status"] == "succeeded" else "failed")
            or request["operation"] not in {"archive", "restore", "delete"}
            or transaction.measure_intent_records().records
        ):
            raise ArchiveRemoteError("terminal verification requires a fully reconciled job")
        _validate_request_integrity(job)
        _validate_result_binding(job, result)
        _validate_result_audit(transaction, job, result)
        authority = cast(dict[str, object], job["sourceAuthority"])
        source = cast(dict[str, object], authority["manifest"])
        expected = cast(dict[str, object], job["expectedSource"])
        if manifest_digest(source).to_dict() != expected["manifestDigest"]:
            raise ArchiveRemoteError("terminal job lost its authorized source")
        source_archive = authority["archiveRecord"]
        if request["operation"] in {"restore", "delete"} or source_archive is not None:
            if (
                type(source_archive) is not dict
                or archive_record_digest(source_archive).to_dict()
                != expected["archiveRecordDigest"]
            ):
                raise ArchiveRemoteError("terminal job lost its authorized archive")
            mode = (
                "retired"
                if result["status"] == "succeeded" and request["operation"] in {"restore", "delete"}
                else "retained"
            )
            return mode, source_archive
        archive = result.get("archiveRecord")
        if archive is None and result["status"] == "failed":
            return "accounted", None
        if type(archive) is not dict:
            raise ArchiveRemoteError("archive result omitted exact candidate evidence")
        validate_contract(archive, expected_kind=ContractKind.ARCHIVE_RECORD)
        candidate = deepcopy(source)
        spec = cast(dict[str, object], candidate["spec"])
        desired = cast(dict[str, object], spec["desiredDeployment"])
        spec["desiredState"] = "archived"
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(request["tenantId"], desired["id"])
        ).document
        if (
            archive["tenantId"] != request["tenantId"]
            or archive["deploymentId"] != desired["id"]
            or archive["correlationId"] != request["correlationId"]
            or archive["manifestDigest"] != manifest_digest(candidate).to_dict()
            or archive["releaseTreeDigest"] != deployment["releaseTreeDigest"]
            or (result["status"] == "succeeded" and result["manifest"] != candidate)
        ):
            raise ArchiveRemoteError("terminal archive exceeds its authorized candidate")
        return ("retained" if result["status"] == "succeeded" else "retired"), archive
