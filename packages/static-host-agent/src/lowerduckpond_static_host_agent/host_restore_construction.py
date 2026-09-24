"""Classify a captured unpublished upload without adopting a newer remote timeline."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

from lowerduckpond_static_contracts import ContractKind, deployment_record_digest, validate_contract

from lowerduckpond_static_host_agent.archive_journal import (
    _archive_record,
    _failed_construction_source,
)
from lowerduckpond_static_host_agent.archive_remote import RemoteInventory, archive_key
from lowerduckpond_static_host_agent.execution import (
    _expected_source_error,
    _require_same_authority,
    _validate_request_integrity,
)
from lowerduckpond_static_host_agent.host_restore_archives import RestoreArchive
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.repository import StateRecordPath, _StateTransaction


def classify_unbound_construction(
    transaction: _StateTransaction,
    intent_id: str,
    inventory: RemoteInventory,
    *,
    bucket: str,
) -> RestoreArchive | None:
    """Return an exact optional version to read/verify before terminal retirement.

    This is valid only after proving the original live source and the sole
    construction journal. It performs no remote or local mutation. In particular,
    a lost upload response never authorizes a second upload or a mutable-key GET.
    The complete inventory must still pass verify_restore_archives, including
    actual bundle parsing, before the credential-isolated helper may retire it.
    """
    identities = transaction.measure_intent_records().records
    if len(identities) != 1 or identities[0].intent_id != intent_id:
        raise HostRestoreError("restore_construction_is_not_unbound")
    path, stored = transaction.read_intent(intent_id)
    intent = stored.document
    if path.contract_kind is not ContractKind.ARCHIVE_CONSTRUCTION_INTENT:
        raise HostRestoreError("restore_construction_kind_invalid")
    validate_contract(intent, expected_kind=ContractKind.ARCHIVE_CONSTRUCTION_INTENT)
    job = transaction.read(StateRecordPath.authorization_job(intent["jobId"])).document
    _validate_request_integrity(job)
    request = cast(dict[str, object], job["request"])
    correlation = transaction.read(
        StateRecordPath.authorization_correlation(intent["correlationId"])
    ).document
    _require_same_authority(job, correlation)
    if (
        correlation["jobId"] != job["jobId"]
        or correlation["requestDigest"] != job["requestDigest"]
        or job["phase"] not in {"claimed", "failed"}
        or request["operation"] != "archive"
        or request["tenantId"] != intent["tenantId"]
        or request["correlationId"] != intent["correlationId"]
        or job["operatorPrincipal"] != intent["operatorPrincipal"]
        or intent["key"] != archive_key(intent["uploadAttemptId"])
        or intent["bucket"] != bucket
        or _expected_source_error(transaction, job) is not None
    ):
        raise HostRestoreError("restore_construction_source_changed")
    desired = _failed_construction_source(job, intent)
    deployment = transaction.read(
        StateRecordPath.tenant_deployment(intent["tenantId"], desired["id"])
    ).document
    if (
        deployment_record_digest(deployment).to_dict() != intent["deploymentRecordDigest"]
        or deployment["releaseTreeDigest"] != intent["releaseTreeDigest"]
    ):
        raise HostRestoreError("restore_construction_deployment_changed")
    versions = [version for version in inventory.versions if version.key == intent["key"]]
    if (
        len(versions) > 1
        or any(row.delete_marker for row in versions)
        or any(key == intent["key"] for key, _upload in inventory.multipart_uploads)
    ):
        raise HostRestoreError("restore_construction_remote_ambiguous")
    if versions and (
        versions[0].size != intent["bundleSize"]
        or (intent["versionId"] is not None and versions[0].version_id != intent["versionId"])
    ):
        raise HostRestoreError("restore_construction_remote_changed")
    if intent["versionId"] is None and not versions:
        return None
    # The record is a private verification projection. Preserve the original
    # prepared/uploaded journal and its allowed immutable terminal result.
    projected = {
        **intent,
        "versionId": versions[0].version_id if intent["versionId"] is None else intent["versionId"],
    }
    source = cast(dict[str, object], cast(dict[str, object], job["sourceAuthority"])["manifest"])
    candidate = deepcopy(source)
    cast(dict[str, object], candidate["spec"])["desiredState"] = "archived"
    return RestoreArchive(_archive_record(projected, deployment), candidate, required=False)
