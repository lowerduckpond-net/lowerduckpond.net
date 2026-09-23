"""Short state transactions for one sealed audit attempt and exact local removal."""

from __future__ import annotations

import hashlib
import os

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent import audit_archive_store as store
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.audit_archive_admission import (
    AuditArchiveCapacityError,
    rotation_reservation,
)
from lowerduckpond_static_host_agent.audit_archive_inventory import ProtectedProof
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.capacity import (
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, DurableDirectory


def require_rotation_capacity(root: DurableDirectory, current: local.LocalArchive) -> None:
    with root.open_descendant(("audit", "archive")) as directory:
        reserve = rotation_reservation(directory)
        if (
            current.prefix.allocated_bytes + reserve.allocated_bytes
            > formats.MAX_ARCHIVE_METADATA_BYTES
            or current.prefix.inodes + reserve.unique_inodes > formats.MAX_ARCHIVE_METADATA_INODES
            or current.audit.allocated_bytes + reserve.allocated_bytes
            > DEFAULT_AUDIT_LIMITS.maximum_ordinary_bytes
            or len(current.prefix.segments) >= formats.MAX_ARCHIVED_SEGMENTS
        ):
            raise AuditArchiveCapacityError("audit rotation cannot preserve ordinary headroom")
        descriptor = directory.duplicate_descriptor()
        try:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                reserve,
                measure_filesystem_capacity_descriptor(descriptor),
            )
        finally:
            os.close(descriptor)


def prepare_rotation(  # noqa: PLR0913 - sealed authority and durable failure boundaries
    root: DurableDirectory,
    current: local.LocalArchive,
    owner: int,
    rotation_id: str,
    created_at: str,
    *,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> bool:
    """Seal the oldest closed segment before any snapshot child can start."""
    local.head_digest(current.prefix)
    if current.prefix.rotation_intent is not None or current.prefix.maintenance_intent is not None:
        raise BackupIdentityError("audit rotation cannot replace a pending operation")
    with root.open_descendant(("audit", "archive")) as directory:
        local._sync(directory)  # Finish a previous intent removal whose parent sync was lost.
    number = len(current.prefix.segments)
    if current.audit.segment_count <= number + 1:
        return False
    require_rotation_capacity(root, current)
    path = ("audit", formats.segment_name(number))
    raw = root.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=formats.MAX_SEGMENT_BYTES
    )
    evidence = formats.inspect_segment(raw)
    head = current.prefix.head
    assert head is not None  # noqa: S101 - initialized above
    record = formats.validate_rotation(
        {
            "schema": formats.ROTATION_SCHEMA,
            "rotationId": rotation_id,
            "lineageId": current.lineage["lineageId"],
            "repositoryBinding": current.lineage["repositoryBinding"],
            "createdAt": created_at,
            "segmentNumber": number,
            "segmentName": path[1],
            "firstSequence": evidence.first_sequence,
            "lastSequence": evidence.first_sequence + evidence.entry_count - 1,
            "entryCount": evidence.entry_count,
            "segmentBytes": len(raw),
            "segmentSha256": hashlib.sha256(raw).hexdigest(),
            "predecessorEntryDigest": evidence.predecessor,
            "terminalEntryDigest": evidence.terminal,
            "previousDescriptorDigest": head["lastDescriptorDigest"],
            "witnessFormat": formats.WITNESS_FORMAT,
            "witnessBytes": len(evidence.witness),
            "witnessDigest": framed_digest(formats.WITNESS_FORMAT, evidence.witness),
        }
    )
    store._require_extension(
        {"descriptor": record, "previousIndexDigest": head["lastIndexDigest"]},
        head,
        current.lineage,
    )
    intent = journal.decode_rotation_intent(
        canonical_json_bytes(
            {
                "schema": journal.ROTATION_INTENT_SCHEMA,
                "descriptor": record,
                "expectedHeadDigest": local.head_digest(current.prefix),
                "sourceGeneration": [
                    str(value)
                    for value in root.regular_metadata_generation(
                        path, expected_owner=owner, expected_mode=0o600
                    )
                ],
                "phase": "prepared",
                "snapshotIds": [],
            },
            maximum_bytes=journal.MAX_JOURNAL_BYTES,
        )
    )
    local.publish_records(
        root,
        current,
        owner,
        [("rotation-intent.json", canonical_json_bytes(intent), False)],
        failure_hook=failure_hook,
    )
    return True


def source_bytes(root: DurableDirectory, current: local.LocalArchive, owner: int) -> bytes | None:
    intent = current.prefix.rotation_intent
    if intent is None:
        raise BackupIdentityError("audit rotation has no durable attempt")
    record = formats.validate_rotation(intent["descriptor"])
    number = formats.archive_count(record["segmentNumber"], formats.MAX_ARCHIVED_SEGMENTS - 1)
    if current.audit.segment_count <= number + 1:
        raise BackupIdentityError("audit rotation source has no durable successor")
    path = ("audit", formats.segment_name(number))
    try:
        raw = root.read_regular(
            path, expected_owner=owner, expected_mode=0o600, maximum_bytes=formats.MAX_SEGMENT_BYTES
        )
    except FileNotFoundError:
        if (
            intent["phase"] != "indexed"
            or number >= len(current.prefix.segments)
            or current.prefix.segments[number].descriptor != record
        ):
            raise BackupIdentityError("unindexed audit rotation lost its source") from None
        return None
    generation = [
        str(value)
        for value in root.regular_metadata_generation(
            path, expected_owner=owner, expected_mode=0o600
        )
    ]
    if generation != intent["sourceGeneration"]:
        raise BackupIdentityError("audit rotation source inode changed")
    formats.verify_segment(record, raw)
    return raw


def record_snapshot(
    root: DurableDirectory,
    current: local.LocalArchive,
    owner: int,
    snapshot_id: str,
    *,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> None:
    intent = current.prefix.rotation_intent
    if intent is None or intent["phase"] != "prepared":
        raise BackupIdentityError("audit snapshot response has no prepared attempt")
    source_bytes(root, current, owner)
    updated = {
        **intent,
        "phase": "discovered",
        "snapshotIds": [formats.full_snapshot_id(snapshot_id)],
    }
    raw = canonical_json_bytes(updated, maximum_bytes=journal.MAX_JOURNAL_BYTES)
    journal.decode_rotation_intent(raw)
    local.publish_records(
        root, current, owner, [("rotation-intent.json", raw, False)], failure_hook=failure_hook
    )


def remove_indexed_source(
    root: DurableDirectory,
    current: local.LocalArchive,
    proof: ProtectedProof,
    owner: int,
    *,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> None:
    """Caller supplies this invocation's remote proof, never a cached status."""
    intent = current.prefix.rotation_intent
    if intent is None or intent["phase"] != "indexed":
        raise BackupIdentityError("local audit removal requires a durable indexed attempt")
    record = formats.validate_rotation(intent["descriptor"])
    number = formats.archive_count(record["segmentNumber"], formats.MAX_ARCHIVED_SEGMENTS - 1)
    if number >= len(current.prefix.segments):
        raise BackupIdentityError("local audit removal has no indexed segment")
    archived = current.prefix.segments[number]
    copies = next((item for item in proof.copies if item.descriptor == record), None)
    if (
        archived.descriptor != record
        or copies is None
        or archived.index["snapshotId"] not in copies.snapshot_ids
        or not set(journal.snapshot_ids(intent["snapshotIds"])).issubset(copies.snapshot_ids)
        or not set(copies.snapshot_ids).issubset(proof.snapshot_ids)
    ):
        raise BackupIdentityError("local audit removal lacks its exact protected proof")
    raw = source_bytes(root, current, owner)
    name = formats.segment_name(number)
    if raw is not None:
        if formats.verify_segment(record, raw).witness != archived.witness:
            raise BackupIdentityError("local audit removal disagrees with indexed history")
        hook = None if failure_hook is None else lambda boundary: failure_hook(name, boundary)
        root.remove(("audit", name), failure_hook=hook)
    else:
        with root.open_descendant(("audit",)) as directory:
            local._sync(directory)
        if failure_hook is not None:
            failure_hook(name, DurabilityBoundary.DIRECTORY_SYNC)


def complete_rotation(
    root: DurableDirectory,
    current: local.LocalArchive,
    owner: int,
    *,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> None:
    if source_bytes(root, current, owner) is not None:
        raise BackupIdentityError("audit rotation cannot retire intent before source removal")
    name = "rotation-intent.json"
    hook = None if failure_hook is None else lambda boundary: failure_hook(name, boundary)
    root.remove(("audit", "archive", name), failure_hook=hook)
