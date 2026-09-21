"""Short state transactions for protected proofs; never performs network I/O."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractKind,
    canonical_json_bytes,
    decode_contract,
    platform_state_digest,
)

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_store as store
from lowerduckpond_static_host_agent.audit import (
    DEFAULT_AUDIT_LIMITS,
    AuditLimits,
    AuditState,
    inspect_audit_readonly,
)
from lowerduckpond_static_host_agent.audit_archive_admission import AuditArchiveCapacityError
from lowerduckpond_static_host_agent.audit_archive_inventory import (
    ProtectedProof,
    is_audit_snapshot,
)
from lowerduckpond_static_host_agent.backup_coordinator import _require_current_root
from lowerduckpond_static_host_agent.backup_identity import (
    BackupIdentityError,
    framed_digest,
    require_digest,
)
from lowerduckpond_static_host_agent.backup_lineage import (
    _require_current_state_lease,
    require_initial_lineage_prefix,
)
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

ArchiveFailureHook = Callable[[str, DurabilityBoundary], None]


class AuditRotationPendingError(BackupIdentityError):
    """A durable prepared attempt has no verified snapshot to adopt yet."""


@dataclass(frozen=True, slots=True)
class LocalArchive:
    lineage: dict[str, object]
    prefix: store.ArchivePrefix
    audit: AuditState


@contextmanager
def archive_transaction(
    path: Path, owner: int, *, mode: LockMode = LockMode.EXCLUSIVE, blocking: bool = True
) -> Iterator[DurableDirectory]:
    with (
        DurableDirectory.open(path, expected_owner=owner, expected_directory_mode=0o700) as root,
        root.open_descendant(("locks",)) as directory,
        LockManager(directory, expected_owner=owner, expected_directory_mode=0o700) as locks,
        locks.acquire(LockName.TENANT_STATE, mode=mode, blocking=blocking),
    ):
        _require_current_root(root, path)
        _require_current_state_lease(directory, locks, owner, mode=mode)
        yield root


def _require_lineage(root: DurableDirectory, lineage: dict[str, object], owner: int) -> None:
    if store._lineage(root, owner) != lineage:
        raise BackupIdentityError("protected audit local lineage changed")
    raw = root.read_regular(
        ("platform", "namespace.json"),
        expected_owner=owner,
        expected_mode=0o600,
        maximum_bytes=MAX_CANONICAL_BYTES,
    )
    namespace = decode_contract(raw, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    if (
        canonical_json_bytes(namespace) != raw
        or platform_state_digest(namespace).to_dict() != lineage["namespaceDigest"]
    ):
        raise BackupIdentityError("protected audit namespace binding changed")


def observe_archive(
    root: DurableDirectory,
    lineage: dict[str, object],
    owner: int,
    *,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> LocalArchive:
    _require_lineage(root, lineage, owner)
    audit = inspect_audit_readonly(
        root,
        expected_owner=owner,
        expected_directory_mode=0o700,
        expected_record_mode=0o600,
        limits=limits,
    )
    require_initial_lineage_prefix(root, owner, lineage, audit)
    return LocalArchive(lineage, store.read_archive_prefix(root, expected_owner=owner), audit)


def head_digest(prefix: store.ArchivePrefix) -> dict[str, str]:
    if prefix.head is None:
        raise BackupIdentityError("protected audit index is not initialized")
    return framed_digest(formats.HEAD_FORMAT, canonical_json_bytes(prefix.head))


def _sync(directory: DurableDirectory) -> None:
    descriptor = directory.duplicate_descriptor()
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def initialize_empty_archive(
    root: DurableDirectory,
    lineage: dict[str, object],
    snapshots: tuple[RepositorySnapshot, ...],
    owner: int,
    *,
    failure_hook: ArchiveFailureHook | None = None,
) -> None:
    """Explicit initialization only, after an independently verified remote genesis.

    An interrupted empty-directory creation may be resumed, but any committed
    archive record or remote rotation forbids recreating a missing head. Readers
    never invoke this migration, and no proof is written until full inspection.
    """
    _require_lineage(root, lineage, owner)
    with root.open_descendant(("audit",)) as audit:
        descriptor = audit.duplicate_descriptor()
        try:
            with suppress(FileExistsError):
                os.mkdir("archive", mode=0o700, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if failure_hook is not None:
            failure_hook("archive", DurabilityBoundary.DIRECTORY_SYNC)
    with root.open_descendant(("audit", "archive")) as directory:
        raw, allocated, inodes = store._inventory(directory, owner)
        if "head.json" in raw:
            store.read_archive_prefix(root, expected_owner=owner)
            _sync(directory)
            return
        if raw or any(is_audit_snapshot(item) for item in snapshots):
            raise BackupIdentityError(
                "missing audit head cannot replace existing archive authority"
            )
        # The only surviving files can be bounded, safe publication temporaries.
        reserve_records(
            directory,
            allocated,
            inodes,
            allocated,
            [("head.json", canonical_json_bytes(store.head_for_indexes(lineage, ())), True)],
        )
        directory.remove_abandoned_publication_temporaries(
            expected_owner=owner,
            expected_mode=0o600,
            maximum_entries=formats.MAX_ARCHIVE_METADATA_INODES,
        )
        _publish(
            directory,
            "head.json",
            canonical_json_bytes(store.head_for_indexes(lineage, ())),
            owner,
            immutable=True,
            failure_hook=failure_hook,
        )


def reserve_records(
    directory: DurableDirectory,
    allocated: int,
    inodes: int,
    audit_bytes: int,
    records: list[tuple[str, bytes, bool]],
) -> None:
    """Charge all possible new generations before the first publication."""
    count = len(records)
    allocation = sum(directory.allocation_upper_bound(len(raw)) for _, raw, _ in records)
    allocation += directory.namespace_allocation_upper_bound(count)
    if (
        allocated + allocation > formats.MAX_ARCHIVE_METADATA_BYTES
        or inodes + count > formats.MAX_ARCHIVE_METADATA_INODES
        or audit_bytes + allocation > DEFAULT_AUDIT_LIMITS.maximum_ordinary_bytes
    ):
        raise AuditArchiveCapacityError(
            "protected audit metadata cannot preserve ordinary capacity"
        )
    descriptor = directory.duplicate_descriptor()
    try:
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(allocation, count),
            measure_filesystem_capacity_descriptor(descriptor),
        )
    finally:
        os.close(descriptor)


def _publish(  # noqa: PLR0913 - immutable publication and failure boundaries
    directory: DurableDirectory,
    name: str,
    raw: bytes,
    owner: int,
    *,
    immutable: bool,
    failure_hook: ArchiveFailureHook | None,
) -> None:
    try:
        existing = directory.read_regular(
            (name,),
            expected_owner=owner,
            expected_mode=0o600,
            maximum_bytes=formats.MAX_ARCHIVE_METADATA_BYTES,
        )
    except FileNotFoundError:
        existing = None
    if existing == raw:
        _sync(directory)  # Complete an earlier rename whose parent sync was interrupted.
        return
    if immutable and existing is not None:
        raise BackupIdentityError("protected audit immutable authority changed")
    hook = None if failure_hook is None else lambda boundary: failure_hook(name, boundary)
    method = directory.create_immutable if immutable else directory.replace
    method((name,), raw, mode=0o600, failure_hook=hook)


def publish_records(
    root: DurableDirectory,
    current: LocalArchive,
    owner: int,
    records: list[tuple[str, bytes, bool]],
    *,
    failure_hook: ArchiveFailureHook | None = None,
) -> None:
    with root.open_descendant(("audit", "archive")) as directory:
        reserve_records(
            directory,
            current.prefix.allocated_bytes,
            current.prefix.inodes,
            current.audit.allocated_bytes,
            records,
        )
        directory.remove_abandoned_publication_temporaries(
            expected_owner=owner,
            expected_mode=0o600,
            maximum_entries=formats.MAX_ARCHIVE_METADATA_INODES,
        )
        for name, raw, immutable in records:
            _publish(directory, name, raw, owner, immutable=immutable, failure_hook=failure_hook)


def require_same_authority(captured: LocalArchive, current: LocalArchive) -> None:
    before, after = captured.prefix, current.prefix
    if captured.lineage != current.lineage or any(
        getattr(before, field) != getattr(after, field)
        for field in (
            "head",
            "segments",
            "rotation_intent",
            "duplicates",
            "maintenance_intent",
            "pending_index",
            "pending_witness",
        )
    ):
        raise BackupIdentityError("protected audit authority changed during remote verification")


def _index_for_orphan(
    root: DurableDirectory, current: LocalArchive, proof: ProtectedProof, owner: int
) -> tuple[dict[str, object], dict[str, object]]:
    orphan = proof.orphan
    assert orphan is not None  # noqa: S101 - internal caller
    descriptor = formats.validate_rotation(orphan.descriptor)
    if (
        canonical_json_bytes(descriptor) != orphan.descriptor_bytes
        or formats.verify_segment(descriptor, orphan.segment).witness != orphan.witness
    ):
        raise BackupIdentityError("unindexed audit proof changed before publication")
    number = formats.archive_count(descriptor["segmentNumber"], formats.MAX_ARCHIVED_SEGMENTS - 1)
    if current.audit.segment_count <= number + 1:
        raise BackupIdentityError("unindexed audit snapshot lacks a durable local successor")
    path = ("audit", formats.segment_name(number))
    raw = root.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=formats.MAX_SEGMENT_BYTES
    )
    generation = [
        str(value)
        for value in root.regular_metadata_generation(
            path, expected_owner=owner, expected_mode=0o600
        )
    ]
    if raw != orphan.segment:
        raise BackupIdentityError("unindexed audit snapshot differs from closed local authority")
    copies = next(item.snapshot_ids for item in proof.copies if item.descriptor == descriptor)
    previous = current.prefix.rotation_intent
    if previous is not None and previous["sourceGeneration"] != generation:
        raise BackupIdentityError("pending audit rotation source inode changed")
    intent = journal.decode_rotation_intent(
        canonical_json_bytes(
            {
                "schema": journal.ROTATION_INTENT_SCHEMA,
                "descriptor": descriptor,
                "expectedHeadDigest": head_digest(current.prefix),
                "sourceGeneration": generation,
                "phase": "verified",
                "snapshotIds": list(copies),
            },
            maximum_bytes=journal.MAX_JOURNAL_BYTES,
        )
    )
    head = current.prefix.head
    assert head is not None  # noqa: S101 - initialized above
    index = current.prefix.pending_index or formats.decode_index(
        canonical_json_bytes(
            {
                "schema": formats.INDEX_SCHEMA,
                "descriptor": descriptor,
                "snapshotId": orphan.snapshot_id,
                "requiredTags": list(formats.required_archive_tags(descriptor)),
                "descriptorDigest": framed_digest(
                    formats.DESCRIPTOR_FORMAT, orphan.descriptor_bytes
                ),
                "witnessDigest": descriptor["witnessDigest"],
                "previousIndexDigest": head["lastIndexDigest"],
            },
            maximum_bytes=formats.MAX_INDEX_BYTES,
        )
    )
    store._require_extension(index, head, current.lineage)
    if index["snapshotId"] not in copies:
        raise BackupIdentityError("pending audit index lost its selected snapshot")
    return intent, index


def commit_protected_proof(  # noqa: PLR0913 - state proof and failure boundaries
    root: DurableDirectory,
    current: LocalArchive,
    proof: ProtectedProof,
    owner: int,
    verified_at: str,
    *,
    failure_hook: ArchiveFailureHook | None = None,
) -> None:
    head_digest(current.prefix)
    records: list[tuple[str, bytes, bool]] = []
    indexes = tuple(segment.index for segment in current.prefix.segments)
    intent = current.prefix.rotation_intent
    if (
        intent is not None
        and proof.orphan is None
        and formats.validate_rotation(intent["descriptor"])["segmentNumber"] == len(indexes)
    ):
        raise AuditRotationPendingError("pending audit rotation lacks a verified snapshot")
    if proof.orphan is not None:
        if current.prefix.maintenance_intent is not None:
            raise BackupIdentityError("unindexed rotation appeared during maintenance")
        intent, index = _index_for_orphan(root, current, proof, owner)
        number = len(indexes)
        records.extend(
            [
                (
                    "rotation-intent.json",
                    canonical_json_bytes(intent, maximum_bytes=journal.MAX_JOURNAL_BYTES),
                    False,
                ),
                (store.witness_name(number), proof.orphan.witness, True),
                (
                    store.index_name(number),
                    canonical_json_bytes(index, maximum_bytes=formats.MAX_INDEX_BYTES),
                    True,
                ),
            ]
        )
        indexes = (*indexes, index)
    duplicate_rows = []
    for copies in proof.copies:
        number = formats.archive_count(
            copies.descriptor["segmentNumber"], formats.MAX_ARCHIVED_SEGMENTS - 1
        )
        others = tuple(
            value for value in copies.snapshot_ids if value != indexes[number]["snapshotId"]
        )
        if others:
            duplicate_rows.append(
                {
                    "descriptorDigest": indexes[number]["descriptorDigest"],
                    "snapshotIds": list(others),
                }
            )
    duplicate_rows.sort(
        key=lambda row: require_digest(row["descriptorDigest"], formats.DESCRIPTOR_FORMAT)["value"]
    )
    duplicates = journal.decode_duplicates(
        canonical_json_bytes(
            {
                "schema": journal.DUPLICATES_SCHEMA,
                "lineageId": current.lineage["lineageId"],
                "repositoryBinding": current.lineage["repositoryBinding"],
                "entries": duplicate_rows,
            },
            maximum_bytes=journal.MAX_JOURNAL_BYTES,
        )
    )
    records.append(
        (
            "duplicates.json",
            canonical_json_bytes(duplicates, maximum_bytes=journal.MAX_JOURNAL_BYTES),
            False,
        )
    )
    head = store.head_for_indexes(current.lineage, indexes)
    records.append(("head.json", canonical_json_bytes(head), False))
    if intent is not None:
        records.append(
            (
                "rotation-intent.json",
                canonical_json_bytes(
                    {**intent, "phase": "indexed"}, maximum_bytes=journal.MAX_JOURNAL_BYTES
                ),
                False,
            )
        )
    status = journal.decode_protection_status(
        canonical_json_bytes(
            {
                "schema": journal.PROTECTION_SCHEMA,
                "lineageId": current.lineage["lineageId"],
                "repositoryBinding": current.lineage["repositoryBinding"],
                "headDigest": framed_digest(formats.HEAD_FORMAT, canonical_json_bytes(head)),
                "verifiedAt": verified_at,
                "protectedInventoryDigest": proof.inventory_digest,
                "protectedSnapshotCount": len(proof.snapshot_ids),
                "protectedBytes": proof.protected_bytes,
                "category": "verified",
            }
        )
    )
    records.append(("protection-status.json", canonical_json_bytes(status), False))
    publish_records(root, current, owner, records, failure_hook=failure_hook)
    # P3 deliberately leaves every local segment in place. Rotation is a later
    # root-only protocol with another exact-ID proof before unlink.
