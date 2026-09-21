"""Read and bind the bounded local archive prefix without repairing authority."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent.backup_identity import (
    GENESIS_PATH,
    LINEAGE_PATH,
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    decode_lineage,
    framed_digest,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, validate_state_directory

_INDEX_NAME: Final = re.compile(r"index-([0-9]{20})\.json", re.ASCII)
_WITNESS_NAME: Final = re.compile(r"witness-([0-9]{20})\.json", re.ASCII)
_RECORD_MODE: Final = 0o600
_RECORD_LIMITS: Final = {
    "head.json": formats.MAX_DESCRIPTOR_BYTES,
    "rotation-intent.json": journal.MAX_JOURNAL_BYTES,
    "duplicates.json": journal.MAX_JOURNAL_BYTES,
    "maintenance-intent.json": journal.MAX_JOURNAL_BYTES,
    "protection-status.json": journal.MAX_STATUS_BYTES,
}


@dataclass(frozen=True, slots=True)
class ArchivedSegment:
    index: dict[str, object]
    witness: bytes

    @property
    def descriptor(self) -> dict[str, object]:
        return formats.validate_rotation(self.index["descriptor"])

    @property
    def data(self) -> bytes:
        # Keep only bounded witness bytes between passes. Never inflate the
        # complete archived history into resident canonical segment copies.
        return formats.segment_from_witness(self.witness)


@dataclass(frozen=True, slots=True)
class ArchivePrefix:
    head: dict[str, object] | None
    segments: tuple[ArchivedSegment, ...] = ()
    allocated_bytes: int = 0
    inodes: int = 0
    rotation_intent: dict[str, object] | None = None
    duplicates: dict[str, object] | None = None
    maintenance_intent: dict[str, object] | None = None
    protection_status: dict[str, object] | None = None
    pending_index: dict[str, object] | None = None
    pending_witness: bytes | None = None


def index_name(number: int) -> str:
    return f"index-{formats.archive_count(number, formats.MAX_ARCHIVED_SEGMENTS - 1):020d}.json"


def witness_name(number: int) -> str:
    return f"witness-{formats.archive_count(number, formats.MAX_ARCHIVED_SEGMENTS - 1):020d}.json"


def head_for_indexes(
    lineage: dict[str, object], indexes: tuple[dict[str, object], ...]
) -> dict[str, object]:
    terminal: dict[str, object] | None = None
    if indexes:
        terminal = formats.validate_rotation(indexes[-1]["descriptor"])
    head = {
        "schema": formats.HEAD_SCHEMA,
        "lineageId": lineage["lineageId"],
        "repositoryBinding": lineage["repositoryBinding"],
        "indexCount": len(indexes),
        "entryCount": 0
        if terminal is None
        else formats.archive_count(terminal["lastSequence"], formats.MAX_WITNESSED_ENTRIES - 1) + 1,
        "terminalEntryDigest": None if terminal is None else terminal["terminalEntryDigest"],
        "lastIndexDigest": None
        if not indexes
        else framed_digest(
            formats.INDEX_FORMAT,
            canonical_json_bytes(indexes[-1], maximum_bytes=formats.MAX_INDEX_BYTES),
        ),
        "lastDescriptorDigest": None if not indexes else indexes[-1]["descriptorDigest"],
    }
    return formats.decode_head(canonical_json_bytes(head))


def _generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_blocks,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _names(descriptor: int) -> tuple[str, ...]:
    names = []
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            names.append(entry.name)
            if len(names) + 1 > formats.MAX_ARCHIVE_METADATA_INODES:
                raise BackupIdentityError("audit archive metadata exceeds its inode bound")
    return tuple(sorted(names))


def _inventory(directory: DurableDirectory, owner: int) -> tuple[dict[str, bytes], int, int]:
    temporaries = directory.publication_temporaries(
        expected_owner=owner,
        expected_mode=0o600,
        maximum_entries=formats.MAX_ARCHIVE_METADATA_INODES,
    )
    descriptor = directory.duplicate_descriptor()
    try:
        before = validate_state_directory(descriptor, expected_owner=owner, expected_mode=0o700)
        names = _names(descriptor)
        allocated = before.st_blocks * 512
        logical = 0
        metadata = {}
        limits = {}
        for name in names:
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or current.st_uid != owner
                or stat.S_IMODE(current.st_mode) != _RECORD_MODE
                or current.st_dev != before.st_dev
            ):
                raise BackupIdentityError("audit archive record has unsafe inode metadata")
            limit = _RECORD_LIMITS.get(name)
            if _INDEX_NAME.fullmatch(name):
                limit = formats.MAX_INDEX_BYTES
            elif _WITNESS_NAME.fullmatch(name):
                limit = formats.MAX_SEGMENT_BYTES
            elif name in temporaries:
                limit = formats.MAX_ARCHIVE_METADATA_BYTES
            if limit is None or current.st_size > limit:
                raise BackupIdentityError("audit archive contains an unknown or oversized record")
            logical += current.st_size
            allocated += current.st_blocks * 512
            if max(logical, allocated) > formats.MAX_ARCHIVE_METADATA_BYTES:
                raise BackupIdentityError("audit archive metadata exceeds its byte bound")
            metadata[name] = current
            limits[name] = limit
        result = {}
        for name in names:
            if name not in temporaries:
                result[name] = directory.read_regular(
                    (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=limits[name]
                )
            after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _generation(after) != _generation(metadata[name]):
                raise BackupIdentityError("audit archive record changed while it was read")
        after = validate_state_directory(descriptor, expected_owner=owner, expected_mode=0o700)
        if _names(descriptor) != names or _generation(after) != _generation(before):
            raise BackupIdentityError("audit archive directory changed while it was read")
        return result, allocated, len(names) + 1
    finally:
        os.close(descriptor)


def _lineage(root: DurableDirectory, owner: int) -> dict[str, object]:
    primary = decode_lineage(
        root.read_regular(
            LINEAGE_PATH,
            expected_owner=owner,
            expected_mode=0o600,
            maximum_bytes=MAX_IDENTITY_BYTES,
        )
    )
    genesis = decode_lineage(
        root.read_regular(
            GENESIS_PATH,
            expected_owner=owner,
            expected_mode=0o600,
            maximum_bytes=MAX_IDENTITY_BYTES,
        )
    )
    if primary != genesis:
        raise BackupIdentityError("audit archive lineage disagrees with immutable genesis")
    return primary


def _require_binding(record: dict[str, object], lineage: dict[str, object]) -> None:
    if any(record[key] != lineage[key] for key in ("lineageId", "repositoryBinding")):
        raise BackupIdentityError("audit archive belongs to another lineage or repository")


def _require_extension(
    index: dict[str, object], expected: dict[str, object], lineage: dict[str, object]
) -> None:
    descriptor = formats.validate_rotation(index["descriptor"])
    _require_binding(descriptor, lineage)
    if (
        descriptor["segmentNumber"] != expected["indexCount"]
        or descriptor["firstSequence"] != expected["entryCount"]
        or descriptor["predecessorEntryDigest"] != expected["terminalEntryDigest"]
        or descriptor["previousDescriptorDigest"] != expected["lastDescriptorDigest"]
        or index["previousIndexDigest"] != expected["lastIndexDigest"]
    ):
        raise BackupIdentityError("audit archive index is not a contiguous prefix")


def _require_witness(index: dict[str, object], witness: bytes) -> None:
    descriptor = formats.validate_rotation(index["descriptor"])
    if framed_digest(formats.WITNESS_FORMAT, witness) != descriptor["witnessDigest"]:
        raise BackupIdentityError("audit archive witness disagrees with its immutable index")
    formats.verify_segment(descriptor, formats.segment_from_witness(witness))


def _pending(  # noqa: PLR0913 - complete captured local authority
    raw: dict[str, bytes],
    *,
    lineage: dict[str, object],
    head: dict[str, object],
    indexes: tuple[dict[str, object], ...],
    intent: dict[str, object] | None,
    expected_names: set[str],
) -> tuple[dict[str, object] | None, bytes | None]:
    if intent is None:
        return None, None
    descriptor = formats.validate_rotation(intent["descriptor"])
    _require_binding(descriptor, lineage)
    number = formats.archive_count(descriptor["segmentNumber"], formats.MAX_ARCHIVED_SEGMENTS - 1)
    if number not in {len(indexes), len(indexes) - 1}:
        raise BackupIdentityError("audit rotation intent has an unrelated prefix position")
    committed = number < len(indexes)
    expected_head = head_for_indexes(lineage, indexes[:number])
    _require_extension(
        {"descriptor": descriptor, "previousIndexDigest": expected_head["lastIndexDigest"]},
        expected_head,
        lineage,
    )
    if intent["expectedHeadDigest"] != framed_digest(
        formats.HEAD_FORMAT, canonical_json_bytes(expected_head)
    ):
        raise BackupIdentityError("audit rotation intent expected another index head")
    names = (index_name(number), witness_name(number))
    expected_names.update(names)
    pending_index = formats.decode_index(raw[names[0]]) if names[0] in raw else None
    pending_witness = raw.get(names[1])
    if (pending_index is not None or pending_witness is not None) and intent["phase"] not in {
        "verified",
        "indexed",
    }:
        raise BackupIdentityError("audit rotation published authority before verification")
    if committed:
        if indexes[number]["descriptor"] != descriptor or head["indexCount"] != number + 1:
            raise BackupIdentityError("audit rotation intent conflicts with the committed index")
    elif intent["phase"] == "indexed":
        raise BackupIdentityError("audit rotation lost its committed index head")
    if pending_index is not None:
        _require_extension(pending_index, expected_head, lineage)
        if pending_index["descriptor"] != descriptor or pending_index[
            "snapshotId"
        ] not in journal.snapshot_ids(intent["snapshotIds"]):
            raise BackupIdentityError("audit pending index differs from its rotation attempt")
        if pending_witness is None:
            raise BackupIdentityError("audit pending index lacks its verified witness")
        _require_witness(pending_index, pending_witness)
    elif pending_witness is not None:
        formats.verify_segment(descriptor, formats.segment_from_witness(pending_witness))
    return (None, None) if committed else (pending_index, pending_witness)


def read_archive_prefix(root: DurableDirectory, *, expected_owner: int) -> ArchivePrefix:
    """Caller holds state shared/exclusive; no temporary or missing-file repair."""
    try:
        directory = root.open_descendant(("audit", "archive"))
    except FileNotFoundError:
        return ArchivePrefix(None)
    with directory:
        raw, allocated, inodes = _inventory(directory, expected_owner)
    if "head.json" not in raw:
        raise BackupIdentityError(
            "audit archive head is missing; explicit initialization is required"
        )
    lineage = _lineage(root, expected_owner)
    head = formats.decode_head(raw["head.json"])
    _require_binding(head, lineage)
    count = formats.archive_count(head["indexCount"], formats.MAX_ARCHIVED_SEGMENTS)
    expected_names = set(_RECORD_LIMITS)
    indexes: list[dict[str, object]] = []
    segments = []
    snapshots: set[str] = set()
    for number in range(count):
        names = (index_name(number), witness_name(number))
        expected_names.update(names)
        if any(name not in raw for name in names):
            raise BackupIdentityError("audit archive index or witness is missing")
        index = formats.decode_index(raw[names[0]])
        _require_extension(index, head_for_indexes(lineage, tuple(indexes)), lineage)
        snapshot = formats.full_snapshot_id(index["snapshotId"])
        if snapshot in snapshots:
            raise BackupIdentityError("audit archive indexes reuse a snapshot identity")
        snapshots.add(snapshot)
        _require_witness(index, raw[names[1]])
        indexes.append(index)
        segments.append(ArchivedSegment(index, raw[names[1]]))
    if head_for_indexes(lineage, tuple(indexes)) != head:
        raise BackupIdentityError("audit archive head disagrees with its immutable index chain")
    rotation = (
        journal.decode_rotation_intent(raw["rotation-intent.json"])
        if "rotation-intent.json" in raw
        else None
    )
    pending_index, pending_witness = _pending(
        raw,
        lineage=lineage,
        head=head,
        indexes=tuple(indexes),
        intent=rotation,
        expected_names=expected_names,
    )
    if not set(raw).issubset(expected_names):
        raise BackupIdentityError("audit archive contains uncommitted authority without an intent")
    duplicates = (
        journal.decode_duplicates(raw["duplicates.json"]) if "duplicates.json" in raw else None
    )
    if duplicates is not None:
        _require_binding(duplicates, lineage)
        _require_duplicates(duplicates, tuple(indexes), rotation, snapshots)
    maintenance = (
        journal.decode_maintenance_intent(raw["maintenance-intent.json"])
        if "maintenance-intent.json" in raw
        else None
    )
    if maintenance is not None:
        _require_binding(maintenance, lineage)
        if maintenance["expectedHeadDigest"] != framed_digest(
            formats.HEAD_FORMAT, raw["head.json"]
        ):
            raise BackupIdentityError("audit maintenance intent expected another index head")
    status = (
        journal.decode_protection_status(raw["protection-status.json"])
        if "protection-status.json" in raw
        else None
    )
    return ArchivePrefix(
        head,
        tuple(segments),
        allocated,
        inodes,
        rotation,
        duplicates,
        maintenance,
        status,
        pending_index,
        pending_witness,
    )


def _require_duplicates(
    duplicates: dict[str, object],
    indexes: tuple[dict[str, object], ...],
    rotation: dict[str, object] | None,
    snapshots: set[str],
) -> None:
    allowed = [index["descriptorDigest"] for index in indexes]
    if rotation is not None:
        allowed.append(
            framed_digest(formats.DESCRIPTOR_FORMAT, canonical_json_bytes(rotation["descriptor"]))
        )
    entries = duplicates["entries"]
    assert type(entries) is list  # noqa: S101 - decoded above
    for entry in entries:
        assert type(entry) is dict  # noqa: S101 - decoded above
        if entry["descriptorDigest"] not in allowed or snapshots.intersection(
            journal.snapshot_ids(entry["snapshotIds"])
        ):
            raise BackupIdentityError("audit duplicates do not extend known immutable authority")
