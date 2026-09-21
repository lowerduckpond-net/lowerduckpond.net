"""Canonical protected-audit descriptors and exact historical lookup witnesses."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractError,
    ContractKind,
    audit_entry_digest,
    canonical_json_bytes,
    decode_contract,
    decode_json_object,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.backup_identity import (
    BINDING_FORMAT,
    BackupIdentityError,
    framed_digest,
    require_digest,
)

ROTATION_SCHEMA: Final = "lowerduckpond-audit-rotation-v1"
DESCRIPTOR_FORMAT: Final = "lowerduckpond-audit-descriptor-v1"
WITNESS_FORMAT: Final = "lowerduckpond-audit-lookup-witness-v1"
INDEX_SCHEMA: Final = "lowerduckpond-audit-index-v1"
INDEX_FORMAT: Final = "lowerduckpond-audit-index-v1"
HEAD_SCHEMA: Final = "lowerduckpond-audit-index-head-v1"
HEAD_FORMAT: Final = "lowerduckpond-audit-index-head-v1"
AUDIT_ENTRY_FORMAT: Final = "lowerduckpond-audit-entry-v1"
ARCHIVE_TAG: Final = "lowerduckpond-audit-archive"
MAX_DESCRIPTOR_BYTES: Final = 16 * 1024
MAX_INDEX_BYTES: Final = 32 * 1024
MAX_SEGMENT_BYTES: Final = 8 * 1024 * 1024
MAX_ARCHIVED_SEGMENTS: Final = 4_096
MAX_WITNESSED_ENTRIES: Final = 65_536
MAX_ARCHIVE_METADATA_BYTES: Final = 32 * 1024 * 1024
MAX_ARCHIVE_METADATA_INODES: Final = 8_192
_HEX: Final = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ROW_FIELDS: Final = (
    "sequence",
    "previousEntryDigest",
    "timestamp",
    "operatorPrincipal",
    "operation",
    "tenantId",
    "correlationId",
    "resultDigest",
    "resultStatus",
    "deletionEvidence",
)


def archive_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise BackupIdentityError("audit archive object has unexpected members")
    return value


def archive_count(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise BackupIdentityError("audit archive count exceeds its bound")
    return value


def full_snapshot_id(value: object) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise BackupIdentityError("audit archive requires a full SHA-256 identity")
    return value


def archive_timestamp(value: object) -> str:
    if type(value) is not str:
        raise BackupIdentityError("audit archive time is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise BackupIdentityError("audit archive time is invalid") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise BackupIdentityError("audit archive time is not canonical")
    return value


def canonical_archive_object(raw: bytes, maximum: int) -> dict[str, object]:
    try:
        value = decode_json_object(raw, maximum_bytes=maximum)
        if canonical_json_bytes(value, maximum_bytes=maximum) != raw:
            raise BackupIdentityError("audit archive bytes are not canonical")
        return value
    except ContractError as error:
        raise BackupIdentityError("audit archive JSON is invalid") from error


def segment_name(number: int) -> str:
    return f"segment-{archive_count(number, MAX_ARCHIVED_SEGMENTS - 1):020d}.jsonl"


def _position_digest(value: object, position: int, format_identifier: str) -> None:
    if position == 0:
        if value is not None:
            raise BackupIdentityError("empty audit archive boundary has a digest")
    else:
        require_digest(value, format_identifier)


def validate_rotation(value: object) -> dict[str, object]:
    document = archive_object(
        value,
        {
            "schema",
            "rotationId",
            "lineageId",
            "repositoryBinding",
            "createdAt",
            "segmentNumber",
            "segmentName",
            "firstSequence",
            "lastSequence",
            "entryCount",
            "segmentBytes",
            "segmentSha256",
            "predecessorEntryDigest",
            "terminalEntryDigest",
            "previousDescriptorDigest",
            "witnessFormat",
            "witnessBytes",
            "witnessDigest",
        },
    )
    if document["schema"] != ROTATION_SCHEMA or document["witnessFormat"] != WITNESS_FORMAT:
        raise BackupIdentityError("unsupported audit archive format")
    try:
        validate_uuid7(document["rotationId"])
        validate_uuid7(document["lineageId"])
    except ContractError as error:
        raise BackupIdentityError("audit archive identity is invalid") from error
    require_digest(document["repositoryBinding"], BINDING_FORMAT)
    archive_timestamp(document["createdAt"])
    number = archive_count(document["segmentNumber"], MAX_ARCHIVED_SEGMENTS - 1)
    first = archive_count(document["firstSequence"], MAX_WITNESSED_ENTRIES - 1)
    last = archive_count(document["lastSequence"], MAX_WITNESSED_ENTRIES - 1)
    count = archive_count(document["entryCount"], MAX_WITNESSED_ENTRIES)
    size = archive_count(document["segmentBytes"], MAX_SEGMENT_BYTES)
    witness_size = archive_count(document["witnessBytes"], MAX_SEGMENT_BYTES)
    if (
        document["segmentName"] != segment_name(number)
        or (number == 0) != (first == 0)
        or not count
        or last - first + 1 != count
        or not size
        or not 0 < witness_size <= size
    ):
        raise BackupIdentityError("audit archive segment boundary is invalid")
    full_snapshot_id(document["segmentSha256"])
    _position_digest(document["predecessorEntryDigest"], first, AUDIT_ENTRY_FORMAT)
    require_digest(document["terminalEntryDigest"], AUDIT_ENTRY_FORMAT)
    _position_digest(document["previousDescriptorDigest"], number, DESCRIPTOR_FORMAT)
    require_digest(document["witnessDigest"], WITNESS_FORMAT)
    canonical_json_bytes(document, maximum_bytes=MAX_DESCRIPTOR_BYTES)
    return document


def decode_rotation(raw: bytes) -> dict[str, object]:
    return validate_rotation(canonical_archive_object(raw, MAX_DESCRIPTOR_BYTES))


@dataclass(frozen=True, slots=True)
class SegmentEvidence:
    first_sequence: int
    entry_count: int
    predecessor: dict[str, str] | None
    terminal: dict[str, str]
    witness: bytes


def inspect_segment(raw: bytes) -> SegmentEvidence:
    """Validate one exact canonical segment, preserving all original entry fields."""
    if not raw or len(raw) > MAX_SEGMENT_BYTES or not raw.endswith(b"\n"):
        raise BackupIdentityError("audit archive segment exceeds its byte boundary")
    rows: list[list[object]] = []
    seen: set[str] = set()
    first = 0
    predecessor: dict[str, str] | None = None
    terminal: dict[str, str] | None = None
    try:
        for line in raw.splitlines(keepends=True):
            document = decode_contract(
                line, expected_kind=ContractKind.AUDIT_ENTRY, maximum_raw_bytes=MAX_CANONICAL_BYTES
            )
            if canonical_json_bytes(document) != line:
                raise BackupIdentityError("audit archive entry is not canonical")
            sequence = archive_count(document["sequence"], MAX_WITNESSED_ENTRIES - 1)
            previous = document["previousEntryDigest"]
            if not rows:
                first = sequence
                predecessor = (
                    None if previous is None else require_digest(previous, AUDIT_ENTRY_FORMAT)
                )
                terminal = predecessor
            if sequence != first + len(rows) or previous != terminal:
                raise BackupIdentityError("audit archive segment breaks its hash chain")
            correlation = validate_uuid7(document["correlationId"])
            if correlation in seen:
                raise BackupIdentityError("audit archive repeats a correlation")
            seen.add(correlation)
            rows.append([document.get(key) for key in _ROW_FIELDS])
            if len(rows) > MAX_WITNESSED_ENTRIES:
                raise BackupIdentityError("audit archive witness exceeds its entry boundary")
            terminal = audit_entry_digest(document).to_dict()
        witness = canonical_json_bytes(rows, maximum_bytes=MAX_SEGMENT_BYTES)
    except ContractError as error:
        raise BackupIdentityError("audit archive contains an invalid entry") from error
    assert terminal is not None  # noqa: S101 - nonempty validated segment
    return SegmentEvidence(first, len(rows), predecessor, terminal, witness)


def segment_from_witness(raw: bytes) -> bytes:
    """Expand the fixed-order rows without inventing or dropping historical fields."""
    if len(raw) > MAX_SEGMENT_BYTES:
        raise BackupIdentityError("audit archive witness exceeds its byte boundary")
    try:
        wrapped = decode_json_object(b'{"rows":' + raw + b"}", maximum_bytes=MAX_SEGMENT_BYTES + 16)
        rows = wrapped.get("rows")
        if (
            set(wrapped) != {"rows"}
            or type(rows) is not list
            or not 0 < len(rows) <= MAX_WITNESSED_ENTRIES
            or canonical_json_bytes(rows, maximum_bytes=MAX_SEGMENT_BYTES) != raw
        ):
            raise BackupIdentityError("audit archive witness is not a canonical row array")
        result = bytearray()
        for row in rows:
            if type(row) is not list or len(row) != len(_ROW_FIELDS):
                raise BackupIdentityError("audit archive witness row has unexpected members")
            document = {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "AuditEntry",
                **dict(zip(_ROW_FIELDS, row, strict=True)),
            }
            if document["deletionEvidence"] is None:
                del document["deletionEvidence"]
            validate_contract(document, expected_kind=ContractKind.AUDIT_ENTRY)
            result.extend(canonical_json_bytes(document))
            if len(result) > MAX_SEGMENT_BYTES:
                raise BackupIdentityError("audit archive witness expands beyond one segment")
    except ContractError as error:
        raise BackupIdentityError("audit archive witness contains an invalid entry") from error
    segment = bytes(result)
    if inspect_segment(segment).witness != raw:
        raise BackupIdentityError("audit archive witness does not preserve its segment")
    return segment


def verify_segment(descriptor: dict[str, object], raw: bytes) -> SegmentEvidence:
    validate_rotation(descriptor)
    evidence = inspect_segment(raw)
    if (
        len(raw) != descriptor["segmentBytes"]
        or hashlib.sha256(raw).hexdigest() != descriptor["segmentSha256"]
        or evidence.first_sequence != descriptor["firstSequence"]
        or evidence.entry_count != descriptor["entryCount"]
        or evidence.predecessor != descriptor["predecessorEntryDigest"]
        or evidence.terminal != descriptor["terminalEntryDigest"]
        or len(evidence.witness) != descriptor["witnessBytes"]
        or framed_digest(WITNESS_FORMAT, evidence.witness) != descriptor["witnessDigest"]
    ):
        raise BackupIdentityError("restored audit segment disagrees with its descriptor")
    return evidence


def required_archive_tags(descriptor: dict[str, object]) -> tuple[str, ...]:
    validate_rotation(descriptor)
    binding = require_digest(descriptor["repositoryBinding"], BINDING_FORMAT)
    return tuple(
        sorted(
            (
                ARCHIVE_TAG,
                f"lineage-{descriptor['lineageId']}",
                f"rotation-{descriptor['rotationId']}",
                f"repository-{binding['value']}",
            )
        )
    )


def decode_index(raw: bytes) -> dict[str, object]:
    document = archive_object(
        canonical_archive_object(raw, MAX_INDEX_BYTES),
        {
            "schema",
            "descriptor",
            "snapshotId",
            "requiredTags",
            "descriptorDigest",
            "witnessDigest",
            "previousIndexDigest",
        },
    )
    if document["schema"] != INDEX_SCHEMA:
        raise BackupIdentityError("unsupported audit index format")
    descriptor = validate_rotation(document["descriptor"])
    full_snapshot_id(document["snapshotId"])
    expected = framed_digest(DESCRIPTOR_FORMAT, canonical_json_bytes(descriptor))
    if (
        document["requiredTags"] != list(required_archive_tags(descriptor))
        or document["descriptorDigest"] != expected
        or document["witnessDigest"] != descriptor["witnessDigest"]
    ):
        raise BackupIdentityError("audit index binding disagrees with its descriptor")
    _position_digest(
        document["previousIndexDigest"],
        archive_count(descriptor["segmentNumber"], MAX_ARCHIVED_SEGMENTS - 1),
        INDEX_FORMAT,
    )
    return document


def decode_head(raw: bytes) -> dict[str, object]:
    document = archive_object(
        canonical_archive_object(raw, MAX_DESCRIPTOR_BYTES),
        {
            "schema",
            "lineageId",
            "repositoryBinding",
            "indexCount",
            "entryCount",
            "terminalEntryDigest",
            "lastIndexDigest",
            "lastDescriptorDigest",
        },
    )
    if document["schema"] != HEAD_SCHEMA:
        raise BackupIdentityError("unsupported audit index head format")
    try:
        validate_uuid7(document["lineageId"])
    except ContractError as error:
        raise BackupIdentityError("audit index head identity is invalid") from error
    require_digest(document["repositoryBinding"], BINDING_FORMAT)
    count = archive_count(document["indexCount"], MAX_ARCHIVED_SEGMENTS)
    entries = archive_count(document["entryCount"], MAX_WITNESSED_ENTRIES)
    if (count == 0) != (entries == 0) or count > entries:
        raise BackupIdentityError("audit index head has an invalid chain boundary")
    for key, format_identifier in (
        ("terminalEntryDigest", AUDIT_ENTRY_FORMAT),
        ("lastIndexDigest", INDEX_FORMAT),
        ("lastDescriptorDigest", DESCRIPTOR_FORMAT),
    ):
        _position_digest(document[key], count, format_identifier)
    return document
