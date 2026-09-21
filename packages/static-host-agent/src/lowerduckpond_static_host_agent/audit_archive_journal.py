"""Bounded local intent, duplicate, and verification records for protected audit."""

from __future__ import annotations

import re
from typing import Final

from lowerduckpond_static_contracts import ContractError, validate_uuid7

from lowerduckpond_static_host_agent.audit_archive_formats import (
    DESCRIPTOR_FORMAT,
    HEAD_FORMAT,
    MAX_ARCHIVED_SEGMENTS,
    archive_count,
    archive_object,
    archive_timestamp,
    canonical_archive_object,
    full_snapshot_id,
    validate_rotation,
)
from lowerduckpond_static_host_agent.backup_identity import (
    BINDING_FORMAT,
    BackupIdentityError,
    require_digest,
)

ROTATION_INTENT_SCHEMA: Final = "lowerduckpond-audit-rotation-intent-v1"
DUPLICATES_SCHEMA: Final = "lowerduckpond-audit-duplicates-v1"
MAINTENANCE_SCHEMA: Final = "lowerduckpond-audit-maintenance-intent-v1"
PROTECTION_SCHEMA: Final = "lowerduckpond-audit-protection-status-v1"
PROTECTION_INVENTORY_FORMAT: Final = "lowerduckpond-audit-protected-inventory-v1"
MAX_JOURNAL_BYTES: Final = 2 * 1024 * 1024
MAX_PROTECTED_SNAPSHOTS: Final = 8_192
MAX_STATUS_BYTES: Final = 16 * 1024
_DECIMAL: Final = re.compile(r"0|[1-9][0-9]{0,19}", re.ASCII)
_ROTATION_PHASES: Final = frozenset({"prepared", "discovered", "verified", "indexed"})
_MAINTENANCE_PHASES: Final = frozenset({"prepared", "forgotten", "pruning", "checked"})
_FAILURE_CATEGORIES: Final = frozenset(
    {
        "protection",
        "rotation-pending",
        "index-corruption",
        "archive-unavailable",
        "resource-exhaustion",
    }
)


def snapshot_ids(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_PROTECTED_SNAPSHOTS:
        raise BackupIdentityError("audit snapshot inventory exceeds its bound")
    result = tuple(full_snapshot_id(item) for item in value)
    if result != tuple(sorted(set(result))):
        raise BackupIdentityError("audit snapshot inventory is not sorted and unique")
    return result


def _binding(document: dict[str, object]) -> None:
    try:
        validate_uuid7(document["lineageId"])
    except ContractError as error:
        raise BackupIdentityError("audit journal identity is invalid") from error
    require_digest(document["repositoryBinding"], BINDING_FORMAT)


def decode_rotation_intent(raw: bytes) -> dict[str, object]:
    document = archive_object(
        canonical_archive_object(raw, MAX_JOURNAL_BYTES),
        {"schema", "descriptor", "expectedHeadDigest", "sourceGeneration", "phase", "snapshotIds"},
    )
    if document["schema"] != ROTATION_INTENT_SCHEMA:
        raise BackupIdentityError("unsupported audit rotation intent")
    validate_rotation(document["descriptor"])
    require_digest(document["expectedHeadDigest"], HEAD_FORMAT)
    phase = document["phase"]
    if type(phase) is not str or phase not in _ROTATION_PHASES:
        raise BackupIdentityError("unsupported audit rotation phase")
    generation = document["sourceGeneration"]
    if (
        type(generation) is not list
        or len(generation) != 5  # noqa: PLR2004 - dev, inode, size, mtime_ns, ctime_ns
        or any(type(value) is not str or _DECIMAL.fullmatch(value) is None for value in generation)
    ):
        raise BackupIdentityError("audit rotation source generation is invalid")
    descriptor = validate_rotation(document["descriptor"])
    if any(int(value) > (1 << 64) - 1 for value in generation) or generation[2] != str(
        descriptor["segmentBytes"]
    ):
        raise BackupIdentityError("audit rotation source generation exceeds its bound")
    identifiers = snapshot_ids(document["snapshotIds"])
    if (phase == "prepared") != (not identifiers):
        raise BackupIdentityError("audit rotation phase has inconsistent snapshot authority")
    return document


def decode_duplicates(raw: bytes) -> dict[str, object]:
    document = archive_object(
        canonical_archive_object(raw, MAX_JOURNAL_BYTES),
        {"schema", "lineageId", "repositoryBinding", "entries"},
    )
    if document["schema"] != DUPLICATES_SCHEMA:
        raise BackupIdentityError("unsupported audit duplicate inventory")
    _binding(document)
    entries = document["entries"]
    if type(entries) is not list or len(entries) > MAX_ARCHIVED_SEGMENTS:
        raise BackupIdentityError("audit duplicate descriptor inventory exceeds its bound")
    descriptors: list[str] = []
    identifiers: set[str] = set()
    for value in entries:
        row = archive_object(value, {"descriptorDigest", "snapshotIds"})
        descriptors.append(require_digest(row["descriptorDigest"], DESCRIPTOR_FORMAT)["value"])
        copies = snapshot_ids(row["snapshotIds"])
        if not copies or identifiers.intersection(copies):
            raise BackupIdentityError("audit duplicate snapshot authority is ambiguous")
        identifiers.update(copies)
        if len(identifiers) > MAX_PROTECTED_SNAPSHOTS:
            raise BackupIdentityError("audit duplicate snapshot inventory exceeds its bound")
    if descriptors != sorted(set(descriptors)):
        raise BackupIdentityError("audit duplicate descriptors are not sorted and unique")
    return document


def decode_maintenance_intent(raw: bytes) -> dict[str, object]:
    document = archive_object(
        canonical_archive_object(raw, MAX_JOURNAL_BYTES),
        {
            "schema",
            "maintenanceId",
            "lineageId",
            "repositoryBinding",
            "expectedHeadDigest",
            "protectedInventoryDigest",
            "protectedSnapshotIds",
            "removeIds",
            "phase",
        },
    )
    if document["schema"] != MAINTENANCE_SCHEMA:
        raise BackupIdentityError("unsupported audit maintenance intent")
    _binding(document)
    try:
        validate_uuid7(document["maintenanceId"])
    except ContractError as error:
        raise BackupIdentityError("audit maintenance identity is invalid") from error
    require_digest(document["expectedHeadDigest"], HEAD_FORMAT)
    require_digest(document["protectedInventoryDigest"], PROTECTION_INVENTORY_FORMAT)
    phase = document["phase"]
    if type(phase) is not str or phase not in _MAINTENANCE_PHASES:
        raise BackupIdentityError("unsupported audit maintenance phase")
    protected = snapshot_ids(document["protectedSnapshotIds"])
    removals = snapshot_ids(document["removeIds"])
    if not protected or set(protected).intersection(removals):
        raise BackupIdentityError("audit maintenance would remove protected authority")
    return document


def decode_protection_status(raw: bytes) -> dict[str, object]:
    document = archive_object(
        canonical_archive_object(raw, MAX_STATUS_BYTES),
        {
            "schema",
            "lineageId",
            "repositoryBinding",
            "headDigest",
            "verifiedAt",
            "protectedInventoryDigest",
            "protectedSnapshotCount",
            "protectedBytes",
            "category",
        },
    )
    if document["schema"] != PROTECTION_SCHEMA:
        raise BackupIdentityError("unsupported audit protection status")
    _binding(document)
    require_digest(document["headDigest"], HEAD_FORMAT)
    archive_timestamp(document["verifiedAt"])
    category = document["category"]
    if type(category) is not str or category not in {"verified", *_FAILURE_CATEGORIES}:
        raise BackupIdentityError("unsupported audit protection failure category")
    count = archive_count(document["protectedSnapshotCount"], MAX_PROTECTED_SNAPSHOTS)
    archive_count(document["protectedBytes"], (1 << 53) - 1)
    if category == "verified":
        require_digest(document["protectedInventoryDigest"], PROTECTION_INVENTORY_FORMAT)
        if not count:
            raise BackupIdentityError("audit protection omits permanent lineage evidence")
    elif document["protectedInventoryDigest"] is not None or count:
        raise BackupIdentityError("failed audit protection cannot assert a protected inventory")
    return document
