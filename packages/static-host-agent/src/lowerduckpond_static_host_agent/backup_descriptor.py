"""Strict bounded recovery descriptor for one coherent static backup boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from lowerduckpond_static_contracts import (
    ContractError,
    ContractKind,
    canonical_json_bytes,
    decode_json_object,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.backup_identity import (
    MAX_LINEAGE_ENTRIES,
    BackupIdentityError,
    framed_digest,
    require_digest,
    validate_lineage,
)
from lowerduckpond_static_host_agent.backup_sources import (
    MAX_TREE_BYTES,
    MAX_TREE_ENTRIES,
    TREE_FORMAT,
    source_policy_digest,
)

BACKUP_SCHEMA: Final = "lowerduckpond-static-backup-v1"
MAX_BACKUP_DESCRIPTOR_BYTES: Final = 256 * 1024
# The artifact identity remains the existing SHA-256 of the built tar bytes.
ARTIFACT_DIGEST_FORMAT: Final = "lowerduckpond-static-host-agent-artifact-v1"
LAUNCH_DIGEST_FORMAT: Final = "lowerduckpond-backup-launch-record-v1"
OBSERVED_DIGEST_FORMAT: Final = "lowerduckpond-backup-observed-state-v1"
INTENT_DIGEST_FORMAT: Final = "lowerduckpond-backup-intent-v1"
MAX_BACKUP_TENANTS: Final = 25
# Three retained deployments plus an interrupted candidate; this is a capture
# bound, never admission authority for a new tenant/release mutation.
MAX_BACKUP_DEPLOYMENTS: Final = 4
MAX_BACKUP_INTENTS: Final = 2
_INTENT_KINDS: Final = frozenset(
    {
        ContractKind.TRANSACTION_INTENT.value,
        ContractKind.EMERGENCY_DELETION_INTENT.value,
        ContractKind.ARCHIVE_CONSTRUCTION_INTENT.value,
        ContractKind.ARCHIVE_RETIREMENT_INTENT.value,
    }
)


def _object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise BackupIdentityError("backup descriptor object has unexpected members")
    return value


def _count(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise BackupIdentityError("backup descriptor count exceeds its bound")
    return value


def _timestamp(value: object) -> str:
    if type(value) is not str:
        raise BackupIdentityError("backup capture time is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise BackupIdentityError("backup capture time is invalid") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise BackupIdentityError("backup capture time is not canonical")
    return value


def _optional_digest(value: object, format_identifier: str) -> None:
    if value is not None:
        require_digest(value, format_identifier)


def _rows(value: object, maximum: int) -> list[object]:
    if type(value) is not list or len(value) > maximum:
        raise BackupIdentityError("backup descriptor inventory exceeds its bound")
    return value


def _ordered_ids(identifiers: list[str]) -> None:
    if identifiers != sorted(set(identifiers)):
        raise BackupIdentityError("backup descriptor inventory is not sorted and unique")


def _deployments(value: object, *, digest_key: str, format_identifier: str) -> None:
    identifiers = []
    for item in _rows(value, MAX_BACKUP_DEPLOYMENTS):
        row = _object(item, {"deploymentId", digest_key})
        identifiers.append(validate_uuid7(row["deploymentId"]))
        require_digest(row[digest_key], format_identifier)
    _ordered_ids(identifiers)


def _tenants(value: object) -> None:
    identifiers = []
    for item in _rows(value, MAX_BACKUP_TENANTS):
        row = _object(
            item,
            {
                "tenantId",
                "desiredDigest",
                "observedDigest",
                "deployments",
                "archives",
                "releases",
            },
        )
        identifiers.append(validate_uuid7(row["tenantId"]))
        _optional_digest(row["desiredDigest"], "lowerduckpond-manifest-v1")
        _optional_digest(row["observedDigest"], OBSERVED_DIGEST_FORMAT)
        for key, format_identifier in (
            ("deployments", "lowerduckpond-deployment-record-v1"),
            ("archives", "lowerduckpond-archive-record-v1"),
            ("releases", "lowerduckpond-release-tree-v1"),
        ):
            _deployments(
                row[key],
                digest_key="treeDigest" if key == "releases" else "recordDigest",
                format_identifier=format_identifier,
            )
    _ordered_ids(identifiers)


def _intents(value: object) -> None:
    identifiers = []
    for item in _rows(value, MAX_BACKUP_INTENTS):
        row = _object(item, {"intentId", "tenantId", "kind", "digest"})
        identifiers.append(validate_uuid7(row["intentId"]))
        validate_uuid7(row["tenantId"])
        if type(row["kind"]) is not str or row["kind"] not in _INTENT_KINDS:
            raise BackupIdentityError("backup descriptor intent kind is invalid")
        require_digest(row["digest"], INTENT_DIGEST_FORMAT)
    _ordered_ids(identifiers)


def validate_backup_descriptor(document: dict[str, object]) -> dict[str, object]:
    """Validate structure and internal bindings, without granting restore authority.

    Restore must separately verify repository/snapshot/descriptor binding, the
    actual restored tree and contracts, audit history, exact remote versions,
    and interrupted operations. Schema acceptance alone never permits service.
    """

    canonical_json_bytes(document, maximum_bytes=MAX_BACKUP_DESCRIPTOR_BYTES)
    _object(
        document,
        {
            "schema",
            "captureId",
            "capturedAt",
            "sourcePolicyDigest",
            "artifactDigest",
            "lineage",
            "namespaceDigest",
            "launchDigest",
            "audit",
            "authority",
            "tenants",
            "intents",
            "caddy",
        },
    )
    if document["schema"] != BACKUP_SCHEMA:
        raise BackupIdentityError("backup descriptor schema is unsupported")
    validate_uuid7(document["captureId"])
    captured_at = _timestamp(document["capturedAt"])
    if document["sourcePolicyDigest"] != source_policy_digest():
        raise BackupIdentityError("backup descriptor source policy is unsupported")
    require_digest(document["artifactDigest"], ARTIFACT_DIGEST_FORMAT)
    lineage = document["lineage"]
    if type(lineage) is not dict:
        raise BackupIdentityError("backup descriptor lineage is invalid")
    validate_lineage(lineage)
    initialized_at = lineage["initializedAt"]
    assert type(initialized_at) is str  # noqa: S101 - validate_lineage proves this
    if captured_at < initialized_at:
        raise BackupIdentityError("backup capture predates its lineage")
    if document["namespaceDigest"] != lineage["namespaceDigest"]:
        raise BackupIdentityError("backup namespace disagrees with its lineage")
    _optional_digest(document["launchDigest"], LAUNCH_DIGEST_FORMAT)
    audit = _object(document["audit"], {"entryCount", "segmentCount", "terminalEntryDigest"})
    entries = _count(audit["entryCount"], MAX_LINEAGE_ENTRIES)
    segments = _count(audit["segmentCount"], MAX_LINEAGE_ENTRIES)
    if segments > entries or (entries > 0 and segments == 0):
        raise BackupIdentityError("backup audit segment count is inconsistent")
    if entries == 0:
        if audit["terminalEntryDigest"] is not None:
            raise BackupIdentityError("empty backup audit has terminal authority")
    else:
        require_digest(audit["terminalEntryDigest"], "lowerduckpond-audit-entry-v1")
    initial_entries = lineage["initialEntryCount"]
    assert type(initial_entries) is int  # noqa: S101 - validate_lineage proves this
    if entries < initial_entries or (
        entries == initial_entries
        and audit["terminalEntryDigest"] != lineage["initialTerminalEntryDigest"]
    ):
        raise BackupIdentityError("backup audit predates or forks its lineage")
    authority = _object(document["authority"], {"treeDigest", "entryCount", "contentBytes"})
    require_digest(authority["treeDigest"], TREE_FORMAT)
    if not _count(authority["entryCount"], MAX_TREE_ENTRIES):
        raise BackupIdentityError("backup authority has no source roots")
    _count(authority["contentBytes"], MAX_TREE_BYTES)
    _tenants(document["tenants"])
    _intents(document["intents"])
    CaddyBackupEvidence.from_dict(document["caddy"])
    return document


def encode_backup_descriptor(document: dict[str, object]) -> bytes:
    return canonical_json_bytes(
        validate_backup_descriptor(document),
        maximum_bytes=MAX_BACKUP_DESCRIPTOR_BYTES,
    )


def decode_backup_descriptor(raw: bytes) -> dict[str, object]:
    try:
        document = decode_json_object(raw, maximum_bytes=MAX_BACKUP_DESCRIPTOR_BYTES)
        if encode_backup_descriptor(document) != raw:
            raise BackupIdentityError("backup descriptor bytes are not canonical")
        return document
    except ContractError as error:
        raise BackupIdentityError("backup descriptor contains invalid contract evidence") from error


def backup_descriptor_digest(raw: bytes) -> dict[str, str]:
    decode_backup_descriptor(raw)
    return framed_digest(BACKUP_SCHEMA, raw)
