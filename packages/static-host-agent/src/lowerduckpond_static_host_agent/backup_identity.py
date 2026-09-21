"""Private, canonical repository binding and immutable audit-lineage records."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Final
from urllib.parse import urlsplit

from lowerduckpond_static_contracts import (
    ContractError,
    canonical_json_bytes,
    decode_json_object,
    validate_uuid7,
)

IDENTITY_SCHEMA: Final = "lowerduckpond-backup-repository-v1"
BINDING_FORMAT: Final = "lowerduckpond-backup-repository-binding-v1"
LINEAGE_SCHEMA: Final = "lowerduckpond-audit-lineage-v1"
LINEAGE_PATH: Final = ("platform", "audit-lineage.json")
GENESIS_PATH: Final = ("locks", "audit-lineage-genesis.json")
MAX_IDENTITY_BYTES: Final = 16 * 1024
MAX_LINEAGE_ENTRIES: Final = (1 << 53) - 1
_HEX: Final = re.compile(r"[0-9a-f]{64}", re.ASCII)
_NODE: Final = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}", re.ASCII)
_COMPONENT: Final = re.compile(r"[a-zA-Z0-9_.-]+", re.ASCII)
_FORMAT: Final = re.compile(r"lowerduckpond-[a-z0-9]+(?:-[a-z0-9]+)*-v1", re.ASCII)


class BackupIdentityError(RuntimeError):
    """Backup authority cannot be established without replacing history."""


def framed_digest(format_identifier: str, payload: bytes) -> dict[str, str]:
    """M3.11 H: domain, NUL, unsigned 64-bit length, exact canonical bytes.

    Existing contract/audit digests keep their original 32-bit framing; this
    helper is only for the newly versioned backup/recovery formats in ADR 0030.
    """
    if _FORMAT.fullmatch(format_identifier) is None:
        raise BackupIdentityError("unsupported backup digest format")
    value = hashlib.sha256(
        format_identifier.encode("ascii") + b"\0" + len(payload).to_bytes(8, "big") + payload
    ).hexdigest()
    return {"format": format_identifier, "algorithm": "sha256", "value": value}


def require_digest(value: object, format_identifier: str) -> dict[str, str]:
    if (
        type(value) is not dict
        or set(value) != {"format", "algorithm", "value"}
        or value["format"] != format_identifier
        or value["algorithm"] != "sha256"
        or type(value["value"]) is not str
        or _HEX.fullmatch(value["value"]) is None
    ):
        raise BackupIdentityError("invalid backup digest")
    return {"format": format_identifier, "algorithm": "sha256", "value": value["value"]}


def canonical_locator(repository: str) -> str:
    """Normalize supported Restic local/S3 locators without accepting credentials.

    Prefix components remain case sensitive. Reject ambiguous dot, URL-encoded,
    query, fragment and repeated-slash paths rather than binding a different
    location from the one passed to Restic.
    """
    if type(repository) is not str or not repository or len(repository) > 4096:  # noqa: PLR2004
        raise BackupIdentityError("invalid backup repository locator")
    if repository.startswith("/"):
        if repository.startswith("//") or "\0" in repository:
            raise BackupIdentityError("invalid local backup repository locator")
        resolved = PurePosixPath(repository)
        if ".." in resolved.parts or resolved == PurePosixPath("/"):
            raise BackupIdentityError("invalid local backup repository locator")
        return str(resolved)
    if not repository.startswith("s3:"):
        raise BackupIdentityError("unsupported backup repository backend")
    address = repository.removeprefix("s3:")
    if address.startswith("//"):
        address = address.removeprefix("//")
    if "://" not in address:
        address = "https://" + address
    try:
        parsed = urlsplit(address)
        port = parsed.port
    except ValueError as error:
        raise BackupIdentityError("invalid S3 backup repository locator") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or _NODE.fullmatch(parsed.hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or any(character.isspace() or ord(character) < 32 for character in address)  # noqa: PLR2004
    ):
        raise BackupIdentityError("unsafe S3 backup repository locator")
    parts = parsed.path.removeprefix("/").removesuffix("/").split("/")
    if any(part in {"", ".", ".."} or _COMPONENT.fullmatch(part) is None for part in parts):
        raise BackupIdentityError("ambiguous S3 backup repository path")
    authority = parsed.hostname.lower()
    if port is not None and port != 443:  # noqa: PLR2004
        authority += f":{port}"
    return f"s3:https://{authority}/{'/'.join(parts)}"


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    config_id: str
    node_name: str
    locator: str

    def __post_init__(self) -> None:
        if (
            type(self.config_id) is not str
            or _HEX.fullmatch(self.config_id) is None
            or type(self.node_name) is not str
            or _NODE.fullmatch(self.node_name) is None
            or canonical_locator(self.locator) != self.locator
        ):
            raise BackupIdentityError("invalid canonical repository identity")

    def document(self) -> dict[str, object]:
        return {
            "schema": IDENTITY_SCHEMA,
            "configId": self.config_id,
            "nodeName": self.node_name,
            "locator": self.locator,
        }

    def binding(self) -> dict[str, str]:
        return framed_digest(BINDING_FORMAT, canonical_json_bytes(self.document()))


def _timestamp(value: object) -> str:
    if type(value) is not str:
        raise BackupIdentityError("invalid lineage initialization time")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise BackupIdentityError("invalid lineage initialization time") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise BackupIdentityError("noncanonical lineage initialization time")
    return value


def validate_lineage(document: dict[str, object]) -> dict[str, object]:
    if (
        set(document)
        != {
            "schema",
            "lineageId",
            "repository",
            "repositoryBinding",
            "namespaceDigest",
            "initializedAt",
            "initialEntryCount",
            "initialTerminalEntryDigest",
        }
        or document["schema"] != LINEAGE_SCHEMA
    ):
        raise BackupIdentityError("unsupported audit lineage schema")
    try:
        if validate_uuid7(document["lineageId"]) != document["lineageId"]:
            raise BackupIdentityError("noncanonical audit lineage identity")
    except ContractError as error:
        raise BackupIdentityError("invalid audit lineage identity") from error
    _timestamp(document["initializedAt"])
    identity = document["repository"]
    if type(identity) is not dict or set(identity) != {"schema", "configId", "nodeName", "locator"}:
        raise BackupIdentityError("invalid lineage repository identity")
    if identity["schema"] != IDENTITY_SCHEMA or any(
        type(identity[key]) is not str for key in ("configId", "nodeName", "locator")
    ):
        raise BackupIdentityError("invalid lineage repository identity")
    repository = RepositoryIdentity(identity["configId"], identity["nodeName"], identity["locator"])
    if require_digest(document["repositoryBinding"], BINDING_FORMAT) != repository.binding():
        raise BackupIdentityError("lineage repository binding mismatch")
    require_digest(document["namespaceDigest"], "lowerduckpond-platform-state-v1")
    count = document["initialEntryCount"]
    if type(count) is not int or not 0 <= count <= MAX_LINEAGE_ENTRIES:
        raise BackupIdentityError("invalid lineage audit boundary")
    terminal = document["initialTerminalEntryDigest"]
    if count == 0:
        if terminal is not None:
            raise BackupIdentityError("empty lineage has an audit digest")
    else:
        require_digest(terminal, "lowerduckpond-audit-entry-v1")
    return document


def decode_lineage(raw: bytes) -> dict[str, object]:
    try:
        document = decode_json_object(raw, maximum_bytes=MAX_IDENTITY_BYTES)
        if canonical_json_bytes(document, maximum_bytes=MAX_IDENTITY_BYTES) != raw:
            raise BackupIdentityError("audit lineage bytes are not canonical")
    except ContractError as error:
        raise BackupIdentityError("invalid audit lineage JSON") from error
    return validate_lineage(document)
