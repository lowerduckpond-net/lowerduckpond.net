"""Run-scoped qualification identity bound to one disposable Droplet."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

SESSION_SCHEMA: Final = "lowerduckpond.m3-qualification-session/v1"
SOURCE_REVISION_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
SESSION_FIELDS: Final = frozenset(
    {"schema", "run_id", "source_revision", "droplet_id", "droplet_urn", "ipv4_address"}
)
IDENTITY_FIELDS: Final = frozenset({"droplet_id", "droplet_urn", "ipv4_address"})
SESSION_MODE: Final = 0o600
IPV4_VERSION: Final = 4
UUID_VERSION: Final = 7


class UnsafeSessionError(ValueError):
    """Raised when a session is malformed or no longer matches its source."""


@dataclass(frozen=True, slots=True)
class QualificationSession:
    """One live qualification run and the exact infrastructure it may target."""

    schema: str
    run_id: str
    source_revision: str
    droplet_id: str
    droplet_urn: str
    ipv4_address: str

    @classmethod
    def create(
        cls, *, identity: object, source_revision: str, run_id: str | None = None
    ) -> QualificationSession:
        normalized = _normalize_identity(identity)
        validate_source_revision(source_revision)
        selected_run_id = run_id or str(uuid.uuid7())
        validate_run_id(selected_run_id)
        return cls(
            schema=SESSION_SCHEMA,
            run_id=selected_run_id,
            source_revision=source_revision,
            droplet_id=normalized["droplet_id"],
            droplet_urn=normalized["droplet_urn"],
            ipv4_address=normalized["ipv4_address"],
        )

    @classmethod
    def from_json(cls, raw: str) -> QualificationSession:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != SESSION_FIELDS:
            raise UnsafeSessionError("qualification session shape is not recognized")
        if value["schema"] != SESSION_SCHEMA:
            raise UnsafeSessionError("qualification session schema is not supported")
        return cls.create(
            identity={key: value[key] for key in IDENTITY_FIELDS},
            source_revision=_require_string(value["source_revision"]),
            run_id=_require_string(value["run_id"]),
        )

    @classmethod
    def read(cls, path: Path) -> QualificationSession:
        return cls.from_json(path.read_text(encoding="utf-8"))

    def verify(self, *, identity: object, source_revision: str) -> None:
        expected = _normalize_identity(identity)
        validate_source_revision(source_revision)
        if source_revision != self.source_revision:
            raise UnsafeSessionError("qualification source revision changed")
        observed = {key: getattr(self, key) for key in IDENTITY_FIELDS}
        if observed != expected:
            raise UnsafeSessionError("qualification Droplet identity changed")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, SESSION_MODE)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(self.to_json())
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.replace(path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise


def _normalize_identity(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
        raise UnsafeSessionError("OpenTofu identity shape is not recognized")
    droplet_id = _require_string(value["droplet_id"])
    droplet_urn = _require_string(value["droplet_urn"])
    ipv4_address = _require_string(value["ipv4_address"])
    if not droplet_id.isdigit() or int(droplet_id) <= 0:
        raise UnsafeSessionError("OpenTofu Droplet ID is invalid")
    if droplet_urn != f"do:droplet:{droplet_id}":
        raise UnsafeSessionError("OpenTofu Droplet URN does not match its ID")
    try:
        address = ipaddress.ip_address(ipv4_address)
    except ValueError as error:
        raise UnsafeSessionError("OpenTofu Droplet address is invalid") from error
    if address.version != IPV4_VERSION or not address.is_global:
        raise UnsafeSessionError("OpenTofu Droplet address is not a global IPv4 address")
    return {
        "droplet_id": droplet_id,
        "droplet_urn": droplet_urn,
        "ipv4_address": ipv4_address,
    }


def validate_source_revision(value: str) -> None:
    """Require the canonical committed revision representation used by the gate."""
    if not SOURCE_REVISION_PATTERN.fullmatch(value):
        raise UnsafeSessionError("source revision is not a lowercase SHA-1 object ID")


def validate_run_id(value: str) -> None:
    """Require a canonical UUIDv7 qualification run identifier."""
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise UnsafeSessionError("run ID is not a UUID") from error
    if str(parsed) != value or parsed.version != UUID_VERSION or parsed.variant != uuid.RFC_4122:
        raise UnsafeSessionError("run ID is not a canonical UUIDv7")


def _require_string(value: object) -> str:
    if not isinstance(value, str):
        raise UnsafeSessionError("qualification session values must be strings")
    return value
