"""Protected local identity for one disposable Droplet enrollment."""

from __future__ import annotations

import base64
import os
import re
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from lowerduckpond_static_host_agent.durable import DurableDirectory
from scripts.m3_12_contracts import (
    DISPOSABLE,
    MAX_RECORD_BYTES,
    PRODUCTION_IDENTITY,
    Document,
    ValidationError,
    decode,
    digest,
    require,
)

DOCKER_MARKER = Path("/.dockerenv")
MACHINE_ID = Path("/etc/machine-id")
SYSTEM_UUID = Path("/sys/devices/virtual/dmi/id/product_uuid")
HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
TARGET = "droplet-target.json"
ENROLLMENT = "droplet-enrollment.json"
EXCLUSIONS = "droplet-production-exclusions.json"
IDENTITY_LIMIT = 4096
ED25519_WIRE_HEADER = b"\0\0\0\x0bssh-ed25519\0\0\0\x20"


@dataclass(frozen=True)
class DropletEnrollment:
    target: Document
    registration: Document
    production_identifiers: frozenset[str | int]
    observed_identifiers: frozenset[str | int]

    def require_binding(self, binding: Document) -> None:
        require(
            binding["targetKind"] == DISPOSABLE
            and binding["purpose"] == self.target["purpose"]
            and binding["runId"] == self.registration["runId"]
            and binding["targetSha256"] == digest(self.target),
            "droplet-launch-binding-changed",
        )


def protected_record(authority: DurableDirectory, name: str, owner: int) -> bytes:
    return authority.read_regular(
        (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
    )


def _system_file(path: Path, owner: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        status = os.fstat(source.fileno())
        require(
            stat.S_ISREG(status.st_mode)
            and status.st_uid == owner
            and status.st_nlink == 1
            and not status.st_mode & 0o022,
            "droplet-host-identity-unsafe",
        )
        value = source.read(IDENTITY_LIMIT + 1)
    require(0 < len(value) <= IDENTITY_LIMIT, "droplet-host-identity-unsafe")
    return value.strip()


def host_identity(owner: int = 0) -> dict[str, str]:
    """Reobserve host-local facts without network access from publication workers."""
    machine = _system_file(MACHINE_ID, owner)
    require(
        re.fullmatch(rb"[0-9a-f]{32}", machine) is not None and machine != b"0" * 32,
        "droplet-machine-id-invalid",
    )
    try:
        system_uuid = UUID(_system_file(SYSTEM_UUID, owner).decode("ascii"))
    except ValueError:
        raise ValidationError("droplet-system-uuid-invalid") from None
    require(
        system_uuid not in {UUID(int=0), UUID(int=(1 << 128) - 1)}, "droplet-system-uuid-invalid"
    )
    try:
        key_type, key, *_ = _system_file(HOST_KEY, owner).split(maxsplit=2)
        wire_key = base64.b64decode(key, validate=True)
    except ValueError:
        raise ValidationError("droplet-host-key-invalid") from None
    require(
        key_type == b"ssh-ed25519"
        and wire_key.startswith(ED25519_WIRE_HEADER)
        and len(wire_key) == len(ED25519_WIRE_HEADER) + 32,
        "droplet-host-key-invalid",
    )
    return {
        "machineSha256": sha256(machine).hexdigest(),
        "systemUuidSha256": sha256(system_uuid.bytes).hexdigest(),
        "hostKeySha256": sha256(wire_key).hexdigest(),
    }


def lease_domain(run_id: str, system_uuid_sha256: str) -> str:
    return digest({"runId": run_id, "systemUuidSha256": system_uuid_sha256})


def read_enrollment(path: Path, authority: DurableDirectory, *, owner: int) -> DropletEnrollment:
    require(
        not os.path.lexists(DOCKER_MARKER)
        and not any(
            os.path.lexists(path / name)
            for name in ("transaction.json", "installed-target.json", "revoked")
        ),
        "droplet-enrollment-conflicts",
    )
    target = decode(protected_record(authority, TARGET, owner), "target")
    registration = decode(protected_record(authority, ENROLLMENT, owner), "droplet-enrollment")
    exclusions = decode(
        protected_record(authority, EXCLUSIONS, owner), "droplet-production-exclusions"
    )
    local = host_identity(owner)
    require(
        target["targetKind"] == DISPOSABLE
        and target["transport"] == {"kind": "ssh", "identitySha256": local["hostKeySha256"]}
        and all(registration[key] == value for key, value in local.items())
        and target["enrollmentSha256"] == digest(registration)
        and target["allocationSha256"] == registration["allocationSha256"]
        and target["addressSetSha256"] == digest({"ipv4": registration["ipv4"]})
        and target["leaseDomainSha256"]
        == lease_domain(registration["runId"], local["systemUuidSha256"])
        and registration["productionExclusionsSha256"] == digest(exclusions),
        "droplet-enrollment-changed",
    )
    production, observed = check_production_exclusions(
        exclusions, target, local, registration["ipv4"]
    )
    return DropletEnrollment(target, registration, production, observed)


def check_production_exclusions(
    exclusions: Document, target: Document, local: dict[str, str], ipv4: str
) -> tuple[frozenset[str | int], frozenset[str | int]]:
    """Check independently selected provider and guest identities before enrollment or use."""
    production = frozenset(
        (*exclusions["dropletIds"], *exclusions["addresses"], *exclusions["identityDigests"])
    )
    droplet = target["droplet"]
    observed = frozenset(
        (
            *local.values(),
            ipv4,
            droplet["dropletId"],
            droplet["providerIdentitySha256"],
            droplet["metadataIdentitySha256"],
            *(target[field] for field in PRODUCTION_IDENTITY),
        )
    )
    require(not production.intersection(observed), "production-crossover")
    return production, observed
