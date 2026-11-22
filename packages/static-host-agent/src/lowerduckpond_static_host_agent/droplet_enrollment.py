"""Protected local identity for one disposable Droplet enrollment."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from lowerduckpond_static_host_agent.durable import DurableDirectory
from scripts.m3_12_contracts import (
    DISPOSABLE,
    MAX_RECORD_BYTES,
    PRODUCTION_IDENTITY,
    Document,
    decode,
    digest,
    require,
)
from scripts.m3_12_droplet_observe import host_identity

DOCKER_MARKER = Path("/.dockerenv")
PUBLICATION_VIEW = "droplet-publication"
TARGET = "droplet-target.json"
ENROLLMENT = "droplet-enrollment.json"
EXCLUSIONS = "droplet-production-exclusions.json"


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


def lease_domain(run_id: str, system_uuid_sha256: str) -> str:
    return digest({"runId": run_id, "systemUuidSha256": system_uuid_sha256})


def read_enrollment(path: Path, authority: DurableDirectory, *, owner: int) -> DropletEnrollment:
    require(
        path.name == PUBLICATION_VIEW
        and not os.path.lexists(DOCKER_MARKER)
        and not any(
            os.path.lexists(directory / name)
            for directory in (path, path.parent)
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
