"""Construct protected enrollment from independently read disposable identities."""

from __future__ import annotations

from dataclasses import dataclass

from lowerduckpond_static_host_agent.droplet_enrollment import (
    check_production_exclusions,
    lease_domain,
)

from scripts.m3_12_contracts import DISPOSABLE, Document, decode, digest, encode, require


@dataclass(frozen=True)
class ProviderIdentity:
    project_id_sha256: str
    droplet_id: int
    ipv4: str

    def document(self) -> Document:
        return {
            "projectIdSha256": self.project_id_sha256,
            "dropletId": self.droplet_id,
            "ipv4": self.ipv4,
        }


@dataclass(frozen=True)
class ApprovedAllocation:
    """The reviewed per-run state and provider binding from exact OpenTofu readback."""

    run_id: str
    state_sha256: str
    allocation_sha256: str
    inventory_sha256: str
    transaction_namespace_sha256: str
    identity: ProviderIdentity


@dataclass(frozen=True)
class ConnectedDroplet:
    """Independent provider readback and observations through the pinned SSH host."""

    provider: ProviderIdentity
    metadata_id: int
    metadata_ipv4: str
    host_identity: dict[str, str]
    pinned_host_key_sha256: str


def enrollment_records(
    allocation: ApprovedAllocation, observation: ConnectedDroplet, production_exclusions: bytes
) -> tuple[Document, Document]:
    """Build records for verified transport to seal under the enrolled attempt.

    Callers obtain the allocation and production exclusions from reviewed custody.
    They read provider identity separately, and establish the SSH pin from the
    authenticated provisioning chain before obtaining any guest observations.
    """
    production = decode(production_exclusions, "droplet-production-exclusions")
    identity = allocation.identity
    host = observation.host_identity
    require(
        identity == observation.provider
        and identity.droplet_id == observation.metadata_id
        and identity.ipv4 == observation.metadata_ipv4
        and host.get("hostKeySha256") == observation.pinned_host_key_sha256,
        "droplet-allocation-observation-changed",
    )
    registration = decode(
        encode(
            {
                "format": "lowerduckpond-m3-12-droplet-enrollment-v1",
                **host,
                "runId": allocation.run_id,
                "allocationSha256": allocation.allocation_sha256,
                "ipv4": identity.ipv4,
                "productionExclusionsSha256": digest(production),
            }
        ),
        "droplet-enrollment",
    )
    target = decode(
        encode(
            {
                "targetKind": DISPOSABLE,
                "purpose": "disposable-qualification",
                "enrollmentSha256": digest(registration),
                "allocationSha256": allocation.allocation_sha256,
                "inventorySha256": allocation.inventory_sha256,
                "stateSha256": allocation.state_sha256,
                "transactionNamespaceSha256": allocation.transaction_namespace_sha256,
                "addressSetSha256": digest({"ipv4": identity.ipv4}),
                "leaseDomainSha256": lease_domain(allocation.run_id, host["systemUuidSha256"]),
                "transport": {"kind": "ssh", "identitySha256": observation.pinned_host_key_sha256},
                "droplet": {
                    "projectIdSha256": identity.project_id_sha256,
                    "dropletId": identity.droplet_id,
                    "providerIdentitySha256": digest(observation.provider.document()),
                    "metadataIdentitySha256": digest(
                        {"dropletId": observation.metadata_id, "ipv4": observation.metadata_ipv4}
                    ),
                },
            }
        ),
        "target",
    )
    check_production_exclusions(production, target, host, identity.ipv4)
    return target, registration
