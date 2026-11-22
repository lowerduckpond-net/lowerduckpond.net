"""Validate the exact operator-reviewed scope before any journey adapter runs."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address
from itertools import combinations

from lowerduckpond_static_host_agent.droplet_enrollment import (
    check_production_exclusions,
    lease_domain,
)

from scripts.m3_12_contracts import DISPOSABLE, Document, decode, digest, require
from scripts.m3_12_diagnostic_store import Attempt
from scripts.m3_12_droplet_plan import HOST_FIELDS, _address_set
from scripts.m3_12_successor import accepted_predecessor

ROLES = ("source", "restore", "fresh")
PRODUCTION_ZONES = frozenset({"lowerduckpond.net", "lowerduckpond.com"})


@dataclass(frozen=True)
class ReviewedJourney:
    """Independently selected inputs from reviewed custody, outside the manifest."""

    manifest_sha256: str
    predecessor_records: tuple[tuple[str, bytes], ...]
    predecessor_bootstrap_sha256: str
    site_policy_sha256: str
    candidate: bytes
    observed_resources: bytes
    production_exclusions: bytes


def _host(role: str, host: Document, run: str, production: Document) -> Document:
    target, enrolled = host["target"], host["enrollment"]
    address = IPv4Address(enrolled["ipv4"])
    require(address.is_global and not address.is_multicast, "droplet-journey-address-invalid")
    require(
        _address_set(host["adminCidrs"], admin=True) == frozenset(host["adminCidrs"]),
        "droplet-journey-admin-cidrs-invalid",
    )
    identity = {
        key: enrolled[key] for key in ("hostKeySha256", "machineSha256", "systemUuidSha256")
    }
    require(
        host["stateKey"] == f"qualification/m3-12/{run}/{role}.tfstate"
        and target["targetKind"] == DISPOSABLE
        and enrolled["runId"] == run
        and enrolled["productionExclusionsSha256"] == digest(production)
        and target["enrollmentSha256"] == digest(enrolled)
        and target["allocationSha256"] == enrolled["allocationSha256"]
        and target["addressSetSha256"] == digest({"ipv4": enrolled["ipv4"]})
        and target["transport"] == {"kind": "ssh", "identitySha256": identity["hostKeySha256"]}
        and target["leaseDomainSha256"] == lease_domain(run, identity["systemUuidSha256"]),
        "droplet-journey-host-binding-changed",
    )
    droplet = target["droplet"]
    provider = {"projectIdSha256": droplet["projectIdSha256"], "dropletId": droplet["dropletId"]}
    require(
        droplet["providerIdentitySha256"] == digest({**provider, "ipv4": enrolled["ipv4"]})
        and droplet["metadataIdentitySha256"]
        == digest({"dropletId": droplet["dropletId"], "ipv4": enrolled["ipv4"]})
        and provider["projectIdSha256"] not in production["identityDigests"],
        "droplet-journey-provider-changed",
    )
    check_production_exclusions(production, target, identity, enrolled["ipv4"])
    return {
        **identity,
        "ipv4": enrolled["ipv4"],
        "dropletId": droplet["dropletId"],
        **{
            key: target[key]
            for key in (
                "stateSha256",
                "allocationSha256",
                "inventorySha256",
                "transactionNamespaceSha256",
            )
        },
    }


def _under(name: str, zone: str) -> bool:
    return name == zone or name.endswith("." + zone)


def _overlaps(first: str, second: str) -> bool:
    return _under(first, second) or _under(second, first)


def _edge(edge: Document, production: Document) -> None:
    reserved = PRODUCTION_ZONES.union(production["zoneNames"])
    zone_ids: list[str] = []
    sites: list[str] = []
    certificates: list[str] = []
    for zone in edge.values():
        zone_name = zone["zoneName"]
        site = zone["registrableDomain"]
        sites.append(site)
        zone_ids.append(zone["zoneId"])
        require(
            _under(zone_name, site)
            and all(not _overlaps(site, prod) for prod in reserved)
            and zone["zoneId"] not in production["zoneIds"],
            "droplet-journey-zone-crossover",
        )
        source, fresh = zone["source"], zone["fresh"]
        require(
            _under(source["name"], zone_name)
            and _under(fresh["name"], zone_name)
            and not _overlaps(source["name"], fresh["name"]),
            "droplet-journey-dns-scope-overlap",
        )
        certificates.extend((*source["certificateIds"].values(), *fresh["certificateIds"].values()))
    require(
        all(not _overlaps(a, b) for a, b in combinations(sites, 2))
        and len(zone_ids) == len(set(zone_ids))
        and len(certificates) == len(set(certificates))
        and not set(certificates).intersection(production["certificateIds"]),
        "droplet-journey-edge-identity-overlap",
    )


def _storage(storage: Document, production: Document) -> None:
    # The archive lifecycle inventories whole buckets, so prefixes cannot isolate it
    # from another role or the Restic repository.
    resources = [resource for role in storage.values() for resource in role.values()]
    buckets = {resource["bucket"] for resource in resources}
    require(
        len(buckets) == len(resources)
        and not buckets.intersection(production["buckets"])
        and all(resource["region"] != HOST_FIELDS["region"] for resource in resources),
        "droplet-journey-storage-crossover",
    )


def approved_scope(attempt: Attempt, raw: bytes, reviewed: ReviewedJourney) -> Document:
    """Reconcile independently admitted facts and the historical M3.11 receipt."""
    require(sha256(raw).hexdigest() == reviewed.manifest_sha256, "droplet-journey-review-changed")
    manifest = decode(raw, "droplet-journey-allocation")
    excluded = decode(reviewed.production_exclusions, "droplet-journey-exclusions")
    resources = manifest["resources"]
    predecessor, _ = accepted_predecessor(list(reviewed.predecessor_records))
    require(
        manifest["runId"] == attempt.directory.parent.name
        and manifest["invocationId"] == attempt.directory.name
        and manifest["productionExclusionsSha256"] == digest(excluded)
        and manifest["predecessorSha256"] == predecessor
        and manifest["predecessorBootstrapSha256"] == reviewed.predecessor_bootstrap_sha256
        and manifest["sitePolicySha256"] == reviewed.site_policy_sha256
        and manifest["candidate"] == decode(reviewed.candidate, "candidate")
        and resources == decode(reviewed.observed_resources, "droplet-journey-resources"),
        "droplet-journey-inputs-changed",
    )
    hosts = [
        _host(role, resources["hosts"][role], manifest["runId"], excluded["hosts"])
        for role in ROLES
    ]
    require(
        all(len({host[key] for host in hosts}) == len(hosts) for key in hosts[0]),
        "droplet-journey-hosts-overlap",
    )
    _edge(resources["edge"], excluded)
    _storage(resources["storage"], excluded)
    return manifest
