"""Prepare exact edge and browser proof subjects from the witnessed P4 scope."""

from __future__ import annotations

from dataclasses import dataclass

from lowerduckpond_m3_qualification.browser import BrowserOrigins
from lowerduckpond_static_contracts import (
    ContractError,
    decode_json_object,
    validate_slug,
    validate_uuid7,
)

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import read
from scripts.m3_12_droplet_native import AdapterInputs

EDGE_PHASES = frozenset({"edge"})


@dataclass(frozen=True)
class EdgeSubjects:
    origin_ipv4: str
    browser: BrowserOrigins
    certificate_subjects: dict[str, tuple[str, str]]
    zone_ids: dict[str, str]
    zone_names: dict[str, str]
    certificate_ids: dict[str, dict[str, str]]


def prepare_edge_proof(inputs: AdapterInputs, fixture_raw: bytes) -> EdgeSubjects:
    """Use a test tenant and unknown name from the original functional receipt."""
    scope, intent = inputs.open(EDGE_PHASES)
    original = intent["prerequisites"]["functional"]
    receipt = read(inputs.attempt.directory, original["file"])
    try:
        fixture = decode_json_object(fixture_raw, maximum_bytes=MAX_RECORD_BYTES)
        require(
            set(fixture) == {"format", "tenantId", "alias", "unknown"}
            and fixture["format"] == "lowerduckpond-m3-12-edge-tenant-v1"
            and encode(fixture) == fixture_raw
            and digest(receipt) == original["sha256"]
            and digest(fixture) == receipt["evidence"]["lifecycle"],
            "droplet-edge-original-fixture-changed",
        )
        tenant_id = validate_uuid7(fixture["tenantId"])
        alias = validate_slug(fixture["alias"])
        unknown = validate_slug(fixture["unknown"])
    except ContractError:
        raise ValidationError("droplet-edge-fixture-invalid") from None

    resource = scope["resources"]
    zones = resource["edge"]
    platform_scope, tenant_scope = (
        zones[name]["source"]["name"] for name in ("platform", "tenant")
    )
    # The existing browser assertions run unchanged against these exact origins.
    hosts = (
        platform_scope,
        f"{alias}.{tenant_scope}",
        f"t-{tenant_id.replace('-', '')}.{tenant_scope}",
        f"{unknown}.{tenant_scope}",
    )
    browser = BrowserOrigins(
        *(f"https://{host}" for host in hosts),
        approved_scopes=(platform_scope, tenant_scope),
    )
    return EdgeSubjects(
        resource["hosts"]["source"]["enrollment"]["ipv4"],
        browser,
        {
            name: (scope_name, f"*.{scope_name}")
            for name, scope_name in (
                ("platform", platform_scope),
                ("tenant", tenant_scope),
            )
        },
        {name: row["zoneId"] for name, row in zones.items()},
        {name: row["zoneName"] for name, row in zones.items()},
        {name: row["source"]["certificateIds"] for name, row in zones.items()},
    )


def prove_edge_associations(approved: EdgeSubjects, captured: Document, *, generation: str) -> str:
    """Validate a fresh independent provider projection without calling a provider."""
    require(generation in {"primary", "replacement"}, "droplet-edge-generation-invalid")
    expected = {
        zone: {
            "zoneId": approved.zone_ids[zone],
            "zoneName": approved.zone_names[zone],
            "ssl": "strict",
            "alwaysOnline": False,
            "dns": {host: {"origin": approved.origin_ipv4, "proxied": True} for host in subjects},
            "originPulls": dict.fromkeys(subjects, approved.certificate_ids[zone][generation]),
        }
        for zone, subjects in approved.certificate_subjects.items()
    }
    # Compare canonical bytes so integers cannot substitute for boolean fields.
    require(encode(captured) == encode(expected), "droplet-edge-associations-changed")
    return digest(captured)
