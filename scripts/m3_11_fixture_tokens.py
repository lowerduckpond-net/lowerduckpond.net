"""Expiring fixture-token checks; production's non-expiring validator is unchanged."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

from scripts.check_m3_7_production_edge import (
    AUDIT_TOKEN_PERMISSIONS,
    CADDY_TOKEN_PERMISSIONS,
    MAXIMUM_AUDIT_TOKEN_REMAINING,
    CloudflareClient,
    ProductionEdgePreflightError,
    _account_token_details,
    _require_zone_identity,
    _resolve_permission_groups,
    _timestamp,
    validate_account_token_policy,
)
from scripts.check_m3_10_provider import required
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import ROLES, strings


def check_fixture_tokens(
    environment: Mapping[str, str],
    *,
    account_id: str,
    now: datetime,
    minimum_remaining: timedelta = timedelta(),
) -> None:
    """Independently audit all account-owned fixture roles with the child audit key."""
    roles = (
        ("M3_10_TOKEN_AUDIT_TOKEN", AUDIT_TOKEN_PERMISSIONS, "account"),
        ("CADDY_CLOUDFLARE_API_TOKEN", CADDY_TOKEN_PERMISSIONS, "zone"),
        ("CLOUDFLARE_API_TOKEN", frozenset({"Zone Read", "DNS Read"}), "zone"),
    )
    tokens = [required(environment, name) for name, _, _ in roles]
    document = read_private(Path(required(environment, "LDP_M3_11_MANAGED_INPUTS")))
    receipts = fields(document.get("receipts"), {"production", "fixture"})
    fixture = receipts["fixture"]
    if not isinstance(fixture, dict):
        raise ProductionEdgePreflightError("managed fixture receipt is missing")
    expected_ids = strings(fields(fixture.get("identities_sha256"), set(ROLES)))
    if len(set(tokens)) != len(roles):
        raise ProductionEdgePreflightError("managed fixture token roles are not separated")
    zones = (
        (required(environment, "CLOUDFLARE_ZONE_ID"), "lowerduckpond.net"),
        (required(environment, "CLOUDFLARE_TENANT_ZONE_ID"), "lowerduckpond.com"),
    )
    if len({zone for zone, _ in zones}) != len(zones):
        raise ProductionEdgePreflightError("managed fixture zones are not distinct")
    audit = CloudflareClient(tokens[0])
    identifiers: set[str] = set()
    for (name, permissions, scope), token in zip(roles, tokens, strict=True):
        client = CloudflareClient(token)
        details = _account_token_details(audit, client, account_id=account_id, label="fixture")
        selected = details.get("id")
        if not isinstance(selected, str) or selected in identifiers:
            raise ProductionEdgePreflightError("managed fixture identities are not separated")
        identifiers.add(selected)
        role = {
            "M3_10_TOKEN_AUDIT_TOKEN": "audit",
            "CADDY_CLOUDFLARE_API_TOKEN": "caddy",
            "CLOUDFLARE_API_TOKEN": "observer",
        }[name]
        if hashlib.sha256(selected.encode()).hexdigest() != expected_ids[role]:
            raise ProductionEdgePreflightError(
                "managed fixture token differs from its creation receipt"
            )
        resources = frozenset({f"com.cloudflare.api.account.{account_id}"})
        if scope == "zone":
            resources = frozenset(f"com.cloudflare.api.account.zone.{zone}" for zone, _ in zones)
            for zone, domain in zones:
                if _require_zone_identity(client, zone, domain) != account_id:
                    raise ProductionEdgePreflightError("managed fixture zone account differs")
        resolved = _resolve_permission_groups(
            audit,
            account_id=account_id,
            names=permissions,
            expected_scope="com.cloudflare.api.account" + (".zone" if scope == "zone" else ""),
        )
        validate_account_token_policy(
            details,
            expected_id=selected,
            expected_permissions=resolved,
            expected_resources=resources,
            label="managed fixture",
        )
        maximum = (
            MAXIMUM_AUDIT_TOKEN_REMAINING
            if name == "M3_10_TOKEN_AUDIT_TOKEN"
            else timedelta(hours=14)
        )
        expires = _timestamp(details.get("expires_on"))
        if (
            not now < expires <= now + maximum
            or expires - now < minimum_remaining
            or _timestamp(details.get("issued_on")) > now
            or (details.get("not_before") and _timestamp(details["not_before"]) > now)
        ):
            raise ProductionEdgePreflightError(
                "managed fixture token validity is outside its bound"
            )
    page = CloudflareClient(required(environment, "M3_10_PAGE_RULES_TOKEN")).get(
        "/user/tokens/verify"
    )
    if (
        not isinstance(page, dict)
        or not isinstance(page.get("id"), str)
        or hashlib.sha256(page["id"].encode()).hexdigest() != expected_ids["page-rules"]
    ):
        raise ProductionEdgePreflightError(
            "managed Page Rules token differs from its creation receipt"
        )
