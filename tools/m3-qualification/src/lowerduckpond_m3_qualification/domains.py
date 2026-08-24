"""Registrar attestation and independent Cloudflare-zone qualification."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.report import CheckResult, EvidenceValue

ATTESTATION_SCHEMA: Final = "lowerduckpond.m3-domain-attestation/v1"
DOMAINS: Final = ("lowerduckpond.net", "lowerduckpond.com")
CLOUDFLARE_API_ROOT: Final = "https://api.cloudflare.com/client/v4"
MINIMUM_API_TOKEN_LENGTH: Final = 20
MAXIMUM_ZONE_ID_LENGTH: Final = 64
MINIMUM_NAMESERVERS: Final = 2

type ZoneClient = Callable[[str, str], Mapping[str, object]]


def run_domain_checks(
    *,
    attestation_path: Path,
    zone_ids: Mapping[str, str],
    api_token: str,
    zone_client: ZoneClient | None = None,
) -> tuple[CheckResult, ...]:
    """Require operator control assertions and independently inspect each zone."""
    if len(api_token) < MINIMUM_API_TOKEN_LENGTH or set(zone_ids) != set(DOMAINS):
        return tuple(_failed(domain) for domain in DOMAINS)
    try:
        attestation = _load_attestation(attestation_path)
    except OSError, ValueError, json.JSONDecodeError:
        return tuple(_failed(domain) for domain in DOMAINS)
    client = zone_client or _load_zone
    results: list[CheckResult] = []
    for domain in DOMAINS:
        try:
            assertion = attestation[domain]
            zone = client(zone_ids[domain], api_token)
            evidence = _validate_domain(domain, assertion, zone)
        except Exception:  # Reports intentionally exclude registrar and API response data.
            results.append(_failed(domain))
        else:
            results.append(
                CheckResult(check_id=_check_id(domain), status="passed", evidence=evidence)
            )
    return tuple(results)


def _load_attestation(path: Path) -> dict[str, dict[str, bool]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema", "domains"}:
        raise ValueError
    if value["schema"] != ATTESTATION_SCHEMA:
        raise ValueError
    domains = value["domains"]
    if not isinstance(domains, dict) or set(domains) != set(DOMAINS):
        raise ValueError
    parsed: dict[str, dict[str, bool]] = {}
    for domain, assertion in domains.items():
        if not isinstance(domain, str) or not isinstance(assertion, dict):
            raise ValueError
        if set(assertion) != {"auto_renew_enabled", "registrant_controlled"}:
            raise ValueError
        if any(type(item) is not bool for item in assertion.values()):
            raise ValueError
        parsed[domain] = assertion
    return parsed


def _load_zone(zone_id: str, api_token: str) -> Mapping[str, object]:
    if not zone_id or len(zone_id) > MAXIMUM_ZONE_ID_LENGTH:
        raise ValueError
    request = urllib.request.Request(  # noqa: S310 - URL is fixed to Cloudflare HTTPS.
        f"{CLOUDFLARE_API_ROOT}/zones/{zone_id}",
        headers={"Authorization": f"Bearer {api_token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
        payload = json.load(response)
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ValueError
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ValueError
    return result


def _validate_domain(
    domain: str, assertion: Mapping[str, bool], zone: Mapping[str, object]
) -> dict[str, EvidenceValue]:
    nameservers = zone.get("name_servers")
    if (
        assertion != {"auto_renew_enabled": True, "registrant_controlled": True}
        or zone.get("name") != domain
        or zone.get("status") != "active"
        or zone.get("paused") is not False
        or not isinstance(nameservers, list)
        or len(nameservers) < MINIMUM_NAMESERVERS
        or not all(
            isinstance(item, str) and item.endswith(".ns.cloudflare.com") for item in nameservers
        )
    ):
        raise ValueError
    return {
        "auto_renew": True,
        "cloudflare_active": True,
        "controlled": True,
        "nameservers": len(nameservers),
    }


def _failed(domain: str) -> CheckResult:
    return CheckResult(
        check_id=_check_id(domain),
        status="failed",
        evidence={},
        error_code="probe_failed",
    )


def _check_id(domain: str) -> str:
    return f"m3.0.domain.{domain.replace('.', '-')}"
