#!/usr/bin/env python3
"""Read-only validation of the external inputs for the M3.7 production edge."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Final

API_ROOT: Final = "https://api.cloudflare.com/client/v4"
API_TIMEOUT_SECONDS: Final = 15
MAXIMUM_API_RESPONSE_BYTES: Final = 2_000_000
MAXIMUM_CERTIFICATE_BYTES: Final = 20_000
MINIMUM_TOKEN_LENGTH: Final = 20
CERTIFICATE_IDENTITY_LINE_COUNT: Final = 2
IPV4_VERSION: Final = 4
MAXIMUM_CA_LIFETIME: Final = timedelta(days=1826)
MINIMUM_CA_REMAINING: Final = timedelta(days=366)
MAXIMUM_LEAF_LIFETIME: Final = timedelta(days=366)
MINIMUM_LEAF_REMAINING: Final = timedelta(days=60)
CERTIFICATE_ID_PATTERN: Final = re.compile(
    r"^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$"
)
ZONE_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{32}$")
MANAGED_RULESET_PHASES: Final = frozenset(
    {
        "http_config_settings",
        "http_request_cache_settings",
        "http_request_firewall_custom",
    }
)
ZONE_INPUTS: Final = (
    (
        "lowerduckpond.net",
        "CLOUDFLARE_ZONE_ID",
        "CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID",
        True,
    ),
    (
        "lowerduckpond.com",
        "CLOUDFLARE_TENANT_ZONE_ID",
        "CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID",
        False,
    ),
)


class ProductionEdgePreflightError(RuntimeError):
    """Raised when a production-edge starting condition cannot be proved."""


class CloudflareClient:
    """Bounded, read-only Cloudflare API client."""

    def __init__(self, token: str) -> None:
        if len(token) < MINIMUM_TOKEN_LENGTH:
            raise ProductionEdgePreflightError("a Cloudflare token is malformed")
        self._token = token

    def get(self, path: str, *, query: Mapping[str, str] | None = None) -> object:
        if not path.startswith("/") or ".." in path:
            raise ProductionEdgePreflightError("a Cloudflare API path is unsafe")
        encoded_query = ""
        if query:
            encoded_query = f"?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS API root.
            f"{API_ROOT}{path}{encoded_query}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "lowerduckpond-m3-production-preflight/1",
            },
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 -- request is bound to API_ROOT.
                request, timeout=API_TIMEOUT_SECONDS
            ) as response:
                if response.status != HTTPStatus.OK:
                    raise ProductionEdgePreflightError("Cloudflare did not return HTTP 200")
                raw = response.read(MAXIMUM_API_RESPONSE_BYTES + 1)
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            raise ProductionEdgePreflightError("a Cloudflare API request failed") from error
        if len(raw) > MAXIMUM_API_RESPONSE_BYTES:
            raise ProductionEdgePreflightError("a Cloudflare API response exceeded its bound")
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProductionEdgePreflightError("a Cloudflare API response is invalid") from error
        if not isinstance(value, dict) or value.get("success") is not True:
            raise ProductionEdgePreflightError("Cloudflare rejected a read-only preflight request")
        if "result" not in value:
            raise ProductionEdgePreflightError("a Cloudflare API response omitted its result")
        return value["result"]


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ProductionEdgePreflightError(f"{name} is not set")
    return value


def _timestamp(raw: object) -> datetime:
    if not isinstance(raw, str):
        raise ProductionEdgePreflightError("certificate validity metadata is malformed")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as error:
        raise ProductionEdgePreflightError("certificate validity metadata is malformed") from error


def _openssl(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    try:
        return subprocess.run(  # noqa: S603 -- executable and argument boundary are fixed.
            ("/usr/bin/openssl", *arguments),
            input=input_bytes,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise ProductionEdgePreflightError("a certificate failed OpenSSL validation") from error


def _certificate_dates(pem: bytes) -> tuple[datetime, datetime]:
    output = _openssl("x509", "-noout", "-dates", "-dateopt", "iso_8601", input_bytes=pem)
    try:
        values = dict(
            line.split("=", maxsplit=1)
            for line in output.decode("ascii", errors="strict").splitlines()
        )
        not_before = datetime.strptime(values["notBefore"], "%Y-%m-%d %H:%M:%SZ").replace(
            tzinfo=UTC
        )
        not_after = datetime.strptime(values["notAfter"], "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=UTC)
    except (KeyError, UnicodeError, ValueError) as error:
        raise ProductionEdgePreflightError("certificate dates are malformed") from error
    return not_before, not_after


def _read_ca_path() -> tuple[Path, bytes]:
    raw_paths = _required_environment("CADDY_ORIGIN_PULL_CA_PATHS_JSON")
    try:
        paths = json.loads(raw_paths)
    except json.JSONDecodeError as error:
        raise ProductionEdgePreflightError(
            "CADDY_ORIGIN_PULL_CA_PATHS_JSON is not valid JSON"
        ) from error
    if (
        not isinstance(paths, list)
        or len(paths) != 1
        or not isinstance(paths[0], str)
        or not paths[0].startswith("/")
    ):
        raise ProductionEdgePreflightError(
            "the initial M3.7 gate requires exactly one absolute CA certificate path"
        )
    path = Path(paths[0])
    if not path.is_file() or path.is_symlink():
        raise ProductionEdgePreflightError("the production CA certificate path is unsafe")
    try:
        pem = path.read_bytes()
    except OSError as error:
        raise ProductionEdgePreflightError("the production CA certificate is unreadable") from error
    return path, pem


def _require_safe_pem(pem: bytes, *, label: str) -> None:
    if (
        len(pem) > MAXIMUM_CERTIFICATE_BYTES
        or pem.count(b"-----BEGIN CERTIFICATE-----") != 1
        or pem.count(b"-----END CERTIFICATE-----") != 1
        or b"PRIVATE KEY" in pem
    ):
        raise ProductionEdgePreflightError(f"the {label} certificate PEM is unsafe")


def validate_ca_certificate(path: Path, pem: bytes, *, now: datetime) -> None:
    """Validate the single public production trust anchor."""
    _require_safe_pem(pem, label="CA")
    identity = (
        _openssl(
            "x509",
            "-noout",
            "-subject",
            "-issuer",
            "-nameopt",
            "RFC2253",
            input_bytes=pem,
        )
        .decode("ascii", errors="strict")
        .splitlines()
    )
    details = _openssl("x509", "-noout", "-text", input_bytes=pem)
    _openssl("verify", "-CAfile", os.fspath(path), os.fspath(path))
    if (
        len(identity) != CERTIFICATE_IDENTITY_LINE_COUNT
        or identity[0].removeprefix("subject=") != identity[1].removeprefix("issuer=")
        or b"CA:TRUE" not in details
        or b"Certificate Sign" not in details
    ):
        raise ProductionEdgePreflightError("the production CA constraints are unsafe")
    not_before, not_after = _certificate_dates(pem)
    if (
        not_before > now
        or not_after - not_before > MAXIMUM_CA_LIFETIME
        or not_after - now < MINIMUM_CA_REMAINING
    ):
        raise ProductionEdgePreflightError("the production CA validity is outside policy")


def validate_leaf_certificate(
    certificate: Mapping[str, object],
    *,
    ca_path: Path,
    expected_zone: str,
    expected_id: str,
    now: datetime,
) -> None:
    """Validate one Cloudflare-held public production client leaf."""
    if certificate.get("id") != expected_id or certificate.get("status") != "active":
        raise ProductionEdgePreflightError(
            f"the selected {expected_zone} origin-pull leaf is not active"
        )
    if certificate.get("private_key") not in (None, ""):
        raise ProductionEdgePreflightError("Cloudflare returned unexpected private-key material")
    raw_pem = certificate.get("certificate")
    if not isinstance(raw_pem, str):
        raise ProductionEdgePreflightError("an uploaded origin-pull leaf omitted its certificate")
    try:
        pem = raw_pem.encode("ascii", errors="strict")
    except UnicodeError as error:
        raise ProductionEdgePreflightError("an uploaded origin-pull leaf is not ASCII") from error
    _require_safe_pem(pem, label="leaf")
    details = _openssl("x509", "-noout", "-text", input_bytes=pem)
    with tempfile.NamedTemporaryFile(mode="wb", prefix="m3-7-leaf-", delete=True) as leaf_file:
        leaf_file.write(pem)
        leaf_file.flush()
        _openssl(
            "verify",
            "-purpose",
            "sslclient",
            "-CAfile",
            os.fspath(ca_path),
            leaf_file.name,
        )
    dns_names = frozenset(re.findall(rb"DNS:([^,\s]+)", details))
    if (
        b"CA:FALSE" not in details
        or b"TLS Web Client Authentication" not in details
        or dns_names != {expected_zone.encode("ascii")}
    ):
        raise ProductionEdgePreflightError(
            f"the selected {expected_zone} origin-pull leaf constraints are unsafe"
        )
    not_before, not_after = _certificate_dates(pem)
    api_expiration = _timestamp(certificate.get("expires_on"))
    if (
        not_before > now
        or not_after - not_before > MAXIMUM_LEAF_LIFETIME
        or not_after - now < MINIMUM_LEAF_REMAINING
        or abs((api_expiration - not_after).total_seconds()) > 1
    ):
        raise ProductionEdgePreflightError(
            f"the selected {expected_zone} origin-pull leaf validity is outside policy"
        )


def _require_zone_identity(client: CloudflareClient, zone_id: str, zone_name: str) -> None:
    zone = client.get(f"/zones/{zone_id}")
    if (
        not isinstance(zone, dict)
        or zone.get("id") != zone_id
        or zone.get("name") != zone_name
        or zone.get("status") != "active"
    ):
        raise ProductionEdgePreflightError(
            f"the Caddy token did not identify the active {zone_name} zone"
        )


def _require_direct_dns(
    client: CloudflareClient,
    *,
    zone_id: str,
    zone_name: str,
    origin_ipv4: str,
    records_expected: bool,
) -> None:
    for hostname in (zone_name, f"*.{zone_name}"):
        records = client.get(
            f"/zones/{zone_id}/dns_records",
            query={"name": hostname, "type": "A", "per_page": "100"},
        )
        if not isinstance(records, list):
            raise ProductionEdgePreflightError("Cloudflare DNS inventory is malformed")
        if records_expected:
            exact = [
                record
                for record in records
                if isinstance(record, dict)
                and record.get("name") == hostname
                and record.get("type") == "A"
            ]
            if len(exact) != 1 or exact[0].get("content") != origin_ipv4:
                raise ProductionEdgePreflightError(f"the direct {hostname} A record is not exact")
            if exact[0].get("proxied") is not False:
                raise ProductionEdgePreflightError(
                    f"the pre-M3.7 {hostname} record is already proxied"
                )
        elif any(
            isinstance(record, dict)
            and record.get("name") == hostname
            and record.get("type") == "A"
            for record in records
        ):
            raise ProductionEdgePreflightError(
                f"the pre-M3.7 {hostname} A record unexpectedly exists"
            )


def _require_unconfigured_edge(client: CloudflareClient, zone_id: str, zone_name: str) -> None:
    setting = client.get(f"/zones/{zone_id}/origin_tls_client_auth/settings")
    if not isinstance(setting, dict) or setting.get("enabled") is not False:
        raise ProductionEdgePreflightError(
            f"zone-level origin pulls are already enabled for {zone_name}"
        )
    hostnames = client.get(f"/zones/{zone_id}/origin_tls_client_auth/hostnames")
    if not isinstance(hostnames, list) or any(
        isinstance(item, dict) and item.get("enabled") is True for item in hostnames
    ):
        raise ProductionEdgePreflightError(
            f"an enabled per-hostname origin-pull override exists in {zone_name}"
        )
    rulesets = client.get(f"/zones/{zone_id}/rulesets")
    if not isinstance(rulesets, list) or any(
        isinstance(item, dict)
        and item.get("kind") == "zone"
        and item.get("phase") in MANAGED_RULESET_PHASES
        for item in rulesets
    ):
        raise ProductionEdgePreflightError(
            f"a zone entrypoint conflicts with the M3.7 policy in {zone_name}"
        )


def _require_selected_leaf(  # noqa: PLR0913 -- every certificate binding is explicit.
    client: CloudflareClient,
    *,
    zone_id: str,
    zone_name: str,
    certificate_id: str,
    ca_path: Path,
    now: datetime,
) -> None:
    certificates = client.get(f"/zones/{zone_id}/origin_tls_client_auth")
    if not isinstance(certificates, list):
        raise ProductionEdgePreflightError(
            f"zone-level origin-pull certificates are unavailable for {zone_name}"
        )
    active = [
        item for item in certificates if isinstance(item, dict) and item.get("status") == "active"
    ]
    if len(active) != 1 or active[0].get("id") != certificate_id:
        raise ProductionEdgePreflightError(
            f"the selected {zone_name} leaf is not the only active zone-level leaf"
        )
    validate_leaf_certificate(
        active[0],
        ca_path=ca_path,
        expected_zone=zone_name,
        expected_id=certificate_id,
        now=now,
    )


def run_preflight() -> None:
    """Validate the production CA, Cloudflare inputs, and direct DNS state."""
    origin_ipv4 = _required_environment("M3_7_PRODUCTION_RESERVED_IPV4")
    try:
        address = ipaddress.ip_address(origin_ipv4)
    except ValueError as error:
        raise ProductionEdgePreflightError("the production reserved IPv4 is malformed") from error
    if address.version != IPV4_VERSION or not address.is_global:
        raise ProductionEdgePreflightError("the production reserved IPv4 is not global")

    edge_token = _required_environment("CLOUDFLARE_API_TOKEN")
    caddy_token = _required_environment("CADDY_CLOUDFLARE_API_TOKEN")
    if edge_token == caddy_token:
        raise ProductionEdgePreflightError("the Caddy and OpenTofu tokens are not separated")

    ca_path, ca_pem = _read_ca_path()
    now = datetime.now(UTC)
    validate_ca_certificate(ca_path, ca_pem, now=now)
    edge_client = CloudflareClient(edge_token)
    caddy_client = CloudflareClient(caddy_token)

    for zone_name, zone_variable, certificate_variable, records_expected in ZONE_INPUTS:
        zone_id = _required_environment(zone_variable)
        certificate_id = _required_environment(certificate_variable)
        if ZONE_ID_PATTERN.fullmatch(zone_id) is None:
            raise ProductionEdgePreflightError(f"{zone_variable} is malformed")
        if CERTIFICATE_ID_PATTERN.fullmatch(certificate_id) is None:
            raise ProductionEdgePreflightError(f"{certificate_variable} is malformed")
        _require_zone_identity(caddy_client, zone_id, zone_name)
        _require_direct_dns(
            edge_client,
            zone_id=zone_id,
            zone_name=zone_name,
            origin_ipv4=origin_ipv4,
            records_expected=records_expected,
        )
        _require_unconfigured_edge(edge_client, zone_id, zone_name)
        _require_selected_leaf(
            edge_client,
            zone_id=zone_id,
            zone_name=zone_name,
            certificate_id=certificate_id,
            ca_path=ca_path,
            now=now,
        )


def main() -> int:
    """Run the fail-closed production edge input check."""
    try:
        run_preflight()
    except (ProductionEdgePreflightError, UnicodeError) as error:
        print(f"M3.7 production edge preflight failed: {error}", file=sys.stderr)
        return 1
    print("M3.7 production CA, leaf, token, and direct-edge inputs passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
