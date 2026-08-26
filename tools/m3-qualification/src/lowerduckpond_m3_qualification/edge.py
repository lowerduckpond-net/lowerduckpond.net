"""Cloudflare-edge preflight, rollover, and steady-state qualification probes."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import shlex
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.report import CheckResult, EvidenceValue

API_ROOT: Final = "https://api.cloudflare.com/client/v4"
PLATFORM_HOST: Final = "m3-qualification.lowerduckpond.net"
ALIAS_HOST: Final = "m3-a.lowerduckpond.com"
UNKNOWN_HOST: Final = "m3-unknown.lowerduckpond.com"
CANONICAL_HOST: Final = "t-0198d17f6f4a70008000000000000001.lowerduckpond.com"
HOSTS_BY_ZONE: Final = {
    "lowerduckpond_net": (PLATFORM_HOST,),
    "lowerduckpond_com": (ALIAS_HOST, UNKNOWN_HOST, CANONICAL_HOST),
}
ZONE_NAMES: Final = {
    "lowerduckpond_net": "lowerduckpond.net",
    "lowerduckpond_com": "lowerduckpond.com",
}
ROLLOVER_STAGES: Final = (
    "primary",
    "replacement",
    "rollback",
    "forward",
    "retired-primary",
    "final",
)
FINAL_EDGE_SUFFIXES: Final = (
    "zone-policy",
    "proxied-dns",
    "certificates",
    "direct-origin",
    "forwarded-address",
    "cache-bypass",
    "representation-fidelity",
    "reserved-path",
    "unknown-host",
    "http-policy",
    "origin-unavailable",
)
STAGE_GENERATIONS: Final = {
    "primary": "primary",
    "replacement": "replacement",
    "rollback": "primary",
    "forward": "replacement",
    "retired-primary": "primary",
    "final": "replacement",
}
EDGE_ERROR_STATUSES: Final = frozenset(range(520, 528))
UNCACHEABLE_EDGE_STATUSES: Final = frozenset({"BYPASS", "DYNAMIC", "UPSTREAM BYPASS"})
CACHE_ROUTE_PATHS: Final = (
    (PLATFORM_HOST, "/fidelity"),
    (ALIAS_HOST, "/"),
    (ALIAS_HOST, "/static"),
    (CANONICAL_HOST, "/static"),
    (UNKNOWN_HOST, "/"),
)
RESERVED_PATHS: Final = ("/cdn-cgi", "/cdn-cgi/", "/CDN-CGI/trace")
API_TIMEOUT_SECONDS: Final = 15
HTTP_TIMEOUT_SECONDS: Final = 10
DIRECT_TIMEOUT_SECONDS: Final = 3
OUTAGE_ATTEMPTS: Final = 12
RECOVERY_ATTEMPTS: Final = 20
RETRY_DELAY_SECONDS: Final = 1.0
AOP_PROPAGATION_ATTEMPTS: Final = 60
AOP_PROPAGATION_RETRY_DELAY_SECONDS: Final = 2.0
LOG_PROPAGATION_ATTEMPTS: Final = 10
LOG_PROPAGATION_RETRY_DELAY_SECONDS: Final = 0.2
MINIMUM_CERTIFICATE_REMAINING: Final = timedelta(days=14)
MINIMUM_CERTIFICATE_LIFETIME: Final = timedelta(days=29)
MAXIMUM_CERTIFICATE_LIFETIME: Final = timedelta(days=31)
MINIMUM_CA_REMAINING: Final = timedelta(days=31)
MAXIMUM_CA_LIFETIME: Final = timedelta(days=1826)
CERTIFICATE_ID_PATTERN: Final = re.compile(
    r"^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$"
)
IPV4_VERSION: Final = 4
MINIMUM_TOKEN_LENGTH: Final = 20
ROLLOVER_CERTIFICATE_COUNT: Final = 4
CERTIFICATE_IDENTITY_LINE_COUNT: Final = 2
# Cloudflare documents 520 for an AOP/origin mismatch and 525 for an origin TLS
# handshake failure. Per-hostname client-certificate rejection can surface as
# either; the retired stage admits no other edge failure and separately proves
# the origin TLS listener remains stable.
RETIRED_AOP_EDGE_STATUSES: Final = frozenset({520, 525})
MAXIMUM_CERTIFICATE_PEM_BYTES: Final = 20_000
MAXIMUM_API_RESPONSE_BYTES: Final = 2_000_000
MAXIMUM_EDGE_RESPONSE_BYTES: Final = 1_000_000
MAXIMUM_LOG_PROBE_BYTES: Final = 1_000_000
SSH_EXECUTABLE: Final = "/usr/bin/ssh"
OPENSSL_EXECUTABLE: Final = "/usr/bin/openssl"
CADDY_LOG_PATH: Final = "/var/log/caddy/m3-qualification.json"
CLOUDFLARE_NETWORKS: Final = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


class EdgeQualificationError(RuntimeError):
    """Raised when a Cloudflare edge invariant cannot be proven."""


@dataclass(frozen=True, slots=True)
class EdgeInputs:
    """Exact non-secret identifiers and live target for one qualification run."""

    origin_ipv4: str
    zone_ids: Mapping[str, str]
    certificate_ids: Mapping[str, Mapping[str, str]]
    api_token: str
    ssh_target: str

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.origin_ipv4)
        except ValueError as error:
            raise EdgeQualificationError("origin address is malformed") from error
        if address.version != IPV4_VERSION or not address.is_global:
            raise EdgeQualificationError("origin address is not a global IPv4 address")
        if set(self.zone_ids) != set(HOSTS_BY_ZONE) or any(
            re.fullmatch(r"[0-9a-f]{32}", value) is None for value in self.zone_ids.values()
        ):
            raise EdgeQualificationError("zone identifiers are malformed")
        _validate_certificate_ids(self.certificate_ids)
        if len(self.api_token) < MINIMUM_TOKEN_LENGTH:
            raise EdgeQualificationError("Cloudflare token is absent")
        if self.ssh_target != f"ldp-admin@{self.origin_ipv4}":
            raise EdgeQualificationError("SSH target is not bound to the disposable origin")


@dataclass(frozen=True, slots=True)
class EdgeResponse:
    status: int
    fields: Mapping[str, str]
    content: bytes


@dataclass(frozen=True, slots=True)
class _LogPosition:
    device: int
    inode: int
    size: int


class CloudflareClient:
    """Minimal read-only Cloudflare API client with fail-closed response parsing."""

    def __init__(self, token: str) -> None:
        if len(token) < MINIMUM_TOKEN_LENGTH:
            raise EdgeQualificationError("Cloudflare token is absent")
        self._token = token

    def get(self, path: str) -> object:
        if not path.startswith("/") or ".." in path:
            raise EdgeQualificationError("Cloudflare API path is unsafe")
        request = urllib.request.Request(  # noqa: S310 - API_ROOT is fixed HTTPS.
            f"{API_ROOT}{path}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                "User-Agent": "lowerduckpond-m3-qualification/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:  # noqa: S310
                if response.status != HTTPStatus.OK:
                    raise EdgeQualificationError("Cloudflare API did not return HTTP 200")
                raw = response.read(MAXIMUM_API_RESPONSE_BYTES + 1)
                if len(raw) > MAXIMUM_API_RESPONSE_BYTES:
                    raise EdgeQualificationError("Cloudflare API response exceeded its bound")
                value = json.loads(raw)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise EdgeQualificationError("Cloudflare API request failed") from error
        if not isinstance(value, dict) or value.get("success") is not True or "result" not in value:
            raise EdgeQualificationError("Cloudflare API response is not successful")
        return value["result"]


def run_preflight(
    *,
    zone_ids: Mapping[str, str],
    certificate_ids: Mapping[str, Mapping[str, str]],
    ca_paths: Mapping[str, Path],
    api_token: str,
    now: datetime | None = None,
) -> None:
    """Qualify account entitlement and read-only zone state before provisioning."""
    _validate_zone_ids(zone_ids)
    _validate_certificate_ids(certificate_ids)
    if set(ca_paths) != {"primary", "replacement"} or any(
        not path.is_absolute() or not path.is_file() for path in ca_paths.values()
    ):
        raise EdgeQualificationError("public origin-pull CA inputs are incomplete")
    client = CloudflareClient(api_token)
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    for ca_path in ca_paths.values():
        _require_ca_certificate(ca_path, now=observed_at)
    for zone_key, zone_id in zone_ids.items():
        _require_zone_settings(client, zone_id)
        _require_no_ruleset_conflicts(client, zone_id)
        certificates = client.get(f"/zones/{zone_id}/origin_tls_client_auth/hostnames/certificates")
        if not isinstance(certificates, list):
            raise EdgeQualificationError("hostname AOP entitlement is unsupported")
        by_id = {item.get("id"): item for item in certificates if isinstance(item, dict)}
        for generation in ("primary", "replacement"):
            certificate_id = certificate_ids[generation][zone_key]
            certificate = by_id.get(certificate_id)
            if not isinstance(certificate, dict):
                raise EdgeQualificationError("uploaded AOP certificate is absent")
            _require_qualification_certificate(certificate, now=observed_at)
            _require_leaf_certificate(
                certificate,
                ca_path=ca_paths[generation],
                expected_zone=ZONE_NAMES[zone_key],
            )


def run_rollover_stage(inputs: EdgeInputs, *, stage: str) -> tuple[CheckResult, ...]:
    """Prove one reviewed AOP association/trust transition."""
    if stage not in ROLLOVER_STAGES:
        raise EdgeQualificationError("rollover stage is not recognized")
    client = CloudflareClient(inputs.api_token)
    generation = STAGE_GENERATIONS[stage]
    _require_associations(client, inputs, generation=generation)
    check_id = f"m3.0.edge.aop-{stage}"
    if stage == "retired-primary":
        _require_retired_aop_rejection(inputs, client=client)
        evidence = {
            "both_zones_checked": True,
            "old_leaf_rejected": True,
            "origin_tls_stable": True,
        }
        return (CheckResult(check_id=check_id, status="passed", evidence=evidence),)

    responses = (
        _request(PLATFORM_HOST, "/fidelity"),
        _request(CANONICAL_HOST, "/static"),
    )
    if any(
        response.status != HTTPStatus.OK or not _origin_reached(response) for response in responses
    ):
        raise EdgeQualificationError("selected origin-pull generation did not reach both zones")
    evidence = {"associations_exact": True, "edge_reachable": True}
    stage_check = CheckResult(check_id=check_id, status="passed", evidence=evidence)
    if stage != "final":
        return (stage_check,)
    return (stage_check, *_run_final_edge_checks(inputs, client=client))


def _require_retired_aop_rejection(inputs: EdgeInputs, *, client: CloudflareClient) -> None:
    targets = ((PLATFORM_HOST, "/fidelity"), (CANONICAL_HOST, "/static"))
    origin_certificates = tuple(_origin_certificate(inputs, hostname) for hostname, _ in targets)
    for attempt in range(AOP_PROPAGATION_ATTEMPTS):
        responses = tuple(_request(hostname, path) for hostname, path in targets)
        if all(
            response.status in RETIRED_AOP_EDGE_STATUSES and not _origin_reached(response)
            for response in responses
        ):
            if (
                tuple(_origin_certificate(inputs, hostname) for hostname, _ in targets)
                != origin_certificates
            ):
                raise EdgeQualificationError("origin TLS listener changed during AOP rejection")
            _require_associations(client, inputs, generation="primary")
            return
        if attempt + 1 < AOP_PROPAGATION_ATTEMPTS:
            time.sleep(AOP_PROPAGATION_RETRY_DELAY_SECONDS)
    raise EdgeQualificationError("old origin-pull leaf was not rejected")


def _run_final_edge_checks(
    inputs: EdgeInputs, *, client: CloudflareClient
) -> tuple[CheckResult, ...]:
    operations: tuple[tuple[str, Callable[[], Mapping[str, EvidenceValue]]], ...] = (
        ("zone-policy", lambda: _check_zone_policy(client, inputs)),
        ("proxied-dns", lambda: _check_proxied_dns(inputs)),
        ("certificates", lambda: _check_certificates(inputs)),
        ("direct-origin", lambda: _check_direct_origin(inputs)),
        ("forwarded-address", lambda: _check_forwarded_address(inputs)),
        ("cache-bypass", _check_cache_bypass),
        ("representation-fidelity", lambda: _check_representation_fidelity(inputs)),
        ("reserved-path", _check_reserved_path),
        ("unknown-host", _check_unknown_host),
        ("http-policy", _check_http_policy),
        ("origin-unavailable", lambda: _check_origin_unavailable(inputs)),
    )
    if tuple(suffix for suffix, _ in operations) != FINAL_EDGE_SUFFIXES:
        raise EdgeQualificationError("final edge check set is inconsistent")
    checks: list[CheckResult] = []
    for suffix, operation in operations:
        check_id = f"m3.0.edge.{suffix}"
        try:
            evidence = operation()
        except OSError, ValueError, EdgeQualificationError, subprocess.SubprocessError:
            checks.append(
                CheckResult(
                    check_id=check_id,
                    status="failed",
                    evidence={},
                    error_code="probe_failed",
                )
            )
        else:
            checks.append(CheckResult(check_id=check_id, status="passed", evidence=evidence))
    return tuple(checks)


def _check_zone_policy(client: CloudflareClient, inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    for zone_id in inputs.zone_ids.values():
        _require_zone_settings(client, zone_id)
    return {"always_online_disabled": True, "full_strict": True}


def _check_proxied_dns(inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    for hostname in (PLATFORM_HOST, ALIAS_HOST, UNKNOWN_HOST, CANONICAL_HOST):
        addresses = {
            str(item[4][0]) for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        }
        if not addresses or inputs.origin_ipv4 in addresses:
            raise EdgeQualificationError("proxied DNS exposed the disposable origin")
        if not all(_is_cloudflare_address(address) for address in addresses):
            raise EdgeQualificationError("proxied DNS returned a non-Cloudflare address")
    return {"origin_hidden": True, "proxy_addresses": True}


def _check_certificates(inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    for hostname in (PLATFORM_HOST, CANONICAL_HOST):
        edge_certificate = _edge_certificate(hostname)
        origin_certificate = _origin_certificate(inputs, hostname)
        if hashlib.sha256(edge_certificate).digest() == hashlib.sha256(origin_certificate).digest():
            raise EdgeQualificationError("edge and origin unexpectedly use the same certificate")
    return {"distinct_certificates": True, "public_edge_valid": True}


def _check_direct_origin(inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    denied: dict[int, bool] = {}
    for port in (80, 443):
        try:
            connection = socket.create_connection(
                (inputs.origin_ipv4, port), timeout=DIRECT_TIMEOUT_SECONDS
            )
        except OSError:
            denied[port] = True
        else:
            connection.close()
            denied[port] = False
    if not all(denied.values()):
        raise EdgeQualificationError("direct origin web access was admitted")
    return {"http_denied": True, "https_denied": True}


def _check_forwarded_address(inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    sentinel = "192.0.2.123"
    nonce = secrets.token_hex(16)
    initial_position = _caddy_log_position(inputs)
    expected_uris: dict[str, str] = {}
    rejected_uris: dict[str, str] = {}
    for index, (hostname, path) in enumerate(
        ((PLATFORM_HOST, "/fidelity"), (CANONICAL_HOST, "/static"))
    ):
        rejected_uri = f"{path}?m3-cf-connecting-ip-spoof={nonce}-{index}"
        rejected_uris[hostname] = rejected_uri
        rejected = _request(
            hostname,
            rejected_uri,
            fields={"CF-Connecting-IP": sentinel},
        )
        if rejected.status != HTTPStatus.FORBIDDEN or _origin_reached(rejected):
            raise EdgeQualificationError("forged Cloudflare address header was not preempted")

        uri = f"{path}?m3-forwarded-for-spoof={nonce}-{index}"
        expected_uris[hostname] = uri
        response = _request(
            hostname,
            uri,
            fields={"X-Forwarded-For": sentinel},
        )
        if response.status != HTTPStatus.OK or not _origin_reached(response):
            raise EdgeQualificationError("forwarding probe did not reach the origin")
    for attempt in range(LOG_PROPAGATION_ATTEMPTS):
        log_delta = _caddy_log_delta(inputs, initial_position)
        if _forwarding_records_are_valid(
            log_delta,
            expected_uris=expected_uris,
            rejected_uris=rejected_uris,
            sentinel=sentinel,
        ):
            return {
                "authentic_address": True,
                "cf_header_rejected": True,
                "xff_spoof_ignored": True,
            }
        if attempt + 1 < LOG_PROPAGATION_ATTEMPTS:
            time.sleep(LOG_PROPAGATION_RETRY_DELAY_SECONDS)
    raise EdgeQualificationError("forwarding probes were absent from the bounded Caddy log")


def _check_cache_bypass() -> dict[str, EvidenceValue]:
    for hostname, path in CACHE_ROUTE_PATHS:
        for _ in range(2):
            response = _request(hostname, path, follow_redirects=False)
            cache_status = response.fields.get("cf-cache-status", "").upper()
            if cache_status not in UNCACHEABLE_EDGE_STATUSES or "age" in response.fields:
                raise EdgeQualificationError("qualification response became edge-cache eligible")
    return {"classes_bypassed": True, "repeat_bypassed": True}


def _check_representation_fidelity(inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    forbidden = (b"cloudflare-static", b"email-decode", b"rocket-loader", b"beacon.min.js")
    for hostname in (PLATFORM_HOST, CANONICAL_HOST):
        origin = _ssh(
            inputs,
            "curl",
            "--silent",
            "--show-error",
            "--header",
            f"Host: {hostname}",
            "http://127.0.0.1:18081/fidelity",
        ).stdout
        response = _request(hostname, "/fidelity")
        if (
            response.status != HTTPStatus.OK
            or response.content != origin
            or any(marker in response.content for marker in forbidden)
        ):
            raise EdgeQualificationError("Cloudflare changed the origin representation")
        if "no-transform" not in response.fields.get("cache-control", ""):
            raise EdgeQualificationError("origin omitted the no-transform directive")
    return {"representations_equal": True, "transforms_absent": True}


def _check_reserved_path() -> dict[str, EvidenceValue]:
    for hostname in (PLATFORM_HOST, CANONICAL_HOST):
        for path in RESERVED_PATHS:
            response = _request(hostname, path)
            if response.status != HTTPStatus.FORBIDDEN or _origin_reached(response):
                raise EdgeQualificationError("reserved Cloudflare namespace reached the origin")
    return {"origin_preempted": True, "provider_namespace_blocked": True}


def _check_unknown_host() -> dict[str, EvidenceValue]:
    response = _request(UNKNOWN_HOST, "/")
    if response.status != HTTPStatus.NOT_FOUND or not _origin_reached(response):
        raise EdgeQualificationError("unknown disposable host did not fail at Caddy")
    expected = b"No Lower Duck Pond site has been provisioned for this name."
    if response.content != expected:
        raise EdgeQualificationError("unknown disposable host returned a non-generic response")
    return {"generic_failure": True, "origin_reached": True}


def _check_http_policy() -> dict[str, EvidenceValue]:
    cases = (
        ("GET", PLATFORM_HOST, "/fidelity?m3=platform"),
        ("GET", ALIAS_HOST, "/?m3=alias"),
        ("POST", ALIAS_HOST, "/not-root?m3=method"),
        ("GET", CANONICAL_HOST, "/static?m3=tenant"),
        ("GET", UNKNOWN_HOST, "/missing?m3=unknown"),
    )
    for method, hostname, path in cases:
        response = _request(
            hostname,
            path,
            https=False,
            method=method,
            follow_redirects=False,
        )
        if (
            response.status != HTTPStatus.PERMANENT_REDIRECT
            or response.fields.get("location") != f"https://{hostname}{path}"
            or _origin_reached(response)
        ):
            raise EdgeQualificationError("public HTTP did not preserve redirect semantics")
    return {"redirect_only": True}


def _check_origin_unavailable(inputs: EdgeInputs) -> dict[str, EvidenceValue]:
    targets = ((PLATFORM_HOST, "/fidelity"), (CANONICAL_HOST, "/static"))
    prior = tuple(_request(hostname, path) for hostname, path in targets)
    if any(response.status != HTTPStatus.OK or not _origin_reached(response) for response in prior):
        raise EdgeQualificationError("origin was not healthy before the outage probe")
    _ssh(inputs, "sudo", "systemctl", "stop", "caddy.service")
    try:
        for (hostname, path), prior_response in zip(targets, prior, strict=True):
            unavailable: EdgeResponse | None = None
            for _ in range(OUTAGE_ATTEMPTS):
                candidate = _request(hostname, path)
                if candidate.status in EDGE_ERROR_STATUSES:
                    unavailable = candidate
                    break
                time.sleep(RETRY_DELAY_SECONDS)
            if unavailable is None:
                raise EdgeQualificationError(
                    "origin outage did not produce a documented edge error"
                )
            if _origin_reached(unavailable) or unavailable.content == prior_response.content:
                raise EdgeQualificationError("origin outage served a prior representation")
    finally:
        _ssh(inputs, "sudo", "systemctl", "start", "caddy.service")
    for _ in range(RECOVERY_ATTEMPTS):
        recovered = tuple(_request(hostname, path) for hostname, path in targets)
        if all(
            response.status == HTTPStatus.OK and _origin_reached(response) for response in recovered
        ):
            return {
                "provider_error_observed": True,
                "recovered": True,
                "representations_absent": True,
            }
        time.sleep(RETRY_DELAY_SECONDS)
    raise EdgeQualificationError("origin did not recover through the edge")


def _require_zone_settings(client: CloudflareClient, zone_id: str) -> None:
    ssl_setting = client.get(f"/zones/{zone_id}/settings/ssl")
    always_online = client.get(f"/zones/{zone_id}/settings/always_online")
    if not isinstance(ssl_setting, dict) or ssl_setting.get("value") != "strict":
        raise EdgeQualificationError("zone SSL mode is not Full strict")
    if not isinstance(always_online, dict) or always_online.get("value") != "off":
        raise EdgeQualificationError("Always Online must be disabled before qualification")


def _require_no_ruleset_conflicts(client: CloudflareClient, zone_id: str) -> None:
    rulesets = client.get(f"/zones/{zone_id}/rulesets")
    if not isinstance(rulesets, list):
        raise EdgeQualificationError("zone ruleset entitlement is unsupported")
    managed_phases = {
        "http_request_cache_settings",
        "http_request_firewall_custom",
        "http_config_settings",
    }
    if any(
        isinstance(item, dict)
        and item.get("kind") == "zone"
        and item.get("phase") in managed_phases
        for item in rulesets
    ):
        raise EdgeQualificationError("a zone entrypoint conflicts with disposable edge policy")


def _require_qualification_certificate(certificate: Mapping[str, object], *, now: datetime) -> None:
    if certificate.get("status") != "active":
        raise EdgeQualificationError("uploaded AOP certificate is not active")
    uploaded = _timestamp(certificate.get("uploaded_on"))
    expires = _timestamp(certificate.get("expires_on"))
    lifetime = expires - uploaded
    if (
        expires - now < MINIMUM_CERTIFICATE_REMAINING
        or lifetime < MINIMUM_CERTIFICATE_LIFETIME
        or lifetime > MAXIMUM_CERTIFICATE_LIFETIME
    ):
        raise EdgeQualificationError("qualification AOP certificate lifetime is outside policy")


def _require_ca_certificate(path: Path, *, now: datetime) -> None:
    try:
        raw = path.read_text(encoding="ascii", errors="strict")
        encoded = raw.encode("ascii", errors="strict")
        if (
            len(encoded) > MAXIMUM_CERTIFICATE_PEM_BYTES
            or raw.count("-----BEGIN CERTIFICATE-----") != 1
            or raw.count("-----END CERTIFICATE-----") != 1
        ):
            raise EdgeQualificationError("origin-pull CA input is malformed")
        identity = (
            subprocess.run(  # noqa: S603
                (
                    OPENSSL_EXECUTABLE,
                    "x509",
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-nameopt",
                    "RFC2253",
                ),
                input=encoded,
                capture_output=True,
                check=True,
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            .stdout.decode("ascii", errors="strict")
            .splitlines()
        )
        constraints = subprocess.run(  # noqa: S603
            (OPENSSL_EXECUTABLE, "x509", "-noout", "-text"),
            input=encoded,
            capture_output=True,
            check=True,
            timeout=HTTP_TIMEOUT_SECONDS,
        ).stdout
        dates = subprocess.run(  # noqa: S603
            (OPENSSL_EXECUTABLE, "x509", "-noout", "-dates", "-dateopt", "iso_8601"),
            input=encoded,
            capture_output=True,
            check=True,
            timeout=HTTP_TIMEOUT_SECONDS,
        ).stdout.decode("ascii", errors="strict")
        subprocess.run(  # noqa: S603
            (OPENSSL_EXECUTABLE, "verify", "-CAfile", str(path), str(path)),
            capture_output=True,
            check=True,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise EdgeQualificationError("origin-pull CA input did not verify") from error
    if (
        len(identity) != CERTIFICATE_IDENTITY_LINE_COUNT
        or not identity[0].startswith("subject=")
        or not identity[1].startswith("issuer=")
        or identity[0].removeprefix("subject=") != identity[1].removeprefix("issuer=")
        or b"CA:TRUE" not in constraints
        or b"Certificate Sign" not in constraints
    ):
        raise EdgeQualificationError("origin-pull CA constraints are unsafe")
    values = dict(line.split("=", maxsplit=1) for line in dates.splitlines() if "=" in line)
    try:
        not_before = datetime.strptime(values["notBefore"], "%Y-%m-%d %H:%M:%SZ").replace(
            tzinfo=UTC
        )
        not_after = datetime.strptime(values["notAfter"], "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=UTC)
    except (KeyError, ValueError) as error:
        raise EdgeQualificationError("origin-pull CA validity is malformed") from error
    if (
        not_before > now
        or not_after - now < MINIMUM_CA_REMAINING
        or not_after - not_before > MAXIMUM_CA_LIFETIME
    ):
        raise EdgeQualificationError("origin-pull CA validity is outside policy")


def _require_leaf_certificate(
    certificate: Mapping[str, object], *, ca_path: Path, expected_zone: str
) -> None:
    raw = certificate.get("certificate")
    if (
        not isinstance(raw, str)
        or len(raw) > MAXIMUM_CERTIFICATE_PEM_BYTES
        or not raw.startswith("-----BEGIN CERTIFICATE-----\n")
        or not raw.rstrip().endswith("-----END CERTIFICATE-----")
    ):
        raise EdgeQualificationError("uploaded AOP leaf is malformed")
    try:
        encoded = raw.encode("ascii", errors="strict")
        subprocess.run(  # noqa: S603 - executable and argument boundary are fixed.
            (
                OPENSSL_EXECUTABLE,
                "verify",
                "-purpose",
                "sslclient",
                "-CAfile",
                str(ca_path),
                "/dev/stdin",
            ),
            input=encoded,
            capture_output=True,
            check=True,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        constraints = subprocess.run(  # noqa: S603
            (
                OPENSSL_EXECUTABLE,
                "x509",
                "-noout",
                "-text",
            ),
            input=encoded,
            capture_output=True,
            check=True,
            timeout=HTTP_TIMEOUT_SECONDS,
        ).stdout
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise EdgeQualificationError("uploaded AOP leaf did not verify") from error
    dns_names = frozenset(re.findall(rb"DNS:([^,\s]+)", constraints))
    if (
        b"CA:FALSE" not in constraints
        or b"TLS Web Client Authentication" not in constraints
        or dns_names != {expected_zone.encode("ascii")}
    ):
        raise EdgeQualificationError("uploaded AOP leaf constraints are unsafe")


def _require_associations(client: CloudflareClient, inputs: EdgeInputs, *, generation: str) -> None:
    for zone_key, hostnames in HOSTS_BY_ZONE.items():
        zone_id = inputs.zone_ids[zone_key]
        expected_id = inputs.certificate_ids[generation][zone_key]
        for hostname in hostnames:
            encoded = urllib.parse.quote(hostname, safe="")
            result = client.get(f"/zones/{zone_id}/origin_tls_client_auth/hostnames/{encoded}")
            if isinstance(result, list) and len(result) == 1:
                result = result[0]
            if (
                not isinstance(result, dict)
                or result.get("hostname") != hostname
                or result.get("cert_id") != expected_id
                or result.get("enabled") is not True
                or result.get("cert_status") != "active"
            ):
                raise EdgeQualificationError("AOP hostname association is not exact and active")


def _request(  # noqa: PLR0913 - an HTTP probe needs explicit bounded controls.
    hostname: str,
    path: str,
    *,
    https: bool = True,
    method: str = "GET",
    fields: Mapping[str, str] | None = None,
    follow_redirects: bool = False,
) -> EdgeResponse:
    if hostname not in {PLATFORM_HOST, ALIAS_HOST, UNKNOWN_HOST, CANONICAL_HOST}:
        raise EdgeQualificationError("edge request hostname is not allowlisted")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise EdgeQualificationError("edge request path is unsafe")
    if method not in {"GET", "HEAD", "POST"}:
        raise EdgeQualificationError("edge request method is not allowlisted")
    request_fields = {"User-Agent": "lowerduckpond-m3-qualification/1", **(fields or {})}
    connection_class = http.client.HTTPSConnection if https else http.client.HTTPConnection
    connection = connection_class(hostname, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.request(method, path, headers=request_fields)
        response = connection.getresponse()
        content = response.read(MAXIMUM_EDGE_RESPONSE_BYTES + 1)
        if len(content) > MAXIMUM_EDGE_RESPONSE_BYTES:
            raise EdgeQualificationError("edge response exceeded its bound")
        response_fields = {key.lower(): value.strip() for key, value in response.getheaders()}
    except (OSError, http.client.HTTPException) as error:
        raise EdgeQualificationError("edge request failed") from error
    finally:
        connection.close()
    result = EdgeResponse(status=response.status, fields=response_fields, content=content)
    if follow_redirects and response.status in {301, 302, 307, 308}:
        raise EdgeQualificationError("implicit redirects are not permitted by this probe")
    return result


def _origin_reached(response: EdgeResponse) -> bool:
    return response.fields.get("x-m3-origin-reached") == "true"


def _edge_certificate(hostname: str) -> bytes:
    context = ssl.create_default_context()
    with (
        socket.create_connection((hostname, 443), timeout=HTTP_TIMEOUT_SECONDS) as connection,
        context.wrap_socket(connection, server_hostname=hostname) as secured,
    ):
        certificate = secured.getpeercert(binary_form=True)
    if not certificate:
        raise EdgeQualificationError("edge did not present a public certificate")
    return certificate


def _origin_certificate(inputs: EdgeInputs, hostname: str) -> bytes:
    result = _ssh(
        inputs,
        "sudo",
        "openssl",
        "s_client",
        "-connect",
        "127.0.0.1:443",
        "-servername",
        hostname,
        "-showcerts",
        check=False,
    )
    match = re.search(
        rb"-----BEGIN CERTIFICATE-----\r?\n.+?-----END CERTIFICATE-----",
        result.stdout,
        re.DOTALL,
    )
    if match is None:
        raise EdgeQualificationError("origin certificate could not be observed")
    return ssl.PEM_cert_to_DER_cert(match.group(0).decode("ascii"))


def _caddy_log_position(inputs: EdgeInputs) -> _LogPosition:
    result = _ssh(
        inputs,
        "sudo",
        "/usr/bin/stat",
        "--format=%d:%i:%s",
        CADDY_LOG_PATH,
    )
    try:
        device, inode, size = (
            int(value) for value in result.stdout.decode("ascii").strip().split(":")
        )
    except (UnicodeError, ValueError) as error:
        raise EdgeQualificationError("Caddy log position is malformed") from error
    if device < 1 or inode < 1 or size < 0:
        raise EdgeQualificationError("Caddy log position is unsafe")
    return _LogPosition(device=device, inode=inode, size=size)


def _caddy_log_delta(inputs: EdgeInputs, initial: _LogPosition) -> bytes:
    current = _caddy_log_position(inputs)
    if (current.device, current.inode) != (
        initial.device,
        initial.inode,
    ) or current.size < initial.size:
        raise EdgeQualificationError("Caddy log rotated during the forwarding probe")
    length = current.size - initial.size
    if length > MAXIMUM_LOG_PROBE_BYTES:
        raise EdgeQualificationError("Caddy log probe exceeded its bound")
    if length == 0:
        return b""
    result = _ssh(
        inputs,
        "sudo",
        "/usr/bin/dd",
        f"if={CADDY_LOG_PATH}",
        "iflag=skip_bytes,count_bytes",
        f"skip={initial.size}",
        f"count={length}",
        "status=none",
    )
    if len(result.stdout) != length:
        raise EdgeQualificationError("Caddy log probe was not read exactly")
    return result.stdout


def _forwarding_records_are_valid(
    raw: bytes,
    *,
    expected_uris: Mapping[str, str],
    rejected_uris: Mapping[str, str],
    sentinel: str,
) -> bool:
    records: dict[str, Mapping[str, object]] = {}
    for line in raw.splitlines():
        parsed = _parse_caddy_log_line(line)
        if parsed is None:
            continue
        value, request = parsed
        hostname = request.get("host")
        uri = request.get("uri")
        if isinstance(hostname, str) and rejected_uris.get(hostname) == uri:
            raise EdgeQualificationError("preempted Cloudflare address spoof reached the origin")
        if isinstance(hostname, str) and expected_uris.get(hostname) == uri:
            if hostname in records:
                raise EdgeQualificationError("forwarding probe log identity was duplicated")
            records[hostname] = value
    if set(records) != set(expected_uris):
        return False
    for hostname, record in records.items():
        record_request = record.get("request")
        if not isinstance(record_request, dict) or record.get("status") != HTTPStatus.OK:
            raise EdgeQualificationError("forwarding probe log record is malformed")
        remote_raw = record_request.get("remote_ip")
        client_raw = record_request.get("client_ip")
        if not isinstance(remote_raw, str) or not isinstance(client_raw, str):
            raise EdgeQualificationError("forwarding probe addresses are absent")
        try:
            remote = ipaddress.ip_address(remote_raw)
            client = ipaddress.ip_address(client_raw)
        except ValueError as error:
            raise EdgeQualificationError("forwarding probe addresses are malformed") from error
        if (
            not _is_cloudflare_address(str(remote))
            or not client.is_global
            or str(client) == sentinel
            or client == remote
        ):
            raise EdgeQualificationError(f"forwarding identity was not authentic for {hostname}")
    return True


def _parse_caddy_log_line(
    line: bytes,
) -> tuple[Mapping[str, object], Mapping[str, object]] | None:
    try:
        value = json.loads(line)
    except UnicodeError, json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    request = value.get("request")
    if not isinstance(request, dict):
        return None
    return value, request


def _ssh(
    inputs: EdgeInputs, *remote_command: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    if not remote_command or any("\x00" in argument for argument in remote_command):
        raise EdgeQualificationError("remote command is malformed")
    return subprocess.run(  # noqa: S603
        (
            SSH_EXECUTABLE,
            "-o",
            "BatchMode=yes",
            inputs.ssh_target,
            shlex.join(remote_command),
        ),
        input=b"",
        capture_output=True,
        check=check,
        timeout=HTTP_TIMEOUT_SECONDS,
    )


def _is_cloudflare_address(raw: str) -> bool:
    address = ipaddress.ip_address(raw)
    return any(address in ipaddress.ip_network(network) for network in CLOUDFLARE_NETWORKS)


def _validate_zone_ids(zone_ids: Mapping[str, str]) -> None:
    if set(zone_ids) != set(HOSTS_BY_ZONE) or any(
        re.fullmatch(r"[0-9a-f]{32}", value) is None for value in zone_ids.values()
    ):
        raise EdgeQualificationError("zone identifiers are malformed")


def _validate_certificate_ids(value: Mapping[str, Mapping[str, str]]) -> None:
    if set(value) != {"primary", "replacement"}:
        raise EdgeQualificationError("AOP certificate generations are incomplete")
    observed: set[str] = set()
    for generation in ("primary", "replacement"):
        ids = value[generation]
        if set(ids) != set(HOSTS_BY_ZONE):
            raise EdgeQualificationError("AOP certificate zone IDs are incomplete")
        for certificate_id in ids.values():
            if CERTIFICATE_ID_PATTERN.fullmatch(certificate_id) is None:
                raise EdgeQualificationError("AOP certificate ID is malformed")
            observed.add(certificate_id)
    if len(observed) != ROLLOVER_CERTIFICATE_COUNT:
        raise EdgeQualificationError("AOP rollover requires four distinct certificate IDs")


def load_certificate_ids(path: Path | None) -> dict[str, dict[str, str]]:
    """Load the non-secret Terraform input shape from a bounded JSON file or stdin."""
    if path is None:
        raise EdgeQualificationError("certificate ID input is required")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(isinstance(item, dict) for item in value.values()):
        raise EdgeQualificationError("certificate ID input shape is malformed")
    normalized = {
        str(generation): {str(zone): str(identifier) for zone, identifier in ids.items()}
        for generation, ids in value.items()
    }
    _validate_certificate_ids(normalized)
    return normalized


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise EdgeQualificationError("certificate timestamp is absent")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EdgeQualificationError("certificate timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise EdgeQualificationError("certificate timestamp lacks a timezone")
    return parsed.astimezone(UTC)
