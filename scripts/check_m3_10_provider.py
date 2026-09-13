#!/usr/bin/env python3
"""Read-only Spaces policy/inventory and enforced Cloudflare edge checks."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import Protocol, cast

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import (
    S3Client,
    assert_storage_empty,
    assert_versioning_enabled,
)
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.check_m3_7_production_edge import (
    CloudflareClient,
    ProductionEdgePreflightError,
    _read_ca_path,
    validate_ca_certificate,
    validate_leaf_certificate,
)
from scripts.m3_10_policy_client import make_policy_client


class GateError(RuntimeError):
    """A required live starting condition could not be proved."""


class PolicyClient(S3Client, Protocol):
    def get_bucket_acl(self, **kwargs: object) -> dict[str, object]: ...

    def get_bucket_policy(self, **kwargs: object) -> dict[str, object]: ...

    def get_bucket_lifecycle_configuration(self, **kwargs: object) -> dict[str, object]: ...


def _require_absent_configuration(
    operation: Callable[..., dict[str, object]], *, bucket: str, missing_code: str
) -> None:
    try:
        operation(Bucket=bucket)
    except ClientError as error:
        response = error.response
        if (
            response.get("Error", {}).get("Code") == missing_code
            and response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.NOT_FOUND
        ):
            return
        raise GateError("bucket configuration could not be read") from error
    raise GateError("archive bucket has an unexpected policy or lifecycle configuration")


def check_storage(client: PolicyClient, *, bucket: str, require_empty: bool = True) -> None:
    """Require private versioned storage, optionally including whole-bucket absence.

    This uses the workstation's existing Spaces operator key for bucket policy
    reads. The limited archive runtime key is never promoted to that role.
    AccessDenied is a failed proof, never evidence of missing configuration.
    """
    acl = client.get_bucket_acl(Bucket=bucket)
    owner = acl.get("Owner")
    grants = acl.get("Grants")
    if (
        not isinstance(owner, dict)
        or not isinstance(owner.get("ID"), str)
        or not owner["ID"]
        or not isinstance(grants, list)
        or len(grants) != 1
        or not isinstance(grants[0], dict)
    ):
        raise GateError("archive bucket ACL is not an exact private owner grant")
    grant = grants[0]
    grantee = grant.get("Grantee")
    if (
        grant.get("Permission") != "FULL_CONTROL"
        or not isinstance(grantee, dict)
        or grantee.get("Type") != "CanonicalUser"
        or grantee.get("ID") != owner["ID"]
    ):
        raise GateError("archive bucket ACL is not an exact private owner grant")
    _require_absent_configuration(
        client.get_bucket_policy, bucket=bucket, missing_code="NoSuchBucketPolicy"
    )
    _require_absent_configuration(
        client.get_bucket_lifecycle_configuration,
        bucket=bucket,
        missing_code="NoSuchLifecycleConfiguration",
    )
    if require_empty:
        assert_storage_empty(client, bucket=bucket, prefix="")
    else:
        assert_versioning_enabled(client, bucket=bucket)


def expected_rules(domain: str) -> dict[str, dict[str, object]]:
    host = f'(http.host eq "{domain}" or ends_with(http.host, ".{domain}"))'
    return {
        "http_request_cache_settings": {
            "action": "set_cache_settings",
            "expression": host,
            "enabled": True,
            "ref": "lowerduckpond_m3_cache_bypass",
            "action_parameters": {"cache": False},
        },
        "http_config_settings": {
            "action": "set_config",
            "expression": host,
            "enabled": True,
            "ref": "lowerduckpond_m3_transform_disable",
            "action_parameters": {
                "automatic_https_rewrites": False,
                "disable_rum": True,
                "disable_zaraz": True,
                "email_obfuscation": False,
                "fonts": False,
                "rocket_loader": False,
            },
        },
        "http_request_firewall_custom": {
            "action": "block",
            "expression": (
                f'{host} and (lower(http.request.uri.path) eq "/cdn-cgi" '
                'or starts_with(lower(http.request.uri.path), "/cdn-cgi/"))'
            ),
            "enabled": True,
            "ref": "lowerduckpond_m3_cdn_cgi_block",
        },
    }


def check_edge(  # noqa: PLR0912, PLR0913 - explicit enforced-edge identity and trust
    client: CloudflareClient,
    *,
    zone_id: str,
    certificate_id: str,
    domain: str,
    origin: str,
    ca_path: Path,
    now: datetime,
) -> None:
    if (
        re.fullmatch(r"[0-9a-f]{32}", zone_id) is None
        or re.fullmatch(
            r"(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", certificate_id
        )
        is None
    ):
        raise GateError("edge identity is malformed")
    zone = f"/zones/{zone_id}"
    details = client.get(zone)
    if (
        not isinstance(details, dict)
        or details.get("name") != domain
        or details.get("status") != "active"
        or details.get("paused") is not False
    ):
        raise GateError("edge zone identity, active status, or proxy pause state drifted")
    records = client.get_collection(f"{zone}/dns_records")
    routing = [
        item
        for item in records
        if not isinstance(item, dict) or item.get("type") not in {"CAA", "MX", "TXT"}
    ]
    expected_names = {domain, f"*.{domain}"}
    if len(routing) != len(expected_names):
        raise GateError("edge routing inventory drifted")
    observed_names = set()
    for record in routing:
        if (
            not isinstance(record, dict)
            or record.get("type") != "A"
            or record.get("content") != origin
            or record.get("proxied") is not True
            or record.get("ttl") != 1
            or record.get("name") not in expected_names
        ):
            raise GateError("edge routing policy drifted")
        observed_names.add(record["name"])
    if observed_names != expected_names:
        raise GateError("edge routing identity drifted")
    for setting, expected in {
        "ssl": "strict",
        "always_online": "off",
        "always_use_https": "off",
    }.items():
        value = client.get(f"{zone}/settings/{setting}")
        if not isinstance(value, dict) or value.get("value") != expected:
            raise GateError("edge TLS or response policy drifted")
    aop = client.get_aop_setting(zone_id)
    if not isinstance(aop, dict) or aop.get("enabled") is not True:
        raise GateError("edge origin pulls are not enabled")
    if client.get_collection(f"{zone}/origin_tls_client_auth/hostnames"):
        raise GateError("edge has unexpected hostname-level origin-pull overrides")
    certificates = client.get_collection(f"{zone}/origin_tls_client_auth")
    active = [
        certificate
        for certificate in certificates
        if isinstance(certificate, dict) and certificate.get("status") == "active"
    ]
    if (
        any(not isinstance(certificate, dict) for certificate in certificates)
        or len(active) != 1
        or active[0].get("id") != certificate_id
    ):
        raise GateError("edge active origin-pull certificate inventory drifted")
    validate_leaf_certificate(
        active[0], ca_path=ca_path, expected_zone=domain, expected_id=certificate_id, now=now
    )
    phase_rules = expected_rules(domain)
    inventory = client.get_cursor_collection(f"{zone}/rulesets")
    if any(
        not isinstance(item, dict) or item.get("kind") not in {"managed", "custom", "zone"}
        for item in inventory
    ):
        raise GateError("edge ruleset inventory is malformed")
    # Cloudflare also lists available account/managed rulesets. Only kind=zone
    # denotes this zone's configured phase entrypoint; every such phase must
    # match the reviewed inventory before any individual rule is accepted.
    phases = [
        item.get("phase") for item in inventory if isinstance(item, dict) and item["kind"] == "zone"
    ]
    if len(phases) != len(phase_rules) or any(
        not isinstance(phase, str) or phase not in phase_rules for phase in phases
    ):
        raise GateError("edge has unexpected or missing ruleset phases")
    if len(set(phases)) != len(phase_rules):
        raise GateError("edge ruleset phases are duplicated")
    for phase, expected_rule in phase_rules.items():
        entrypoint = client.get(f"{zone}/rulesets/phases/{phase}/entrypoint")
        rules = entrypoint.get("rules") if isinstance(entrypoint, dict) else None
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            raise GateError("edge ruleset inventory drifted")
        if any(rules[0].get(key) != value for key, value in expected_rule.items()):
            raise GateError("edge ruleset policy drifted")
        if "action_parameters" not in expected_rule and rules[0].get("action_parameters") not in (
            None,
            {},
        ):
            raise GateError("edge block response policy drifted")


def required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise GateError(f"required environment variable {name} is missing")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage-only", action="store_true")
    parser.add_argument("--allow-existing-archives", action="store_true")
    arguments = parser.parse_args()
    try:
        configuration = ArchiveConfiguration(
            required(os.environ, "SPACES_REGION"),
            required(os.environ, "SPACES_ARCHIVE_BUCKET"),
            required(os.environ, "SPACES_ACCESS_KEY_ID"),
            required(os.environ, "SPACES_SECRET_ACCESS_KEY"),
        )
        client = cast(PolicyClient, make_policy_client(configuration))
        check_storage(
            client, bucket=configuration.bucket, require_empty=not arguments.allow_existing_archives
        )
        storage_proof = (
            "private/versioned/no-lifecycle storage"
            if arguments.allow_existing_archives
            else "private/versioned/no-lifecycle storage and whole-bucket absence"
        )
        if arguments.storage_only:
            print(f"M3.10 {storage_proof} passed.")
            return 0
        edge = CloudflareClient(required(os.environ, "CLOUDFLARE_API_TOKEN"))
        ca_path, ca_pem = _read_ca_path()
        now = datetime.now(UTC)
        validate_ca_certificate(ca_path, ca_pem, now=now)
        for domain, prefix in (
            ("lowerduckpond.net", "CLOUDFLARE"),
            ("lowerduckpond.com", "CLOUDFLARE_TENANT"),
        ):
            check_edge(
                edge,
                zone_id=required(os.environ, f"{prefix}_ZONE_ID"),
                certificate_id=required(os.environ, f"{prefix}_ORIGIN_PULL_CERTIFICATE_ID"),
                domain=domain,
                origin=required(os.environ, "PRODUCTION_ORIGIN_IPV4"),
                ca_path=ca_path,
                now=now,
            )
    except (BotoCoreError, ClientError, RuntimeError, ValueError, OSError) as error:
        # Provider exceptions can include request URLs, headers, and credentials.
        message = (
            str(error)
            if isinstance(error, (GateError, ProductionEdgePreflightError))
            else type(error).__name__
        )
        print(f"M3.10 provider preflight failed closed: {message}.", file=sys.stderr)
        return 1
    print(f"M3.10 {storage_proof} passed; both edges remain enforced.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
