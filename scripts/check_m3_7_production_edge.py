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
MAXIMUM_API_COLLECTION_ITEMS: Final = 5_000
MAXIMUM_API_PAGES: Final = 100
API_PAGE_SIZE: Final = 50
DEFAULT_RESPONSE_STATUSES: Final = frozenset({HTTPStatus.OK})
AOP_SETTING_RESPONSE_STATUSES: Final = frozenset({HTTPStatus.OK, HTTPStatus.ACCEPTED})
MAXIMUM_CERTIFICATE_BYTES: Final = 20_000
MINIMUM_TOKEN_LENGTH: Final = 20
CERTIFICATE_IDENTITY_LINE_COUNT: Final = 2
CLOUDFLARE_TOKEN_ROLE_COUNT: Final = 3
IPV4_VERSION: Final = 4
MAXIMUM_CA_LIFETIME: Final = timedelta(days=1826)
MINIMUM_CA_REMAINING: Final = timedelta(days=366)
MAXIMUM_LEAF_LIFETIME: Final = timedelta(days=366)
MINIMUM_LEAF_REMAINING: Final = timedelta(days=60)
MAXIMUM_AUDIT_TOKEN_LIFETIME: Final = timedelta(days=7)
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
CADDY_TOKEN_PERMISSIONS: Final = frozenset({"Zone Read", "DNS Write"})
EDGE_TOKEN_PERMISSIONS: Final = frozenset(
    {
        "DNS Write",
        "Zone Settings Write",
        "Cache Settings Write",
        "Config Settings Write",
        "Zone WAF Write",
        "SSL and Certificates Write",
    }
)
AUDIT_TOKEN_PERMISSIONS: Final = frozenset({"Account API Tokens Read"})


class ProductionEdgePreflightError(RuntimeError):
    """Raised when a production-edge starting condition cannot be proved."""


class CloudflareClient:
    """Bounded, read-only Cloudflare API client."""

    def __init__(self, token: str) -> None:
        if len(token) < MINIMUM_TOKEN_LENGTH:
            raise ProductionEdgePreflightError("a Cloudflare token is malformed")
        self._token = token

    def _get_response(
        self,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        accepted_statuses: frozenset[HTTPStatus] = DEFAULT_RESPONSE_STATUSES,
    ) -> dict[str, object]:
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
                if response.status not in accepted_statuses:
                    raise ProductionEdgePreflightError(
                        "Cloudflare returned an unexpected HTTP status"
                    )
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
        return value

    def get(self, path: str, *, query: Mapping[str, str] | None = None) -> object:
        """Return the result of one read-only Cloudflare request."""
        return self._get_response(path, query=query)["result"]

    def get_aop_setting(self, zone_id: str) -> object:
        """Read the one endpoint observed returning either 200 or 202."""
        if ZONE_ID_PATTERN.fullmatch(zone_id) is None:
            raise ProductionEdgePreflightError("a Cloudflare zone ID is malformed")
        return self._get_response(
            f"/zones/{zone_id}/origin_tls_client_auth/settings",
            accepted_statuses=AOP_SETTING_RESPONSE_STATUSES,
        )["result"]

    def get_collection(self, path: str, *, query: Mapping[str, str] | None = None) -> list[object]:
        """Return a complete, bounded page-paginated collection or fail closed."""
        base_query = dict(query or {})
        if "page" in base_query or "per_page" in base_query:
            raise ProductionEdgePreflightError("Cloudflare pagination is caller-controlled")
        collection: list[object] = []
        expected_total_pages: int | None = None
        expected_total_count: int | None = None
        for page in range(1, MAXIMUM_API_PAGES + 1):
            page_query = {
                **base_query,
                "page": str(page),
                "per_page": str(API_PAGE_SIZE),
            }
            response = self._get_response(path, query=page_query)
            result = response["result"]
            result_info = response.get("result_info")
            if not isinstance(result, list) or not isinstance(result_info, dict):
                raise ProductionEdgePreflightError(
                    "Cloudflare collection pagination metadata is malformed"
                )
            current_page = result_info.get("page")
            total_pages = result_info.get("total_pages")
            total_count = result_info.get("total_count")
            count = result_info.get("count")
            if (
                not isinstance(current_page, int)
                or isinstance(current_page, bool)
                or current_page != page
                or not isinstance(total_pages, int)
                or isinstance(total_pages, bool)
                or not 0 <= total_pages <= MAXIMUM_API_PAGES
                or not isinstance(total_count, int)
                or isinstance(total_count, bool)
                or not 0 <= total_count <= MAXIMUM_API_COLLECTION_ITEMS
                or (total_count == 0 and total_pages not in (0, 1))
                or (total_count > 0 and total_pages == 0)
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count != len(result)
            ):
                raise ProductionEdgePreflightError(
                    "Cloudflare collection pagination metadata is malformed"
                )
            if expected_total_pages is None:
                expected_total_pages = total_pages
                expected_total_count = total_count
            elif total_pages != expected_total_pages or total_count != expected_total_count:
                raise ProductionEdgePreflightError(
                    "Cloudflare collection pagination changed during preflight"
                )
            collection.extend(result)
            if len(collection) > MAXIMUM_API_COLLECTION_ITEMS:
                raise ProductionEdgePreflightError("a Cloudflare collection exceeded its bound")
            if page == max(total_pages, 1):
                if len(collection) != total_count:
                    raise ProductionEdgePreflightError(
                        "Cloudflare collection pagination is incomplete"
                    )
                return collection
        raise ProductionEdgePreflightError("a Cloudflare collection exceeded its page bound")

    def get_cursor_collection(
        self, path: str, *, query: Mapping[str, str] | None = None
    ) -> list[object]:
        """Return a complete, bounded cursor-paginated collection or fail closed."""
        base_query = dict(query or {})
        if "cursor" in base_query or "per_page" in base_query:
            raise ProductionEdgePreflightError("Cloudflare pagination is caller-controlled")
        collection: list[object] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(1, MAXIMUM_API_PAGES + 1):
            page_query = {**base_query, "per_page": str(API_PAGE_SIZE)}
            if cursor is not None:
                page_query["cursor"] = cursor
            response = self._get_response(path, query=page_query)
            result = response["result"]
            result_info = response.get("result_info")
            if not isinstance(result, list):
                raise ProductionEdgePreflightError(
                    "Cloudflare cursor pagination metadata is malformed"
                )
            if "result_info" in response and not isinstance(result_info, dict):
                raise ProductionEdgePreflightError(
                    "Cloudflare cursor pagination metadata is malformed"
                )
            cursors_present = isinstance(result_info, dict) and "cursors" in result_info
            cursors = result_info.get("cursors") if isinstance(result_info, dict) else None
            if cursors_present and not isinstance(cursors, dict):
                raise ProductionEdgePreflightError(
                    "Cloudflare cursor pagination metadata is malformed"
                )
            after = cursors.get("after") if isinstance(cursors, dict) else None
            if after is not None and (not isinstance(after, str) or not after):
                raise ProductionEdgePreflightError(
                    "Cloudflare cursor pagination metadata is malformed"
                )
            collection.extend(result)
            if len(collection) > MAXIMUM_API_COLLECTION_ITEMS:
                raise ProductionEdgePreflightError("a Cloudflare collection exceeded its bound")
            if after is None:
                return collection
            if after in seen_cursors:
                raise ProductionEdgePreflightError("Cloudflare cursor pagination repeated")
            seen_cursors.add(after)
            cursor = after
        raise ProductionEdgePreflightError("a Cloudflare collection exceeded its page bound")


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


def _require_zone_identity(client: CloudflareClient, zone_id: str, zone_name: str) -> str:
    zone = client.get(f"/zones/{zone_id}")
    account = zone.get("account") if isinstance(zone, dict) else None
    account_id = account.get("id") if isinstance(account, dict) else None
    if (
        not isinstance(zone, dict)
        or zone.get("id") != zone_id
        or zone.get("name") != zone_name
        or zone.get("status") != "active"
        or not isinstance(account_id, str)
        or ZONE_ID_PATTERN.fullmatch(account_id) is None
    ):
        raise ProductionEdgePreflightError(
            f"the Caddy token did not identify the active {zone_name} zone"
        )
    return account_id


def validate_account_token_policy(
    token: Mapping[str, object],
    *,
    expected_id: str,
    expected_permissions: Mapping[str, str],
    expected_resources: frozenset[str],
    label: str,
) -> None:
    """Prove an account token has exactly the reviewed grants and resources."""
    if token.get("id") != expected_id or token.get("status") != "active":
        raise ProductionEdgePreflightError(f"the {label} token is not active")
    policies = token.get("policies")
    if not isinstance(policies, list) or not policies:
        raise ProductionEdgePreflightError(f"the {label} token policy is malformed")
    permissions: dict[str, str] = {}
    resource_bindings: dict[str, set[str]] = {}
    for policy in policies:
        if not isinstance(policy, dict) or policy.get("effect") != "allow":
            raise ProductionEdgePreflightError(f"the {label} token policy is malformed")
        permission_groups = policy.get("permission_groups")
        resources = policy.get("resources")
        if (
            not isinstance(permission_groups, list)
            or not permission_groups
            or not isinstance(resources, dict)
            or not resources
        ):
            raise ProductionEdgePreflightError(f"the {label} token policy is malformed")
        for permission_group in permission_groups:
            name = permission_group.get("name") if isinstance(permission_group, dict) else None
            identifier = permission_group.get("id") if isinstance(permission_group, dict) else None
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(identifier, str)
                or ZONE_ID_PATTERN.fullmatch(identifier) is None
            ):
                raise ProductionEdgePreflightError(f"the {label} token policy is malformed")
            if identifier in permissions and permissions[identifier] != name:
                raise ProductionEdgePreflightError(f"the {label} token policy is malformed")
            permissions[identifier] = name
        if any(not isinstance(key, str) or value != "*" for key, value in resources.items()):
            raise ProductionEdgePreflightError(f"the {label} token policy is malformed")
        for identifier in (
            group.get("id") for group in permission_groups if isinstance(group, dict)
        ):
            if isinstance(identifier, str):
                resource_bindings.setdefault(identifier, set()).update(resources)
    if (
        permissions != expected_permissions
        or set(resource_bindings) != set(expected_permissions)
        or any(resources != expected_resources for resources in resource_bindings.values())
    ):
        raise ProductionEdgePreflightError(
            f"the {label} token does not have the exact reviewed policy"
        )


def validate_non_expiring_account_token(token: Mapping[str, object], *, label: str) -> None:
    """Reject an expiry boundary on a durable runtime token."""
    if token.get("expires_on") not in (None, ""):
        raise ProductionEdgePreflightError(f"the {label} token unexpectedly expires")


def _resolve_permission_groups(
    client: CloudflareClient,
    *,
    account_id: str,
    names: frozenset[str],
    expected_scope: str,
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for name in sorted(names):
        result = client.get(
            f"/accounts/{account_id}/tokens/permission_groups",
            query={"name": name},
        )
        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
            raise ProductionEdgePreflightError(
                "Cloudflare token permission-group metadata is malformed"
            )
        group = result[0]
        identifier = group.get("id")
        scopes = group.get("scopes")
        if (
            group.get("name") != name
            or not isinstance(identifier, str)
            or ZONE_ID_PATTERN.fullmatch(identifier) is None
            or not isinstance(scopes, list)
            or expected_scope not in scopes
            or identifier in resolved
        ):
            raise ProductionEdgePreflightError(
                "Cloudflare token permission-group metadata is malformed"
            )
        resolved[identifier] = name
    return resolved


def _account_token_details(
    audit_client: CloudflareClient,
    target_client: CloudflareClient,
    *,
    account_id: str,
    label: str,
) -> Mapping[str, object]:
    verification = target_client.get(f"/accounts/{account_id}/tokens/verify")
    token_id = verification.get("id") if isinstance(verification, dict) else None
    if (
        not isinstance(verification, dict)
        or verification.get("status") != "active"
        or not isinstance(token_id, str)
        or ZONE_ID_PATTERN.fullmatch(token_id) is None
    ):
        raise ProductionEdgePreflightError(f"the {label} token did not verify as active")
    details = audit_client.get(f"/accounts/{account_id}/tokens/{token_id}")
    if not isinstance(details, dict) or details.get("id") != token_id:
        raise ProductionEdgePreflightError(f"the {label} token details are malformed")
    return details


def _require_account_token_policies(  # noqa: PLR0913 -- all credential roles are explicit.
    *,
    audit_client: CloudflareClient,
    caddy_client: CloudflareClient,
    edge_client: CloudflareClient,
    account_id: str,
    zone_ids: frozenset[str],
    now: datetime,
) -> None:
    audit_details = _account_token_details(
        audit_client,
        audit_client,
        account_id=account_id,
        label="temporary token-audit",
    )
    audit_id = audit_details.get("id")
    if not isinstance(audit_id, str):
        raise ProductionEdgePreflightError("the temporary token-audit details are malformed")
    audit_permissions = _resolve_permission_groups(
        audit_client,
        account_id=account_id,
        names=AUDIT_TOKEN_PERMISSIONS,
        expected_scope="com.cloudflare.api.account",
    )
    validate_account_token_policy(
        audit_details,
        expected_id=audit_id,
        expected_permissions=audit_permissions,
        expected_resources=frozenset({f"com.cloudflare.api.account.{account_id}"}),
        label="temporary token-audit",
    )
    issued_on = _timestamp(audit_details.get("issued_on"))
    expires_on = _timestamp(audit_details.get("expires_on"))
    if (
        issued_on > now
        or expires_on <= now
        or expires_on - issued_on > MAXIMUM_AUDIT_TOKEN_LIFETIME
    ):
        raise ProductionEdgePreflightError("the temporary token-audit lifetime is outside policy")

    zone_resources = frozenset(f"com.cloudflare.api.account.zone.{zone_id}" for zone_id in zone_ids)
    zone_permissions = _resolve_permission_groups(
        audit_client,
        account_id=account_id,
        names=CADDY_TOKEN_PERMISSIONS | EDGE_TOKEN_PERMISSIONS,
        expected_scope="com.cloudflare.api.account.zone",
    )
    for client, permissions, label in (
        (caddy_client, CADDY_TOKEN_PERMISSIONS, "Caddy runtime"),
        (edge_client, EDGE_TOKEN_PERMISSIONS, "OpenTofu edge"),
    ):
        details = _account_token_details(
            audit_client,
            client,
            account_id=account_id,
            label=label,
        )
        token_id = details.get("id")
        if not isinstance(token_id, str):
            raise ProductionEdgePreflightError(f"the {label} token details are malformed")
        validate_account_token_policy(
            details,
            expected_id=token_id,
            expected_permissions={
                identifier: name
                for identifier, name in zone_permissions.items()
                if name in permissions
            },
            expected_resources=zone_resources,
            label=label,
        )
        if label == "Caddy runtime":
            validate_non_expiring_account_token(details, label=label)


def _require_direct_dns(
    client: CloudflareClient,
    *,
    zone_id: str,
    zone_name: str,
    origin_ipv4: str,
    records_expected: bool,
) -> None:
    records = client.get_collection(f"/zones/{zone_id}/dns_records")
    if any(not isinstance(record, dict) for record in records):
        raise ProductionEdgePreflightError("Cloudflare DNS inventory is malformed")
    for hostname in (zone_name, f"*.{zone_name}"):
        exact = [
            record
            for record in records
            if isinstance(record, dict) and record.get("name") == hostname
        ]
        if records_expected:
            if (
                len(exact) != 1
                or exact[0].get("type") != "A"
                or exact[0].get("content") != origin_ipv4
            ):
                raise ProductionEdgePreflightError(
                    f"the direct {hostname} DNS inventory is not exact"
                )
            if exact[0].get("proxied") is not False:
                raise ProductionEdgePreflightError(
                    f"the pre-M3.7 {hostname} record is already proxied"
                )
        elif exact:
            raise ProductionEdgePreflightError(
                f"the pre-M3.7 {hostname} DNS inventory is not empty"
            )


def _require_unconfigured_edge(client: CloudflareClient, zone_id: str, zone_name: str) -> None:
    setting = client.get_aop_setting(zone_id)
    if not isinstance(setting, dict) or setting.get("enabled") is not False:
        raise ProductionEdgePreflightError(
            f"zone-level origin pulls are already enabled for {zone_name}"
        )
    hostnames = client.get_collection(f"/zones/{zone_id}/origin_tls_client_auth/hostnames")
    if any(not isinstance(item, dict) for item in hostnames):
        raise ProductionEdgePreflightError("Cloudflare hostname inventory is malformed")
    if any(isinstance(item, dict) and item.get("enabled") is True for item in hostnames):
        raise ProductionEdgePreflightError(
            f"an enabled per-hostname origin-pull override exists in {zone_name}"
        )
    rulesets = client.get_cursor_collection(f"/zones/{zone_id}/rulesets")
    if any(not isinstance(item, dict) for item in rulesets):
        raise ProductionEdgePreflightError("Cloudflare ruleset inventory is malformed")
    if any(
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
    certificates = client.get_collection(f"/zones/{zone_id}/origin_tls_client_auth")
    if any(not isinstance(item, dict) for item in certificates):
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
    audit_token = _required_environment("M3_7_TOKEN_AUDIT_TOKEN")
    if len({edge_token, caddy_token, audit_token}) != CLOUDFLARE_TOKEN_ROLE_COUNT:
        raise ProductionEdgePreflightError("the Cloudflare token roles are not separated")

    ca_path, ca_pem = _read_ca_path()
    now = datetime.now(UTC)
    validate_ca_certificate(ca_path, ca_pem, now=now)
    edge_client = CloudflareClient(edge_token)
    caddy_client = CloudflareClient(caddy_token)
    audit_client = CloudflareClient(audit_token)

    zones: list[tuple[str, str, str, bool]] = []
    account_ids: set[str] = set()
    for zone_name, zone_variable, certificate_variable, records_expected in ZONE_INPUTS:
        zone_id = _required_environment(zone_variable)
        certificate_id = _required_environment(certificate_variable)
        if ZONE_ID_PATTERN.fullmatch(zone_id) is None:
            raise ProductionEdgePreflightError(f"{zone_variable} is malformed")
        if CERTIFICATE_ID_PATTERN.fullmatch(certificate_id) is None:
            raise ProductionEdgePreflightError(f"{certificate_variable} is malformed")
        account_ids.add(_require_zone_identity(caddy_client, zone_id, zone_name))
        zones.append((zone_name, zone_id, certificate_id, records_expected))
    if len(account_ids) != 1:
        raise ProductionEdgePreflightError("the production zones do not share one account")
    account_id = account_ids.pop()
    _require_account_token_policies(
        audit_client=audit_client,
        caddy_client=caddy_client,
        edge_client=edge_client,
        account_id=account_id,
        zone_ids=frozenset(zone_id for _, zone_id, _, _ in zones),
        now=now,
    )

    for zone_name, zone_id, certificate_id, records_expected in zones:
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
