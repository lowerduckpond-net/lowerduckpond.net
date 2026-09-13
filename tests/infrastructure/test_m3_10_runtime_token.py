from __future__ import annotations

import sys
from contextlib import nullcontext
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts import check_m3_10_provider as provider
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError

_ACCOUNT = "a" * 32
_ZONES = {"b" * 32: "lowerduckpond.net", "c" * 32: "lowerduckpond.com"}
_RUNTIME = "d" * 32
_AUDIT = "e" * 32
_PERMISSIONS = {"Zone Read": "1" * 32, "DNS Write": "2" * 32, "Account API Tokens Read": "3" * 32}
_SECRETS = {
    "caddy": "caddy-token-canary",
    "audit": "audit-token-canary",
    "edge": "edge-token-canary",
}


class TokenFixture:
    def __init__(self, defect: str | None) -> None:
        self.defect = defect
        self.calls: list[tuple[str, str]] = []

    def client(self, token: str) -> provider.CloudflareClient:
        role = next(role for role, value in _SECRETS.items() if value == token)
        fixture = self

        class Client:
            def get(self, path: str, *, query: dict[str, str] | None = None) -> object:
                fixture.calls.append((role, path))
                return fixture.response(role, path, query)

        return cast(provider.CloudflareClient, Client())

    def response(  # noqa: PLR0912 - explicit independent provider defects
        self, role: str, path: str, query: dict[str, str] | None
    ) -> object:
        if path.startswith("/zones/"):
            assert role == "caddy"
            zone_id = path.removeprefix("/zones/")
            if self.defect == "zone-denied":
                raise ProductionEdgePreflightError("runtime zone read denied")
            return {
                "id": zone_id,
                "name": _ZONES[zone_id],
                "status": "active",
                "account": {"id": "f" * 32 if self.defect == "other-account" else _ACCOUNT},
            }
        assert path.startswith(f"/accounts/{_ACCOUNT}/tokens/")
        if path.endswith("/verify"):
            assert role in {"caddy", "audit"}
            if self.defect == "verification-unavailable":
                raise ProductionEdgePreflightError("token verification unavailable")
            return {
                "id": _RUNTIME if role == "caddy" else _AUDIT,
                "status": "disabled" if self.defect == f"{role}-revoked" else "active",
            }
        assert role == "audit"
        if path.endswith("/permission_groups"):
            assert query is not None
            name = query["name"]
            return [
                {
                    "id": _PERMISSIONS[name],
                    "name": name,
                    "scopes": [
                        "com.cloudflare.api.account"
                        + ("" if name.startswith("Account") else ".zone")
                    ],
                }
            ]
        runtime = path.endswith("/" + _RUNTIME)
        assert runtime or path.endswith("/" + _AUDIT)
        resources = (
            {f"com.cloudflare.api.account.zone.{zone}": "*" for zone in _ZONES}
            if runtime
            else {f"com.cloudflare.api.account.{_ACCOUNT}": "*"}
        )
        permissions = ["Zone Read", "DNS Write"] if runtime else ["Account API Tokens Read"]
        if runtime:
            if self.defect == "dns-write-missing":
                permissions.remove("DNS Write")
            if self.defect == "zone-read-missing":
                permissions.remove("Zone Read")
            if self.defect == "excess-permission":
                permissions.append("Account API Tokens Read")
            if self.defect == "one-zone":
                resources.pop(next(iter(resources)))
            if self.defect == "all-zones":
                resources = {"com.cloudflare.api.account.zone.*": "*"}
        elif self.defect == "audit-excess-permission":
            permissions.append("DNS Write")
        now = datetime.now(UTC)
        document: dict[str, object] = {
            "id": _RUNTIME if runtime else _AUDIT,
            "status": "active",
            "issued_on": (now - timedelta(days=1)).isoformat(),
            "expires_on": None if runtime else (now + timedelta(days=1)).isoformat(),
            "policies": [
                {
                    "effect": "allow",
                    "resources": resources,
                    "permission_groups": [
                        {"id": _PERMISSIONS[name], "name": name} for name in permissions
                    ],
                }
            ],
        }
        if runtime and self.defect == "details-id-mismatch":
            document["id"] = "f" * 32
        if runtime and self.defect == "runtime-expiry":
            document["expires_on"] = (now + timedelta(days=1)).isoformat()
        if not runtime and self.defect == "audit-expired":
            document["expires_on"] = (now - timedelta(hours=1)).isoformat()
        if not runtime and self.defect == "audit-too-long":
            document["expires_on"] = (now + timedelta(days=8)).isoformat()
        return deepcopy(document)


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "caddy-missing",
        "audit-missing",
        "roles-shared",
        "caddy-revoked",
        "audit-revoked",
        "zone-denied",
        "other-account",
        "verification-unavailable",
        "dns-write-missing",
        "zone-read-missing",
        "excess-permission",
        "one-zone",
        "all-zones",
        "details-id-mismatch",
        "runtime-expiry",
        "audit-excess-permission",
        "audit-expired",
        "audit-too-long",
    ],
)
def test_provider_completion_requires_the_current_runtime_token_policy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], defect: str | None
) -> None:
    fixture = TokenFixture(defect)
    environment = {
        "SPACES_REGION": "fra1",
        "SPACES_ARCHIVE_BUCKET": "archive-fixture",
        "SPACES_ACCESS_KEY_ID": "spaces-fixture",
        "SPACES_SECRET_ACCESS_KEY": "spaces-canary",
        "CLOUDFLARE_API_TOKEN": _SECRETS["edge"],
        "CADDY_CLOUDFLARE_API_TOKEN": _SECRETS["caddy"],
        "M3_10_TOKEN_AUDIT_TOKEN": _SECRETS["audit"],
        "CLOUDFLARE_ZONE_ID": "b" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "c" * 32,
        "CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID": "1" * 32,
        "CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID": "2" * 32,
        "PRODUCTION_ORIGIN_IPV4": "192.0.2.1",
    }
    if defect in {"caddy-missing", "audit-missing"}:
        environment[
            "CADDY_CLOUDFLARE_API_TOKEN" if defect == "caddy-missing" else "M3_10_TOKEN_AUDIT_TOKEN"
        ] = ""
    if defect == "roles-shared":
        environment["CADDY_CLOUDFLARE_API_TOKEN"] = _SECRETS["edge"]
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["provider-check"])
    monkeypatch.setattr(provider, "CloudflareClient", fixture.client)
    monkeypatch.setattr(provider, "make_policy_client", lambda _configuration: object())
    monkeypatch.setattr(provider, "check_storage", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(provider, "check_edge", lambda *_args, **_kwargs: _ACCOUNT)
    monkeypatch.setattr(
        provider, "verified_ca_bundle", lambda **_kwargs: nullcontext(Path("/fixture/ca.pem"))
    )
    assert provider.main() == (0 if defect is None else 1)
    output = capsys.readouterr()
    assert all(value not in output.out + output.err for value in _SECRETS.values())
    if defect is None:
        assert ("caddy", f"/accounts/{_ACCOUNT}/tokens/verify") in fixture.calls
        assert ("audit", f"/accounts/{_ACCOUNT}/tokens/{_RUNTIME}") in fixture.calls
        assert all(("caddy", f"/zones/{zone}") in fixture.calls for zone in _ZONES)
