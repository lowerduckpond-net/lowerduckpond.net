from __future__ import annotations

import urllib.request
from contextlib import nullcontext
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts import check_m3_10_provider as provider
from scripts.check_m3_7_production_edge import CloudflareClient, ProductionEdgePreflightError
from scripts.m3_10_page_rules import PageRulesClient

from .test_m3_7_production_gate import _certificate_fixture, _CloudflareResponse
from .test_m3_10_production_gate import Edge

_NOW = datetime(2026, 9, 13, tzinfo=UTC)
_ZONES = frozenset({"a" * 32, "b" * 32})


class UserClient:
    def __init__(self, overrides: dict[str, object] | None = None) -> None:
        self.calls: list[str] = []
        self.verification: dict[str, object] = {
            "id": "c" * 32,
            "status": "active",
            "expires_on": (_NOW + timedelta(days=30)).isoformat(),
            **(overrides or {}),
        }
        self.inventory: object = []

    def get(self, path: str) -> object:
        self.calls.append(path)
        if path == "/user/tokens/verify":
            return deepcopy(self.verification)
        assert path in {f"/zones/{zone}/pagerules" for zone in _ZONES}
        if isinstance(self.inventory, Exception):
            raise self.inventory
        return deepcopy(self.inventory)


def test_cfut_token_is_sent_intact_only_to_user_verification_and_page_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "cfut_page_rules_test_canary_0000000000000000"
    raw = UserClient()

    def respond(request: urllib.request.Request, *, timeout: int) -> _CloudflareResponse:
        assert timeout > 0
        assert request.get_header("Authorization") == f"Bearer {canary}"
        root = "https://api.cloudflare.com/client/v4"
        assert request.full_url.startswith(root)
        return _CloudflareResponse(
            {"success": True, "result": raw.get(request.full_url[len(root) :])}
        )

    monkeypatch.setattr(urllib.request, "urlopen", respond)
    pages = PageRulesClient(CloudflareClient(canary), zone_ids=_ZONES, now=_NOW)
    for zone in sorted(_ZONES):
        assert pages.get(f"/zones/{zone}/pagerules") == []
    assert raw.calls == [
        "/user/tokens/verify",
        *(f"/zones/{zone}/pagerules" for zone in sorted(_ZONES)),
    ]


@pytest.mark.parametrize("remaining_days", [1, 30, 60, 90])
def test_page_rules_user_token_has_bounded_expiry_and_only_two_inventory_paths(
    remaining_days: int,
) -> None:
    raw = UserClient({"expires_on": (_NOW + timedelta(days=remaining_days)).isoformat()})
    client = PageRulesClient(cast(CloudflareClient, raw), zone_ids=_ZONES, now=_NOW)
    for zone in sorted(_ZONES):
        assert client.get(f"/zones/{zone}/pagerules") == []
    assert raw.calls == [
        "/user/tokens/verify",
        *(f"/zones/{zone}/pagerules" for zone in sorted(_ZONES)),
    ]
    before = list(raw.calls)
    for path in (
        "/user/tokens/verify",
        "/accounts/" + "a" * 32 + "/tokens/verify",
        "/zones/" + "d" * 32 + "/pagerules",
        "/zones/" + "a" * 32 + "/dns_records",
        "/zones/" + "a" * 32 + "/pagerules?status=active",
    ):
        with pytest.raises(ProductionEdgePreflightError, match="escaped its read scope"):
            client.get(path)
    assert raw.calls == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "disabled"},
        {"status": None},
        {"id": None},
        {"id": "not-a-token-id"},
        {"expires_on": None},
        {"expires_on": ""},
        {"expires_on": "invalid"},
        {"expires_on": "2026-10-13T00:00:00"},
        {"expires_on": _NOW.isoformat()},
        {"expires_on": (_NOW - timedelta(seconds=1)).isoformat()},
        {"expires_on": (_NOW + timedelta(days=90, seconds=1)).isoformat()},
        {"not_before": (_NOW + timedelta(seconds=1)).isoformat()},
        {"not_before": "invalid"},
    ],
)
def test_page_rules_refuses_invalid_user_token_before_any_inventory_read(
    overrides: dict[str, object],
) -> None:
    raw = UserClient(overrides)
    with pytest.raises(ProductionEdgePreflightError, match="Page Rules user token"):
        PageRulesClient(cast(CloudflareClient, raw), zone_ids=_ZONES, now=_NOW)
    assert raw.calls == ["/user/tokens/verify"]


@pytest.mark.parametrize(
    "zones", [frozenset(), frozenset({"a" * 32}), frozenset({"invalid", "b" * 32})]
)
def test_invalid_page_rules_zone_scope_fails_before_sending_the_user_token(
    zones: frozenset[str],
) -> None:
    raw = UserClient()
    with pytest.raises(ProductionEdgePreflightError, match="two exact zones"):
        PageRulesClient(cast(CloudflareClient, raw), zone_ids=zones, now=_NOW)
    assert not raw.calls


@pytest.mark.parametrize("result", [[], [{"id": "existing-rule"}], None, "denied"])
def test_edge_routes_only_page_rules_reads_to_the_user_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: object
) -> None:
    edge = Edge(*_certificate_fixture(tmp_path))
    account_get = edge.get
    account_calls: list[str] = []

    def get(path: str) -> object:
        assert not path.endswith("/pagerules")
        assert not path.startswith("/user/")
        account_calls.append(path)
        return account_get(path)

    monkeypatch.setattr(edge, "get", get)
    user = UserClient()
    user.inventory = (
        ProductionEdgePreflightError("Page Rules denied") if result == "denied" else result
    )
    pages = PageRulesClient(cast(CloudflareClient, user), zone_ids=_ZONES, now=_NOW)
    with (
        nullcontext()
        if result == []
        else pytest.raises((provider.GateError, ProductionEdgePreflightError), match="Page Rules")
    ):
        assert (
            provider.check_edge(
                cast(CloudflareClient, edge),
                page_rules_client=pages,
                zone_id="a" * 32,
                certificate_id="b" * 32,
                domain="lowerduckpond.net",
                origin="192.0.2.1",
                ca_path=edge.ca_path,
                now=edge.now,
            )
            == "e" * 32
        )
    assert user.calls == ["/user/tokens/verify", "/zones/" + "a" * 32 + "/pagerules"]
    assert "/accounts/" + "e" * 32 + "/tokens/verify" in account_calls


@pytest.mark.parametrize(
    "role", ["CLOUDFLARE_API_TOKEN", "CADDY_CLOUDFLARE_API_TOKEN", "M3_10_TOKEN_AUDIT_TOKEN"]
)
def test_page_rules_user_token_must_be_separate_from_every_account_token(role: str) -> None:
    environment = {
        "CLOUDFLARE_API_TOKEN": "edge-canary",
        "CADDY_CLOUDFLARE_API_TOKEN": "caddy-canary",
        "M3_10_TOKEN_AUDIT_TOKEN": "audit-canary",
    }
    environment["M3_10_PAGE_RULES_TOKEN"] = environment[role]
    with pytest.raises(provider.GateError, match="must be separate"):
        provider.page_rules_client(environment, now=_NOW)
