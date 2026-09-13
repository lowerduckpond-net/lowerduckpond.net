from __future__ import annotations

import io
import traceback
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import cast

import pytest

from scripts import check_m3_10_provider as provider
from scripts.check_m3_7_production_edge import (
    CloudflareClient,
    ProductionEdgePreflightError,
)
from scripts.m3_10_page_rules import PageRulesClient

from .test_m3_7_production_gate import _CloudflareResponse

_TOKEN = "cfat_workstation_test_canary_0000000000000000"  # noqa: S105 - synthetic canary
_ZONE = "a" * 32
_ACCOUNT = "b" * 32


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (f"/zones/{_ZONE}/pagerules", "/zones/{zone_id}/pagerules"),
        (f"/zones/{_ZONE}/workers/routes", "/zones/{zone_id}/workers/routes"),
        (f"/accounts/{_ACCOUNT}/tokens/verify", "/accounts/{account_id}/tokens/verify"),
        (
            f"/accounts/{_ACCOUNT}/tokens/" + "c" * 32,
            "/accounts/{account_id}/tokens/{token_id}",
        ),
        (f"/zones/{_ZONE}/{_TOKEN}", "<unrecognized endpoint>"),
    ],
)
@pytest.mark.parametrize("failure", ["http", "network", "rejection", "json", "status"])
def test_cloudflare_failures_identify_the_endpoint_without_disclosing_secrets(
    monkeypatch: pytest.MonkeyPatch, path: str, expected: str, failure: str
) -> None:
    def respond(request: urllib.request.Request, *, timeout: int) -> _CloudflareResponse:
        assert timeout > 0
        assert request.get_header("Authorization") == f"Bearer {_TOKEN}"
        if failure == "http":
            raise urllib.error.HTTPError(
                request.full_url,
                403,
                _TOKEN,
                Message(),
                io.BytesIO(_TOKEN.encode()),
            )
        if failure == "network":
            raise urllib.error.URLError(_TOKEN)
        if failure == "json":
            response = _CloudflareResponse({})
            response._payload = _TOKEN.encode()
            return response
        return _CloudflareResponse(
            {"success": False, "errors": [{"message": _TOKEN}]},
            status=202 if failure == "status" else 200,
        )

    monkeypatch.setattr(urllib.request, "urlopen", respond)
    client = CloudflareClient(_TOKEN)
    with pytest.raises(ProductionEdgePreflightError) as raised:
        client.get(path, query={"secret-canary": _TOKEN})
    diagnostic = "".join(traceback.format_exception(raised.value))
    assert f"Cloudflare GET {expected}:" in str(raised.value)
    assert _TOKEN not in diagnostic
    assert _ZONE not in diagnostic
    assert _ACCOUNT not in diagnostic
    assert "secret-canary" not in str(raised.value)
    if failure == "http":
        assert "HTTP 403" in str(raised.value)


@pytest.mark.parametrize("verified", [True, False])
def test_edge_uses_account_verification_before_reading_legacy_page_rules(
    monkeypatch: pytest.MonkeyPatch, verified: bool
) -> None:
    requested: list[str] = []

    def respond(request: urllib.request.Request, *, timeout: int) -> _CloudflareResponse:
        assert timeout > 0
        assert request.get_header("Authorization") == f"Bearer {_TOKEN}"
        path = request.full_url.removeprefix("https://api.cloudflare.com/client/v4")
        requested.append(path)
        if path == f"/zones/{_ZONE}":
            return _CloudflareResponse(
                {
                    "success": True,
                    "result": {
                        "id": _ZONE,
                        "name": "lowerduckpond.net",
                        "status": "active",
                        "paused": False,
                        "account": {"id": _ACCOUNT},
                    },
                }
            )
        if path == f"/accounts/{_ACCOUNT}/tokens/verify":
            return _CloudflareResponse(
                {
                    "success": True,
                    "result": {"id": "c" * 32, "status": "active" if verified else "disabled"},
                }
            )
        assert path == f"/zones/{_ZONE}/workers/routes"
        raise urllib.error.HTTPError(request.full_url, 403, "denied", Message(), None)

    monkeypatch.setattr(urllib.request, "urlopen", respond)
    with pytest.raises(
        ProductionEdgePreflightError,
        match="HTTP 403" if verified else "OpenTofu edge token did not verify as active",
    ):
        provider.check_edge(
            CloudflareClient(_TOKEN),
            page_rules_client=cast(PageRulesClient, object()),
            zone_id=_ZONE,
            certificate_id="d" * 32,
            domain="lowerduckpond.net",
            origin="192.0.2.1",
            ca_path=Path("/unused/ca.pem"),
            now=datetime.now(UTC),
        )
    assert requested[:2] == [f"/zones/{_ZONE}", f"/accounts/{_ACCOUNT}/tokens/verify"]
    assert len(requested) == (3 if verified else 2)
