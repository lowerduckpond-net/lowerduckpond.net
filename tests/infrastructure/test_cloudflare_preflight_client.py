from __future__ import annotations

import http.client
import io
import json
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import check_m3_10_provider as provider
from scripts import cloudflare_read_diagnostics as diagnostics
from scripts.check_m3_7_production_edge import (
    CloudflareClient,
    CloudflareReadError,
    ProductionEdgePreflightError,
)
from scripts.m3_10_page_rules import PageRulesClient

from .cloudflare_transport_support import mock_urlopen
from .test_m3_7_production_gate import _CloudflareResponse

_TOKEN = "cfat_workstation_test_canary_0000000000000000"  # noqa: S105 - synthetic canary
_ZONE = "a" * 32
_ACCOUNT = "b" * 32


@pytest.mark.parametrize(
    ("reason", "kind"),
    [
        (TimeoutError(_TOKEN), "TimeoutError"),
        (socket.gaierror(socket.EAI_AGAIN, _TOKEN), "gaierror"),
        (ssl.SSLCertVerificationError(1, _TOKEN), "SSLCertVerificationError"),
        (ConnectionResetError(104, _TOKEN), "ConnectionResetError"),
    ],
)
def test_transport_chain_and_monotonic_elapsed_survive_without_retry_or_secret_text(
    monkeypatch: pytest.MonkeyPatch, reason: Exception, kind: str
) -> None:
    ticks = iter([100.0, 137.5])
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    opener = Mock(side_effect=urllib.error.URLError(reason))
    mock_urlopen(monkeypatch, opener)
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(_TOKEN).get(f"/zones/{_ZONE}/dns_records", query={"name": _TOKEN})
    value = raised.value.diagnostic
    chain = cast("dict[str, object]", value["exception_chain"])
    nodes = cast("list[dict[str, object]]", chain["nodes"])
    assert [node["type"] for node in nodes] == ["URLError", kind]
    assert nodes[1]["relation"] == "reason" and nodes[1]["parent"] == 0
    assert value["stage"] == "open" and value["http_status"] is None
    # A socket timeout is not a wall-time cap; retain actual slow elapsed time.
    assert cast(float, value["elapsed_seconds"]) > cast(int, value["socket_timeout_seconds"])
    assert value["attempt"] == 1
    opener.assert_called_once()
    rendered = "".join(traceback.format_exception(raised.value))
    assert _TOKEN not in rendered and _ZONE not in rendered


@pytest.mark.parametrize("status", [401, 403, 429, 503])
def test_http_failure_keeps_status_but_never_retries_or_exports_headers(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    headers = Message()
    for key in ("Location", "Set-Cookie", "CF-Ray", "Retry-After"):
        headers[key] = _TOKEN
    body = io.BytesIO(_TOKEN.encode())
    opener = Mock(
        side_effect=urllib.error.HTTPError(
            "https://example.invalid/" + _TOKEN, status, _TOKEN, headers, body
        )
    )
    mock_urlopen(monkeypatch, opener)
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(_TOKEN).get(f"/zones/{_ZONE}/dns_records")
    assert raised.value.diagnostic["http_status"] == status
    assert raised.value.diagnostic["stage"] == "response-status"
    assert body.closed
    opener.assert_called_once()
    assert _TOKEN not in "".join(traceback.format_exception(raised.value))


def test_body_failure_retains_received_status_without_leaking_partial_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _CloudflareResponse({"success": True})
    monkeypatch.setattr(
        response, "read", Mock(side_effect=http.client.IncompleteRead(_TOKEN.encode()))
    )
    opener = Mock(return_value=response)
    mock_urlopen(monkeypatch, opener)
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(_TOKEN).get(f"/zones/{_ZONE}/dns_records")
    value = raised.value.diagnostic
    assert value["stage"] == "response-body"
    assert value["http_status"] == HTTPStatus.OK and value["response_bytes"] is None
    assert "IncompleteRead" in json.dumps(value)
    assert _TOKEN not in "".join(traceback.format_exception(raised.value))
    opener.assert_called_once()


def test_diagnostic_chain_bounds_cycles_unknown_classes_and_numeric_attributes() -> None:
    root = urllib.error.URLError(_TOKEN)
    root.reason = root
    unknown = type(_TOKEN, (OSError,), {})(1, _TOKEN)
    root.__cause__ = unknown
    root.__context__ = unknown
    value = diagnostics.exception_chain(root)
    assert value["repeated"] is True
    assert "unknown" in json.dumps(value) and _TOKEN not in json.dumps(value)
    previous: BaseException = root
    for _ in range(diagnostics.MAX_CHAIN * 2):
        linked = OSError(1, _TOKEN)
        previous.__cause__ = linked
        previous = linked
    value = diagnostics.exception_chain(root)
    assert value["truncated"] is True
    assert len(cast(list[object], value["nodes"])) == diagnostics.MAX_CHAIN
    assert _TOKEN not in json.dumps(value)


def test_diagnostic_keeps_only_bounded_integer_error_codes() -> None:
    unable_to_get_local_issuer = 20
    error = ssl.SSLCertVerificationError(1, _TOKEN)
    error.verify_code = unable_to_get_local_issuer
    value = diagnostics.exception_chain(error)
    nodes = cast("list[dict[str, object]]", value["nodes"])
    assert nodes[0]["errno"] == 1 and nodes[0]["verify_code"] == unable_to_get_local_issuer
    for invalid in (True, _TOKEN, diagnostics.MAX_CODE + 1):
        error.errno = invalid  # type: ignore[assignment]
        error.verify_code = invalid  # type: ignore[assignment]
        node = cast("list[dict[str, object]]", diagnostics.exception_chain(error)["nodes"])[0]
        assert "errno" not in node and "verify_code" not in node


def test_direct_script_preflight_still_imports_without_repository_pythonpath(
    tmp_path: Path,
) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts/check_m3_7_production_edge.py"
    result = subprocess.run(  # noqa: S603 - fixed checked-out script; empty environment
        [sys.executable, str(script)],
        cwd=tmp_path,
        env={},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    assert b"production edge preflight failed:" in result.stderr
    assert b"ModuleNotFoundError" not in result.stderr


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

    mock_urlopen(monkeypatch, respond)
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

    mock_urlopen(monkeypatch, respond)
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
