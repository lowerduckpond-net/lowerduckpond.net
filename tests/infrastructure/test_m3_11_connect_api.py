"""Real local HTTP boundaries for the credential-bearing Connect client."""

from __future__ import annotations

import json
import threading
import time
import traceback
from collections.abc import Iterator
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import override

import pytest

from scripts.m3_11_unattended import connect_api
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_diagnostics import retain_failure, verified_failure
from scripts.m3_11_unattended.model import LifecycleError

CANARY = "connect-api-private-canary"
VAULT, ITEM = "v" * 26, "i" * 26


class Server(ThreadingHTTPServer):
    status: int = 200
    body: bytes = b"[]"
    received: list[tuple[str, str, str | None, bytes]]
    raw: bytes | None = None
    drip: str | None = None

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.received = []
        self.disconnected = threading.Event()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:" + str(self.server_port)


class Handler(BaseHTTPRequestHandler):
    server: Server

    @override
    def log_message(self, _format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.respond()

    def do_POST(self) -> None:
        self.respond()

    def respond(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.received.append(
            (self.command, self.path, self.headers.get("Authorization"), body)
        )
        if self.server.raw is not None:
            self.wfile.write(self.server.raw)
            return
        if self.server.drip is not None:
            raw = (
                b"HTTP/1.0 200 OK\r\nX-Slow: " + b" " * 100 + b"\r\n\r\n[]"
                if self.server.drip == "headers"
                else b"HTTP/1.0 200 OK\r\n\r\n[" + b" " * 100 + b"]"
            )
            try:
                for byte in raw:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.02)
            except OSError:
                self.server.disconnected.set()
            return
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        if self.server.status in (301, 302, 307, 308):
            self.send_header("Location", self.server.url + "/never-follow")
        self.end_headers()
        self.wfile.write(self.server.body)


@pytest.fixture
def server() -> Iterator[Server]:
    instance = Server()
    thread = threading.Thread(
        target=instance.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_bounded_vault_and_item_read_with_ambient_proxy_disabled(
    server: Server, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    client = Connect(server.url, CANARY, local_cleanup=True)
    server.body = json.dumps([{"id": VAULT}]).encode()
    assert client.vaults() == [{"id": VAULT}]
    server.body = json.dumps(
        {"id": ITEM, "vault": {"id": VAULT}, "fields": [{"value": CANARY}]}
    ).encode()
    assert client.item(VAULT, ITEM)["id"] == ITEM
    assert all(entry[2] == "Bearer " + CANARY for entry in server.received)
    assert CANARY not in capsys.readouterr().out
    assert CANARY not in repr(client)


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 429, 500, 503])
def test_no_redirect_no_retry_and_sanitized_errors(server: Server, status: int) -> None:
    server.status, server.body = status, CANARY.encode()
    with pytest.raises(LifecycleError) as error:
        Connect(server.url, CANARY, local_cleanup=True).vaults()
    assert len(server.received) == 1
    assert CANARY not in str(error.value)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_credential_status_is_explicit_and_cannot_be_empty_success(
    server: Server, status: int
) -> None:
    server.status, server.body = status, CANARY.encode()
    client = Connect(server.url, CANARY, local_cleanup=True)
    result = client.request("GET", "/v1/vaults")
    assert result.status == status
    assert result.body is None
    with pytest.raises(LifecycleError, match="visibility"):
        client.vaults()


@pytest.mark.parametrize(
    "url",
    [
        "http://connect.test",
        "http://127.0.0.1:8000",
        "https://token@connect.test",
        "https://connect.test/path",
        "https://connect.test/?token=x",
        "https://connect.test:0",
    ],
)
def test_unsafe_shared_origin_rejected(url: str) -> None:
    with pytest.raises(LifecycleError):
        Connect(url, CANARY)


@pytest.mark.parametrize(
    "url", ["http://localhost:8000", "http://127.0.0.2:8000", "http://[::1]:8000"]
)
def test_cleanup_exception_only_accepts_explicit_ipv4_loopback(url: str) -> None:
    with pytest.raises(LifecycleError):
        Connect(url, CANARY, local_cleanup=True)


@pytest.mark.parametrize(
    "body", [b'[{"id":"x","id":"y"}]', b'"scalar"', b"bad-json", b'[{"id": 5}]']
)
def test_invalid_or_ambiguous_responses_fail_closed(server: Server, body: bytes) -> None:
    server.body = body
    with pytest.raises(LifecycleError):
        Connect(server.url, CANARY, local_cleanup=True).vaults()


def test_oversize_response_and_wrong_item_identity_rejected(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.body = b" " * 201
    monkeypatch.setattr(connect_api, "MAX_BYTES", 200)
    client = Connect(server.url, CANARY, local_cleanup=True)
    with pytest.raises(LifecycleError, match="bound"):
        client.vaults()
    server.body = json.dumps({"id": "x" * 26, "vault": {"id": VAULT}}).encode()
    with pytest.raises(LifecycleError, match="identity"):
        client.item(VAULT, ITEM)


def test_mutation_timeout_response_is_not_replayed(server: Server) -> None:
    server.status, server.body = 503, CANARY.encode()
    client = Connect(server.url, CANARY, local_cleanup=True)
    with pytest.raises(LifecycleError, match="unresolved"):
        client.request("POST", f"/v1/vaults/{VAULT}/items", {"title": "test"})
    assert len(server.received) == 1


@pytest.mark.parametrize(
    "raw",
    [
        CANARY.encode() + b"\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + CANARY.encode() + b"\r\n",
    ],
)
def test_malformed_http_never_exports_reflected_credential(
    server: Server, raw: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    server.raw = raw
    with pytest.raises(LifecycleError, match="unresolved") as error:
        Connect(server.url, CANARY, local_cleanup=True).vaults()
    assert CANARY not in "".join(traceback.format_exception(error.value))
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err


@pytest.mark.parametrize("part", ["headers", "body"])
def test_deadline_terminates_trickling_mutation_without_replay(
    server: Server, part: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.drip = part
    monkeypatch.setattr(connect_api, "TIMEOUT_SECONDS", 0.6)
    started = time.monotonic()
    with pytest.raises(LifecycleError, match="unresolved"):
        Connect(server.url, CANARY, local_cleanup=True).request(
            "POST", f"/v1/vaults/{VAULT}/items", {"title": "test"}
        )
    assert time.monotonic() - started < 1.5  # noqa: PLR2004 - bound including test scheduling slack
    assert server.disconnected.wait(1.0), "the timed-out child must close its live socket"
    assert len(server.received) == 1


@pytest.mark.parametrize("part", ["headers", "body"])
def test_remaining_read_budget_terminates_live_exchange_and_restores_defaults(
    server: Server, part: str
) -> None:
    server.drip = part
    client = Connect(server.url, CANARY, local_cleanup=True)
    started = time.monotonic()
    with pytest.raises(LifecycleError, match="unresolved"), client.timeout_budget(0.6):
        client.vaults()
    assert time.monotonic() - started < 1.5  # noqa: PLR2004 - bounded process plus scheduling slack
    assert server.disconnected.wait(1.0)
    assert len(server.received) == 1
    assert client._request_timeout == connect_api.TIMEOUT_SECONDS
    independent = Connect(server.url, CANARY, local_cleanup=True)
    assert independent._request_timeout == connect_api.TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "status,body,check,body_type",
    [
        (401, {"secret": CANARY}, "item-status", "null"),
        (403, {"secret": CANARY}, "item-status", "null"),
        (404, {"secret": CANARY}, "item-status", "null"),
        (200, [CANARY], "item-body", "array"),
        (200, {"id": CANARY}, "item-id", "object"),
        (200, {"id": ITEM, "vault": {"id": CANARY}}, "item-vault", "object"),
    ],
)
def test_response_checks_survive_private_failure_retention_and_export(  # noqa: PLR0913, PLR0917 - response matrix
    server: Server, tmp_path: Path, status: int, body: object, check: str, body_type: str
) -> None:
    server.status, server.body = status, json.dumps(body).encode()
    client = Connect(server.url, CANARY, local_cleanup=True)
    path = tmp_path / "failure.json"
    with pytest.raises(connect_api.ConnectResponseError) as captured:
        client.item(VAULT, ITEM)
    retain_failure(path, binding={}, stage="provisioning", error=captured.value)
    retained = json.loads(path.read_bytes())
    exported = verified_failure(retained, binding={}, stages=frozenset({"provisioning"}))
    detail = exported["failure"]
    assert isinstance(detail, dict)
    assert detail["response"] == {
        "status": status,
        "check": check,
        "body_type": body_type,
    }
    assert detail["exchange"]["status"] == status
    assert CANARY not in path.read_text() + str(captured.value) + repr(captured.value)
    assert len(server.received) == 1
    # Preserve the first failure, including its response details, on later errors.
    before = path.read_bytes()
    retain_failure(path, binding={}, stage="cleanup", error=ValueError(CANARY))
    assert path.read_bytes() == before
    # The export schema rejects injected content and contradictory status claims.
    retained["failure"]["response"]["body"] = CANARY
    with pytest.raises(ValueError, match="fields are incomplete or unknown"):
        verified_failure(retained, binding={}, stages=frozenset({"provisioning"}))
    del retained["failure"]["response"]["body"]
    retained["failure"]["response"]["status"] = 503
    with pytest.raises(LifecycleError, match="statuses differ"):
        verified_failure(retained, binding={}, stages=frozenset({"provisioning"}))


def test_visibility_wait_respects_outer_budget_without_a_useless_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_m3_11_lease_inventory import VisibilityClock  # noqa: PLC0415

    clock = VisibilityClock()
    monkeypatch.setattr(connect_api, "time", clock)
    client = Connect("https://connect.example.invalid", CANARY)
    calls = 0

    def missing(
        method: str, path: str, body: dict[str, object] | None = None
    ) -> connect_api.Response:
        nonlocal calls
        assert method == "GET" and body is None
        assert path == f"/v1/vaults/{VAULT}/items/{ITEM}"
        calls += 1
        clock.seconds += 0.2
        return connect_api.Response(404, None)

    monkeypatch.setattr(client, "request", missing)
    with pytest.raises(connect_api.ConnectResponseError) as captured, client.timeout_budget(0.6):
        client.published_item(VAULT, ITEM)
    assert calls == 1
    assert clock.seconds == 0.2  # noqa: PLR2004 - no sleep with no useful next read
    assert client._request_timeout == connect_api.TIMEOUT_SECONDS
    path = tmp_path / "failure.json"
    retain_failure(path, binding={}, stage="provisioning", error=captured.value)
    retained = json.loads(path.read_bytes())
    verified_failure(retained, binding={}, stages=frozenset({"provisioning"}))
    assert retained["failure"]["response"]["visibility_wait"] == {
        "attempts": 1,
        "timeout_ms": 600,
        "elapsed_ms": 200,
    }
    assert CANARY not in path.read_text()
    retained["failure"]["response"]["visibility_wait"]["body"] = CANARY
    with pytest.raises(ValueError, match="fields are incomplete or unknown"):
        verified_failure(retained, binding={}, stages=frozenset({"provisioning"}))


@pytest.mark.parametrize("initial_missing", [False, True])
@pytest.mark.parametrize("terminal", ["timeout", "denial"])
def test_visibility_failure_retains_terminal_error_and_only_observed_prior_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, initial_missing: bool, terminal: str
) -> None:
    import subprocess  # noqa: PLC0415

    from .test_m3_11_lease_inventory import VisibilityClock  # noqa: PLC0415

    clock = VisibilityClock()
    monkeypatch.setattr(connect_api, "time", clock)
    calls = 0

    def exchange(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        if initial_missing and calls == 1:
            clock.seconds += 0.25
            return subprocess.CompletedProcess(command, 0, b'{"status":404,"body":null}')
        if terminal == "timeout":
            timeout = float(str(kwargs["timeout"]))
            clock.seconds += timeout
            raise subprocess.TimeoutExpired(command, timeout)
        clock.seconds += 0.25
        return subprocess.CompletedProcess(command, 0, b'{"status":403,"body":null}')

    monkeypatch.setattr(subprocess, "run", exchange)
    client = Connect("https://connect.example.invalid", CANARY)
    expected = (
        connect_api.ConnectTimeoutError
        if terminal == "timeout"
        else connect_api.ConnectResponseError
    )
    with pytest.raises(expected) as captured, client.timeout_budget(4):
        client.published_item(VAULT, ITEM)
    assert calls == 1 + initial_missing
    path = tmp_path / "failure.json"
    retain_failure(path, binding={}, stage="provisioning", error=captured.value)
    retained = json.loads(path.read_bytes())
    verified_failure(retained, binding={}, stages=frozenset({"provisioning"}))
    primary = retained["failure"]
    assert primary["exchange"]["outcome"] == (
        "timeout" if terminal == "timeout" else "http-response"
    )
    assert primary["exchange"]["status"] == (None if terminal == "timeout" else 403)
    assert ("response" in primary) == (terminal == "denial")
    related = retained.get("related_failures", [])
    assert sum("response" in detail for detail in related) == int(initial_missing)
    if initial_missing:
        assert len(related) == 1
        assert related[0]["response"] == {
            "status": 404,
            "check": "item-status",
            "body_type": "null",
            "visibility_wait": {
                "attempts": 2,
                "timeout_ms": 4000,
                "elapsed_ms": 4000 if terminal == "timeout" else 1500,
            },
        }
    assert CANARY not in path.read_text()
    assert client._request_timeout == connect_api.TIMEOUT_SECONDS


@pytest.mark.parametrize("related", [False, True])
@pytest.mark.parametrize("category", ["input", "io", "subprocess", "unexpected"])
def test_response_diagnostic_requires_lifecycle_category(category: str, related: bool) -> None:
    detail = {
        "category": category,
        "origin": None,
        "response": {"status": 404, "check": "item-status", "body_type": "null"},
    }
    value: dict[str, object] = {"binding": {}, "stage": "provisioning", "failure": detail}
    if related:
        value["failure"] = {"category": "lifecycle", "origin": None}
        value["related_failures"] = [detail]
    with pytest.raises(LifecycleError, match="requires a lifecycle"):
        verified_failure(value, binding={}, stages=frozenset({"provisioning"}))


@pytest.mark.parametrize("status", [404, HTTPStatus.NOT_FOUND])
def test_response_error_normalizes_only_httpstatus(status: int) -> None:
    error = connect_api.ConnectResponseError(
        connect_api.Response(status, None), "item-status", "missing"
    )
    assert error.response["status"] == 404  # noqa: PLR2004
    assert type(error.response["status"]) is int


@pytest.mark.parametrize("status", [True, 404.0, "404", 99, 600, 999])
def test_invalid_response_status_still_fails_closed(status: object) -> None:
    from typing import cast  # noqa: PLC0415

    with pytest.raises(LifecycleError, match="diagnostic is invalid"):
        connect_api.ConnectResponseError(
            connect_api.Response(cast(int, status), None), "item-status", "missing"
        )


@pytest.mark.parametrize("status", [429, 500])
def test_visibility_wait_does_not_retry_other_http_failures(server: Server, status: int) -> None:
    server.status, server.body = status, CANARY.encode()
    client = Connect(server.url, CANARY, local_cleanup=True)
    with pytest.raises(connect_api.ConnectExchangeError) as captured:
        client.published_item(VAULT, ITEM)
    assert captured.value.exchange["status"] == status
    assert len(server.received) == 1
    assert CANARY not in str(captured.value)


def test_nested_read_budgets_cannot_extend_outer_deadline_and_restore_on_failure(
    server: Server,
) -> None:
    client = Connect(server.url, CANARY, local_cleanup=True)
    budget = 5
    with pytest.raises(LifecycleError, match="test interruption"), client.timeout_budget(budget):
        with client.timeout_budget(budget * 2):
            assert client._request_timeout == budget
        with client.timeout_budget(1):
            assert client._request_timeout == 1
        assert client._request_timeout == budget
        raise LifecycleError("test interruption")
    assert client._request_timeout == connect_api.TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "method,path",
    [
        ("DELETE", f"/v1/vaults/{VAULT}/items/{ITEM}"),
        ("GET", "//evil.test/v1/vaults"),
        ("POST", "/v1/vaults"),
        ("GET", "/v1/vaults?filter=x"),
    ],
)
def test_no_destructive_or_unbounded_routes(server: Server, method: str, path: str) -> None:
    with pytest.raises(LifecycleError, match="bounded"):
        Connect(server.url, CANARY, local_cleanup=True).request(method, path)
    assert server.received == []


def test_manifest_note_preserves_legacy_cli_field_normalization(server: Server) -> None:
    server.body = json.dumps(
        {
            "id": ITEM,
            "vault": {"id": VAULT},
            "fields": [
                {"id": "notesPlain", "purpose": "NOTES", "type": "STRING", "value": ""},
                {"id": "notesPlain", "type": "STRING", "value": CANARY},
            ],
        }
    ).encode()
    assert (
        Connect(server.url, CANARY, local_cleanup=True).read(f"op://{VAULT}/{ITEM}/notesPlain")
        == CANARY
    )


def test_reference_field_separation_and_duplicate_rejection(server: Server) -> None:
    client = Connect(server.url, CANARY, local_cleanup=True)
    value: dict[str, object] = {
        "id": ITEM,
        "vault": {"id": VAULT},
        "sections": [{"id": "section-id", "label": "provider"}],
        "fields": [
            {"id": "one", "label": "credential", "value": "root-value"},
            {"id": "two", "label": "credential", "value": CANARY, "section": {"id": "section-id"}},
        ],
    }
    server.body = json.dumps(value).encode()
    assert client.read(f"op://{VAULT}/{ITEM}/credential") == "root-value"
    assert client.read(f"op://{VAULT}/{ITEM}/provider/credential") == CANARY
    value["fields"] = [
        {"id": "one", "label": "credential", "value": "one"},
        {"id": "credential", "label": "other", "value": CANARY},
    ]
    server.body = json.dumps(value).encode()
    with pytest.raises(LifecycleError, match="ambiguous"):
        client.read(f"op://{VAULT}/{ITEM}/credential")
