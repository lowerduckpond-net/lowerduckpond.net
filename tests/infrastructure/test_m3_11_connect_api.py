"""Real local HTTP boundaries for the credential-bearing Connect client."""

from __future__ import annotations

import json
import threading
import time
import traceback
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import override

import pytest

from scripts.m3_11_unattended import connect_api
from scripts.m3_11_unattended.connect_api import Connect
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
