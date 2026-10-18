from __future__ import annotations

import errno
import io
import json
import socket
import ssl
import traceback
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from scripts import cloudflare_read_diagnostics as diagnostics
from scripts import cloudflare_read_transport as transport
from scripts.check_m3_7_production_edge import CloudflareClient, CloudflareReadError

CANARY = "synthetic-secret-bearing-address-url-header-body"
MIXED_CANDIDATE_COUNT = 2
ZONE = "a" * 32
OK = b'HTTP/1.1 200 OK\r\nContent-Length: 28\r\n\r\n{"success":true,"result":[]}'


class FakeSocket:
    def __init__(self, error: OSError | None, responses: list[bytes]) -> None:
        self.error = error
        self.responses = iter(responses)
        self.closed = False
        self.timeouts: list[object] = []
        self.addresses: list[object] = []
        self.sent: list[bytes] = []

    def settimeout(self, timeout: object) -> None:
        self.timeouts.append(timeout)

    def bind(self, source: object) -> None:
        self.addresses.append(source)

    def connect(self, target: object) -> None:
        self.addresses.append(target)
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        self.closed = True

    def setsockopt(self, *arguments: object) -> None:
        pass

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def makefile(self, *arguments: object) -> io.BytesIO:
        return io.BytesIO(next(self.responses))


@pytest.fixture
def sockets(monkeypatch: pytest.MonkeyPatch) -> list[FakeSocket]:
    created: list[FakeSocket] = []
    monkeypatch.setattr(urllib.request, "getproxies", dict)

    def unexpected(*arguments: object, **keywords: object) -> None:
        pytest.fail("unmocked socket or resolution; tests must remain offline")

    monkeypatch.setattr(socket, "socket", unexpected)
    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    return created


def arrange(
    monkeypatch: pytest.MonkeyPatch,
    sockets: list[FakeSocket],
    errors: list[OSError | None],
    *,
    responses: list[bytes] | None = None,
) -> None:
    outcomes: Iterator[OSError | None] = iter(errors)

    def create(*arguments: object) -> FakeSocket:
        value = FakeSocket(next(outcomes), responses or [OK])
        sockets.append(value)
        return value

    monkeypatch.setattr(socket, "socket", create)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [
            (socket.AF_INET6 if i else socket.AF_INET, socket.SOCK_STREAM, 0, "", (CANARY, i))
            for i in range(len(errors))
        ],
    )


def test_all_failed_candidates_survive_with_original_last_error_and_no_application_retry(
    monkeypatch: pytest.MonkeyPatch, sockets: list[FakeSocket]
) -> None:
    first = ConnectionRefusedError(errno.ECONNREFUSED, CANARY)
    last = OSError(errno.ENETUNREACH, CANARY)
    arrange(monkeypatch, sockets, [first, last])
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(CANARY).get(f"/zones/{ZONE}/dns_records", query={"name": CANARY})
    value: Any = raised.value.diagnostic
    connection = value["connections"][0]
    assert connection["target"] == "origin" and connection["stage"] == "resolve-connect"
    assert connection["failed_candidates"] == MIXED_CANDIDATE_COUNT
    assert [node.get("errno") for node in connection["candidate_errors"]["nodes"]] == [
        None,
        errno.ECONNREFUSED,
        errno.ENETUNREACH,
    ]
    assert value["exception_chain"]["nodes"][0]["type"] == "URLError"
    assert value["exception_chain"]["nodes"][1]["errno"] == errno.ENETUNREACH
    assert value["attempt"] == 1 and value["connection_count"] == 1
    assert len(sockets) == MIXED_CANDIDATE_COUNT and all(item.closed for item in sockets)
    assert all(item.timeouts == [value["socket_timeout_seconds"]] for item in sockets)
    assert sockets[0].addresses == [(CANARY, 0)] and sockets[1].addresses == [(CANARY, 1)]
    assert connection["elapsed_seconds"] >= connection["resolve_connect_elapsed_seconds"] >= 0
    rendered = "".join(traceback.format_exception(raised.value))
    assert CANARY not in rendered and ZONE not in rendered


@pytest.mark.parametrize("proxy", [False, True])
def test_success_after_failed_candidate_keeps_proxy_tls_and_header_boundaries(
    monkeypatch: pytest.MonkeyPatch, sockets: list[FakeSocket], proxy: bool
) -> None:
    responses = ([b"HTTP/1.0 200 Connection established\r\n\r\n"] if proxy else []) + [OK]
    arrange(monkeypatch, sockets, [OSError(errno.ENETUNREACH, CANARY), None], responses=responses)
    if proxy:
        monkeypatch.setattr(
            urllib.request,
            "getproxies",
            lambda: {"https": "http://user:password@proxy.invalid:8080"},
        )
        monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _: False)
    wrapped: list[str] = []

    def tls(context: ssl.SSLContext, sock: FakeSocket, *, server_hostname: str) -> FakeSocket:
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        wrapped.append(server_hostname)
        return sock

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", tls)
    observation = diagnostics.ReadDiagnostic(15)
    request = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/zones/" + ZONE,
        headers={"Authorization": "Bearer " + CANARY},
    )
    with transport.open_request(request, timeout=15, diagnostic=observation) as response:
        assert json.loads(response.read())["success"] is True
    assert wrapped == ["api.cloudflare.com"]
    assert all(item.closed for item in sockets)
    connection = observation.connections[0]
    assert connection["stage"] == "connected"
    assert connection["target"] == ("proxy" if proxy else "origin")
    assert connection["failed_candidates"] is None  # stdlib discards failures on success
    assert "candidate_errors" not in connection
    assert b"Authorization: Bearer " + CANARY.encode() in sockets[-1].sent[-1]
    assert b"Proxy-Authorization" not in sockets[-1].sent[-1]
    if proxy:
        assert b"Proxy-Authorization" in sockets[-1].sent[0]
        assert CANARY.encode() not in sockets[-1].sent[0]
    assert CANARY not in json.dumps(observation.document())


def test_dns_failure_precedes_socket_creation_and_preserves_resolver_type(
    monkeypatch: pytest.MonkeyPatch, sockets: list[FakeSocket]
) -> None:
    def resolve(*arguments: object) -> None:
        raise socket.gaierror(socket.EAI_AGAIN, CANARY)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(CANARY).get(f"/zones/{ZONE}/dns_records")
    assert not sockets
    value: Any = raised.value.diagnostic
    assert value["connections"][0]["failed_candidates"] is None
    assert value["connections"][0]["exception_chain"]["nodes"][0]["type"] == "gaierror"


@pytest.mark.parametrize("proxy", [False, True])
def test_tls_validation_failure_is_not_retried_and_keeps_connection_stage(
    monkeypatch: pytest.MonkeyPatch, sockets: list[FakeSocket], proxy: bool
) -> None:
    arrange(monkeypatch, sockets, [None], responses=[b"HTTP/1.0 200 OK\r\n\r\n"])
    if proxy:
        monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://proxy.invalid"})
        monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _: False)

    def tls(*args: object, **kwargs: object) -> None:
        raise ssl.SSLCertVerificationError(1, CANARY)

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", tls)
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(CANARY).get(f"/zones/{ZONE}/dns_records")
    value: Any = raised.value.diagnostic
    assert value["connections"][0]["stage"] == (
        "after-proxy-tunnel" if proxy else "after-tcp-connect"
    )
    assert "SSLCertVerificationError" in json.dumps(value)
    assert len(sockets) == 1 and sockets[0].closed
    assert CANARY not in "".join(traceback.format_exception(raised.value))


def test_proxy_tunnel_rejection_is_distinct_from_origin_connect(
    monkeypatch: pytest.MonkeyPatch, sockets: list[FakeSocket]
) -> None:
    arrange(
        monkeypatch, sockets, [None], responses=[b"HTTP/1.0 407 " + CANARY.encode() + b"\r\n\r\n"]
    )
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://proxy.invalid"})
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _: False)
    with pytest.raises(CloudflareReadError) as raised:
        CloudflareClient(CANARY).get(f"/zones/{ZONE}/dns_records")
    value: Any = raised.value.diagnostic
    assert value["connections"][0]["target"] == "proxy"
    assert value["connections"][0]["stage"] == "proxy-tunnel"
    assert len(sockets) == 1 and sockets[0].closed
    assert CANARY not in "".join(traceback.format_exception(raised.value))


def test_group_and_connection_diagnostics_are_bounded_isolated_and_payload_free() -> None:
    unknown = type(CANARY, (OSError,), {})(1, CANARY)
    group = ExceptionGroup(CANARY, [unknown] * (diagnostics.MAX_CHAIN * 10))
    chain: Any = diagnostics.exception_chain(group)
    assert chain["truncated"] is True and chain["repeated"] is True
    assert len(chain["nodes"]) <= diagnostics.MAX_CHAIN
    assert CANARY not in json.dumps(chain)
    first = diagnostics.ReadDiagnostic(15)
    second = diagnostics.ReadDiagnostic(15)
    for _ in range(diagnostics.MAX_CONNECTIONS * 2):
        first.connection(tunnel=False)
    assert len(first.connections) == diagnostics.MAX_CONNECTIONS
    assert first.document()["connections_truncated"] is True
    assert first.connections[-1]["sequence"] == first.connection_count
    assert second.connections == [] and second.connection_count == 0
