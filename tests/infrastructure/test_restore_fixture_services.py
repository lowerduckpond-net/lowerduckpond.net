"""The disposable provider adapter must preserve real DNS validation obligations."""

from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import ssl
import struct
import threading
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from config.ansible.molecule.m3_8.prepare_archive_storage import _certificates

ROOT = Path(__file__).resolve().parents[2] / "config/ansible/molecule/m3_8"


def module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_archive_faults_target_only_the_original_version_and_preserve_length() -> None:
    proxy = module("restore_archive_proxy")
    policy = {"bucket": "owned", "key": "archives/test.zip", "versionId": "v+1", "fault": "deny"}
    assert proxy.fault_for("/owned/archives/test.zip?versionId=v%2B1", policy) == "deny"
    for path in (
        "/owned?versions=",
        "/owned/archives/test.zip",
        "/owned/archives/test.zip?versionId=other",
        "/owned/archives/test.zip?versionId=v%2B1&versionId=other",
        "/other/archives/test.zip?versionId=v%2B1",
    ):
        assert proxy.fault_for(path, policy) == "none"
    original = b"original real version bytes"
    assert proxy.damage(original, fault="corrupt", first=True) == b"n" + original[1:]
    assert proxy.damage(original, fault="corrupt", first=False) == original


def test_dns_zone_discovery_and_real_txt_forwarding(monkeypatch: pytest.MonkeyPatch) -> None:
    dns = module("restore_dns_server")
    resolver = dns.Resolver("192.0.2.18", "192.0.2.99")

    def query(name: str, kind: int) -> bytes:
        return (
            struct.pack("!HHHHHH", 123, 0x0100, 1, 0, 0, 0)
            + dns.encoded(name)
            + struct.pack("!HH", kind, 1)
        )

    assert struct.unpack("!6H", resolver.answer(query("lowerduckpond.com", 6))[:12])[3:5] == (1, 0)
    assert struct.unpack(
        "!6H", resolver.answer(query("_acme-challenge.lowerduckpond.com", 6))[:12]
    )[3:5] == (0, 1)
    assert dns.encoded("ns.lowerduckpond.net") in resolver.answer(query("lowerduckpond.net", 2))
    assert socket.inet_aton("192.0.2.18") in resolver.answer(query("ns.lowerduckpond.net", 1))
    # TXT answers are never synthesized by this adapter. Forward the complete
    # wire response from the real challenge responder, including failure rcodes.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
        upstream.bind(("127.0.0.1", 0))
        upstream.settimeout(5)
        monkeypatch.setattr(dns, "TXT_PORT", upstream.getsockname()[1])
        request = query("_acme-challenge.lowerduckpond.net", 16)
        response = request[:2] + b"\x81\x82" + request[4:]

        def respond() -> None:
            packet, address = upstream.recvfrom(65535)
            assert packet == request
            upstream.sendto(response, address)

        thread = threading.Thread(target=respond)
        thread.start()
        assert resolver.answer(request) == response
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize("packet", [b"", b"x" * 12, b"x" * 100, b"\0" * 16])
def test_dns_rejects_malformed_questions(packet: bytes) -> None:
    dns = module("restore_dns_server")
    with pytest.raises(ValueError):
        dns.question(packet)


@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("quoted", [False, True])
def test_concurrent_apex_and_wildcard_challenges_keep_both_txt_values(
    monkeypatch: pytest.MonkeyPatch,
    *,
    relative: bool,
    quoted: bool,
) -> None:
    acme = module("restore_acme_server")
    state = acme.State()
    values: dict[str, list[str]] = {}

    def dns(action: str, body: dict[str, str]) -> None:
        if action == "/clear-txt":
            values[body["host"]] = []
        else:
            assert action == "/set-txt"
            values[body["host"]].append(body["value"])

    monkeypatch.setattr(state, "dns", dns)
    endpoint = "/client/v4/zones/" + "1" * 32 + "/dns_records"
    records = []
    for content in ("apex-proof", "wildcard-proof"):
        records.append(  # noqa: PERF401 - exercise separate sequential provider requests
            state.cloudflare(
                "POST",
                endpoint,
                json.dumps(
                    {
                        "type": "TXT",
                        "name": "_acme-challenge"
                        if relative
                        else "_acme-challenge.lowerduckpond.com.",
                        "content": json.dumps(content) if quoted else content,
                    }
                ).encode(),
            )
        )
    assert values == {"_acme-challenge.lowerduckpond.com.": ["apex-proof", "wildcard-proof"]}
    state.cloudflare("DELETE", endpoint + "/" + records[0]["id"], b"")
    assert values == {"_acme-challenge.lowerduckpond.com.": ["wildcard-proof"]}
    assert (
        state.cloudflare("GET", endpoint + "?name=_acme-challenge.lowerduckpond.com.&type=TXT", b"")
        == records[1:]
    )
    state.cloudflare("DELETE", endpoint + "/" + records[1]["id"], b"")
    assert values == {"_acme-challenge.lowerduckpond.com.": []}
    assert state.created == state.deleted == len(records)


@pytest.mark.parametrize("suffix", ["", "."])
def test_cloudflare_discovery_accepts_absolute_dns_names(suffix: str) -> None:
    state = module("restore_acme_server").State()
    zones = state.cloudflare("GET", f"/client/v4/zones?name=lowerduckpond.net{suffix}", b"")
    assert zones == [{"id": "2" * 32, "name": "lowerduckpond.net", "status": "active"}]
    for name in ("lowerduckpond.net..", "foreign.example", "child.lowerduckpond.net"):
        assert state.cloudflare("GET", f"/client/v4/zones?name={name}", b"") == []
    assert (
        state.cloudflare(
            "GET", "/client/v4/zones?name=lowerduckpond.net&name=lowerduckpond.com", b""
        )
        == []
    )


@pytest.mark.parametrize(
    "name",
    [
        "production.example.com",
        "lowerduckpond.com",
        "_acme-challenge.other.lowerduckpond.com",
        "_acme-challenge.lowerduckpond.net",
        "_acme-challenge.lowerduckpond.com..",
    ],
)
def test_dns_adapter_refuses_records_outside_its_two_owned_challenges(name: str) -> None:
    state = module("restore_acme_server").State()
    with pytest.raises(ValueError, match="outside"):
        state.cloudflare(
            "POST",
            "/client/v4/zones/" + "1" * 32 + "/dns_records",
            json.dumps({"type": "TXT", "name": name, "content": "proof"}).encode(),
        )
    assert not state.records


def test_acme_proxy_preserves_client_headers_and_issuer_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acme = module("restore_acme_server")
    _certificates(tmp_path)
    (tmp_path / "proxy-ca.crt").write_bytes((tmp_path / "ca.crt").read_bytes())
    monkeypatch.setattr(acme, "ROOT", tmp_path)
    requests: list[tuple[str, str, str, str, bytes]] = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(
                (
                    self.path,
                    self.headers["Host"],
                    self.headers.get("User-Agent", ""),
                    self.headers.get("Content-Type", ""),
                    body,
                )
            )
            payload = json.dumps(
                {"newOrder": "https://" + self.headers["Host"] + "/order"}
            ).encode()
            self.send_response(200 if self.headers.get("User-Agent") else 400)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Replay-Nonce", "test-nonce")
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Upstream) as upstream:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tmp_path / "public.crt", tmp_path / "private.key")
        upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
        real_connection = http.client.HTTPSConnection

        def connect(
            host: str, port: int, *, context: ssl.SSLContext, timeout: int
        ) -> http.client.HTTPSConnection:
            assert (host, port) == ("localhost", 14000)
            return real_connection(
                "127.0.0.1", upstream.server_port, context=context, timeout=timeout
            )

        monkeypatch.setattr(
            acme, "http", SimpleNamespace(client=SimpleNamespace(HTTPSConnection=connect))
        )
        with ThreadingHTTPServer(("127.0.0.1", 0), acme.Handler) as proxy:
            threads = [
                threading.Thread(target=server.serve_forever) for server in (upstream, proxy)
            ]
            for thread in threads:
                thread.start()
            try:
                for host in (
                    "acme-v02.api.letsencrypt.org",
                    "acme-staging-v02.api.letsencrypt.org",
                ):
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", proxy.server_port, timeout=5
                    )
                    try:
                        connection.request(
                            "POST",
                            "/directory",
                            b"signed-request",
                            {
                                "Host": host,
                                "User-Agent": "Caddy test client",
                                "Content-Type": "application/jose+json",
                            },
                        )
                        response = connection.getresponse()
                        assert response.status == HTTPStatus.OK
                        assert response.getheader("Replay-Nonce") == "test-nonce"
                        assert json.load(response) == {"newOrder": f"https://{host}/order"}
                        assert requests[-1] == (
                            "/dir",
                            host,
                            "Caddy test client",
                            "application/jose+json",
                            b"signed-request",
                        )
                    finally:
                        connection.close()
            finally:
                for server in (upstream, proxy):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=5)
                    assert not thread.is_alive()


@pytest.mark.parametrize("becomes_ready", [False, True])
def test_provider_fault_waits_for_systemd_readiness_within_the_existing_bound(
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
    *,
    becomes_ready: bool,
) -> None:
    fixture_module = installed_module("restore_fixture")
    running = iter((False, becomes_ready))
    observations: list[str] = []

    def service(name: str) -> SimpleNamespace:
        observations.append(name)
        return SimpleNamespace(is_running=next(running))

    fixture = SimpleNamespace(acme=object(), destination=SimpleNamespace(service=service))
    monkeypatch.setattr(fixture_module, "checked", lambda host, code: '{"deniedDns": 1}')
    clock = iter((0, 1, 2, 121))
    monkeypatch.setattr(
        fixture_module,
        "time",
        SimpleNamespace(
            monotonic=lambda: next(clock),
            sleep=lambda seconds: None,
        ),
    )
    if becomes_ready:
        fixture_module.Fixture.fault_observed(fixture, "deniedDns")
    else:
        with pytest.raises(AssertionError, match="native Caddy did not observe"):
            fixture_module.Fixture.fault_observed(fixture, "deniedDns")
    assert observations == ["caddy", "caddy"]
