"""The disposable provider adapter must preserve real DNS validation obligations."""

from __future__ import annotations

import importlib.util
import json
import socket
import struct
import threading
from pathlib import Path
from types import ModuleType

import pytest

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


def test_concurrent_apex_and_wildcard_challenges_keep_both_txt_values(
    monkeypatch: pytest.MonkeyPatch,
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
                        "name": "_acme-challenge.lowerduckpond.com",
                        "content": content,
                    }
                ).encode(),
            )
        )
    assert values == {"_acme-challenge.lowerduckpond.com.": ["apex-proof", "wildcard-proof"]}
    state.cloudflare("DELETE", endpoint + "/" + records[0]["id"], b"")
    assert values == {"_acme-challenge.lowerduckpond.com.": ["wildcard-proof"]}
    assert (
        state.cloudflare("GET", endpoint + "?name=_acme-challenge.lowerduckpond.com&type=TXT", b"")
        == records[1:]
    )
    state.cloudflare("DELETE", endpoint + "/" + records[1]["id"], b"")
    assert values == {"_acme-challenge.lowerduckpond.com.": []}
    assert state.created == state.deleted == len(records)


@pytest.mark.parametrize(
    "name",
    ["production.example.com", "lowerduckpond.com", "_acme-challenge.other.lowerduckpond.com"],
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
