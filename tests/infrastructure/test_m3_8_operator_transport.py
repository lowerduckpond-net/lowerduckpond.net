from __future__ import annotations

import json

import pytest

from config.ansible.molecule.m3_8 import resolve_operator_transport


def test_local_tcp_endpoint_uses_container_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateways: list[str] = []
    monkeypatch.setattr(
        resolve_operator_transport,
        "_connected_addresses",
        lambda host, port: ("127.0.0.1", "127.0.0.1"),
    )
    monkeypatch.setattr(
        resolve_operator_transport,
        "_container_gateway",
        lambda container: gateways.append(container) or "172.17.0.1",
    )

    assert resolve_operator_transport.resolve_operator_transport(
        "tcp://127.0.0.1:2375", "lowerduckpond-ubuntu-2604"
    ) == {
        "peerAddress": "127.0.0.1",
        "sourceCidr": "172.17.0.1/32",
    }
    assert gateways == ["lowerduckpond-ubuntu-2604"]


def test_remote_tcp_endpoint_uses_connected_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        resolve_operator_transport,
        "_connected_addresses",
        lambda host, port: ("192.0.2.20", "198.51.100.30"),
    )

    def unexpected_gateway(container: str) -> str:
        raise AssertionError(f"unexpected gateway lookup for {container}")

    monkeypatch.setattr(
        resolve_operator_transport,
        "_container_gateway",
        unexpected_gateway,
    )

    assert resolve_operator_transport.resolve_operator_transport(
        "tcp://docker.example:2375", "lowerduckpond-ubuntu-2604"
    ) == {
        "peerAddress": "198.51.100.30",
        "sourceCidr": "192.0.2.20/32",
    }


def test_container_gateway_requires_one_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Inspection:
        stdout = json.dumps(
            [
                {
                    "NetworkSettings": {
                        "Networks": {
                            "first": {"Gateway": "172.17.0.1"},
                            "second": {"Gateway": "172.18.0.1"},
                        }
                    }
                }
            ]
        )

    def inspect(*args: object, **kwargs: object) -> Inspection:
        return Inspection()

    monkeypatch.setattr(resolve_operator_transport.subprocess, "run", inspect)

    with pytest.raises(RuntimeError, match="container gateway is ambiguous"):
        resolve_operator_transport._container_gateway("lowerduckpond-ubuntu-2604")
