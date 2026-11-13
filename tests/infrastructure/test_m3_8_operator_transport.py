from __future__ import annotations

import json
import subprocess
import uuid

import pytest

from config.ansible.molecule.m3_8 import resolve_operator_transport


@pytest.fixture(autouse=True)
def published_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LDP_QUALIFICATION_UNIX_PEER_ADDRESS", raising=False)
    monkeypatch.setattr(
        resolve_operator_transport, "_published_ssh_port", lambda container: "32123"
    )


_published_ssh_port = resolve_operator_transport._published_ssh_port


@pytest.mark.parametrize("role", ["host", "destination"])
def test_explicit_unix_peer_uses_exact_routed_source_for_owned_minio_fixture(
    monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    run_id = uuid.uuid7().hex
    monkeypatch.setenv("LDP_QUALIFICATION_RUN_ID", run_id)
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")
    monkeypatch.setenv("LDP_QUALIFICATION_UNIX_PEER_ADDRESS", "172.19.0.2")
    monkeypatch.delenv("LDP_M3_11_MANAGED_INPUTS", raising=False)
    monkeypatch.delenv("M3_11_COMBINED_BACKEND", raising=False)
    monkeypatch.delenv("M3_10_INSTALLED_REPORT", raising=False)
    calls: list[tuple[str, int]] = []

    def routed(peer: object, port: int) -> str:
        calls.append((str(peer), port))
        return "172.19.0.3"

    monkeypatch.setattr(resolve_operator_transport, "_routed_source", routed)
    assert resolve_operator_transport.resolve_operator_transport(
        "unix:///docker-sock/docker.sock", f"ldp-m3-{run_id}-{role}"
    ) == {
        "peerAddress": "172.19.0.2",
        "sourceCidr": "172.19.0.3/32",
        "sshPort": "32123",
    }
    assert calls == [("172.19.0.2", 32123)]


@pytest.mark.parametrize(
    "restriction", ["live", "combined", "managed", "managed-empty", "report", "unowned", "remote"]
)
def test_explicit_unix_peer_rejects_nonlocal_or_unowned_authority(
    monkeypatch: pytest.MonkeyPatch, restriction: str
) -> None:
    run_id = uuid.uuid7().hex
    monkeypatch.setenv("LDP_QUALIFICATION_RUN_ID", run_id)
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "spaces" if restriction == "live" else "minio")
    monkeypatch.setenv("LDP_QUALIFICATION_UNIX_PEER_ADDRESS", "172.19.0.2")
    monkeypatch.delenv("LDP_M3_11_MANAGED_INPUTS", raising=False)
    monkeypatch.delenv("M3_11_COMBINED_BACKEND", raising=False)
    monkeypatch.delenv("M3_10_INSTALLED_REPORT", raising=False)
    if restriction == "combined":
        monkeypatch.setenv("M3_11_COMBINED_BACKEND", "spaces")
    if restriction == "managed":
        monkeypatch.setenv("LDP_M3_11_MANAGED_INPUTS", "/private/managed")
    if restriction == "managed-empty":
        monkeypatch.setenv("LDP_M3_11_MANAGED_INPUTS", "")
    if restriction == "report":
        monkeypatch.setenv("M3_10_INSTALLED_REPORT", "/private/report")
    container = "unowned-host" if restriction == "unowned" else f"ldp-m3-{run_id}-host"
    endpoint = "tcp://192.0.2.1:2375" if restriction == "remote" else "unix:///docker.sock"
    with pytest.raises(RuntimeError, match="restricted to local MinIO"):
        resolve_operator_transport.resolve_operator_transport(endpoint, container)


@pytest.mark.parametrize("peer", ["0.0.0.0", "224.0.0.1", "docker", "invalid"])  # noqa: S104 - invalid test input
def test_explicit_unix_peer_rejects_non_unicast_or_non_numeric_addresses(
    monkeypatch: pytest.MonkeyPatch, peer: str
) -> None:
    run_id = uuid.uuid7().hex
    monkeypatch.setenv("LDP_QUALIFICATION_RUN_ID", run_id)
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")
    monkeypatch.setenv("LDP_QUALIFICATION_UNIX_PEER_ADDRESS", peer)
    monkeypatch.delenv("LDP_M3_11_MANAGED_INPUTS", raising=False)
    monkeypatch.delenv("M3_11_COMBINED_BACKEND", raising=False)
    monkeypatch.delenv("M3_10_INSTALLED_REPORT", raising=False)
    with pytest.raises(ValueError):
        resolve_operator_transport.resolve_operator_transport(
            "unix:///docker.sock", f"ldp-m3-{run_id}-host"
        )


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
        "sshPort": "32123",
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
        "sshPort": "32123",
    }


def test_ssh_endpoint_uses_openssh_and_preserves_the_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="203.0.113.20 41234 192.0.2.30 2200\n",
        )

    monkeypatch.setattr(resolve_operator_transport.subprocess, "run", run)

    assert resolve_operator_transport.resolve_operator_transport(
        "ssh://docker-user@deployment-docker:2200", "lowerduckpond-ubuntu-2604"
    ) == {"sourceCidr": "203.0.113.20/32", "sshPort": "32123"}
    assert commands == [
        [
            "/usr/bin/ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-l",
            "docker-user",
            "-p",
            "2200",
            "--",
            "deployment-docker",
            'printf "%s\\n" "$SSH_CONNECTION"',
        ]
    ]


def test_local_ssh_endpoint_uses_container_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateways: list[str] = []
    monkeypatch.setattr(
        resolve_operator_transport,
        "_ssh_connection_addresses",
        lambda endpoint: ("127.0.0.1", "127.0.0.1"),
    )
    monkeypatch.setattr(
        resolve_operator_transport,
        "_container_gateway",
        lambda container: gateways.append(container) or "172.17.0.1",
    )

    assert resolve_operator_transport.resolve_operator_transport(
        "ssh://deployment-docker", "lowerduckpond-ubuntu-2604"
    ) == {"sourceCidr": "172.17.0.1/32", "sshPort": "32123"}
    assert gateways == ["lowerduckpond-ubuntu-2604"]


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


@pytest.mark.parametrize(
    "bindings",
    [
        None,
        [],
        {},
        [None],
        [{"HostPort": "0"}],
        [{"HostPort": "65536"}],
        [{"HostPort": 2222}],
        [{"HostPort": "22\n"}],
        [{"HostPort": "22"}, {"HostPort": "23"}],
    ],
)
def test_published_port_rejects_missing_invalid_or_ambiguous_bindings(
    monkeypatch: pytest.MonkeyPatch, bindings: object
) -> None:
    monkeypatch.setattr(
        resolve_operator_transport.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, json.dumps(bindings)),
    )
    with pytest.raises(RuntimeError, match="SSH port"):
        _published_ssh_port("owned-fixture")


def test_published_port_accepts_matching_ipv4_and_ipv6_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def inspect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                [{"HostIp": "0.0.0.0", "HostPort": "32123"}, {"HostIp": "::", "HostPort": "32123"}]  # noqa: S104 - Docker inspect fixture
            ),
        )

    monkeypatch.setattr(resolve_operator_transport.subprocess, "run", inspect)
    assert _published_ssh_port("owned-fixture") == "32123"
    assert commands[0][-1] == "owned-fixture"


def test_restarted_fixture_uses_new_port_with_same_access_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = {"sourceCidr": "172.17.0.1/32", "peerAddress": "127.0.0.1", "sshPort": "32123"}
    current = {**recorded, "sshPort": "32124"}
    monkeypatch.setattr(
        resolve_operator_transport, "resolve_operator_transport", lambda *args: current
    )
    assert (
        resolve_operator_transport.current_operator_transport(
            "unix:///var/run/docker.sock", "owned-fixture", recorded
        )
        == current
    )
    assert recorded["sshPort"] == "32123"


@pytest.mark.parametrize("field", ["sourceCidr", "peerAddress"])
def test_restarted_fixture_rejects_changed_access_boundary(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    recorded = {"sourceCidr": "172.17.0.1/32", "peerAddress": "127.0.0.1", "sshPort": "32123"}
    monkeypatch.setattr(
        resolve_operator_transport,
        "resolve_operator_transport",
        lambda *args: {**recorded, field: "192.0.2.10"},
    )
    with pytest.raises(RuntimeError, match="access boundary changed"):
        resolve_operator_transport.current_operator_transport(
            "unix:///var/run/docker.sock", "owned-fixture", recorded
        )
