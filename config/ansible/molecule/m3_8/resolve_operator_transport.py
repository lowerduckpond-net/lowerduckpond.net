from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
from collections.abc import Sequence
from urllib.parse import SplitResult, urlsplit

_ARGUMENT_COUNT = 2


def _container_gateway(container: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed Docker command with a scenario container
        ["/usr/bin/docker", "inspect", container],
        check=True,
        capture_output=True,
        text=True,
    )
    inspection = json.loads(result.stdout)
    networks = inspection[0]["NetworkSettings"]["Networks"]
    gateways = {network["Gateway"] for network in networks.values() if network.get("Gateway")}
    if len(gateways) != 1:
        raise RuntimeError("M3.8 container gateway is ambiguous")
    return gateways.pop()


def _connected_addresses(host: str, port: int) -> tuple[str, str]:
    with socket.create_connection((host, port)) as connection:
        return connection.getsockname()[0], connection.getpeername()[0]


def _ssh_connection_addresses(endpoint: SplitResult) -> tuple[str, str]:
    command = [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ClearAllForwardings=yes",
    ]
    if endpoint.username:
        command.extend(("-l", endpoint.username))
    if endpoint.port:
        command.extend(("-p", str(endpoint.port)))
    if not endpoint.hostname:
        raise RuntimeError("SSH Docker endpoint has no hostname")
    command.extend(("--", endpoint.hostname, 'printf "%s\\n" "$SSH_CONNECTION"'))
    result = subprocess.run(  # noqa: S603 - fixed OpenSSH command with a Docker endpoint
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    fields = result.stdout.strip().split()
    if len(fields) != 4:  # noqa: PLR2004 - SSH_CONNECTION has exactly four fields
        raise RuntimeError("OpenSSH returned malformed SSH_CONNECTION evidence")
    return fields[0], fields[2]


def resolve_operator_transport(docker_host: str, container: str) -> dict[str, str]:
    endpoint = urlsplit(docker_host)
    peer: str | None
    if endpoint.scheme == "ssh":
        source, ssh_server = _ssh_connection_addresses(endpoint)
        if ipaddress.ip_address(ssh_server).is_loopback:
            source = _container_gateway(container)
        peer = None
    elif endpoint.scheme in {"tcp", "http", "https"} and endpoint.hostname:
        default_ports = {"tcp": 2375, "http": 2375, "https": 2376}
        port = endpoint.port or default_ports[endpoint.scheme]
        source, peer = _connected_addresses(endpoint.hostname, port)
        if ipaddress.ip_address(peer).is_loopback:
            source = _container_gateway(container)
    elif not endpoint.scheme or endpoint.scheme == "unix":
        source = _container_gateway(container)
        peer = "127.0.0.1"
    else:
        raise RuntimeError("unsupported Docker endpoint for M3.8 transport")

    source_address = ipaddress.ip_address(source)
    transport = {
        "sourceCidr": f"{source_address.compressed}/{source_address.max_prefixlen}",
    }
    if peer is not None:
        transport["peerAddress"] = ipaddress.ip_address(peer).compressed
    return transport


def main(arguments: Sequence[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != _ARGUMENT_COUNT:
        raise SystemExit("usage: resolve_operator_transport.py DOCKER_HOST CONTAINER")
    print(
        json.dumps(
            resolve_operator_transport(values[0], values[1]),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
