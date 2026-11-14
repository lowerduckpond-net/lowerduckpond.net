from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import traceback
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

_ARGUMENT_COUNT = 2
_MAX_PORT = 65535
_UNIX_PEER_ENV = "LDP_QUALIFICATION_UNIX_PEER_ADDRESS"
_DIAGNOSTIC = "failure-transport.json"
_REASONS = {
    "explicit Unix Docker peer is restricted to local MinIO qualification": (
        "local-authority-rejected"
    ),
    "explicit Unix Docker peer is restricted to local MinIO qualification: "
    "container identity mismatch": "local-identity-mismatch",
    "M3.8 container has no published SSH port": "ssh-port-unavailable",
    "M3.8 container SSH port is invalid": "ssh-port-invalid",
    "M3.8 container SSH port is ambiguous": "ssh-port-ambiguous",
    "M3.8 operator transport access boundary changed": "access-boundary-changed",
    "Unix Docker peer must be a unicast address": "invalid-peer",
    "unsupported Docker endpoint for M3.8 transport": "unsupported-endpoint",
}
_DIAGNOSTIC_GROUPS = frozenset(
    {
        "core",
        "accounting",
        "archive",
        "archive-credentials",
        "archive-cycles",
        "audit-protection",
        "audit-rotation",
        "backup-coherence",
        "backup-identity",
        "backup-mutation-overlap",
        "combined-reconstruction",
        "configuration-generation",
        "configuration-publication",
        "cross-feature",
        "credentials",
        "deletion",
        "deletion-quarantine",
        "export-import",
        "export-recovery",
        "export-roundtrip",
        "failed-retirement",
        "full-size-archive",
        "overlap-deployment",
        "overlap-routing",
        "production-rollout",
        "quarantine-recovery",
        "reboot-capture",
        "reboot-verify",
        "restore-reconstruction",
        "restore-negative",
        "restore-tls-bootstrap",
        "storage-credentials",
        "transport-recovery",
        "reboot-journey",
        "unclassified",
    }
)


def _diagnostic_path() -> Path | None:
    events = os.environ.get("LDP_QUALIFICATION_TIMING_EVENTS")
    return Path(events).parent / _DIAGNOSTIC if events else None


def _clear_diagnostic() -> None:
    path = _diagnostic_path()
    if path is not None:
        with suppress(OSError):
            path.unlink(missing_ok=True)


def _record_diagnostic(error: Exception) -> None:
    """Record only fixed causes and our own traceback coordinates, never raw output."""
    path = _diagnostic_path()
    if path is None:
        return
    frames = [
        {"file": "resolve_operator_transport.py", "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
        if Path(frame.filename).resolve() == Path(__file__).resolve()
    ][-8:]
    reason = _REASONS.get(str(error), "resolution-failed")
    group = os.environ.get("LDP_QUALIFICATION_TIMING_GROUP", "unknown")
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                json.dump(
                    {
                        "format": "lowerduckpond-transport-failure-v1",
                        "reason": reason,
                        "group": group if group in _DIAGNOSTIC_GROUPS else "unknown",
                        "frames": frames,
                    },
                    stream,
                    sort_keys=True,
                )
                stream.write("\n")
                stream.close()
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
    except OSError:
        pass  # Do not hide the original exception if recording is unavailable.


def _owned_unix_container(container: str, run_id: str) -> bool:
    """Accept a full immutable ID only when Docker proves the same owned role."""
    names = {f"ldp-m3-{run_id}-host", f"ldp-m3-{run_id}-destination"}
    if container in names:
        return True
    if re.fullmatch(r"[0-9a-f]{64}", container) is None:
        return False
    result = subprocess.run(  # noqa: S603 - exact full ID and fixed, non-secret Docker fields
        [
            "/usr/bin/docker",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"name":{{json .Name}},"owner":'
            '{{json (index .Config.Labels "lowerduckpond.qualification.run")}}}',
            container,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        return False
    try:
        identity = json.loads(result.stdout)
    except ValueError:
        return False
    return (
        isinstance(identity, dict)
        and identity.get("id") == container
        and identity.get("name") in {f"/{name}" for name in names}
        and identity.get("owner") == run_id
    )


def _require_local_peer(endpoint: SplitResult, container: str, run_id: str) -> None:
    if (
        endpoint.scheme not in {"", "unix"}
        or os.environ.get("M3_10_ARCHIVE_BACKEND") != "minio"
        or os.environ.get("M3_11_COMBINED_BACKEND") == "spaces"
        or "LDP_M3_11_MANAGED_INPUTS" in os.environ
        or os.environ.get("M3_10_INSTALLED_REPORT")
        or re.fullmatch(r"[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}", run_id) is None
    ):
        raise RuntimeError("explicit Unix Docker peer is restricted to local MinIO qualification")
    if not _owned_unix_container(container, run_id):
        raise RuntimeError(
            "explicit Unix Docker peer is restricted to local MinIO qualification: "
            "container identity mismatch"
        )


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
    gateway = gateways.pop()
    if not isinstance(gateway, str):
        raise RuntimeError("M3.8 container gateway is invalid")
    return gateway


def _published_ssh_port(container: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed Docker metadata query for this fixture
        [
            "/usr/bin/docker",
            "inspect",
            "--format",
            '{{json (index .NetworkSettings.Ports "22/tcp")}}',
            container,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    bindings = json.loads(result.stdout)
    if not isinstance(bindings, list) or not bindings:
        raise RuntimeError("M3.8 container has no published SSH port")
    ports = set()
    for binding in bindings:
        port = binding.get("HostPort") if isinstance(binding, dict) else None
        if not isinstance(port, str) or not port.isascii() or not port.isdecimal():
            raise RuntimeError("M3.8 container SSH port is invalid")
        if not 1 <= int(port) <= _MAX_PORT:
            raise RuntimeError("M3.8 container SSH port is invalid")
        ports.add(str(int(port)))
    if len(ports) != 1:
        raise RuntimeError("M3.8 container SSH port is ambiguous")
    return ports.pop()


def _connected_addresses(host: str, port: int) -> tuple[str, str]:
    with socket.create_connection((host, port)) as connection:
        return connection.getsockname()[0], connection.getpeername()[0]


def _routed_source(peer: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> str:
    """Resolve the local route without sending a datagram or requiring SSH to be started."""
    family = socket.AF_INET if isinstance(peer, ipaddress.IPv4Address) else socket.AF_INET6
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.connect((str(peer), port))
        return str(connection.getsockname()[0])


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
    explicit_peer = os.environ.get(_UNIX_PEER_ENV)
    run_id = os.environ.get("LDP_QUALIFICATION_RUN_ID", "")
    if explicit_peer:
        _require_local_peer(endpoint, container, run_id)
    published_port = _published_ssh_port(container)
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
        if explicit_peer:
            peer_address = ipaddress.ip_address(explicit_peer)
            if peer_address.is_unspecified or peer_address.is_multicast:
                raise ValueError("Unix Docker peer must be a unicast address")
            peer = peer_address.compressed
            source = _routed_source(peer_address, int(published_port))
            if ipaddress.ip_address(source).is_loopback:
                source = _container_gateway(container)
        else:
            source = _container_gateway(container)
            peer = "127.0.0.1"
    else:
        raise RuntimeError("unsupported Docker endpoint for M3.8 transport")

    source_address = ipaddress.ip_address(source)
    transport = {
        "sourceCidr": f"{source_address.compressed}/{source_address.max_prefixlen}",
        "sshPort": published_port,
    }
    if peer is not None:
        transport["peerAddress"] = ipaddress.ip_address(peer).compressed
    return transport


def current_operator_transport(
    docker_host: str, container: str, recorded: dict[str, str]
) -> dict[str, str]:
    """Refresh Docker's ephemeral port without accepting a changed access boundary."""
    _clear_diagnostic()
    try:
        current = resolve_operator_transport(docker_host, container)
        if {key: value for key, value in current.items() if key != "sshPort"} != {
            key: value for key, value in recorded.items() if key != "sshPort"
        }:
            raise RuntimeError("M3.8 operator transport access boundary changed")
        return current
    except Exception as error:
        _record_diagnostic(error)
        raise


def main(arguments: Sequence[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != _ARGUMENT_COUNT:
        raise SystemExit("usage: resolve_operator_transport.py DOCKER_HOST CONTAINER")
    _clear_diagnostic()
    try:
        result = resolve_operator_transport(values[0], values[1])
    except Exception as error:
        _record_diagnostic(error)
        raise
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
