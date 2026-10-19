"""The synthetic Docker boundary executes the native daemon failure contract."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import connect_activate, connect_delivery
from scripts.m3_11_unattended.docker import SOCKET, Docker, prepare, utility_arguments

from .operator_flow_support import SOURCE, Services
from .operator_host_support import Host


@pytest.mark.parametrize("route", ["docker", "ssh"])
@pytest.mark.parametrize(
    "error_type",
    [FileNotFoundError, PermissionError, RuntimeError, ValueError, KeyError, TypeError],
)
def test_native_utility_errors_cross_daemon_boundary_as_sanitized_failed_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception], route: str
) -> None:
    services = Services(monkeypatch)
    host = Host(tmp_path / "daemon", services, monkeypatch)
    prepared = prepare(Docker(), SOURCE)
    originals = host.original_files()
    envelope: dict[str, object] = {
        "format": connect_activate.UTILITY_FORMAT,
        "prepared": prepared,
        "operation": "admission",
        "payload": {},
    }

    def unavailable(_value: object, **_kwargs: object) -> dict[str, object]:
        raise error_type("SYNTHETIC private evidence path or credential")

    monkeypatch.setattr(connect_activate, "daemon_utility", unavailable)
    arguments = utility_arguments(prepared, operation="admission", daemon_socket=SOCKET)
    command = (
        ["docker", *arguments]
        if route == "docker"
        else [
            "ssh",
            "-T",
            "-o",
            "ConnectTimeout=10",
            "--",
            "coder@synthetic.test",
            shlex.join([*connect_delivery.PARENT_DOCKER, *arguments]),
        ]
    )
    result = services.process(command, input=canonical_bytes(envelope))
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == (
        b"Daemon migration operation is unresolved; preserve original evidence.\n"
    )
    assert host.original_files() == originals
    assert host.launched == []
    assert services.exchanges == []


def test_unexpected_filesystem_error_outside_native_utility_remains_a_harness_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = Services(monkeypatch)

    def broken_fixture(_arguments: list[str], _stdin: bytes | None) -> bytes:
        raise FileNotFoundError("SYNTHETIC fixture initialization bug")

    services.docker_handler = broken_fixture
    with pytest.raises(AssertionError, match="synthetic daemon filesystem boundary failed"):
        services.process(["docker", "inspect", "synthetic-container"])
