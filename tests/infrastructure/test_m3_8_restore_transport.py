"""Exercise the restore fixture's actual bootstrap and connection ID paths."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from config.ansible.molecule.m3_8 import resolve_operator_transport as transport


def test_restore_bootstrap_and_refresh_use_owned_full_destination_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
) -> None:
    restore = installed_module("restore_fixture")
    run_id = uuid.uuid7().hex
    destination_id = "d" * 64
    endpoint = "unix:///docker.sock"
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    monkeypatch.setenv("LDP_QUALIFICATION_RUN_ID", run_id)
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")
    monkeypatch.setenv("LDP_QUALIFICATION_UNIX_PEER_ADDRESS", "172.19.0.2")
    for key in ("LDP_M3_11_MANAGED_INPUTS", "M3_11_COMBINED_BACKEND", "M3_10_INSTALLED_REPORT"):
        monkeypatch.delenv(key, raising=False)

    inspections: list[str] = []

    def inspect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        inspections.append(command[-1])
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {"id": destination_id, "name": f"/ldp-m3-{run_id}-destination", "owner": run_id}
            ),
            "",
        )

    monkeypatch.setattr(transport.subprocess, "run", inspect)
    ports = iter(("32123", "32124"))
    monkeypatch.setattr(transport, "_published_ssh_port", lambda identity: next(ports))
    monkeypatch.setattr(transport, "_routed_source", lambda *args: "172.19.0.3")

    def command(*arguments: str) -> bytes:
        assert arguments[2:] == (endpoint, destination_id)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert transport.main(arguments[2:]) == 0
        return output.getvalue().encode()

    class BootstrapReachedError(Exception):
        pass

    def save_then_stop(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        raise BootstrapReachedError

    fixture = SimpleNamespace(
        command=command,
        environment={"DOCKER_HOST": endpoint},
        destination_id=destination_id,
        root=tmp_path,
        destination=SimpleNamespace(file=lambda path: SimpleNamespace(exists=True)),
    )
    monkeypatch.setattr(restore, "private", save_then_stop)
    with pytest.raises(BootstrapReachedError):
        restore.Fixture._bootstrap(fixture)
    assert json.loads(fixture.transport.read_text())["sshPort"] == "32123"

    monkeypatch.setattr(restore.owned, "require_environment", lambda environment: None)
    monkeypatch.setattr(restore.support, "_initialize_admission_pacing", lambda host: None)
    monkeypatch.setattr(restore.support, "_run", lambda args: "disposable-operator-key")
    _, _, ssh = restore.Fixture.connection.__wrapped__(fixture, tmp_path / "connection")
    assert "-p 32124" in ssh.read_text()
    assert "Hostname=172.19.0.2" in ssh.read_text()
    assert inspections == [destination_id, destination_id]
