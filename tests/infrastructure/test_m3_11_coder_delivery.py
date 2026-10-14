"""Coder joins argv into a shell command; exercise quoting and fail-closed identity."""

# ruff: noqa: PLR2004 - exact transport positions and bounds

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.m3_11_unattended.coder_delivery import PROBE, SOCKET, CoderDelivery
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_connect_delivery import WORKSPACE_ID, Client
from .test_m3_11_connect_setup import CANARY, run

DAEMON_ID = "11111111-1111-4111-8111-111111111111"
BUILD = "22222222-2222-4222-8222-222222222222"
AGENT = "33333333-3333-4333-8333-333333333333"


class CoderClient(CoderDelivery, Client):
    def __init__(self) -> None:
        Client.__init__(self)
        CoderDelivery.__init__(self, "owner/ldp", WORKSPACE_ID, DAEMON_ID)
        self.listing = [
            {
                "id": WORKSPACE_ID,
                "name": "ldp",
                "owner_name": "owner",
                "latest_build": {
                    "id": BUILD,
                    "status": "running",
                    "resources": [{"agents": [{"id": AGENT, "status": "connected"}]}],
                },
            }
        ]
        self.runtime = {
            "workspace_id": WORKSPACE_ID,
            "uid": 1000,
            "home": "/home/coder",
            "home_volume_root": "/volumes/coder-" + WORKSPACE_ID + "-home/_data",
            "daemon": {"ID": DAEMON_ID},
        }
        self.transfer = False
        self.change_after = False
        self.lost_response = False
        self.utility_timeout = 0

    def command(
        self, program: str, *arguments: str, stdin: bytes | None = None, timeout: int = 90
    ) -> bytes:
        if program != "coder":
            return Client.command(self, program, *arguments, stdin=stdin, timeout=timeout)
        self.calls.append((program, arguments, stdin))
        assert CANARY not in json.dumps(arguments)
        if arguments[0] == "list":
            return json.dumps(self.listing).encode()
        assert arguments[:8] == (
            "ssh",
            "--disable-autostart",
            "--tty=false",
            "--forward-agent=false",
            "--forward-gpg=false",
            "--wait=no",
            "owner/ldp",
            "--",
        )
        # Actual cli/ssh.go strings.Join(inv.Args[1:], " ") contract.
        remote = shlex.split(" ".join(arguments[8:]))
        assert remote[:3] == ["python3", "-c", PROBE]
        if len(remote) == 5:
            if self.transfer and self.change_after:
                return json.dumps({**self.runtime, "home": "/different"}).encode()
            return json.dumps(self.runtime).encode()
        assert json.loads(remote[5]) == self.runtime
        assert stdin is not None
        self.transfer = True
        if self.lost_response:
            raise LifecycleError("synthetic lost response")
        if remote[6:9] == ["docker", "--host", SOCKET]:
            self.utility_timeout = timeout
            return b"{}"
        return hashlib.sha256(stdin).hexdigest().encode()


def test_coder_delivery_preserves_private_bundle_separation(tmp_path: Path) -> None:
    run(tmp_path)
    client = CoderClient()
    client.install(tmp_path)
    writes = [(program, data) for program, _, data in client.calls if data]
    assert writes == [
        ("coder", (tmp_path / "controller-connect.json").read_bytes()),
        ("gh", (tmp_path / "github-connect.json").read_bytes()),
    ]
    assert client.remote_docker(["info"], b"private-utility-stdin") == b"{}"
    assert client.utility_timeout == 1200


@pytest.mark.parametrize(
    "fault", ["stopped", "foreign", "disconnected", "changed", "lost-response", "github-approval"]
)
def test_coder_failure_never_installs_github_cleanup(tmp_path: Path, fault: str) -> None:
    run(tmp_path)
    client = CoderClient()
    build = cast(dict[str, object], client.listing[0]["latest_build"])
    if fault == "stopped":
        build["status"] = "stopped"
    elif fault == "foreign":
        client.listing[0]["id"] = DAEMON_ID
    elif fault == "disconnected":
        resources = cast(list[dict[str, object]], build["resources"])
        cast(list[dict[str, object]], resources[0]["agents"])[0]["status"] = "disconnected"
    elif fault == "changed":
        client.change_after = True
    elif fault == "lost-response":
        client.lost_response = True
    else:
        client.approver = True
    with pytest.raises(LifecycleError):
        client.install(tmp_path)
    assert not any(program == "gh" and data for program, _, data in client.calls)
    assert sum(data is not None for _, _, data in client.calls) <= 1


@pytest.mark.parametrize(
    "fault", [None, "workspace", "uid", "home", "mount", "read-only", "daemon"]
)
def test_actual_remote_probe_checks_identity_before_exec(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], fault: str | None
) -> None:
    monkeypatch.setenv("CODER_WORKSPACE_ID", "wrong" if fault == "workspace" else WORKSPACE_ID)
    monkeypatch.setattr(os, "geteuid", lambda: 0 if fault == "uid" else 1000)
    monkeypatch.setattr(
        Path, "stat", lambda self: SimpleNamespace(st_uid=0 if fault == "home" else 1000)
    )
    monkeypatch.setattr(Path, "resolve", lambda self: self)
    volume = "wrong" if fault == "mount" else WORKSPACE_ID
    mode = "ro" if fault == "read-only" else "rw"
    mount = (
        f"1 2 0:1 /volumes/coder-{volume}-home/_data /home/coder {mode} - btrfs /dev/test {mode}\n"
    )
    monkeypatch.setattr(Path, "read_text", lambda self: mount)
    info = {
        "ID": "wrong" if fault == "daemon" else DAEMON_ID,
        "Name": "test",
        "DockerRootDir": "/docker",
        "ServerVersion": "test",
    }
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(info).encode())
    )
    monkeypatch.setattr(sys, "argv", ["probe", WORKSPACE_ID, DAEMON_ID])
    if fault:
        with pytest.raises(SystemExit, match="verification failed"):
            exec(PROBE, {})  # noqa: S102 - run the exact reviewed remote program with mocked reads
    else:
        exec(PROBE, {})  # noqa: S102 - same exact read-only program
        value = json.loads(capsys.readouterr().out)
        assert value["daemon"] == info
        assert value["home_volume_root"].endswith(WORKSPACE_ID + "-home/_data")
        # The checked transfer runs the same probe again before touching stdin.
        invoked = []
        monkeypatch.setattr(os, "execvp", lambda program, args: invoked.append((program, args)))
        arguments = ["python3", "-c", "literal ; $shell `argument`", "private-path"]
        monkeypatch.setattr(
            sys, "argv", ["probe", WORKSPACE_ID, DAEMON_ID, json.dumps(value), *arguments]
        )
        exec(PROBE, {})  # noqa: S102 - exact checked transfer branch; exec mocked
        assert invoked == [("python3", arguments)]
        value["home_volume_root"] = "/foreign"
        monkeypatch.setattr(
            sys, "argv", ["probe", WORKSPACE_ID, DAEMON_ID, json.dumps(value), *arguments]
        )
        with pytest.raises(SystemExit, match="verification failed"):
            exec(PROBE, {})  # noqa: S102
        assert invoked == [("python3", arguments)]


def test_coder_shell_contract_preserves_literal_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    client = CoderDelivery("owner/ldp", WORKSPACE_ID, DAEMON_ID)
    local_run = subprocess.run

    def joined(program: str, *args: str, **kwargs: object) -> bytes:
        assert program == "coder"
        command = " ".join(args[args.index("--") + 1 :])
        return local_run(
            ["/bin/sh", "-c", command], capture_output=True, check=True, timeout=5
        ).stdout

    monkeypatch.setattr(client, "command", joined)
    value = "spaces ; $literal `literal` ' \" "
    assert json.loads(
        client.ssh(
            [sys.executable, "-c", "import json,sys; print(json.dumps(sys.argv[1:]))", value]
        )
    ) == [value]
