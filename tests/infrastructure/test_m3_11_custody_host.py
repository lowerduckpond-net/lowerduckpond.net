"""Read-only native host capture cannot hide a restart or newer failure."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, override

import pytest

from scripts import m3_11_custody_host as host
from scripts.m3_11_unattended.docker import (
    CLEANUP_VOLUME,
    EVIDENCE_VOLUME,
    OWNER,
    SOCKET,
    helper_volume,
)

STARTED = "2026-10-10T00:00:00Z"
OBSERVED = "2026-10-10T00:01:00Z"
EMITTED = "2026-10-10T00:02:00Z"


def context() -> tuple[dict[str, Any], dict[str, Any]]:
    contract = {
        "host_id": "a" * 64,
        "host_helper": "b" * 40,
        "host_started_at": STARTED,
        "cleanup_configuration_sha256": "c" * 64,
        "daemon_socket": "/exact/docker.sock",
        "runtime": {
            "daemon_id": "synthetic-daemon",
            "image": "sha256:" + "d" * 64,
            "evidence_volume_created_at": STARTED,
        },
    }
    value = {
        "Id": contract["host_id"],
        "Name": "/ldp-m311-watchdog-" + contract["host_helper"][:12],
        "Image": contract["runtime"]["image"],
        "RestartCount": 0,
        "Config": {
            "Cmd": host.COMMAND,
            "Entrypoint": ["/usr/local/bin/mise", "exec", "--"],
            "Env": ["DOCKER_HOST=unix://" + SOCKET, "UV_CACHE_DIR=/tmp/uv-cache"],
            "Labels": {
                OWNER: "true",
                OWNER + ".helper": contract["host_helper"],
                OWNER + ".configuration": contract["cleanup_configuration_sha256"],
            },
        },
        "State": {
            "Running": True,
            "Paused": False,
            "Restarting": False,
            "StartedAt": STARTED,
            "Pid": 42,
        },
        "HostConfig": {
            "NetworkMode": "host",
            "ReadonlyRootfs": True,
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "Mounts": [],
    }
    for destination, name, writable in [
        ("/opt/lifecycle", helper_volume(contract["host_helper"]), False),
        ("/evidence", EVIDENCE_VOLUME, True),
        ("/cleanup", CLEANUP_VOLUME, False),
    ]:
        value["Mounts"].append(
            {
                "Type": "volume",
                "Name": name,
                "Source": "/volumes/" + name,
                "Destination": destination,
                "RW": writable,
            }
        )
    value["Mounts"].append(
        {"Type": "bind", "Source": contract["daemon_socket"], "Destination": SOCKET, "RW": True}
    )
    return contract, value


class ReadDocker(host.HostDocker):
    def __init__(self, contract: dict[str, Any], value: dict[str, Any]) -> None:
        self.endpoint = "unix://" + contract["daemon_socket"]
        self.contract, self.value = contract, value
        self.calls: list[tuple[str, ...]] = []
        self.inspections = 0
        self.restart = False

    @override
    def command(self, *args: str, stdin: bytes | None = None, timeout: int = 1200) -> bytes:
        self.calls.append(args)
        assert timeout == 30  # noqa: PLR2004 - fixed read bound
        if args[0] == "info":
            return json.dumps({"ID": self.contract["runtime"]["daemon_id"]}).encode()
        if args[0] == "inspect":
            self.inspections += 1
            row = deepcopy(self.value)
            if self.restart and self.inspections > 1:
                row["State"]["StartedAt"] = EMITTED
            return json.dumps([row]).encode()
        if args[:2] == ("volume", "inspect"):
            return json.dumps(
                [
                    {
                        "CreatedAt": STARTED,
                        "Name": EVIDENCE_VOLUME,
                        "Mountpoint": "/volumes/" + EVIDENCE_VOLUME,
                        "Labels": {OWNER: "true"},
                    }
                ]
            ).encode()
        assert args[:2] == ("exec", "--interactive") and args[-1] == host.CONFIGURATION_PROGRAM
        assert stdin is not None and json.loads(stdin) == {
            "helper": self.contract["host_helper"],
            "configuration_sha256": self.contract["cleanup_configuration_sha256"],
        }
        return json.dumps(
            {
                "mode": "cleanup-only",
                "helper_revision": self.contract["host_helper"],
                "configuration_sha256": self.contract["cleanup_configuration_sha256"],
            }
        ).encode()

    @override
    def cleanup_logs(self, container_id: str) -> bytes:
        assert container_id == self.contract["host_id"]
        return (
            EMITTED
            + " "
            + json.dumps(
                {
                    "format": "lowerduckpond-m3-11-lease-cleanup-v1",
                    "actor": "watchdog",
                    "status": "ready",
                    "observed_at": OBSERVED,
                }
            )
            + "\n"
        ).encode()


def test_capture_reads_exact_actor_configuration_and_receipt_without_mutation(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    contract, value = context()
    docker = ReadDocker(contract, value)
    proof = host.capture(docker, contract, tmp_path / "host.json")
    assert proof["before"] == proof["after"]
    assert proof["provider_calls"] == proof["new_dispatches"] == proof["live_mutations"] == 0
    assert {c[0] for c in docker.calls} == {"info", "inspect", "volume", "exec"}


@pytest.mark.parametrize(
    "change",
    [
        "image",
        "helper",
        "configuration",
        "start",
        "running",
        "command",
        "network",
        "writable-config",
        "shadow",
        "extra-mount",
        "evidence-source",
        "restart",
        "socket",
        "daemon-environment",
        "entrypoint",
    ],
)
def test_capture_rejects_another_domain_or_actor(tmp_path: Path, change: str) -> None:  # noqa: PLR0912 - independent boundaries
    tmp_path.chmod(0o700)
    contract, value = context()
    docker = ReadDocker(contract, value)
    if change == "image":
        value["Image"] = "sha256:" + "f" * 64
    elif change == "helper":
        value["Config"]["Labels"][OWNER + ".helper"] = "f" * 40
    elif change == "configuration":
        value["Config"]["Labels"][OWNER + ".configuration"] = "f" * 64
    elif change == "start":
        value["State"]["StartedAt"] = EMITTED
    elif change == "running":
        value["State"]["Running"] = False
    elif change == "command":
        value["Config"]["Cmd"] = ["other-program"]
    elif change == "network":
        value["HostConfig"]["NetworkMode"] = "other"
    elif change == "writable-config":
        value["Mounts"][2]["RW"] = True
    elif change == "shadow":
        value["Mounts"].append({"Type": "bind", "Destination": "/evidence/shadow"})
    elif change == "extra-mount":
        value["Mounts"].append({"Type": "bind", "Destination": "/other"})
    elif change == "evidence-source":
        value["Mounts"][1]["Source"] = "/copied/evidence"
    elif change == "restart":
        docker.restart = True
    elif change == "socket":
        docker.endpoint = "unix:///other.sock"
    elif change == "daemon-environment":
        value["Config"]["Env"] = ["DOCKER_HOST=unix:///other.sock"]
    elif change == "entrypoint":
        value["Config"]["Entrypoint"] = ["other-program"]
    with pytest.raises(ValueError):
        host.capture(docker, contract, tmp_path / "host.json")
    assert not (tmp_path / "host.json").exists()


def test_latest_failure_cannot_be_hidden_by_earlier_ready_stdout() -> None:
    ready = {"format": "lowerduckpond-m3-11-lease-cleanup-v1", "status": "ready"}
    raw = (
        OBSERVED
        + " "
        + json.dumps(ready)
        + "\n"
        + EMITTED
        + " Credential cleanup unresolved; obligations retained.\n"
    ).encode()
    with pytest.raises(ValueError, match="latest ready"):
        host.receipt(raw)
    with pytest.raises(ValueError, match="unrecognized output"):
        host.receipt(raw + b"2026-10-10T00:03:00Z SYNTHETIC-PRIVATE-CANARY\n")


@pytest.mark.parametrize("same_timestamp", [False, True])
def test_newer_or_same_time_failure_cannot_be_replaced_by_older_ready(same_timestamp: bool) -> None:
    ready = {"format": "lowerduckpond-m3-11-lease-cleanup-v1", "status": "ready"}
    old = EMITTED if same_timestamp else OBSERVED
    raw = (
        EMITTED
        + " Credential cleanup unresolved; obligations retained.\n"
        + old
        + " "
        + json.dumps(ready)
        + "\n"
    ).encode()
    with pytest.raises(ValueError, match="chronology"):
        host.receipt(raw)


def test_actual_log_process_is_bounded_before_output_is_buffered_or_exposed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys  # noqa: PLC0415 - current test interpreter only

    cli = tmp_path / "synthetic-docker"
    cli.write_text(
        "#!"
        + sys.executable
        + "\nimport sys\nsys.stdout.buffer.write(b'SYNTHETIC-PRIVATE-CANARY' * 300000)\n"
    )
    cli.chmod(0o700)
    docker = object.__new__(host.HostDocker)
    docker.executable = str(cli)
    docker.environment = {}
    with pytest.raises(ValueError, match="output exceeds bound"):
        docker.cleanup_logs("a" * 64)
    captured = capsys.readouterr()
    assert "SYNTHETIC-PRIVATE-CANARY" not in captured.out + captured.err
