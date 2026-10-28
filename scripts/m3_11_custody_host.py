"""Read-only authenticated observation of the exact pre-armed cleanup actor.

No provider client, dispatch or credential delivery is exposed. The collector
retains constructed receipts and the exact public daemon/configuration binding,
never environment values, raw logs, configuration bodies or exception payloads.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_custody_plan import require
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_retirement_files import record
from scripts.m3_11_unattended.docker import (
    CLEANUP_VOLUME,
    EVIDENCE_VOLUME,
    OWNER,
    SOCKET,
    Docker,
    helper_volume,
)
from scripts.m3_11_unattended.model import fingerprint, instant, stamp

FORMAT = "lowerduckpond-m3-11-custody-host-observation-v1"
MAX_LOG_BYTES = 4 * 1024 * 1024
COMMAND = [
    "uv",
    "run",
    "--no-sync",
    "--frozen",
    "python",
    "-m",
    "scripts.m3_11_unattended.cleanup",
    "--config",
    "/cleanup/cleanup.json",
    "--actor",
    "watchdog",
    "--watch",
    "--runs",
    "/evidence/runs",
]
CONFIGURATION_PROGRAM = """import sys,json
from pathlib import Path
sys.path.insert(0,'/opt/lifecycle')
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import digest
wanted=json.load(sys.stdin)
c=LeaseConfiguration.load(Path('/cleanup/cleanup.json'))
if c.mode!='cleanup-only' or c.production is not None:raise ValueError('cleanup isolation differs')
if c.helper_revision!=wanted['helper'] or digest(c.document())!=wanted['configuration_sha256']:
 raise ValueError('cleanup binding differs')
print(json.dumps({'mode':c.mode,'helper_revision':c.helper_revision,'configuration_sha256':digest(c.document())}))
"""


class HostDocker(Docker):
    def cleanup_logs(self, container_id: str) -> bytes:
        # Docker emits container stderr on CLI stderr. Merge before parsing so
        # a later native unresolved error cannot be hidden behind older stdout.
        process = subprocess.Popen(  # noqa: S603 - fixed read-only Docker log surface
            [self.executable, "logs", "--timestamps", "--tail", "64", container_id],
            env=self.environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 30
        result = bytearray()
        try:
            stream = process.stdout
            if stream is None:
                raise ValueError("custody host log pipe unavailable")
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "custody host log read timed out")
                require(
                    bool(select.select([stream], [], [], remaining)[0]),
                    "custody host log read timed out",
                )
                block = os.read(
                    stream.fileno(), min(65536, MAX_LOG_BYTES + 1 - len(result))
                )
                if not block:
                    break
                result.extend(block)
                require(len(result) <= MAX_LOG_BYTES, "custody host log output exceeds bound")
            require(
                process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                "custody host log observation failed",
            )
            return bytes(result)
        except OSError, subprocess.SubprocessError:
            raise ValueError("custody host log observation failed") from None
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()


def _subset(raw: object, keys: set[str]) -> dict[str, object]:
    require(isinstance(raw, dict) and keys <= set(raw), "custody host inspection fields missing")
    return {key: cast(dict[str, object], raw)[key] for key in keys}


def projection(raw: object, contract: dict[str, object]) -> dict[str, object]:
    require(isinstance(raw, dict), "custody host inspection is missing")
    value = cast(dict[str, object], raw)
    config = _subset(value.get("Config"), {"Cmd", "Labels", "Env", "Entrypoint"})
    state = _subset(
        value.get("State"),
        {"Running", "Paused", "Restarting", "StartedAt", "Pid"},
    )
    host = _subset(
        value.get("HostConfig"),
        {"NetworkMode", "ReadonlyRootfs", "RestartPolicy"},
    )
    environment = config["Env"]
    require(
        isinstance(environment, list) and all(isinstance(v, str) for v in environment),
        "custody host environment metadata invalid",
    )
    selected_environment = [
        v
        for v in cast(list[str], environment)
        if v.startswith(("DOCKER_HOST=", "DOCKER_CONTEXT=", "UV_CACHE_DIR="))
    ]
    require(
        selected_environment == ["DOCKER_HOST=unix://" + SOCKET, "UV_CACHE_DIR=/tmp/uv-cache"],
        "custody host daemon environment differs",
    )
    labels = cast(dict[str, object], config["Labels"])
    runtime = cast(dict[str, object], contract["runtime"])
    helper = str(contract["host_helper"])
    require(
        value.get("Id") == contract["host_id"]
        and value.get("Name") == "/ldp-m311-watchdog-" + helper[:12]
        and value.get("Image") == runtime["image"]
        and config["Cmd"] == COMMAND
        and config["Entrypoint"] == ["/usr/local/bin/mise", "exec", "--"]
        and type(value.get("RestartCount")) is int
        and cast(int, value["RestartCount"]) >= 0
        and isinstance(labels, dict)
        and labels.get(OWNER) == "true"
        and labels.get(OWNER + ".helper") == helper
        and labels.get(OWNER + ".configuration") == contract["cleanup_configuration_sha256"]
        and state["Running"] is True
        and state["Paused"] is False
        and state["Restarting"] is False
        and type(state["Pid"]) is int
        and state["Pid"] > 0
        and state["StartedAt"] == contract["host_started_at"]
        and host["NetworkMode"] == "host"
        and host["ReadonlyRootfs"] is True
        and isinstance(host["RestartPolicy"], dict)
        and host["RestartPolicy"].get("Name") == "unless-stopped",
        "custody host actor, startup configuration or execution contract differs",
    )
    mounts = value.get("Mounts")
    require(
        isinstance(mounts, list) and all(isinstance(v, dict) for v in mounts),
        "custody host mounts unavailable",
    )
    mount_rows = cast(list[dict[str, object]], mounts)
    expected = {
        "/opt/lifecycle": ("volume", helper_volume(helper), False),
        "/evidence": ("volume", EVIDENCE_VOLUME, True),
        "/cleanup": ("volume", CLEANUP_VOLUME, False),
        SOCKET: ("bind", str(contract["daemon_socket"]), True),
    }
    selected = []
    for destination, (kind, source, writable) in expected.items():
        matches = [v for v in mount_rows if v.get("Destination") == destination]
        require(len(matches) == 1, "custody host mount missing or repeated")
        row = matches[0]
        require(
            row.get("Type") == kind
            and row.get("RW") is writable
            and row.get("Name" if kind == "volume" else "Source") == source,
            "custody host uses another volume or socket",
        )
        require(
            not any(
                str(v.get("Destination", "")).startswith(destination + "/") for v in mount_rows
            ),
            "custody host mount is shadowed",
        )
        selected.append({k: row.get(k) for k in ("Type", "Name", "Source", "Destination", "RW")})
    require(
        all(
            v.get("Destination") in expected
            or (v.get("Type") == "tmpfs" and v.get("Destination") == "/tmp")  # noqa: S108 - container-private tmpfs
            for v in mount_rows
        ),
        "custody host has unexpected mounts",
    )
    return {
        "Id": value["Id"],
        "Name": value["Name"],
        "Image": value["Image"],
        "Config": {
            "Cmd": config["Cmd"],
            "Entrypoint": config["Entrypoint"],
            "Env": selected_environment,
            "Labels": {k: labels[k] for k in (OWNER, OWNER + ".helper", OWNER + ".configuration")},
        },
        "State": state,
        "HostConfig": host,
        "RestartCount": value["RestartCount"],
        "Mounts": selected,
    }


def receipt(raw: bytes) -> tuple[dict[str, object], str]:
    require(len(raw) <= MAX_LOG_BYTES, "custody cleanup logs exceed bounded observation")
    latest: tuple[dict[str, object], str] | None = None
    previous: datetime | None = None
    for line in raw.decode().splitlines():
        require(" " in line, "custody cleanup observation has no native timestamp")
        emitted, body = line.split(" ", 1)
        current = instant(emitted)
        require(
            previous is None or current > previous,
            "custody cleanup log chronology is reordered or ambiguous",
        )
        previous = current
        if body == "Credential cleanup unresolved; obligations retained.":
            latest = None
            continue
        try:
            value = json.loads(body)
        except ValueError, TypeError:
            raise ValueError("custody cleanup has unrecognized output") from None
        require(
            isinstance(value, dict)
            and value.get("format") == "lowerduckpond-m3-11-lease-cleanup-v1",
            "custody cleanup has unrecognized receipt",
        )
        latest = (value, emitted)
    require(
        latest is not None and latest[0].get("status") == "ready",
        "custody host has no latest ready native receipt",
    )
    return cast(tuple[dict[str, object], str], latest)


def capture(docker: HostDocker, contract: dict[str, object], output: Path) -> dict[str, object]:
    """Only source-fixed native GET/inspect/logs and private local config-read code."""
    fingerprint(contract["cleanup_configuration_sha256"])
    runtime = cast(dict[str, object], contract["runtime"])
    require(
        docker.endpoint == "unix://" + str(contract["daemon_socket"]),
        "custody cleanup socket differs",
    )
    info = json.loads(docker.command("info", "--format", "{{json .}}", timeout=30))
    require(info["ID"] == runtime["daemon_id"], "custody cleanup daemon differs")

    def inspect() -> dict[str, object]:
        rows = json.loads(docker.command("inspect", str(contract["host_id"]), timeout=30))
        require(isinstance(rows, list) and len(rows) == 1, "custody host identity is ambiguous")
        return projection(rows[0], contract)

    before = inspect()
    volume = json.loads(docker.command("volume", "inspect", EVIDENCE_VOLUME, timeout=30))
    require(
        isinstance(volume, list)
        and len(volume) == 1
        and volume[0].get("CreatedAt") == runtime["evidence_volume_created_at"]
        and volume[0].get("Name") == EVIDENCE_VOLUME
        and isinstance(volume[0].get("Labels"), dict)
        and volume[0]["Labels"].get(OWNER) == "true",
        "custody cleanup evidence volume differs",
    )
    mounted = next(
        row
        for row in cast(list[dict[str, object]], before["Mounts"])
        if row["Destination"] == "/evidence"
    )
    require(
        mounted["Source"] == volume[0].get("Mountpoint"),
        "custody cleanup evidence mount is not native",
    )
    configuration = json.loads(
        docker.command(
            "exec",
            "--interactive",
            str(contract["host_id"]),
            "/opt/lifecycle/.venv/bin/python",
            "-I",
            "-B",
            "-c",
            CONFIGURATION_PROGRAM,
            stdin=canonical_bytes(
                {
                    "helper": contract["host_helper"],
                    "configuration_sha256": contract["cleanup_configuration_sha256"],
                }
            ),
            timeout=30,
        )
    )
    require(
        configuration
        == {
            "mode": "cleanup-only",
            "helper_revision": contract["host_helper"],
            "configuration_sha256": contract["cleanup_configuration_sha256"],
        },
        "custody cleanup configuration readback differs",
    )
    native, emitted = receipt(docker.cleanup_logs(str(contract["host_id"])))
    after = inspect()
    require(after == before, "custody cleanup actor changed during authenticated observation")
    result = {
        "format": FORMAT,
        "before": before,
        "after": after,
        "configuration": configuration,
        "daemon": {"ID": info["ID"], "endpoint": docker.endpoint},
        "volume": {key: volume[0][key] for key in ("Name", "CreatedAt", "Mountpoint")},
        "receipt": native,
        "receipt_emitted_at": emitted,
        "captured_at": stamp(datetime.now(UTC)),
        "provider_calls": 0,
        "new_dispatches": 0,
        "live_mutations": 0,
    }
    record(output, result)
    return result
