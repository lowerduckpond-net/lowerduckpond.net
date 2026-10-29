"""A separately armed native-Docker host watchdog for one diagnostic graph.

The watchdog receives cleanup-only access. It cannot issue a token, publish an
issuance manifest, allocate a fixture or start public recovery. Its same-source
container and shared-volume heartbeat must be proven before every CREATE.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_isolation_access import CleanupAccess
from scripts.m3_11_isolation_host import Host
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_isolation_runtime import Evidence, Fence
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.docker import (
    CLEANUP_VOLUME,
    EVIDENCE_VOLUME,
    OWNER,
    SOCKET,
    Docker,
    helper_volume,
)
from scripts.m3_11_unattended.model import digest, fingerprint, instant, stamp
from scripts.m3_11_unattended.state import replace_private

INTERVAL = 10
MAX_HEARTBEAT = timedelta(seconds=90)


def name(manifest: Manifest) -> str:
    return "ldp-m311-public-ca-watch-" + manifest.plan.run_id.replace("-", "")


def arguments(manifest: Manifest, *, socket: str) -> list[str]:
    if not socket.startswith("/") or any(char in socket for char in (",", "\n", "\0")):
        raise ValueError("isolated watchdog socket is invalid")
    return [
        "create",
        "--name",
        name(manifest),
        "--label",
        OWNER + "=true",
        "--label",
        OWNER + ".public-ca=" + manifest.plan.run_id,
        "--restart",
        "on-failure",
        "--read-only",
        "--network",
        "host",
        "--tmpfs",
        "/tmp:mode=1777",  # noqa: S108 - private ephemeral container tmpfs
        "--env",
        "DOCKER_HOST=unix://" + SOCKET,
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--mount",
        f"type=bind,source={socket},target={SOCKET}",
        "--mount",
        f"type=volume,source={helper_volume(manifest.plan.source_revision)},target=/opt/lifecycle,readonly",
        "--mount",
        f"type=volume,source={EVIDENCE_VOLUME},target=/evidence",
        "--mount",
        f"type=volume,source={CLEANUP_VOLUME},target=/cleanup,readonly",
        "--workdir",
        "/opt/lifecycle",
        "sha256:" + manifest.plan.controller_sha256,
        ".venv/bin/python",
        "-m",
        "scripts.m3_11_isolation_watch",
        manifest.plan.run_id,
    ]


def daemon_socket(host: Host) -> str:
    """Use the prepared controller's actual host bind, not an inner socket path."""
    actor = host.docker.owned(
        str(cast(dict[str, dict[str, object]], host.prepared["actors"])["controller"]["id"])
    )
    raw_mounts = actor.get("Mounts")
    if not isinstance(raw_mounts, list):
        raise ValueError("isolated controller mounts are unavailable")
    matches = [
        item for item in raw_mounts if isinstance(item, dict) and item.get("Destination") == SOCKET
    ]
    if (
        len(matches) != 1
        or matches[0].get("Type") != "bind"
        or not isinstance(matches[0].get("Source"), str)
    ):
        raise ValueError("isolated prepared controller socket bind differs")
    selected = cast(str, matches[0]["Source"])
    if not selected.startswith("/") or any(char in selected for char in (",", "\n", "\0")):
        raise ValueError("isolated prepared socket source is invalid")
    return selected


def require_armed(host: Host, *, now: datetime | None = None) -> None:
    host.require()
    docker, manifest = host.docker, host.manifest
    value = docker.owned(name(manifest))
    config, state, machine = value.get("Config"), value.get("State"), value.get("HostConfig")
    if not isinstance(config, dict) or not isinstance(state, dict) or not isinstance(machine, dict):
        raise ValueError("isolated watchdog metadata is missing")
    socket = daemon_socket(host)
    expected = arguments(manifest, socket=socket)
    command = expected[expected.index("sha256:" + manifest.plan.controller_sha256) + 1 :]
    mounts = value.get("Mounts")
    required = {
        helper_volume(manifest.plan.source_revision): ("/opt/lifecycle", False),
        EVIDENCE_VOLUME: ("/evidence", True),
        CLEANUP_VOLUME: ("/cleanup", False),
    }
    if not isinstance(mounts, list):
        raise ValueError("isolated watchdog mounts are missing")
    for volume, (destination, writable) in required.items():
        matches = [
            item
            for item in mounts
            if isinstance(item, dict) and item.get("Destination") == destination
        ]
        if (
            len(matches) != 1
            or matches[0].get("Type") != "volume"
            or matches[0].get("Name") != volume
            or matches[0].get("RW") is not writable
        ):
            raise ValueError("isolated watchdog native mount differs")
    allowed = {"/opt/lifecycle", "/evidence", "/cleanup", SOCKET, "/tmp"}  # noqa: S108 - exact private tmpfs target
    if any(not isinstance(item, dict) or item.get("Destination") not in allowed for item in mounts):
        raise ValueError("isolated watchdog contains an unexpected/shadow mount")
    sockets = [item for item in mounts if item.get("Destination") == SOCKET]
    if (
        len(sockets) != 1
        or sockets[0].get("Type") != "bind"
        or sockets[0].get("Source") != socket
        or sockets[0].get("RW") is not True
    ):
        raise ValueError("isolated watchdog socket bind differs")
    environment = config.get("Env")
    if not isinstance(environment, list) or any(
        not isinstance(item, str) or "=" not in item for item in environment
    ):
        raise ValueError("isolated watchdog environment is invalid")
    image = json.loads(
        docker.command("image", "inspect", "sha256:" + manifest.plan.controller_sha256)
    )
    if (
        not isinstance(image, list)
        or len(image) != 1
        or image[0].get("Id") != "sha256:" + manifest.plan.controller_sha256
    ):
        raise ValueError("isolated watchdog image metadata differs")
    image_environment = image[0].get("Config", {}).get("Env")
    if not isinstance(image_environment, list):
        raise ValueError("isolated watchdog image environment is missing")
    expected_env = dict(item.split("=", 1) for item in image_environment)
    expected_env.update(DOCKER_HOST="unix://" + SOCKET, PYTHONDONTWRITEBYTECODE="1")
    if (
        len(environment) != len(expected_env)
        or dict(item.split("=", 1) for item in environment) != expected_env
    ):
        raise ValueError("isolated watchdog environment differs from its pinned image")
    if (
        config.get("Entrypoint") != ["/usr/local/bin/mise", "exec", "--"]
        or config.get("WorkingDir") != "/opt/lifecycle"
        or value.get("Name") != "/" + name(manifest)
        or value.get("Image") != "sha256:" + manifest.plan.controller_sha256
        or config.get("Cmd") != command
        or config.get("Labels", {}).get(OWNER + ".public-ca") != manifest.plan.run_id
        or state.get("Running") is not True
        or machine.get("NetworkMode") != "host"
        or machine.get("ReadonlyRootfs") is not True
        or machine.get("RestartPolicy", {}).get("Name") != "on-failure"
    ):
        raise ValueError("isolated watchdog identity/configuration differs")
    heartbeat = read_private(host.root / "watchdog.json")
    observed = instant(heartbeat.get("observed_at"))
    current = datetime.now(UTC) if now is None else now
    if (
        set(heartbeat)
        != {
            "manifest_sha256",
            "container_id",
            "admission_sha256",
            "cleanup_access_verified",
            "observed_at",
        }
        or heartbeat["manifest_sha256"] != manifest.sha256
        or heartbeat["container_id"] != value.get("Id")
        or heartbeat["admission_sha256"] != digest(host.evidence.fence.ticket)
        or heartbeat["cleanup_access_verified"] is not True
        or not timedelta(0) <= current - observed <= MAX_HEARTBEAT
    ):
        raise ValueError("isolated watchdog has no fresh native prearm heartbeat")


def due(host: Host, *, now: datetime) -> bool:
    host.require()
    if (host.root / "stop-requested.json").exists() or (
        host.root / "functional-terminal.json"
    ).exists():
        return True
    if host.actor("controller")["running"] is not True:
        return True
    latest = instant(host.manifest.intents[0].expires_at) - timedelta(
        seconds=host.manifest.plan.cleanup_reserve_seconds
    )
    started = host.phase / "isolation-phase-started.json"
    if started.exists():
        latest = min(latest, instant(read_private(started)["deadline_at"]))
    return now >= latest


def run(host: Host, access: CleanupAccess, *, actor_id: str) -> None:
    """Remain the cleanup owner through closure; never auto-retry recovery."""
    actor_id = fingerprint(actor_id)
    verified = False
    while True:
        host.require()
        requested = due(host, now=datetime.now(UTC))
        if not requested:
            try:
                client = access.client(host.manifest)
                if not verified:
                    access.provider(host.manifest, client=client)
                    verified = True
                from scripts.m3_11_isolation_journal import Journal  # noqa: PLC0415

                journal = Journal(client, host.manifest)
                requested = any(row["kind"] == "stop-requested" for row in journal.all_records())
            except Exception:
                # A restart during an outage must still service the local
                # deadline/death path. It cannot claim authenticated prearm.
                verified = False
        try:
            replace_private(
                host.root / "watchdog.json",
                {
                    "manifest_sha256": host.manifest.sha256,
                    "container_id": actor_id,
                    "admission_sha256": digest(host.evidence.fence.ticket),
                    "cleanup_access_verified": verified,
                    "observed_at": stamp(datetime.now(UTC)),
                },
            )
        except Exception:
            # Failed heartbeat persistence is never permission to leave issued
            # consumers running. Prearm stays unavailable; service cleanup now.
            requested = True
        if requested:
            result = host.cleanup(access)
            replace_private(host.root / "host-cleanup.json", result)
            if result["status"] == "verified":
                return
        time.sleep(INTERVAL)


def main() -> int:
    import sys  # noqa: PLC0415

    from scripts.m3_11_unattended.model import identity  # noqa: PLC0415
    from scripts.production_qualification_inputs import current_candidate  # noqa: PLC0415

    os.umask(0o077)
    # Only a previously prepared native shared-volume run is selectable. There
    # is no stdin bootstrap, arbitrary root or instruction interpreter.
    if len(sys.argv) != len({"program", "run-id"}):
        return 2
    selected = identity(sys.argv[1])
    root = Path("/evidence/public-ca")
    directory = root / "runs" / selected
    try:
        manifest = Manifest.parse(read_private(directory / "manifest.json"))
        current_candidate(Path(__file__).resolve().parents[1], manifest.plan.source_revision)
        docker = Docker()
        actor = docker.owned(name(manifest))
        fence = Fence(docker, read_private(root / (selected + ".admission.json")))
        evidence = Evidence(docker, fence, actor_id=str(actor["Id"]), root=root)
        host = Host(manifest, evidence, directory_path=directory, docker=docker)
        access = CleanupAccess.parse(
            read_private(Path("/cleanup/public-ca") / selected / "access.json")
        )
        run(host, access, actor_id=str(actor["Id"]))
    except Exception:
        # No raw exception, private payload or credential appears in logs.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
