"""Production delivery through an existing Coder workspace, without autostart.

Coder joins remote command arguments with spaces (cli/ssh.go). Pass exactly one
shell-quoted command, including literal Python programs; private bytes use stdin.
"""

from __future__ import annotations

import json
import re
import shlex
import uuid

from scripts.m3_11_unattended.connect_delivery import RECEIVER, Delivery
from scripts.m3_11_unattended.model import LifecycleError

SOCKET = "unix:///docker-sock/docker.sock"

# This same check runs immediately before receiving private stdin or invoking a
# migration utility. It emits only the selected identity, never the environment.
PROBE = r"""
import json, os, re, subprocess, sys
from pathlib import Path

def probe(workspace, daemon):
    home = Path("/home/coder")
    if (os.environ.get("CODER_WORKSPACE_ID") != workspace or os.geteuid() != 1000
            or home.resolve() != home or home.stat().st_uid != 1000):
        raise ValueError()
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        parts = line.split()
        if parts[4] == str(home):
            mounts.append(parts)
    if len(mounts) != 1:
        raise ValueError()
    mount = mounts[0]
    suffix = "/volumes/coder-" + workspace + "-home/_data"
    if not mount[3].endswith(suffix) or "rw" not in mount[5].split(","):
        raise ValueError()
    result = subprocess.run(
        ["docker", "--host", "unix:///docker-sock/docker.sock", "info", "--format", "{{json .}}"],
        capture_output=True, check=True, timeout=30,
    )
    value = json.loads(result.stdout)
    if value.get("ID") != daemon:
        raise ValueError()
    return {"workspace_id": workspace, "uid": 1000, "home": str(home),
            "home_volume_root": mount[3],
            "daemon": {key: value[key] for key in ("ID", "Name", "DockerRootDir", "ServerVersion")}}

try:
    observed = probe(sys.argv[1], sys.argv[2])
    if len(sys.argv) == 3:
        print(json.dumps(observed, sort_keys=True))
    else:
        if observed != json.loads(sys.argv[3]):
            raise ValueError()
        os.execvp(sys.argv[4], sys.argv[4:])
except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
    raise SystemExit("Coder destination verification failed; private inputs retained.") from None
"""


class CoderDelivery(Delivery):
    def __init__(self, workspace: str, workspace_id: str, daemon_id: str) -> None:
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9_-]*", workspace) is None
            or str(uuid.UUID(workspace_id)) != workspace_id
            or str(uuid.UUID(daemon_id)) != daemon_id
        ):
            raise LifecycleError("Coder delivery needs exact workspace and daemon identities")
        self.workspace, self.workspace_id, self.daemon_id = workspace, workspace_id, daemon_id

    def ssh(self, arguments: list[str], stdin: bytes | None = None, *, timeout: int = 90) -> bytes:
        return self.command(
            "coder",
            "ssh",
            "--disable-autostart",
            "--tty=false",
            "--forward-agent=false",
            "--forward-gpg=false",
            "--wait=no",
            self.workspace,
            "--",
            shlex.join(arguments),
            stdin=stdin,
            timeout=timeout,
        )

    def api_identity(self) -> dict[str, str]:
        owner, name = self.workspace.split("/")
        rows = json.loads(
            self.command(
                "coder", "list", "--output", "json", "--search", f"owner:{owner} name:{name}"
            )
        )
        matches = (
            [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("owner_name") == owner
                and row.get("name") == name
            ]
            if isinstance(rows, list)
            else []
        )
        if len(matches) != 1 or matches[0].get("id") != self.workspace_id:
            raise LifecycleError("Coder workspace identity differs")
        build = matches[0].get("latest_build")
        if (
            not isinstance(build, dict)
            or build.get("status") != "running"
            or not isinstance(build.get("resources"), list)
        ):
            raise LifecycleError("Coder workspace is not already running")
        agents = [
            agent for resource in build["resources"] for agent in resource.get("agents") or []
        ]
        if len(agents) != 1 or agents[0].get("status") != "connected":
            raise LifecycleError("Coder needs one connected destination agent")
        return {
            "workspace_id": self.workspace_id,
            "build_id": str(uuid.UUID(build["id"])),
            "agent_id": str(uuid.UUID(agents[0]["id"])),
        }

    def workspace_identity(self) -> str:
        before = self.api_identity()
        runtime = json.loads(self.ssh(["python3", "-c", PROBE, self.workspace_id, self.daemon_id]))
        if self.api_identity() != before or not isinstance(runtime, dict):
            raise LifecycleError("Coder destination changed during verification")
        return json.dumps({"api": before, "runtime": runtime}, sort_keys=True)

    def checked(
        self, original: str, arguments: list[str], stdin: bytes, *, timeout: int = 90
    ) -> bytes:
        value = json.loads(original)
        if self.api_identity() != value["api"]:
            raise LifecycleError("Coder destination changed before private transfer")
        return self.ssh(
            [
                "python3",
                "-c",
                PROBE,
                self.workspace_id,
                self.daemon_id,
                json.dumps(value["runtime"], sort_keys=True),
                *arguments,
            ],
            stdin=stdin,
            timeout=timeout,
        )

    def remote_docker(self, arguments: list[str], stdin: bytes) -> bytes:
        original = self.workspace_identity()
        result = self.checked(
            original, ["docker", "--host", SOCKET, *arguments], stdin, timeout=1200
        )
        if self.workspace_identity() != original:
            raise LifecycleError("Coder destination changed during migration")
        return result

    def receive(self, identity: str, destination: str, expected: str, controller: bytes) -> bytes:
        return self.checked(
            identity, ["python3", "-c", RECEIVER, destination, expected], controller
        )
