"""A daemon-side controller with named volumes; never inherit workspace mounts."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import cast

from scripts.m3_11_unattended.model import LifecycleError
from scripts.production_qualification_inputs import current_candidate, git, revision

OWNER = "lowerduckpond.m3-11.unattended"
EVIDENCE_VOLUME = "ldp-m311-evidence"
LEASE_VOLUME = "ldp-m311-storage-leases"
CONFIG_VOLUME = "ldp-m311-controller-config"
CLEANUP_VOLUME = "ldp-m311-cleanup-config"
SOCKET = "/var/run/docker.sock"
ROOT = Path(__file__).resolve().parents[2]


class Docker:
    def __init__(self) -> None:
        executable = shutil.which("docker")
        if executable is None:
            raise LifecycleError("Docker is unavailable")
        self.executable = executable
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"}
        }
        if self.environment.get("DOCKER_CONTEXT"):
            endpoint = self.command(
                "context",
                "inspect",
                self.environment["DOCKER_CONTEXT"],
                "--format",
                "{{.Endpoints.docker.Host}}",
            )
        elif self.environment.get("DOCKER_HOST"):
            endpoint = self.environment["DOCKER_HOST"].encode()
        else:
            endpoint = self.command("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
        self.endpoint = endpoint.decode().strip()
        if not self.endpoint.startswith("unix:///"):
            raise LifecycleError("the approved Docker host must use its forwarded Unix socket")
        self.environment.pop("DOCKER_CONTEXT", None)
        self.environment["DOCKER_HOST"] = self.endpoint

    def command(self, *arguments: str, stdin: bytes | None = None, timeout: int = 1200) -> bytes:
        try:
            result = subprocess.run(  # noqa: S603 - explicit Docker operations; no secret values in argv
                [self.executable, *arguments],
                env=self.environment,
                input=stdin,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except OSError, subprocess.SubprocessError:
            raise LifecycleError("Docker operation failed; preserve controller volumes") from None
        if result.returncode:
            raise LifecycleError("Docker operation failed; preserve controller volumes")
        return result.stdout

    def volume(self, name: str) -> None:
        self.command("volume", "create", "--label", OWNER + "=true", name)
        value = json.loads(self.command("volume", "inspect", name))
        if (
            not isinstance(value, list)
            or len(value) != 1
            or value[0].get("Labels", {}).get(OWNER) != "true"
        ):
            raise LifecycleError("controller volume ownership is unverified")

    def info(self) -> dict[str, str]:
        value = json.loads(self.command("info", "--format", "{{json .}}"))
        return {key: str(value[key]) for key in ("ID", "Name", "DockerRootDir", "ServerVersion")}

    def owned(self, name: str) -> dict[str, object]:
        values = json.loads(self.command("inspect", name))
        if not isinstance(values, list) or len(values) != 1:
            raise LifecycleError("controller identity is ambiguous")
        value = values[0]
        if value.get("Config", {}).get("Labels", {}).get(OWNER) != "true":
            raise LifecycleError("controller ownership is unverified")
        return cast(dict[str, object], value)

    def remove_controller(self, name: str) -> None:
        self.owned(name)
        self.command("rm", "--force", name)


def image_name(source: str) -> str:
    return "ldp-m311-controller:" + revision(source)


def helper_volume(source: str) -> str:
    return "ldp-m311-helper-" + revision(source)


def source_volume(source: str) -> str:
    return "ldp-m311-source-" + revision(source)


def controller_name(run_id: str) -> str:
    return "ldp-m311-controller-" + uuid.UUID(run_id).hex


def build_image(docker: Docker, source: str) -> str:
    current_candidate(ROOT, source)
    # Explicit allowlist: no checkout context, .env, private config, credentials
    # or local caches can enter the image or its build history.
    context = io.BytesIO()
    with tarfile.open(fileobj=context, mode="w") as archive:
        for name, path in (
            ("Dockerfile", "config/qualification/Dockerfile"),
            ("mise.toml", "mise.toml"),
            ("mise.lock", "mise.lock"),
        ):
            content = git(ROOT, "show", f"{source}:{path}")
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o644
            archive.addfile(info, io.BytesIO(content))
    docker.command(
        "build",
        "--label",
        OWNER + "=true",
        "--label",
        OWNER + ".source=" + source,
        "--tag",
        image_name(source),
        "-",
        stdin=context.getvalue(),
    )
    selected = (
        docker.command("image", "inspect", image_name(source), "--format", "{{.Id}}")
        .decode()
        .strip()
    )
    if re.fullmatch(r"sha256:[0-9a-f]{64}", selected) is None:
        raise LifecycleError("controller image identity is unavailable")
    return selected


def prepare(docker: Docker, source: str) -> dict[str, object]:
    """Install clean committed inputs on the daemon before any credential setup."""
    current_candidate(ROOT, source)
    image = build_image(docker, source)
    for volume in (
        helper_volume(source),
        source_volume(source),
        EVIDENCE_VOLUME,
        LEASE_VOLUME,
        CONFIG_VOLUME,
        CLEANUP_VOLUME,
    ):
        docker.volume(volume)
    name = "ldp-m311-prepare-" + uuid.uuid4().hex
    docker.command(
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        OWNER + "=true",
        "--network",
        "host",
        "--mount",
        f"type=volume,source={helper_volume(source)},target=/opt/lifecycle",
        "--mount",
        f"type=volume,source={source_volume(source)},target=/work/source",
        "--mount",
        f"type=volume,source={EVIDENCE_VOLUME},target=/evidence",
        "--workdir",
        "/opt/qualification-tools",
        image,
        "sleep",
        "infinity",
    )
    try:
        with tempfile.TemporaryDirectory(prefix="ldp-m311-bundle-") as temporary:
            bundle = Path(temporary) / "source.bundle"
            git(ROOT, "bundle", "create", str(bundle), "--all")
            docker.command("cp", str(bundle), name + ":/tmp/source.bundle")
        program = """
set -euo pipefail
umask 077
for root in /opt/lifecycle /work/source; do
    if [[ ! -d "$root/.git" ]]; then
        git clone --quiet /tmp/source.bundle "$root"
        git -C "$root" checkout --quiet --detach "$1"
    fi
    test "$(git -C "$root" rev-parse HEAD)" = "$1"
    test -z "$(git -C "$root" status --porcelain)"
    cd "$root"
    mise exec -- uv sync --all-packages --all-groups --frozen
done
mkdir -p "/evidence/prepared/$1"
chmod 0700 /evidence /evidence/prepared "/evidence/prepared/$1"
mise exec -- scripts/build-static-host-agent "/evidence/prepared/$1/static-host-agent.tar"
rm /tmp/source.bundle
"""
        docker.command("exec", name, "/bin/bash", "-c", program, "prepare", source)
        artifact = (
            docker.command(
                "exec", name, "cat", f"/evidence/prepared/{source}/static-host-agent.tar.sha256"
            )
            .decode()
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", artifact) is None:
            raise LifecycleError("prepared qualification artifact is invalid")
        return {
            "source_revision": source,
            "helper_revision": source,
            "controller_image": image,
            "artifact_sha256": artifact,
            "daemon": docker.info(),
        }
    finally:
        docker.remove_controller(name)


def initialize_run(
    docker: Docker, *, image: str, request: bytes, run_id: str, config: Path
) -> None:
    """Copy only newly configured private inputs; no previous workspace data."""
    name = "ldp-m311-delivery-" + uuid.uuid4().hex
    docker.command(
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        OWNER + "=true",
        "--network",
        "host",
        "--mount",
        f"type=volume,source={EVIDENCE_VOLUME},target=/evidence",
        "--mount",
        f"type=volume,source={CONFIG_VOLUME},target=/configuration",
        "--mount",
        f"type=volume,source={CLEANUP_VOLUME},target=/cleanup",
        "--workdir",
        "/opt/qualification-tools",
        image,
        "sleep",
        "infinity",
    )
    try:
        program = """
import os, sys
from pathlib import Path
os.umask(0o077)
root = Path('/evidence/runs')
root.mkdir(mode=0o700, exist_ok=True)
directory = root / sys.argv[1]
directory.mkdir(mode=0o700)
with (directory / 'request.json').open('xb') as stream:
    stream.write(sys.stdin.buffer.read())
    stream.flush()
    os.fsync(stream.fileno())
"""
        docker.command(
            "exec", "--interactive", name, "python3", "-c", program, run_id, stdin=request
        )
        docker.command("cp", str(config), name + ":/configuration/controller.json")
        # Extract the strict cleanup-only subset inside the private daemon volume.
        program = """
import json, os
from pathlib import Path
os.umask(0o077)
for name in ('/configuration', '/cleanup'):
    Path(name).chmod(0o700)
config = Path('/configuration/controller.json')
config.chmod(0o600)
value = json.loads(config.read_bytes())
selected = {'format':'lowerduckpond-m3-11-cleanup-config-v1',
    **{key:value[key] for key in ('targets','journal_vault','cleanup')}}
Path('/cleanup/cleanup.json').write_text(json.dumps(selected,sort_keys=True,separators=(',',':'))+'\\n')
Path('/cleanup/cleanup.json').chmod(0o600)
"""
        docker.command("exec", name, "python3", "-c", program)
    finally:
        docker.remove_controller(name)


def launch(docker: Docker, *, source: str, image: str, run_id: str, daemon_socket: str) -> None:
    if not daemon_socket.startswith("/") or "," in daemon_socket:
        raise LifecycleError("daemon-side socket path is invalid")
    common = [
        "--detach",
        "--restart",
        "unless-stopped",
        "--network",
        "host",
        "--label",
        OWNER + "=true",
        "--mount",
        f"type=volume,source={helper_volume(source)},target=/opt/lifecycle,readonly",
        "--mount",
        f"type=bind,source={daemon_socket},target={SOCKET}",
    ]
    watchdog = "ldp-m311-watchdog-" + revision(source)[:12]
    names = (
        docker.command(
            "ps", "--all", "--filter", "name=^/" + watchdog + "$", "--format", "{{.Names}}"
        )
        .decode()
        .splitlines()
    )
    if names:
        value = docker.owned(watchdog)
        if value.get("Image") != image:
            raise LifecycleError("existing credential watchdog uses another trusted image")
        docker.command("start", watchdog)
    else:
        docker.command(
            "run",
            *common,
            "--name",
            watchdog,
            "--mount",
            f"type=volume,source={CLEANUP_VOLUME},target=/cleanup,readonly",
            "--mount",
            f"type=volume,source={EVIDENCE_VOLUME},target=/evidence",
            image,
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
        )
    docker.command(
        "run",
        *common,
        "--name",
        controller_name(run_id),
        "--label",
        OWNER + ".source=" + source,
        "--mount",
        f"type=volume,source={source_volume(source)},target=/work/source",
        "--mount",
        f"type=volume,source={EVIDENCE_VOLUME},target=/evidence",
        "--mount",
        f"type=volume,source={CONFIG_VOLUME},target=/configuration,readonly",
        "--mount",
        f"type=volume,source={LEASE_VOLUME},target=/root/.local/share/lowerduckpond.net/storage-leases",
        image,
        "uv",
        "run",
        "--no-sync",
        "--frozen",
        "python",
        "-m",
        "scripts.m3_11_unattended.worker",
        "--config",
        "/configuration/controller.json",
        "--directory",
        "/evidence/runs/" + run_id,
        "--source",
        "/work/source",
    )
