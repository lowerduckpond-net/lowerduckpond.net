"""Ephemeral independent Connect cache, owned by one protected cleanup execution."""

from __future__ import annotations

import io
import json
import re
import tarfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.model import LifecycleError

API_IMAGE = (
    "1password/connect-api:1.8.2@"
    "sha256:e915c0c843972f02b0e7e2de502bda8bd4a092288b3f1866098a857bd715a281"
)
SYNC_IMAGE = (
    "1password/connect-sync:1.8.2@"
    "sha256:6297ca6136c0f0fb096bc64c49e1bc8df2aab35282ebff8c7bb60745ef176d0d"
)
# Reuse the committed qualification base for volume initialization. Connect's
# distroless images deliberately have no shell or ownership utilities.
INITIALIZER_IMAGE = (
    "ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e"
)
OWNER = "lowerduckpond.m3-11.independent-connect"
COMMAND_SECONDS = 120


def credential_archive(credentials: dict[str, object]) -> bytes:
    """The master credential crosses only a private pipe into its owned volume."""
    content = canonical_bytes(credentials)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as stream:
        item = tarfile.TarInfo("1password-credentials.json")
        item.size, item.mode, item.uid, item.gid = len(content), 0o400, 999, 999
        stream.addfile(item, io.BytesIO(content))
    return archive.getvalue()


class ConnectHost:
    def __init__(self, docker: Docker) -> None:
        self.docker = docker
        self.identity = uuid.uuid4().hex
        self.prefix = "ldp-m311-connect-" + self.identity
        self.resources: list[tuple[str, str]] = []

    def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
        return self.docker.command(*arguments, stdin=stdin, timeout=COMMAND_SECONDS)

    def owned(self, kind: str, name: str) -> dict[str, object]:
        value = json.loads(self.command(kind, "inspect", name))
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise LifecycleError("independent Connect resource identity is unavailable")
        row = value[0]
        configuration = row.get("Config")
        labels = (
            configuration.get("Labels")
            if kind == "container" and isinstance(configuration, dict)
            else row.get("Labels")
        )
        if not isinstance(labels, dict) or labels.get(OWNER) != self.identity:
            raise LifecycleError("independent Connect resource ownership differs")
        return row

    def _create(self, kind: str, role: str, *arguments: str) -> str:
        name = self.prefix + "-" + role
        # Retain the exact name/nonce before Docker can lose a creation reply.
        self.resources.append((kind, name))
        command = [kind, "create", "--label", OWNER + "=" + self.identity]
        command.extend(["--name", name, *arguments] if kind == "container" else [*arguments, name])
        self.command(*command)
        self.owned(kind, name)
        return name

    def start(self, credentials: dict[str, object]) -> str:
        for image in (API_IMAGE, SYNC_IMAGE, INITIALIZER_IMAGE):
            self.command("pull", image)
        network = self._create("network", "network")
        data = self._create("volume", "data")
        private = self._create("volume", "credentials")
        initializer = self._create(
            "container",
            "initialize",
            "--network",
            "none",
            "--user",
            "0:0",
            "--mount",
            "type=volume,src=" + private + ",dst=/private",
            "--mount",
            "type=volume,src=" + data + ",dst=/data",
            "--entrypoint",
            "/bin/sh",
            INITIALIZER_IMAGE,
            "-c",
            "chown 999:999 /data /private/1password-credentials.json"
            " && chmod 700 /data && chmod 400 /private/1password-credentials.json",
        )
        self.command(
            "cp",
            "--archive",
            "-",
            initializer + ":/private/",
            stdin=credential_archive(credentials),
        )
        self.command("start", "--attach", initializer)
        state = self.owned("container", initializer).get("State")
        if not isinstance(state, dict) or state.get("ExitCode") != 0:
            raise LifecycleError("independent Connect private volume initialization failed")
        api = ""
        for role, image, peer in (("api", API_IMAGE, "sync"), ("sync", SYNC_IMAGE, "api")):
            arguments = [
                "--network",
                network,
                "--network-alias",
                role,
                "--user",
                "999:999",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",  # noqa: S108 - private container tmpfs
                "--mount",
                "type=volume,src=" + private + ",dst=/private,readonly",
                "--mount",
                "type=volume,src=" + data + ",dst=/home/opuser/.op/data",
                "--env",
                "OP_SESSION=/private/1password-credentials.json",
                "--env",
                "OP_LOG_LEVEL=error",
                "--env",
                "OP_BUS_PORT=11223",
                "--env",
                "OP_BUS_PEERS=" + peer + ":11223",
                "--env",
                "OP_HTTP_PORT=8080",
            ]
            if role == "api":
                arguments += ["--publish", "127.0.0.1::8080"]
            name = self._create("container", role, *arguments, image)
            self.command("start", name)
            if role == "api":
                api = name
        port = self.command("port", api, "8080/tcp").decode().strip()
        if re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", port) is None:
            raise LifecycleError("independent Connect API is not bound solely to loopback")
        return "http://" + port

    def close(self) -> None:
        failed = False
        for kind, name in reversed(self.resources):
            try:
                # A failed create may have created nothing. Inspect the exact
                # kind inventory; a failed list never means absence.
                output = (
                    self.command("container", "ls", "--all", "--format", "{{.Names}}")
                    if kind == "container"
                    else self.command(kind, "ls", "--format", "{{.Name}}")
                )
                if name not in output.decode().splitlines():
                    continue
                self.owned(kind, name)
                self.command(kind, "rm", *(["--force"] if kind == "container" else []), name)
            except LifecycleError, OSError, ValueError:
                failed = True
        if failed:
            raise LifecycleError("independent Connect resource cleanup remains unresolved")


@contextmanager
def independent_server(docker: Docker, credentials: dict[str, object]) -> Iterator[str]:
    host = ConnectHost(docker)
    try:
        yield host.start(credentials)
    finally:
        host.close()
