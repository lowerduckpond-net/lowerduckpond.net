"""Independent cleanup cache ownership, private delivery and interruption bounds."""

from __future__ import annotations

import io
import json
import os
import tarfile
from typing import cast, override

import pytest

from scripts.m3_11_unattended.connect_host import (
    INITIALIZER_IMAGE,
    OWNER,
    ConnectHost,
    independent_server,
)
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.model import LifecycleError

CANARY = "independent-master-CANARY-not-a-real-credential"


class DockerDouble:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, object]] = {}
        self.calls: list[tuple[str, ...]] = []
        self.pipes: list[bytes] = []
        self.lose_creation = ""
        self.port = "127.0.0.1:12345"
        self.inventory_failure = False

    def command(self, *args: str, stdin: bytes | None = None, timeout: int = 0) -> bytes:
        self.calls.append(args)
        assert 0 < timeout <= 120  # noqa: PLR2004 - per-command wall-clock bound
        assert CANARY not in repr(args)
        if stdin:
            self.pipes.append(stdin)
        if args[0] == "port":
            return self.port.encode()
        if args[0] in {"pull", "start", "cp"}:
            return b""
        kind, operation = args[:2]
        if operation == "create":
            name = args[args.index("--name") + 1] if kind == "container" else args[-1]
            label = args[args.index("--label") + 1].split("=", 1)
            row: dict[str, object] = {"Labels": dict([label]), "State": {"ExitCode": 0}}
            if kind == "container":
                row["Config"] = {"Labels": row.pop("Labels")}
            self.objects[kind, name] = row
            if name.endswith(self.lose_creation) and self.lose_creation:
                raise LifecycleError("lost Docker creation response")
            return name.encode()
        if operation == "inspect":
            return json.dumps([self.objects[kind, args[-1]]]).encode()
        if operation == "ls":
            if self.inventory_failure:
                raise LifecycleError("Docker inventory unavailable")
            return "\n".join(name for selected, name in self.objects if selected == kind).encode()
        if operation == "rm":
            del self.objects[kind, args[-1]]
            return b""
        raise AssertionError("unexpected Docker call")


def test_ephemeral_server_delivers_master_only_by_private_pipe_and_exposes_only_loopback() -> None:
    docker = DockerDouble()
    with independent_server(cast(Docker, docker), {"master": CANARY}) as url:
        assert url == "http://127.0.0.1:12345"
        assert len(docker.objects) == 6  # noqa: PLR2004 - network, two volumes, three containers
        with tarfile.open(fileobj=io.BytesIO(docker.pipes[0])) as archive:
            members = archive.getmembers()
            assert len(members) == 1
            member = members[0]
            assert (member.name, member.mode, member.uid, member.gid) == (
                "1password-credentials.json",
                0o400,
                999,
                999,
            )
            stream = archive.extractfile(member)
            assert stream is not None and json.load(stream) == {"master": CANARY}
        services = [args for args in docker.calls if "--cap-drop" in args]
        assert len(services) == 2  # noqa: PLR2004 - API and sync
        assert all("/var/run/docker.sock" not in repr(args) for args in services)
        assert all("no-new-privileges:true" in args and "999:999" in args for args in services)
        assert sum("--publish" in args for args in services) == 1
        assert any("127.0.0.1::8080" in args for args in services)
    assert not docker.objects


@pytest.mark.parametrize(
    "stage", ["-network", "-data", "-credentials", "-initialize", "-api", "-sync"]
)
def test_partial_or_lost_docker_creation_response_cleans_exact_owned_resources(stage: str) -> None:
    docker = DockerDouble()
    docker.lose_creation = stage
    with (
        pytest.raises(LifecycleError, match="lost"),
        independent_server(cast(Docker, docker), {"master": CANARY}),
    ):
        pytest.fail("lost creation must prevent use")
    assert not docker.objects


@pytest.mark.parametrize("port", ["0.0.0.0:8080", "[::]:8080", "127.0.0.1:8080\n0.0.0.0:8080"])
def test_external_or_ambiguous_api_binding_is_rejected_and_removed(port: str) -> None:
    docker = DockerDouble()
    docker.port = port
    with (
        pytest.raises(LifecycleError, match="loopback"),
        independent_server(cast(Docker, docker), {"master": CANARY}),
    ):
        pytest.fail("non-loopback API must not be used")
    assert not docker.objects


def test_interruption_removes_only_this_workers_connect_resources() -> None:
    docker = DockerDouble()
    unrelated = {"Labels": {OWNER: "another-execution"}}
    docker.objects["volume", "qualification-failed-evidence"] = unrelated
    with (
        pytest.raises(KeyboardInterrupt),
        independent_server(cast(Docker, docker), {"master": CANARY}),
    ):
        raise KeyboardInterrupt()
    assert docker.objects == {("volume", "qualification-failed-evidence"): unrelated}


@pytest.mark.parametrize("fault", ["inventory", "owner"])
def test_resource_cleanup_failure_remains_unresolved(fault: str) -> None:
    docker = DockerDouble()
    host = ConnectHost(cast(Docker, docker))
    host.start({"master": CANARY})
    if fault == "inventory":
        docker.inventory_failure = True
    else:
        docker.objects["volume", host.prefix + "-data"]["Labels"] = {OWNER: "not-this-execution"}
    with pytest.raises(LifecycleError, match="cleanup remains unresolved"):
        host.close()
    assert docker.objects


@pytest.mark.skipif(
    os.environ.get("M3_11_TEST_DOCKER") != "1", reason="explicit disposable Docker-host check"
)
def test_actual_daemon_private_volume_ownership_and_fresh_client_cleanup() -> None:
    class OfflineDocker(Docker):
        @override
        def command(
            self, *arguments: str, stdin: bytes | None = None, timeout: int = 1200
        ) -> bytes:
            if arguments[:2] == ("container", "create") and "--cap-drop" in arguments:
                # Use the pinned initialization image and real mounts/namespaces;
                # no Connect master credential or provider authentication is needed.
                arguments = (
                    *arguments[:-1],
                    "--entrypoint",
                    "/bin/sh",
                    INITIALIZER_IMAGE,
                    "-c",
                    "sleep 300",
                )
            return super().command(*arguments, stdin=stdin, timeout=timeout)

    docker = OfflineDocker()
    host = ConnectHost(docker)
    try:
        assert host.start({"master": CANARY}).startswith("http://127.0.0.1:")
        api = host.prefix + "-api"
        assert (
            docker.command(
                "exec", api, "stat", "-c", "%a:%u:%g", "/private/1password-credentials.json"
            ).strip()
            == b"400:999:999"
        )
        assert json.loads(
            docker.command("exec", api, "cat", "/private/1password-credentials.json")
        ) == {"master": CANARY}
        # Dropping the original Docker client does not stop detached services.
        host.docker = Docker()
        state = host.owned("container", api)["State"]
        assert isinstance(state, dict) and state["Running"] is True
    finally:
        host.close()
    for kind, name in host.resources:
        listed = host.command(
            kind, "ls", "--format", "{{.Names}}" if kind == "container" else "{{.Name}}"
        )
        assert name not in listed.decode().splitlines()
