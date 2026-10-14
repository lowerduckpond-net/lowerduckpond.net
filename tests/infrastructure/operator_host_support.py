"""Separate synthetic daemon filesystem behind the actual Docker/SSH command boundary."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import connect_activate, connect_delivery, connect_host, evidence
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import OWNER, SOCKET
from scripts.m3_11_unattended.model import LifecycleError, digest

from .operator_flow_support import ARTIFACT, DAEMON, SOURCE, Services

IMAGE = "sha256:" + "b" * 64


class Host:
    def __init__(self, root: Path, services: Services, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root, self.services = root, services
        self.evidence = root / "evidence"
        self.spool = root / "cleanup" / "legacy-import"
        self.spool.parent.mkdir(parents=True, mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.rows: dict[str, dict[str, object]] = {}
        self.volumes: set[str] = set()
        self.calls: list[tuple[str, ...]] = []
        self.utility_calls: list[dict[str, object]] = []
        self.launched: list[str] = []
        self.connect_resources: dict[tuple[str, str], dict[str, object]] = {}
        self.depth = 0
        self.isolated = False
        self.delivered: dict[str, bytes] = {}
        services.docker_handler = self.command
        services.transport_handler = self.transport
        monkeypatch.setenv("DOCKER_HOST", "unix://" + SOCKET)
        monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
        original_stat, original_lstat, original_open = Path.stat, Path.lstat, os.open

        def hidden(path: object) -> bool:
            return (
                self.isolated
                and not self.depth
                and isinstance(path, (str, Path))
                and Path(path).is_relative_to(self.root)
            )

        def stat_path(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
            if hidden(path):
                raise FileNotFoundError("synthetic host-only filesystem")
            return original_stat(path, follow_symlinks=follow_symlinks)

        def lstat_path(path: Path) -> os.stat_result:
            if hidden(path):
                raise FileNotFoundError("synthetic host-only filesystem")
            return original_lstat(path)

        def open_path(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if hidden(path):
                raise FileNotFoundError("synthetic host-only filesystem")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(Path, "stat", stat_path)
        monkeypatch.setattr(Path, "lstat", lstat_path)
        monkeypatch.setattr(os, "open", open_path)
        original_exists, original_symlink = Path.exists, Path.is_symlink
        monkeypatch.setattr(
            Path,
            "exists",
            lambda path, **kwargs: False if hidden(path) else original_exists(path, **kwargs),
        )
        monkeypatch.setattr(
            Path, "is_symlink", lambda path: False if hidden(path) else original_symlink(path)
        )

    @contextmanager
    def inside(self) -> Iterator[None]:
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1

    def transport(
        self, program: str, arguments: list[str], stdin: bytes | None, _kwargs: dict[str, object]
    ) -> bytes:
        if program == "ssh":
            assert arguments[:5] == ["-T", "-o", "ConnectTimeout=10", "--", "coder@synthetic.test"]
            remote = shlex.split(arguments[-1])
            if remote[: len(connect_delivery.PARENT_DOCKER)] == connect_delivery.PARENT_DOCKER:
                selected = remote[len(connect_delivery.PARENT_DOCKER) :]
                if selected[:2] == ["inspect", "--format"]:
                    return "|".join(
                        json.dumps(value)
                        for value in (
                            "a" * 64,
                            "/synthetic-workspace",
                            True,
                            "11111111-1111-1111-1111-111111111111",
                            "coder-11111111-1111-1111-1111-111111111111-home",
                        )
                    ).encode()
                with self.inside():
                    return self.command(selected, stdin)
            assert "python3" in remote and connect_delivery.RECEIVER in remote and stdin is not None
            path, expected = remote[-2:]
            assert hashlib.sha256(stdin).hexdigest() == expected
            assert LeaseConfiguration.parse(json.loads(stdin)).mode == "controller"
            self.controller = self.root / "home" / Path(path).name
            result = self.services.local_run(
                [sys.executable, "-c", connect_delivery.RECEIVER, str(self.controller), expected],
                input=stdin,
                capture_output=True,
                check=False,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr.decode()
            with self.inside():
                assert self.controller.read_bytes() == stdin
            self.delivered[path] = stdin
            return result.stdout
        if program == "gh":
            if arguments[:2] == ["secret", "set"]:
                assert stdin is not None
                self.delivered[connect_delivery.SECRET_NAME] = stdin
                return b""
            assert arguments[:3] == ["api", "--hostname", "github.com"]
            value = (
                {"branch_policies": [{"name": "main", "type": "branch"}]}
                if arguments[-1].endswith("deployment-branch-policies")
                else {
                    "protection_rules": [{"type": "branch_policy"}],
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                }
            )
            return canonical_bytes(value)
        pytest.fail("unexpected transport " + program)

    def add(self, name: str, *, source: str = SOURCE, running: bool = False) -> dict[str, object]:
        if name in self.rows:
            raise LifecycleError("synthetic occupied container name")
        row: dict[str, object] = {
            "Id": hashlib.sha256(name.encode()).hexdigest(),
            "Name": "/" + name,
            "Image": IMAGE,
            "Config": {"Labels": {OWNER: "true", OWNER + ".source": source}},
            "State": {
                "Running": running,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
                "Status": "running" if running else "exited",
            },
            "HostConfig": {
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "NetworkMode": "host",
            },
            "Mounts": [{"Destination": SOCKET, "Source": SOCKET, "Type": "bind"}],
        }
        self.rows[name] = row
        return row

    def selected(self, identity: str) -> dict[str, object]:
        matches = [row for name, row in self.rows.items() if identity in {name, row["Id"]}]
        if len(matches) != 1:
            raise LifecycleError("synthetic missing or ambiguous container")
        return matches[0]

    def command(self, arguments: list[str], stdin: bytes | None = None) -> bytes:  # noqa: PLR0911, PLR0912, PLR0915 - explicit mocked Docker operations
        self.calls.append(tuple(arguments))
        operation = arguments[0]
        if arguments[:2] == ["container", "ls"] and any(
            arg.startswith("name=^/ldp-m3-") for arg in arguments
        ):
            return self.command(["ps", *arguments[2:]], stdin)
        if operation == "pull":
            assert arguments[1] in {
                connect_host.API_IMAGE,
                connect_host.SYNC_IMAGE,
                connect_host.INITIALIZER_IMAGE,
            }
            return b""
        if operation in {"network", "container", "volume"} and (
            operation != "volume"
            or arguments[1] == "ls"
            or arguments[-1].startswith("ldp-m311-connect-")
        ):
            action, name = arguments[1], arguments[-1]
            if action == "create":
                name = (
                    arguments[arguments.index("--name") + 1] if operation == "container" else name
                )
                label = arguments[arguments.index("--label") + 1].split("=", 1)
                self.connect_resources[operation, name] = {
                    "Name": name,
                    "Config": {"Labels": {label[0]: label[1]}},
                    "Labels": {label[0]: label[1]},
                    "State": {"ExitCode": 0},
                }
                return name.encode()
            if action == "inspect":
                return json.dumps([self.connect_resources[operation, name]]).encode()
            if action == "ls":
                return "".join(
                    name + "\n" for kind, name in self.connect_resources if kind == operation
                ).encode()
            if action == "rm":
                del self.connect_resources[operation, name]
                return b""
        if operation == "port":
            return b"127.0.0.1:12345"
        if operation == "start" and ("container", arguments[-1]) in self.connect_resources:
            return b""
        if operation == "context":
            return ("unix://" + SOCKET).encode()
        if operation == "info":
            return canonical_bytes(DAEMON)
        if operation == "build":
            assert stdin is not None and "--tag" in arguments
            return b""
        if arguments[:2] == ["image", "inspect"]:
            return IMAGE.encode()
        if operation == "volume":
            name = arguments[-1]
            if arguments[1] == "create":
                self.volumes.add(name)
                return name.encode()
            assert name in self.volumes
            return json.dumps([{"Name": name, "Labels": {OWNER: "true"}}]).encode()
        if operation == "inspect":
            row = self.selected(arguments[-1])
            if "--format" in arguments:
                result = {
                    "id": row["Id"],
                    "name": row["Name"],
                    "image": row["Image"],
                    "owner": cast(dict[str, dict[str, str]], row["Config"])["Labels"].get(
                        "lowerduckpond.qualification.run"
                    ),
                    "running": cast(dict[str, object], row["State"])["Running"],
                }
                template = arguments[arguments.index("--format") + 1]
                return canonical_bytes(
                    {key: value for key, value in result.items() if '"' + key + '"' in template}
                )
            return json.dumps([row]).encode()
        if operation == "ps":
            rows = self.rows
            labels = [
                arguments[index + 1][6:].split("=", 1)
                for index, arg in enumerate(arguments[:-1])
                if arg == "--filter" and arguments[index + 1].startswith("label=")
            ]
            for label_key, value in labels:
                rows = {
                    key: row
                    for key, row in rows.items()
                    if cast(dict[str, dict[str, str]], row["Config"])["Labels"].get(label_key)
                    == value
                }
            names = [
                arguments[index + 1][5:]
                for index, arg in enumerate(arguments[:-1])
                if arg == "--filter" and arguments[index + 1].startswith("name=")
            ]
            for name in names:
                rows = {
                    key: row
                    for key, row in rows.items()
                    if re.search(name.removeprefix("^/").removesuffix("$"), key)
                }
            if arguments[-1] == "{{.ID}} {{.Names}}":
                return "".join(
                    str(row["Id"]) + " " + name + "\n" for name, row in rows.items()
                ).encode()
            return "".join(
                str(row["Id"] if arguments[-1] == "{{.ID}}" else key) + "\n"
                for key, row in rows.items()
            ).encode()
        if operation == "create":
            row = self.add(arguments[arguments.index("--name") + 1])
            if "--label" in arguments:
                allocation_label = arguments[arguments.index("--label") + 1]
                if allocation_label.startswith("lowerduckpond.qualification.run="):
                    row["Config"] = {
                        "Labels": {
                            "lowerduckpond.qualification.run": allocation_label.split("=", 1)[1]
                        }
                    }
                    row["Image"] = next(arg for arg in arguments if arg.startswith("sha256:"))
            return str(row["Id"]).encode()
        if operation == "rm":
            row = self.selected(arguments[-1])
            del self.rows[str(row["Name"]).removeprefix("/")]
            return b""
        if operation == "cp":
            if arguments[1:3] == ["--archive", "-"]:
                assert stdin is not None
                return b""
            assert Path(arguments[1]).read_bytes() == b"synthetic-git-bundle"
            return b""
        if operation == "exec":
            if "/bin/bash" in arguments:
                target = self.evidence / "prepared" / SOURCE
                target.mkdir(parents=True, mode=0o700)
                (target / "static-host-agent.tar").write_bytes(ARTIFACT)
                return b""
            if "cat" in arguments:
                return hashlib.sha256(ARTIFACT).hexdigest().encode()
            assert stdin is not None and "python3" in arguments
            value = json.loads(stdin)
            if "binding" in value:
                directory = self.evidence / "runs" / value["binding"]["managed_run_id"]
                directory.mkdir(parents=True, mode=0o700)
                write_private(directory / "request.json", value)
            else:
                config = LeaseConfiguration.parse(value)
                path = self.root / "controller.json"
                path.unlink(missing_ok=True)
                write_private(path, config.document())
            return b""
        if operation == "run" and arguments[-1] == "daemon-utility":
            assert stdin is not None
            envelope = json.loads(stdin)
            assert (
                f"type=volume,source=ldp-m311-helper-{SOURCE},target=/opt/lifecycle,readonly"
                in arguments
            )
            assert "type=volume,source=ldp-m311-evidence,target=/evidence,readonly" in arguments
            assert "--read-only" in arguments and IMAGE in arguments
            assert any("target=/cleanup" in arg for arg in arguments) == (
                envelope["operation"] == "import"
            )
            self.utility_calls.append(envelope)
            with self.inside():
                result = connect_activate.daemon_utility(
                    envelope, evidence_root=self.evidence, import_root=self.spool
                )
            return canonical_bytes(
                {"format": envelope["format"], "input_sha256": digest(envelope), "result": result}
            )
        if operation == "run" and "scripts.m3_11_unattended.evidence" in arguments:
            directory = (
                self.evidence / "runs" / Path(arguments[arguments.index("--directory") + 1]).name
            )
            assert arguments[arguments.index("scripts.m3_11_unattended.evidence") + 1] == "status"
            with self.inside():
                return canonical_bytes(
                    evidence.export(directory, repository=Path.cwd(), include_report=False)
                )
        if operation == "run":
            name = arguments[arguments.index("--name") + 1]
            result = self.add(name, running=True)
            if "scripts.m3_11_unattended.worker" in arguments:
                self.launched.append(str(uuid.UUID(name.removeprefix("ldp-m311-controller-"))))
            return str(result["Id"]).encode()
        if operation in {"start", "stop", "update"}:
            row = self.selected(arguments[-1])
            if operation == "update":
                cast(dict[str, object], row["HostConfig"])["RestartPolicy"] = {
                    "Name": "no",
                    "MaximumRetryCount": 0,
                }
            else:
                cast(dict[str, object], row["State"]).update(
                    Running=operation == "start",
                    Status="running" if operation == "start" else "exited",
                )
            return b""
        pytest.fail("unexpected synthetic Docker command " + repr(arguments))

    def original_files(self) -> dict[str, bytes]:
        return {
            str(path): path.read_bytes()
            for path in self.evidence.glob("runs/**/*")
            if path.is_file()
        }
