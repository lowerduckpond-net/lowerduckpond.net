"""Verify retained consumers through the actual local quiescence entry point."""

from __future__ import annotations

import json
import uuid
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from typing import override

import pytest

from scripts import m3_11_debug_fixture as debug_fixture
from scripts import qualification_restore
from scripts.m3_11_debug_files import MARKER
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.docker import SOCKET, Docker
from scripts.m3_11_unattended.model import LifecycleError, digest
from scripts.m3_11_unattended.state import LeaseState, RunState, replace_private
from scripts.m3_11_unattended.watchdog import quiesce_runtime, require_released_consumers
from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV

from .test_m3_11_lease_inventory import manifest

DAEMON = dict.fromkeys(("ID", "Name", "DockerRootDir", "ServerVersion"), "synthetic-daemon")


class RuntimeDocker(Docker):
    def __init__(self, rows: dict[str, dict[str, object]]) -> None:
        self.endpoint = "unix://" + SOCKET
        self.rows = deepcopy(rows)
        self.mutations: list[tuple[str, ...]] = []
        self.wrong_daemon = False
        self.empty_inventory = False
        self.failed_stop = False
        self.lingering = False

    @override
    def info(self) -> dict[str, str]:
        return {**DAEMON, "ID": "other"} if self.wrong_daemon else DAEMON

    @override
    def command(self, *arguments: str, stdin: bytes | None = None, timeout: int = 1200) -> bytes:
        assert stdin is None
        if arguments[0] == "ps":
            return ("\n".join([] if self.empty_inventory else self.rows) + "\n").encode()
        selected = arguments[-1]
        row = self.rows[selected]
        if arguments[0] == "inspect":
            return json.dumps([row]).encode()
        self.mutations.append(arguments)
        if arguments[0] == "update":
            row["HostConfig"] = {"RestartPolicy": {"Name": "no"}}
        elif arguments[0] == "stop":
            if self.failed_stop:
                raise LifecycleError("synthetic lost stop reply")
            row["State"] = {"Running": self.lingering}
        else:
            pytest.fail("unexpected operation")
        return b""


def runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, LeaseState, RuntimeDocker]:
    selected = manifest()
    run_id, owner = str(uuid.uuid7()), uuid.uuid7().hex
    root = tmp_path / "evidence"
    directory = root / "runs" / run_id
    directory.mkdir(parents=True, mode=0o700)
    binding: dict[str, object] = {
        "managed_run_id": run_id,
        "source_revision": "e" * 40,
        "helper_revision": "f" * 40,
        "artifact_sha256": "a" * 64,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": selected.targets.storage_digest,
    }
    write_private(
        directory / "request.json",
        {"binding": binding, "lease_id": selected.lease_id, "daemon": DAEMON},
    )
    state = LeaseState(root / "leases" / selected.lease_id)
    state.initialize(selected)
    with state.use_lock():
        state.acquire_use(attempt_id=run_id, binding_sha256=digest(binding), kind="attempt")
    run = RunState(directory)
    run.begin(binding)
    run.finish_journey("failed", 1)
    write_private(
        directory / "host-drained.json", {"binding_sha256": digest(binding), "drained": True}
    )
    fixture = directory / "qualification" / "synthetic-fixture"
    (fixture / "restore").mkdir(parents=True, mode=0o700)
    write_private(fixture / "fixture.json", {"format": "synthetic"})
    environment = {
        "DOCKER_HOST": "unix://" + SOCKET,
        RUN_ENV: owner,
        HOST_ENV: f"ldp-m3-{owner}-host",
        ARCHIVE_ENV: f"ldp-m3-{owner}-archive",
    }
    monkeypatch.setattr(qualification_restore, "environment_for", lambda _path: environment)
    rows: dict[str, dict[str, object]] = {}
    ids = {
        kind: str(index) * 64
        for index, kind in enumerate(("host", "archive", "destination", "acme"), 1)
    }
    for kind, selected_id in ids.items():
        row: dict[str, object] = {
            "Id": selected_id,
            "Name": f"/ldp-m3-{owner}-{kind}",
            "Image": "sha256:" + "9" * 64,
            "Config": {"Labels": {"lowerduckpond.qualification.run": owner}},
            "State": {"Running": True},
            "HostConfig": {"RestartPolicy": {"Name": "always"}},
        }
        rows[selected_id] = row
        if kind != "archive":
            write_private(
                fixture / "restore" / (("source" if kind == "host" else kind) + ".json"),
                {"id": selected_id, "name": row["Name"], "image": row["Image"], "owner": owner},
            )
    write_private(
        fixture / "case-containers.json", {HOST_ENV: ids["host"], ARCHIVE_ENV: ids["archive"]}
    )
    return directory, state, RuntimeDocker(rows)


@pytest.mark.parametrize(
    "fault", ["wrong_daemon", "empty_inventory", "wrong_endpoint", "replaced", "missing_receipt"]
)
def test_quiescence_rejects_wrong_or_missing_original_identity_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    directory, state, docker = runtime(tmp_path, monkeypatch)
    if fault == "wrong_endpoint":
        docker.endpoint = "unix:///another.sock"
    elif fault == "replaced":
        docker.rows["1" * 64]["Image"] = "sha256:" + "0" * 64
    elif fault == "missing_receipt":
        (directory / "qualification/synthetic-fixture/restore/acme.json").unlink()
    else:
        setattr(docker, fault, True)
    with pytest.raises((LifecycleError, ValueError, OSError)):
        quiesce_runtime(directory, docker)
    assert docker.mutations == []
    assert not list(state.directory.glob("released-*.json"))


@pytest.mark.parametrize("fault", ["failed_stop", "lingering"])
def test_interrupted_quiescence_retains_ownership_until_exact_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    directory, state, docker = runtime(tmp_path, monkeypatch)
    setattr(docker, fault, True)
    with pytest.raises(LifecycleError):
        quiesce_runtime(directory, docker)
    with state.use_lock(), pytest.raises(LifecycleError, match="quiescence"):
        state.acquire_use(attempt_id=str(uuid.uuid7()), binding_sha256="a" * 64, kind="attempt")
    assert not list(state.directory.glob("released-*.json"))
    setattr(docker, fault, False)
    proof = quiesce_runtime(directory, docker)
    assert proof["complete"] is True
    containers = proof["containers"]
    assert isinstance(containers, list) and len(containers) == len(docker.rows)
    released = read_private(next(state.directory.glob("released-*.json")))
    assert released["quiescence"] == proof
    assert set(docker.rows) == {str(index) * 64 for index in range(1, 5)}
    assert all(command[0] in {"update", "stop"} for command in docker.mutations)
    with state.use_lock():
        state.acquire_use(attempt_id=str(uuid.uuid7()), binding_sha256="b" * 64, kind="attempt")


@pytest.mark.parametrize("fault", ["running", "restart", "image", "extra", "daemon", "none"])
def test_reuse_freshly_checks_released_containers_without_mutating_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:

    directory, state, docker = runtime(tmp_path, monkeypatch)
    quiesce_runtime(directory, docker)
    before = list(docker.mutations)
    if fault == "running":
        docker.rows["1" * 64]["State"] = {"Running": True}
    elif fault == "restart":
        docker.rows["1" * 64]["HostConfig"] = {"RestartPolicy": {"Name": "always"}}
    elif fault == "image":
        docker.rows["1" * 64]["Image"] = "sha256:" + "8" * 64
    elif fault == "extra":
        docker.rows["5" * 64] = deepcopy(docker.rows["1" * 64])
    elif fault == "daemon":
        docker.wrong_daemon = True
    with state.use_lock():
        if fault == "none":
            require_released_consumers(state, docker)
            state.acquire_use(attempt_id=str(uuid.uuid7()), binding_sha256="c" * 64, kind="attempt")
        else:
            with pytest.raises(LifecycleError):
                require_released_consumers(state, docker)
    assert docker.mutations == before
    assert (directory / "journey-result.json").exists()


def test_diagnostic_holds_exclusive_use_and_cannot_rejoin_after_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, state, docker = runtime(tmp_path, monkeypatch)
    request = read_private(directory / "request.json")
    request["format"] = "lowerduckpond-m3-11-unattended-request-v2"
    replace_private(directory / "request.json", request)
    workspace = tmp_path / "diagnostic"
    workspace.mkdir(mode=0o700)
    write_private(
        workspace / MARKER, {"original_run": str(directory / "qualification/synthetic-fixture")}
    )
    with ExitStack() as session:
        monkeypatch.setattr(debug_fixture, "_LEASE_SESSION", session)
        debug_fixture.lease_use(workspace)
        with pytest.raises(LifecycleError, match="already owned"), state.use_lock():
            pytest.fail("diagnostic allowed simultaneous reuse")
    quiesce_runtime(directory, docker)
    with pytest.raises(ValueError, match="exclusive lease use"):
        debug_fixture.lease_use(workspace)
