from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from scripts import qualification_case as case
from scripts import qualification_group_case as groups
from scripts import qualification_local as local
from scripts import qualification_retirement as retirement
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, HOST_ENV, run_lease

HOST_ID = "a" * 64
ARCHIVE_ID = "b" * 64
CREATE_FAILURE = 17


@dataclass
class DockerFixture:
    directory: Path
    present: dict[str, str] = field(
        default_factory=lambda: {HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID}
    )
    states: dict[str, dict[str, object]] = field(default_factory=dict)
    commands: list[list[str]] = field(default_factory=list)
    local_reads: int = 0
    remote_reads: int = 0

    def execute(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[1:4] == ["rm", "--force", "--volumes"]
        self.commands.append(command)
        key = next(key for key, identity in self.present.items() if identity == command[-1])
        del self.present[key]
        return subprocess.CompletedProcess(command, 0)

    def local(self, environment: dict[str, str], identity: str) -> str:
        assert self.states[identity]["running"], "retirement must not execute a stopped host"
        self.local_reads += 1
        return "quiescent-installed"

    def remote(self, environment: dict[str, str], identity: str) -> None:
        assert self.states[identity]["running"], "retirement must not execute stopped storage"
        self.remote_reads += 1


@pytest.fixture
def docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DockerFixture:
    monkeypatch.setattr(retirement, "remove_owned_image", lambda environment: None)
    monkeypatch.setenv("DOCKER_HOST", "unix:///owned/docker.sock")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")
    environment = local.create_environment(tmp_path)
    Path(environment[ARTIFACT_ENV]).write_bytes(b"retained fixture artifact")
    with run_lease(tmp_path, create=True):
        pass
    value = DockerFixture(tmp_path)
    (tmp_path / "case-containers.json").write_text(json.dumps(value.present))
    (tmp_path / "failure.json").write_bytes(b"original failure\n")
    value.states = {
        identity: {
            "started_at": "2026-09-19T00:00:00Z",
            "restarts": 0,
            "running": True,
            "status": "running",
        }
        for identity in value.present.values()
    }
    monkeypatch.setattr(retirement, "owned_containers", lambda *args, **kwargs: dict(value.present))
    monkeypatch.setattr(
        retirement, "snapshot", lambda environment, identity: dict(value.states[identity])
    )
    monkeypatch.setattr(retirement, "local_proof", value.local)
    monkeypatch.setattr(retirement, "independent_storage_absence", value.remote)
    monkeypatch.setattr(subprocess, "run", value.execute)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")
    return value


def test_image_cleanup_failure_can_resume_after_container_removal(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(environment: dict[str, str]) -> None:
        assert not docker.present
        raise ValueError("image still in use")

    monkeypatch.setattr(retirement, "remove_owned_image", unavailable)
    with pytest.raises(ValueError, match="image still in use"):
        retirement.retire(docker.directory)
    assert not docker.present
    assert not (docker.directory / "retirement.json").exists()
    reads = docker.local_reads
    removed: list[dict[str, str]] = []
    monkeypatch.setattr(retirement, "remove_owned_image", removed.append)
    retirement.retire(docker.directory)
    assert len(removed) == 1
    assert docker.local_reads == reads
    assert (docker.directory / "failure.json").read_bytes() == b"original failure\n"


@pytest.mark.parametrize("identity", [HOST_ID, ARCHIVE_ID])
@pytest.mark.parametrize("failure", ["before", "stopped", "removed", "timeout"])
def test_removal_retries_after_docker_errors_without_restarting_services(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch, identity: str, failure: str
) -> None:
    failed = False

    def interrupt(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal failed
        if command[-1] == identity and not failed:
            failed = True
            if failure in {"stopped", "timeout"}:
                docker.states[identity].update(running=False, status="exited")
            elif failure == "removed":
                docker.execute(command)
            if failure == "timeout":
                raise subprocess.TimeoutExpired(command, 40)
            raise subprocess.CalledProcessError(1, command)
        return docker.execute(command)

    monkeypatch.setattr(subprocess, "run", interrupt)
    with pytest.raises(subprocess.SubprocessError):
        retirement.retire(docker.directory)
    assert not (docker.directory / "retirement.json").exists()
    reads = docker.local_reads
    destination = retirement.retire(docker.directory)
    assert not docker.present
    assert json.loads(destination.read_text())["outcome"] == "retired"
    assert (docker.directory / "failure.json").read_bytes() == b"original failure\n"
    if identity == ARCHIVE_ID or failure != "before":
        assert docker.local_reads == reads
    else:
        assert docker.local_reads > reads  # Still-running hosts require new proof.
    assert all(command[1:4] == ["rm", "--force", "--volumes"] for command in docker.commands)
    # The acknowledged transaction is also idempotent after both IDs are gone.
    retirement.retire(docker.directory)


@pytest.mark.parametrize("identity", [HOST_ID, ARCHIVE_ID])
def test_a_stopped_restarted_container_cannot_reuse_removal_authorization(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch, identity: str
) -> None:
    def interrupt(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[-1] == identity:
            docker.states[identity].update(running=False, status="exited")
            raise subprocess.CalledProcessError(1, command)
        return docker.execute(command)

    monkeypatch.setattr(subprocess, "run", interrupt)
    with pytest.raises(subprocess.CalledProcessError):
        retirement.retire(docker.directory)
    docker.states[identity].update(started_at="2026-09-19T01:00:00Z", restarts=1)
    monkeypatch.setattr(subprocess, "run", docker.execute)
    with pytest.raises(ValueError, match="restarted"):
        retirement.retire(docker.directory)
    assert identity in docker.present.values()
    assert not (docker.directory / "retirement.json").exists()


@pytest.mark.parametrize("retained", [[], [HOST_ENV], [ARCHIVE_ENV], [HOST_ENV, ARCHIVE_ENV]])
@pytest.mark.parametrize("started", [False, True])
def test_failed_creation_retires_only_its_proven_empty_partial_fixture(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch, retained: list[str], started: bool
) -> None:
    docker.present = {key: identity for key, identity in docker.present.items() if key in retained}
    (docker.directory / "case-containers.json").write_text(json.dumps(docker.present))
    (docker.directory / "case-create.json").write_text('{"exit_status":17}')
    monkeypatch.setattr(retirement, "local_proof", lambda *args: "empty-before-installation")
    if not started:
        for state in docker.states.values():
            state.update(started_at="0001-01-01T00:00:00Z", running=False, status="created")
    retirement.retire(docker.directory)
    assert {command[-1] for command in docker.commands} == {
        identity
        for key, identity in ((HOST_ENV, HOST_ID), (ARCHIVE_ENV, ARCHIVE_ID))
        if key in retained
    }
    assert not docker.present


def test_missing_ids_without_a_removal_transaction_are_not_adopted(docker: DockerFixture) -> None:
    del docker.present[HOST_ENV]
    with pytest.raises(ValueError, match="identities"):
        retirement.retire(docker.directory)
    assert not docker.commands


def test_no_removal_precedes_durable_authorization(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*args: object) -> None:
        raise OSError("controller storage unavailable")

    monkeypatch.setattr(retirement, "private_document", unavailable)
    with pytest.raises(OSError):
        retirement.retire(docker.directory)
    assert not docker.commands


@pytest.mark.parametrize("retained", [[], [HOST_ENV], [ARCHIVE_ENV], [HOST_ENV, ARCHIVE_ENV]])
def test_create_failure_records_partial_ids_and_preserves_original_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retained: list[str]
) -> None:
    identities = {
        key: identity
        for key, identity in ((HOST_ENV, HOST_ID), (ARCHIVE_ENV, ARCHIVE_ID))
        if key in retained
    }
    calls = []

    def phase(*args: object) -> int:
        calls.append(args[-1])
        return CREATE_FAILURE

    monkeypatch.setattr(groups, "phase", phase)
    monkeypatch.setattr(case, "owned_containers", lambda *args, **kwargs: identities)
    assert groups.run_group(tmp_path, {}, "uv", "core") == CREATE_FAILURE
    assert calls == ["create"]
    assert json.loads((tmp_path / "case-containers.json").read_text()) == identities
    assert json.loads((tmp_path / "case-create.json").read_text()) == {"exit_status": 17}
    assert not (tmp_path / "case.json").exists()


def test_failed_ownership_collection_does_not_mask_create_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(groups, "phase", lambda *args: CREATE_FAILURE)

    def unavailable(*args: object, **kwargs: object) -> dict[str, str]:
        raise ValueError("Docker unavailable")

    monkeypatch.setattr(case, "owned_containers", unavailable)
    assert groups.run_group(tmp_path, {}, "uv", "core") == CREATE_FAILURE
    assert not (tmp_path / "case-containers.json").exists()


@pytest.mark.parametrize("phase", ["host", "archive", "receipt"])
def test_interrupted_receipt_write_can_resume_without_replacing_failure_evidence(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    original = case.private_document
    failed = False

    def write(directory: Path, name: str, value: object) -> None:
        nonlocal failed
        assert isinstance(value, dict)
        chosen = (
            name == "retirement.json"
            if phase == "receipt"
            else (name == "retirement-removal.json" and value["phase"] == phase)
        )
        if chosen and not failed:
            failed = True
            raise OSError("interrupted receipt write")
        original(directory, name, value)

    monkeypatch.setattr(retirement, "private_document", write)
    with pytest.raises(OSError):
        retirement.retire(docker.directory)
    retirement.retire(docker.directory)
    assert not docker.present
    assert (docker.directory / "failure.json").read_bytes() == b"original failure\n"


@pytest.mark.parametrize("change", ["replacement", "artifact", "unexpected-storage-loss"])
def test_changed_authority_blocks_removal_continuation(
    docker: DockerFixture, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    def interrupted(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(subprocess, "run", interrupted)
    with pytest.raises(subprocess.CalledProcessError):
        retirement.retire(docker.directory)
    if change == "replacement":
        docker.present[HOST_ENV] = "c" * 64
    elif change == "artifact":
        (docker.directory / "fixture/static-host-agent.tar").write_bytes(b"different artifact")
    else:
        del docker.present[ARCHIVE_ENV]
    monkeypatch.setattr(subprocess, "run", docker.execute)
    with pytest.raises(ValueError):
        retirement.retire(docker.directory)
    assert not docker.commands
    assert not (docker.directory / "retirement.json").exists()
