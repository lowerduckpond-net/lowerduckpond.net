"""Capture must retain one real Git/storage attempt before any live assertions."""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_m3_archive.report import ArchiveQualificationReport
from lowerduckpond_m3_archive.storage import AcceptanceEvidence

from scripts import m3_11_combined_inputs as inputs
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private
from scripts.production_qualification_inputs import REVOCATIONS, capture_run, git
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV, RESOURCE_ENV, RUN_ENV

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Run:
    directory: Path
    repository: Path
    environment: dict[str, str]


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Run:
    repository = tmp_path / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    git(repository, "config", "user.name", "Combined qualification fixture")
    git(repository, "config", "user.email", "fixture@example.test")
    git(repository, "config", "core.hooksPath", "/dev/null")
    for name in (REVOCATIONS, "platform/versions.yml"):
        path = repository / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    git(repository, "add", ".")
    git(repository, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture inputs")
    source = git(repository, "rev-parse", "HEAD").decode().strip()
    directory = tmp_path / "run"
    directory.mkdir(mode=0o700)
    environment = inputs.allocate(
        directory,
        {
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "SPACES_REGION": "ams3",
            "SPACES_BACKUP_BUCKET": "fixture-backups",
            "SPACES_ARCHIVE_BUCKET": "fixture-archives",
            "SPACES_BACKUP_ACCESS_KEY_ID": "fixture-backup-key",
            "SPACES_BACKUP_SECRET_ACCESS_KEY": "fixture-backup-secret",
            "SPACES_ACCESS_KEY_ID": "fixture-observer-key",
            "SPACES_SECRET_ACCESS_KEY": "fixture-observer-secret",
        },
    )
    for key in ("SPACES_REGION", "SPACES_BACKUP_BUCKET", "SPACES_ARCHIVE_BUCKET"):
        monkeypatch.setenv(key, environment[key])
    (directory / "source-revision").write_text(source + "\n")
    Path(environment[ARTIFACT_ENV]).write_bytes(b"selected fixture artifact")
    capture_run(directory, repository=repository, source=source)
    (directory / "qualification-inputs.json").chmod(0o600)
    ArchiveQualificationReport.create(
        AcceptanceEvidence(True, True, True, True, True, True, True), source_revision=source
    ).write(directory / "storage.json")
    monkeypatch.setattr(
        owned,
        "inspect",
        Mock(
            return_value={
                "id": "1" * 64,
                "name": "/" + environment[HOST_ENV],
                "owner": environment[RUN_ENV],
                "image": "sha256:" + "2" * 64,
                "running": True,
            }
        ),
    )
    monkeypatch.setattr(Target, "clients", Mock(return_value=(object(), object())))
    monkeypatch.setattr(Target, "begin", Mock(return_value="original-owner-version"))
    monkeypatch.setattr(LiveStorage, "require_owner", Mock())
    return Run(directory, repository, environment)


@pytest.mark.parametrize("fault", ["remote", "context", "ambient-run", "public-directory"])
def test_allocation_rejects_unsafe_controller_context_before_creating_files(
    tmp_path: Path, fault: str
) -> None:
    environment = {"DOCKER_HOST": "unix:///var/run/docker.sock"}
    if fault == "remote":
        environment["DOCKER_HOST"] = "ssh://remote-host"
    elif fault == "context":
        environment["DOCKER_CONTEXT"] = "another-daemon"
    elif fault == "ambient-run":
        environment[RUN_ENV] = uuid.uuid7().hex
    else:
        tmp_path.chmod(0o755)
    try:
        with pytest.raises(ValueError):
            inputs.allocate(tmp_path, environment)
        assert not (tmp_path / "fixture").exists()
        assert not (tmp_path / "fixture.json").exists()
    finally:
        tmp_path.chmod(0o700)


def test_owned_environment_cannot_follow_ambient_daemon_or_foreign_names(run: Run) -> None:
    assert inputs.environment_for(run.directory, run.environment) == run.environment
    raw = (run.directory / "fixture.json").read_bytes()
    assert b"fixture-backup-secret" not in raw
    for key, value in (
        ("DOCKER_HOST", "unix:///another-docker.sock"),
        (HOST_ENV, "production-host"),
        ("M3_10_INSTALLED_REPORT", "/foreign/installed.json"),
    ):
        with pytest.raises(ValueError):
            inputs.environment_for(run.directory, {**run.environment, key: value})
    assert (run.directory / "fixture.json").read_bytes() == raw


def test_allocation_cli_exports_only_literal_nonsecret_coordinates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    directory = tmp_path / "literal $(touch unwanted) `command` path"
    directory.mkdir(mode=0o700)
    for key in (*RESOURCE_ENV, "MOLECULE_EPHEMERAL_DIRECTORY", "DOCKER_CONTEXT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("SPACES_SECRET_ACCESS_KEY", "private-environment-canary")
    monkeypatch.setattr(sys, "argv", ["inputs", "allocate", str(directory)])
    assert inputs.main() == 0
    raw = capsysbinary.readouterr().out
    assert b"private-environment-canary" not in raw
    parts = raw.decode().split("\0")
    assert parts.pop() == ""
    exported = dict(zip(parts[::2], parts[1::2], strict=True))
    assert exported == read_private(directory / "fixture.json")["environment"]
    assert inputs.environment_for(directory, {**os.environ, **exported})[ARTIFACT_ENV] == str(
        directory / "fixture/static-host-agent.tar"
    )
    with pytest.raises(FileExistsError):
        inputs.main()


def test_provider_owner_and_private_password_bind_original_storage_report(run: Run) -> None:
    storage = inputs.prepare_storage(run.directory, run.repository, run.environment)
    raw, report = evidence.read_document(run.directory / "storage.json")
    assert storage.binding["storage_run_id"] == report["run_id"]
    assert storage.binding["storage_report_sha256"] == hashlib.sha256(raw).hexdigest()
    assert LiveStorage.load(run.environment) == storage
    with pytest.raises(ValueError, match="original storage"):
        inputs.prepare_storage(run.directory, run.repository, run.environment)


@pytest.mark.parametrize("fault", ["dirty-source", "changed-target", "changed-capture"])
def test_changed_original_inputs_fail_before_provider_ownership(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    begin = Mock(side_effect=AssertionError("provider mutation is forbidden"))
    monkeypatch.setattr(Target, "begin", begin)
    environment = dict(run.environment)
    if fault == "dirty-source":
        (run.repository / "unreviewed.py").write_text("changed = True\n")
    elif fault == "changed-target":
        environment["SPACES_BACKUP_BUCKET"] = "another-fixture-backups"
    else:
        path = run.directory / "qualification-inputs.json"
        captured = read_private(path)
        captured["qualification_inputs_sha256"] = "0" * 64
        path.write_bytes(evidence.canonical_bytes(captured))
    with pytest.raises(ValueError):
        inputs.prepare_storage(run.directory, run.repository, environment)
    begin.assert_not_called()
    assert not (run.directory / "live-storage.json").exists()


@pytest.mark.parametrize("fault", ["none", "another-storage-run", "changed-storage-bytes"])
def test_capture_cannot_rebind_an_owner_to_another_storage_attempt(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    storage = inputs.prepare_storage(run.directory, run.repository, run.environment)
    original_storage = (run.directory / "live-storage.json").read_bytes()
    reservation = Mock(
        return_value={
            "source": {"id": "1" * 64},
            "destination": {"id": "2" * 64},
            "backup_repository_sha256": hashlib.sha256(
                storage.target.repository.encode()
            ).hexdigest(),
        }
    )
    monkeypatch.setattr(inputs, "reserve", reservation)
    monkeypatch.setattr(inputs, "_caddy", Mock(return_value="3" * 64))
    path = run.directory / "storage.json"
    if fault != "none":
        raw, report = evidence.read_document(path)
        report["run_id"] = str(uuid.uuid7())
        path.write_bytes(
            evidence.canonical_bytes(report) if fault == "another-storage-run" else raw + b"\n"
        )
        with pytest.raises(ValueError, match="original storage run"):
            inputs.capture(run.directory, run.repository, run.environment)
        reservation.assert_not_called()
        assert not (run.directory / "combined-context.json").exists()
        return
    context = inputs.capture(run.directory, run.repository, run.environment)
    assert {key: context[key] for key in evidence.BINDING_FIELDS} == storage.binding
    assert context == read_private(run.directory / "combined-context.json")
    evidence.validate_names(run.directory / "combined-names.json", context)
    assert "nonce" not in context and "subjects" not in context
    assert (run.directory / "live-storage.json").read_bytes() == original_storage
    with pytest.raises(ValueError, match="recaptured"):
        inputs.capture(run.directory, run.repository, run.environment)
    reservation.assert_called_once_with(storage)


@pytest.mark.parametrize("binary_receipt", [b"", b"not-a-digest\n"])
def test_context_requires_the_pinned_caddy_binary_before_reserving_destination(
    run: Run, monkeypatch: pytest.MonkeyPatch, binary_receipt: bytes
) -> None:
    inputs.prepare_storage(run.directory, run.repository, run.environment)
    reservation = Mock(side_effect=AssertionError("must not allocate a destination"))
    monkeypatch.setattr(inputs, "reserve", reservation)
    command = Mock(return_value=binary_receipt)
    monkeypatch.setattr(owned, "command", command)
    with pytest.raises(ValueError, match="digest"):
        inputs.capture(run.directory, run.repository, run.environment)
    assert command.call_args.args[-1] == (
        "/usr/local/lib/lowerduckpond/caddy-2.11.4-xcaddy-0.4.7-cloudflare-0.2.4"
    )
    reservation.assert_not_called()
    assert not (run.directory / "combined-context.json").exists()
