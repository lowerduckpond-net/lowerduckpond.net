from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from molecule.config import Config

from scripts import qualification_case as case
from scripts import qualification_local as local
from scripts import qualification_retirement as retirement
from scripts.m3_10_qualification_report import verify_report
from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV, resource_names

HOST_ID = "a" * 64
ARCHIVE_ID = "b" * 64
FAILURE_STATUS = 17


def write_receipt(directory: Path, environment: dict[str, str]) -> None:
    (directory / "case-installed.json").write_text(
        json.dumps(
            {
                "format": case.INSTALLED_FORMAT,
                "run_id": environment[RUN_ENV],
                "artifact_sha256": "c" * 64,
                "content_sha256": "d" * 64,
                "entries": case.ENTRY_COUNT,
                "bytes": case.CONTENT_BYTES,
            }
        )
    )


@pytest.fixture
def environment() -> dict[str, str]:
    return {**resource_names(uuid.uuid7().hex), "DOCKER_HOST": "unix:///owned/docker.sock"}


@pytest.fixture(autouse=True)
def quiescent_accounting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(retirement, "local_proof", lambda *args: "quiescent-installed")


@pytest.mark.parametrize(
    "failed_phase", ["create", "prepare", "converge", "idempotence", "verify", "destroy", None]
)
def test_only_a_complete_case_reaches_independent_proof_and_teardown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
    failed_phase: str | None,
) -> None:
    events: list[str] = []

    def phase(directory: Path, values: dict[str, str], uv: str, name: str) -> int:
        events.append(name)
        if name == "verify":
            write_receipt(directory, values)
        base = json.loads((directory / "case-base.yml").read_text())
        assert base["ansible"]["playbooks"]["verify"].endswith("/verify_full_size_archive.yml")
        assert values[HOST_ENV] == environment[HOST_ENV]
        return FAILURE_STATUS if name == failed_phase else 0

    monkeypatch.setattr(case, "phase", phase)
    monkeypatch.setattr(
        case, "owned_containers", lambda values: {HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID}
    )

    def proof(values: dict[str, str], archive_id: str) -> None:
        assert archive_id == ARCHIVE_ID
        events.append("independent-proof")

    monkeypatch.setattr(case, "independent_storage_absence", proof)

    def local_proof(values: dict[str, str], host_id: str) -> str:
        assert host_id == HOST_ID
        events.append("local-proof")
        return "quiescent-installed"

    monkeypatch.setattr(retirement, "local_proof", local_proof)
    status = case.run_full_size(tmp_path, environment, "uv")
    sequence = [
        "create",
        "prepare",
        "converge",
        "idempotence",
        "verify",
        "local-proof",
        "independent-proof",
        "local-proof",
        "destroy",
    ]
    assert events == (
        sequence if failed_phase is None else sequence[: sequence.index(failed_phase) + 1]
    )
    assert status == (0 if failed_phase is None else FAILURE_STATUS)
    assert (tmp_path / "case.json").exists() is (failed_phase is None)
    assert not (tmp_path / "qualification.json").exists()
    if failed_phase is None:
        report = json.loads((tmp_path / "case.json").read_text())
        assert report["authority"] == "diagnostic-only"
        with pytest.raises(ValueError):
            verify_report(tmp_path / "case.json", source="a" * 40, artifact="a" * 64)


@pytest.mark.parametrize("problem", ["identity", "provider", "local-before", "local-after"])
def test_unknown_or_changed_obligations_retain_the_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], problem: str
) -> None:
    phases: list[str] = []
    monkeypatch.setenv("LDP_QUALIFICATION_TIMING_EVENTS", str(tmp_path / "timing-events.jsonl"))

    def phase(directory: Path, values: dict[str, str], uv: str, name: str) -> int:
        phases.append(name)
        if name == "verify":
            write_receipt(directory, values)
        return 0

    monkeypatch.setattr(case, "phase", phase)
    calls = 0

    def owned(values: dict[str, str]) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {
            HOST_ENV: HOST_ID if calls == 1 or problem != "identity" else "c" * 64,
            ARCHIVE_ENV: ARCHIVE_ID,
        }

    monkeypatch.setattr(case, "owned_containers", owned)

    observations = 0

    def local_proof(values: dict[str, str], host_id: str) -> str:
        nonlocal observations
        observations += 1
        if (problem == "local-before" and observations == 1) or (
            problem == "local-after" and observations > 1
        ):
            raise ValueError("local obligations are not settled")
        return "quiescent-installed"

    monkeypatch.setattr(retirement, "local_proof", local_proof)

    def proof(values: dict[str, str], archive_id: str) -> None:
        if problem == "provider":
            raise ValueError("unavailable independent storage proof")

    monkeypatch.setattr(case, "independent_storage_absence", proof)
    with pytest.raises(ValueError):
        case.run_full_size(tmp_path, environment, "uv")
    assert "destroy" not in phases
    assert not (tmp_path / "case.json").exists()
    assert json.loads((tmp_path / "failure-phase.json").read_text())["phase"] == (
        "final-storage-proof" if problem == "provider" else "final-accounting"
    )


def test_owned_container_queries_reject_another_run(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]
) -> None:
    commands: list[list[str]] = []

    def query(command: list[str], **kwargs: object) -> bytes:
        commands.append(command)
        assert kwargs["environment"] == environment
        return json.dumps({"id": HOST_ID, "owner": uuid.uuid7().hex}).encode()

    monkeypatch.setattr(case, "bounded_command", query)
    with pytest.raises(ValueError, match="ownership"):
        case.owned_containers(environment)
    assert commands[0][-1] == environment[HOST_ENV]


@pytest.mark.parametrize(
    "output", [None, b'{"status":"error"}', b'{"key":"private-object-canary"}']
)
def test_independent_inventory_rejects_error_objects_or_unknown(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], output: bytes | None
) -> None:
    monkeypatch.setattr(case, "bounded_command", lambda *args, **kwargs: output)
    with pytest.raises(ValueError, match="whole-bucket absence") as caught:
        case.independent_storage_absence(environment, ARCHIVE_ID)
    assert "private-object-canary" not in str(caught.value)


def test_independent_inventory_checks_both_buckets_and_uploads(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]
) -> None:
    commands: list[list[str]] = []

    def empty(command: list[str], **kwargs: object) -> bytes:
        commands.append(command)
        assert kwargs["environment"] == environment
        return b""

    monkeypatch.setattr(case, "bounded_command", empty)
    case.independent_storage_absence(environment, ARCHIVE_ID)
    assert {(command[-3], command[-1]) for command in commands} == {
        (mode, f"m310/{bucket}")
        for mode in ("--versions", "--incomplete")
        for bucket in ("molecule-tenant-archives", "molecule-platform-backup")
    }
    assert all(command[2] == ARCHIVE_ID for command in commands)


def test_unavailable_optional_timing_does_not_block_owned_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.delenv("LDP_QUALIFICATION_TIMING_EVENTS", raising=False)
    monkeypatch.setattr(sys, "argv", ["qualification_local.py"])
    directories: list[Path] = []

    def run(directory: Path, **kwargs: object) -> int:
        directories.append(directory)
        assert directory.is_dir()
        return FAILURE_STATUS

    monkeypatch.setattr(local, "run", run)
    previous = os.umask(0o077)
    try:
        assert local.main() == FAILURE_STATUS
    finally:
        os.umask(previous)
    assert len(directories) == 1


@pytest.mark.parametrize("problem", ["missing", "other-run", "incomplete", "extra"])
def test_a_successful_command_without_a_complete_installed_receipt_cannot_destroy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], problem: str
) -> None:
    phases: list[str] = []

    def phase(directory: Path, values: dict[str, str], uv: str, name: str) -> int:
        phases.append(name)
        return 0

    monkeypatch.setattr(case, "phase", phase)
    monkeypatch.setattr(
        case, "owned_containers", lambda values: {HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID}
    )
    if problem != "missing":
        write_receipt(tmp_path, environment)
        path = tmp_path / "case-installed.json"
        receipt = json.loads(path.read_text())
        if problem == "other-run":
            receipt["run_id"] = uuid.uuid7().hex
        elif problem == "incomplete":
            del receipt["artifact_sha256"]
        else:
            receipt["untrusted"] = "ignored-input"
        path.write_text(json.dumps(receipt))
    with pytest.raises((ValueError, FileNotFoundError)):
        case.run_full_size(tmp_path, environment, "uv")
    assert "destroy" not in phases
    assert not (tmp_path / "case.json").exists()


def test_molecule_resolves_the_case_verifier_without_changing_the_complete_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]
) -> None:
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MOLECULE_EPHEMERAL_DIRECTORY", str(tmp_path / "molecule"))
    monkeypatch.setattr(case, "phase", lambda *args: FAILURE_STATUS)
    assert case.run_full_size(tmp_path, environment, "uv") == FAILURE_STATUS
    scenario = str(case.ROOT / "config/ansible/molecule/m3_8/molecule.yml")
    selected = Config(scenario, args={"base_config": [str(tmp_path / "case-base.yml")]})
    assert selected.config_data["ansible"]["playbooks"]["verify"].endswith(
        "/verify_full_size_archive.yml"
    )
    complete = Config(scenario)
    assert complete.config_data["ansible"]["playbooks"]["verify"] == "verify.yml"
    assert (
        complete.config_data["scenario"]["test_sequence"]
        == selected.config_data["scenario"]["test_sequence"]
    )
