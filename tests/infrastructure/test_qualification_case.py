from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from molecule.config import Config

from scripts import qualification_case as case
from scripts import qualification_group_case as groups
from scripts import qualification_local as local
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
        case.installed_receipt(tmp_path, environment)


def test_molecule_resolves_the_case_verifier_without_changing_the_complete_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]
) -> None:
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MOLECULE_EPHEMERAL_DIRECTORY", str(tmp_path / "molecule"))
    monkeypatch.setattr(groups, "phase", lambda *args: FAILURE_STATUS)
    assert groups.run_group(tmp_path, environment, "uv", "core") == FAILURE_STATUS
    scenario = str(case.ROOT / "config/ansible/molecule/m3_8/molecule.yml")
    selected = Config(scenario, args={"base_config": [str(tmp_path / "case-base.yml")]})
    assert selected.config_data["ansible"]["playbooks"]["verify"] == str(tmp_path / "verify.yml")
    complete = Config(scenario)
    assert complete.config_data["ansible"]["playbooks"]["verify"] == "verify.yml"
    assert (
        complete.config_data["scenario"]["test_sequence"]
        == selected.config_data["scenario"]["test_sequence"]
    )


def test_live_molecule_create_leaves_public_inputs_unprepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MOLECULE_EPHEMERAL_DIRECTORY", str(tmp_path / "molecule"))
    scenario = str(case.ROOT / "config/ansible/molecule/m3_8/molecule.yml")
    # Resolve the live wrapper's actual CLI sequence without the installed groups'
    # private base-config override: the default create sequence includes prepare.
    create = Config(scenario, command_args={"subcommand": "create"})
    assert create.scenario.sequence == ["dependency", "create"]
    prepare = Config(scenario, command_args={"subcommand": "prepare"})
    assert prepare.scenario.sequence == ["prepare"]
    complete = Config(scenario, command_args={"subcommand": "test"})
    assert complete.scenario.sequence == [
        "destroy",
        "syntax",
        "create",
        "prepare",
        "converge",
        "idempotence",
        "verify",
        "destroy",
    ]


@pytest.mark.parametrize("present", [[], [HOST_ENV], [ARCHIVE_ENV], [HOST_ENV, ARCHIVE_ENV]])
def test_optional_inventory_proves_absence_without_adopting_other_owners(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], present: list[str]
) -> None:
    identities = {HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID}

    def query(command: list[str], **kwargs: object) -> bytes:
        if command[1:3] == ["container", "ls"]:
            key = next(key for key in identities if f"name=^/{environment[key]}$" in command)
            return (identities[key] + "\n").encode() if key in present else b""
        key = next(key for key in identities if command[-1] == environment[key])
        return json.dumps({"id": identities[key], "owner": environment[RUN_ENV]}).encode()

    monkeypatch.setattr(case, "bounded_command", query)
    assert case.owned_containers(environment, allow_missing=True) == {
        key: identities[key] for key in present
    }


@pytest.mark.parametrize("output", [None, b"not-an-id", (HOST_ID + "\n" + ARCHIVE_ID).encode()])
def test_unknown_inventory_is_not_container_absence(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], output: bytes | None
) -> None:
    monkeypatch.setattr(case, "bounded_command", lambda *args, **kwargs: output)
    with pytest.raises(ValueError):
        case.owned_containers(environment, allow_missing=True)
