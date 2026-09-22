from __future__ import annotations

import json
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from molecule.interpolation import Interpolator, TemplateWithDefaults

from scripts import qualification_context as context
from scripts import qualification_failure as failure
from scripts import qualification_local as local
from scripts import qualification_timing as timing

ROOT = Path(__file__).parents[2]
CANARY = "private-ambient-credential-canary"
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700


@pytest.fixture(autouse=True)
def clean_context(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in context.RESOURCE_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST", "unix:///disposable/docker.sock")
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")


def test_distinct_runs_own_all_mutable_resources(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    environments = [local.create_environment(path) for path in (first, second)]
    configuration = (ROOT / "config/ansible/molecule/m3_8/molecule.yml").read_text()
    for path, environment in zip((first, second), environments, strict=True):
        assert context.host_name(environment) == environment[context.HOST_ENV]
        manifest = json.loads((path / "fixture.json").read_text())
        assert manifest["run_id"] == environment[context.RUN_ENV]
        assert stat.S_IMODE((path / "fixture.json").stat().st_mode) == PRIVATE_FILE_MODE
        assert stat.S_IMODE((path / "fixture").stat().st_mode) == PRIVATE_DIRECTORY_MODE
        rendered = Interpolator(TemplateWithDefaults, environment).interpolate(configuration)
        platforms = yaml.safe_load(rendered)["platforms"]
        assert platforms[0]["name"] == environment[context.HOST_ENV]
        assert platforms[1]["name"] == environment[context.ARCHIVE_ENV]
        assert platforms[0]["published_ports"] == ["0:22"]
        assert platforms[0]["image"] == environment[context.IMAGE_ENV]
        for platform in platforms:
            assert platform["labels"]["lowerduckpond.qualification.run"] == manifest["run_id"]
    for key in context.RESOURCE_ENV - {context.PORT_ENV} | {"MOLECULE_EPHEMERAL_DIRECTORY"}:
        assert environments[0][key] != environments[1][key]
    marker = Path(environments[0][context.ARTIFACT_ENV])
    marker.write_text("first fixture")
    Path(environments[1][context.ARTIFACT_ENV]).write_text("second fixture")
    assert marker.read_text() == "first fixture"
    with pytest.raises(FileExistsError):
        local.create_environment(first)
    assert marker.read_text() == "first fixture"


def test_ambient_local_resources_and_live_inputs_do_not_carry_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in (
        *context.RESOURCE_ENV,
        "MOLECULE_EPHEMERAL_DIRECTORY",
        "M3_10_INSTALLED_REPORT",
        "SPACES_SECRET_ACCESS_KEY",
        "CLOUDFLARE_API_TOKEN",
        "M3_8_ARCHIVE_CONFIGURATION_JSON",
        "M3_8_STATIC_PUBLICATION_ENABLED",
        "M3_11_BACKUP_RECOVERY_ENABLED",
        "M3_11_AUDIT_ROTATION_ENABLED",
    ):
        monkeypatch.setenv(key, CANARY)
    environment = local.create_environment(tmp_path)
    assert CANARY not in json.dumps(environment)
    assert CANARY not in (tmp_path / "fixture.json").read_text()
    assert environment["M3_8_STATIC_PUBLICATION_ENABLED"] == "false"
    assert environment["M3_11_BACKUP_RECOVERY_ENABLED"] == "false"
    assert environment["M3_11_AUDIT_ROTATION_ENABLED"] == "false"
    assert environment["M3_10_ARCHIVE_BACKEND"] == "minio"


def test_live_backend_is_rejected_before_allocating_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "spaces")
    with pytest.raises(ValueError, match="secure-workstation"):
        local.create_environment(tmp_path)
    assert not list(tmp_path.iterdir())


def test_nested_reapply_keeps_the_owned_state_and_certificate_directory(tmp_path: Path) -> None:
    environment = local.create_environment(tmp_path)
    expected = environment["MOLECULE_EPHEMERAL_DIRECTORY"]
    environment.update(
        MOLECULE_EPHEMERAL_DIRECTORY="/unrelated/child-export",
        MOLECULE_INVENTORY_FILE="/unrelated/inventory",
        MOLECULE_SCENARIO_DIRECTORY="/unrelated/scenario",
    )
    nested = context.reapply_environment(environment)
    assert nested["MOLECULE_EPHEMERAL_DIRECTORY"] == expected
    assert {key for key in nested if key.startswith("MOLECULE_")} == {
        "MOLECULE_EPHEMERAL_DIRECTORY"
    }
    assert all(nested[key] == environment[key] for key in context.RESOURCE_ENV)
    assert environment["MOLECULE_EPHEMERAL_DIRECTORY"] == "/unrelated/child-export"


def test_legacy_reapply_keeps_existing_molecule_rediscovery_behavior() -> None:
    assert context.reapply_environment(
        {"PATH": "/bin", "MOLECULE_EPHEMERAL_DIRECTORY": "/child"}
    ) == {"PATH": "/bin"}


@pytest.mark.parametrize("key", sorted(context.RESOURCE_ENV))
def test_partial_or_mixed_resource_ownership_is_rejected(key: str) -> None:
    assert context.host_name({}) == context.LEGACY_HOST
    with pytest.raises(ValueError):
        context.host_name({key: "another-fixture"})
    environment = context.resource_names(uuid.uuid7().hex)
    if key == context.ARTIFACT_ENV:
        return  # Paths are allocated by the launcher, not derived from a run ID.
    environment[key] = "another-fixture"
    with pytest.raises(ValueError):
        context.host_name(environment)


@pytest.mark.parametrize(
    "run_id", ["", "../another", "a" * 32, str(uuid.uuid7()), uuid.uuid4().hex]
)
def test_invalid_run_ids_cannot_become_resource_names(run_id: str) -> None:
    with pytest.raises(ValueError, match="run identity"):
        context.resource_names(run_id)


def test_docker_context_is_resolved_and_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOCKER_CONTEXT", "chosen-fixture-daemon")
    commands: list[list[str]] = []

    def inspect(command: list[str]) -> bytes:
        commands.append(command)
        return b"ssh://docker@disposable.invalid\n"

    monkeypatch.setattr(local, "bounded_command", inspect)
    environment = local.create_environment(tmp_path)
    assert environment["DOCKER_HOST"] == "ssh://docker@disposable.invalid"
    assert "DOCKER_CONTEXT" not in environment
    assert commands == [
        [
            "docker",
            "context",
            "inspect",
            "chosen-fixture-daemon",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ]
    ]


def test_name_collision_never_reaches_molecule_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(shutil, "which", lambda value: f"/usr/bin/{value}")

    def existing(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", existing)

    def forbidden(*args: object, **kwargs: object) -> int:
        pytest.fail("Molecule must not run after an owned-name collision")

    monkeypatch.setattr(subprocess, "call", forbidden)
    with pytest.raises(ValueError, match="already exists"):
        local.run(tmp_path)
    assert all(command[1] in {"info", "inspect"} for command in commands)


def test_diagnostics_inspect_only_their_owned_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = local.create_environment(tmp_path)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(timing.EVENT_ENV, str(tmp_path / "timing-events.jsonl"))
    commands: list[list[str]] = []

    def inspect(command: list[str], **kwargs: object) -> bytes:
        commands.append(command)
        return ("c" * 64).encode()

    monkeypatch.setattr(failure, "bounded_command", inspect)
    failure.capture_fixture()
    assert commands[0][-1] == environment[context.HOST_ENV]

    def inspect_identity(command: list[str]) -> str:
        commands.append(command)
        return "unknown"

    monkeypatch.setattr(timing, "_tool_output", inspect_identity)
    timing.capture_fixture_identity()
    assert commands[1][2] == environment[context.HOST_ENV]
    assert commands[2][-1] == environment[context.HOST_ENV]
    assert context.LEGACY_HOST not in json.dumps(commands)


@pytest.mark.parametrize("case_name,scenario", [("complete", "m3_8"), ("baseline", "default")])
def test_complete_and_baseline_commands_use_only_new_owned_contexts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_name: str, scenario: str
) -> None:
    monkeypatch.setattr(shutil, "which", lambda value: f"/usr/bin/{value}")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0 if command[1] == "info" else 1
        ),
    )
    called: list[list[str]] = []

    def invoke(command: list[str], **kwargs: object) -> int:
        called.append(command)
        values = kwargs["env"]
        assert isinstance(values, dict)
        assert context.host_name(values) != context.LEGACY_HOST
        configuration = (ROOT / f"config/ansible/molecule/{scenario}/molecule.yml").read_text()
        rendered = Interpolator(TemplateWithDefaults, values).interpolate(configuration)
        assert yaml.safe_load(rendered)["platforms"][0]["name"] == values[context.HOST_ENV]
        assert Path(values[context.ARTIFACT_ENV]).is_relative_to(tmp_path)
        return 0

    monkeypatch.setattr(subprocess, "call", invoke)
    cleaned: list[dict[str, str]] = []
    monkeypatch.setattr(local, "remove_owned_image", cleaned.append)
    assert local.run(tmp_path, case=case_name) == 0
    assert called[0][-1] == scenario
    assert len(cleaned) == 1
    assert cleaned[0][context.HOST_ENV] != context.LEGACY_HOST
