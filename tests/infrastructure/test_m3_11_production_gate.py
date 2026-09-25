"""Migration authority prevents accidental feature rollback or repository reset."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml  # type: ignore[import-untyped]

from infrastructure.test_m3_11_production_journal import (
    records as records,  # noqa: PLC0414 - shared original receipt-chain fixture
)
from scripts import m3_11_production_gate as gate
from scripts import m3_11_production_records as wire

ROOT = Path(__file__).parents[2]
OWNER = os.geteuid()
REQUEST: dict[str, object] = {
    "stage": "converge",
    "artifact_sha256": "b" * 64,
    "recovery_enabled": True,
    "rotation_enabled": False,
    "publication_enabled": False,
    "reconstruction_enabled": False,
    "archive_enabled": True,
    "generation_enabled": True,
}


def publish(directory: Path, records: list[tuple[str, bytes]], phase: str) -> None:
    for name, raw in records:
        wire.operate(directory, ["publish", name], raw, owner=OWNER)
        if name == phase:
            break


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    parent = tmp_path / "convergence"
    parent.mkdir(mode=0o700)
    return parent / "m3-11"


@pytest.mark.parametrize(
    ("phase", "stage", "recovery", "rotation"),
    [
        ("namespace.started", "bootstrap", False, False),
        ("converged.started", "converge", True, False),
        ("rotation-enabled.started", "converge", True, True),
        ("accepted.started", "acceptance", True, True),
    ],
)
def test_original_phase_allows_only_its_configuration_without_changing_receipts(  # noqa: PLR0913,PLR0917 - phase matrix
    directory: Path,
    records: list[tuple[str, bytes]],
    phase: str,
    stage: str,
    recovery: bool,
    rotation: bool,
) -> None:
    publish(directory, records, phase)
    request = REQUEST | {
        "stage": stage,
        "recovery_enabled": recovery,
        "rotation_enabled": rotation,
    }
    before = {p.name: (p.stat(), p.read_bytes()) for p in directory.iterdir()}
    for _ in range(2):
        assert gate.require(directory, json.dumps(request).encode(), owner=OWNER) == phase
    for name, (metadata, raw) in before.items():
        path = directory / name
        assert path.read_bytes() == raw
        assert (path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_ctime_ns) == (
            metadata.st_ino,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )


@pytest.mark.parametrize(
    "phase",
    [
        "original",
        "drained.started",
        "drained",
        "namespace",
        "lineage.started",
        "lineage",
        "converged",
        "backup-verified.started",
        "backup-verified",
        "rotation-enabled",
        "accepted",
    ],
)
def test_other_phases_and_completed_rollout_cannot_authorize_another_convergence(
    directory: Path, records: list[tuple[str, bytes]], phase: str
) -> None:
    publish(directory, records, phase)
    with pytest.raises(ValueError, match="does not authorize"):
        gate.require(directory, json.dumps(REQUEST).encode(), owner=OWNER)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", "bootstrap"),
        ("stage", "acceptance"),
        ("artifact_sha256", "c" * 64),
        ("recovery_enabled", False),
        ("rotation_enabled", True),
        ("publication_enabled", True),
        ("reconstruction_enabled", True),
        ("archive_enabled", False),
        ("generation_enabled", False),
    ],
)
def test_downgrade_early_rotation_publication_and_changed_candidate_are_refused(
    directory: Path, records: list[tuple[str, bytes]], field: str, value: object
) -> None:
    publish(directory, records, "converged.started")
    with pytest.raises(ValueError, match="differs"):
        gate.require(directory, json.dumps(REQUEST | {field: value}).encode(), owner=OWNER)


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}])
def test_flags_are_never_coerced_to_booleans(
    directory: Path, records: list[tuple[str, bytes]], value: object
) -> None:
    publish(directory, records, "converged.started")
    for flag in gate.FLAGS:
        with pytest.raises(ValueError, match="invalid"):
            gate.require(directory, json.dumps(REQUEST | {flag: value}).encode(), owner=OWNER)


@pytest.mark.parametrize("fault", ["absent", "partial", "changed", "link"])
def test_incomplete_or_changed_authority_is_preserved_and_refused(
    directory: Path, records: list[tuple[str, bytes]], fault: str
) -> None:
    if fault != "absent":
        publish(directory, records, "converged.started")
        if fault == "partial":
            (directory / ".unknown.partial").touch(mode=0o400)
        elif fault == "changed":
            path = directory / "original.json"
            path.chmod(0o600)
            path.write_bytes(b"{}\n")
            path.chmod(0o400)
        else:
            moved = directory.with_name("original-journal")
            directory.rename(moved)
            directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        gate.require(directory, json.dumps(REQUEST).encode(), owner=OWNER)
    assert directory.exists() == (fault != "absent")


@pytest.mark.parametrize("raw", [b"", b"[]", b"{}", b"x" * (gate.MAX_BYTES + 1)])
def test_invalid_wire_input_cannot_create_authority(directory: Path, raw: bytes) -> None:
    with pytest.raises(ValueError):
        gate.require(directory, raw, owner=OWNER)
    assert not directory.exists()


@pytest.mark.parametrize("kind", ["absent", "directory", "file", "broken-link"])
def test_actual_restic_initialization_fallback_refuses_any_migration_authority(
    tmp_path: Path, kind: str
) -> None:
    tasks = yaml.safe_load((ROOT / "config/ansible/roles/backup/tasks/main.yml").read_text())
    task = next(t for t in tasks if t["name"] == "Initialize the encrypted Restic repository")
    command = cast(str, task["ansible.builtin.shell"]["cmd"])
    lock, environment, invoked = tmp_path / "lock", tmp_path / "environment", tmp_path / "invoked"
    lock.touch()
    environment.write_text("LOWERDUCKPOND_BACKUP_ACTIVATION_SCOPE=fixture\n")
    authority = tmp_path / "m3-11"
    if kind == "directory":
        authority.mkdir()
    elif kind == "file":
        authority.touch()
    elif kind == "broken-link":
        authority.symlink_to(tmp_path / "missing")
    command = (
        command.replace("/var/cache/lowerduckpond-backup/repository.lock", shlex.quote(str(lock)))
        .replace("/etc/lowerduckpond/backup.env", shlex.quote(str(environment)))
        .replace(str(wire.ROOT), shlex.quote(str(authority)))
        .replace("{{ backup_activation_scope | quote }}", "fixture")
        .replace("exec /usr/bin/restic init", "touch " + shlex.quote(str(invoked)))
    )
    result = subprocess.run(["/bin/bash", "-c", command], check=False)  # noqa: S603 - owned fixture
    assert (result.returncode == 0) == (kind == "absent")
    assert invoked.exists() == (kind == "absent")


@pytest.mark.parametrize("kind", ["absent", "directory", "file", "broken-link"])
def test_legacy_configure_probe_stops_before_treating_artifact_selection_as_authority(
    tmp_path: Path, kind: str
) -> None:
    wrapper = (ROOT / "scripts/configure-production").read_text()
    probe = wrapper.split("selected_production_artifact=$(ssh ", 1)[1].split(
        "\ntemporary_directory=", 1
    )[0]
    remote = shlex.split(probe.rsplit(")", 1)[0])[-1]
    arguments = shlex.split(remote)
    assert arguments[:4] == ["sudo", "--non-interactive", "/bin/sh", "-c"]
    selected, authority = tmp_path / "selected", tmp_path / "m3-11"
    selected.mkdir()
    if kind == "directory":
        authority.mkdir()
    elif kind == "file":
        authority.touch()
    elif kind == "broken-link":
        authority.symlink_to(tmp_path / "missing")
    program = arguments[4].replace(str(wire.ROOT), shlex.quote(str(authority)))
    program = program.replace(
        "/opt/lowerduckpond/static-host-agent/current", shlex.quote(str(selected))
    )
    result = subprocess.run(  # noqa: S603 - exact remote script against owned fixture paths
        ["/bin/sh", "-c", program], capture_output=True, check=False
    )
    assert (result.returncode == 0) == (kind == "absent")
    assert result.stdout == (str(selected).encode() + b"\n" if kind == "absent" else b"")
    if kind != "absent":
        assert b"requires its original controller" in result.stderr
