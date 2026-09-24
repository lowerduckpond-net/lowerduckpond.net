from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from ansible.template import Templar, trust_as_template  # type: ignore[import-untyped]

ROLE = Path(__file__).parents[2] / "config/ansible/roles/host_recovery"
RESTORE = "0198d17f-6f4a-7000-8000-000000000001"


def render(name: str, **variables: object) -> str:
    result = Templar(variables=variables).template(
        trust_as_template((ROLE / "templates" / name).read_text())
    )
    assert type(result) is str
    return result


@pytest.mark.parametrize(
    "mode,function",
    [
        ("cli", "restore_cli_main"),
        ("source", "source_fence_main"),
        ("coordinator", "restore_coordinator_main"),
        ("archive-private", None),
        ("archive-installed", None),
    ],
)
def test_rendered_launchers_verify_artifact_under_correct_lease_before_import(
    mode: str,
    function: str | None,
) -> None:
    script = render("host-restore-agent.j2", item={"mode": mode, "function": function})
    ast.parse(script)
    assert script.index("_ARTIFACT = selected_artifact()") < script.index("from lowerduckpond_")
    assert "require_lock(path, descriptor)" in script
    assert ("FLOCK" in script) == (mode in {"source", "coordinator"})
    assert ("fcntl.LOCK_EX)" in script) == (mode == "source")
    assert "backup.env" not in script


def test_repository_environment_is_loaded_only_after_exclusion(tmp_path: Path) -> None:
    script = render(
        "host-restore-with-backup.j2",
        item={"agent": "host-restore-coordinator"},
        backup_activation_scope="a" * 64,
    )
    assert script.index("flock --exclusive 9") < script.index(
        "source /etc/lowerduckpond/backup.env"
    )
    destination = tmp_path / "host-restore-run"
    destination.write_text(script)
    subprocess.run(["bash", "-n", str(destination)], check=True)  # noqa: S603,S607 - syntax only


@pytest.mark.parametrize("mode", ["private", "installed"])
def test_archive_helper_has_no_backup_or_dns_environment_and_keeps_existing_ceiling(
    mode: str,
) -> None:
    state = (
        "/var/lib/lowerduckpond/static"
        if mode == "installed"
        else f"/var/lib/lowerduckpond/.restore-{RESTORE}-state/candidate"
    )
    unit = render(
        "lowerduckpond-host-restore-archive.service.j2",
        item={"mode": mode, "state": state},
        host_recovery_restore_id=RESTORE,
    )
    assert "TemporaryFileSystem=/:ro" in unit
    assert f"BindReadOnlyPaths={state}:/restore-state" in unit
    assert f"BindPaths={state}/intents:/restore-state/intents" in unit
    assert "/etc/lowerduckpond/archive" in unit
    assert "backup.env" not in unit and "BindReadOnlyPaths=/etc/caddy" not in unit
    assert "/var/cache/lowerduckpond-backup" not in unit
    assert "MemoryMax=128M" in unit and "MemorySwapMax=0" in unit
    assert "TasksMax=16" in unit and "TimeoutStartSec=5min" in unit
    assert "LimitCPU=120" in unit and "CPUQuota=100%" in unit
    coordinator = render(
        "lowerduckpond-host-restore.service.j2",
        backup_repository="s3:https://fixture.invalid/backup",
    )
    assert (
        "InaccessiblePaths=-/etc/lowerduckpond/archive -/run/lowerduckpond-archive" in coordinator
    )
    assert "MemoryMax=512M" in coordinator and "MemorySwapMax=0" in coordinator
    assert "TasksMax=32" in coordinator and "TimeoutStartSec=30min" in coordinator


def test_only_activators_can_start_with_completion_token_and_closed_gate() -> None:
    units = yaml.safe_load((ROLE / "vars/main.yml").read_text())["host_recovery_guarded_units"]
    for unit in units:
        dropin = render("restore-admission.conf.j2", item=unit)
        activator = unit.endswith((".timer", ".socket"))
        assert ("schedules-ready" in dropin) == activator
        if unit.endswith(".service"):
            assert "ExecStartPre=!/usr/local/libexec/lowerduckpond/host-restore-gate" in dropin
            assert "--caddy" in dropin if unit == "caddy.service" else "--ordinary" in dropin
    tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    preflight = next(
        index
        for index, task in enumerate(tasks)
        if task.get("register") == "host_recovery_bootstrap_inputs"
    )
    assert all(
        not any(
            key in task
            for key in ("ansible.builtin.copy", "ansible.builtin.file", "ansible.builtin.apt")
        )
        for task in tasks[:preflight]
    )


def test_ordinary_activation_can_resolve_skipped_bootstrap_copy_loop() -> None:
    tasks = yaml.safe_load((ROLE / "tasks/commands.yml").read_text())
    task = next(task for task in tasks if task.get("no_log"))
    # Ansible evaluates loop expressions even for a false task condition. A
    # normal host has only the registered skipped result, with no stdout.
    value = Templar(
        variables={
            "host_recovery_bootstrap_inputs": {"skipped": True},
            "host_recovery_restore_id": "",
        }
    ).template(trust_as_template(task["loop"]))
    assert value == ["target.json", "source-fence-.json"]
