"""Durable service admission survives partial migration and controller death."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from ansible.template import Templar, trust_as_template  # type: ignore[import-untyped]

from infrastructure.test_m3_11_production_journal import (
    records as records,  # noqa: PLC0414 - original receipt-chain fixture
)
from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as wire

OWNER = os.geteuid()
CRASH = 86
PUBLISHED_MODE = 0o400
ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("phase", ["lineage", "converged"])
def test_exact_service_condition_retry_preserves_original_file(
    tmp_path: Path, records: list[tuple[str, bytes]], phase: str
) -> None:
    directory = tmp_path / "unit.service.d"
    raw = fence.content(records[0][1], phase)
    fence.publish(directory, raw, owner=OWNER)
    path = directory / fence.NAME
    before = path.stat()
    fence.publish(directory, raw, owner=OWNER)
    after = path.stat()
    assert path.read_bytes() == raw and stat.S_IMODE(after.st_mode) == PUBLISHED_MODE
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


@pytest.mark.parametrize("point", ["write", "fchmod", "file-fsync", "rename", "dir-fsync"])
def test_actual_process_death_resumes_only_original_condition(
    tmp_path: Path, records: list[tuple[str, bytes]], point: str
) -> None:
    directory = tmp_path / "unit.service.d"
    directory.mkdir(mode=0o700)
    raw = fence.content(records[0][1], "converged")
    source = tmp_path / "original"
    source.write_bytes(raw)
    program = """
import os,stat,sys
from pathlib import Path
from scripts import m3_11_production_fence as fence
point=sys.argv[3]
name='fsync' if point.endswith('fsync') else point
original=getattr(os,name)
def interrupted(*args,**kwargs):
    if name=='write':
        original(args[0],args[1][:17]);os._exit(86)
    result=original(*args,**kwargs)
    directory=stat.S_ISDIR(os.fstat(args[0]).st_mode) if name=='fsync' else False
    if name!='fsync' or (point=='dir-fsync')==directory: os._exit(86)
    return result
setattr(os,name,interrupted)
fence.publish(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes(),owner=os.geteuid())
"""
    result = subprocess.run(  # noqa: S603 - fixed crash harness against owned paths
        [sys.executable, "-c", program, str(directory), str(source), point], check=False
    )
    assert result.returncode == CRASH
    with pytest.raises(ValueError):
        fence.publish(directory, raw.replace(b"converged", b"lineage"), owner=OWNER)
    fence.publish(directory, raw, owner=OWNER)
    assert (directory / fence.NAME).read_bytes() == raw
    assert {p.name for p in directory.iterdir()} == {fence.NAME}


@pytest.mark.parametrize("fault", ["directory-link", "mode", "final-link", "changed", "partial"])
def test_unsafe_or_changed_conditions_are_never_replaced(
    tmp_path: Path, records: list[tuple[str, bytes]], fault: str
) -> None:
    directory = tmp_path / "unit.service.d"
    raw = fence.content(records[0][1], "converged")
    if fault == "directory-link":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        directory.symlink_to(elsewhere, target_is_directory=True)
    else:
        directory.mkdir(mode=0o700)
        if fault == "mode":
            directory.chmod(0o777)
        elif fault == "final-link":
            (directory / fence.NAME).symlink_to(tmp_path / "missing")
        else:
            name = fence.NAME if fault == "changed" else ".m3-11-other.partial"
            (directory / name).write_bytes(b"retained original bytes")
            (directory / name).chmod(0o400)
    with pytest.raises((ValueError, OSError)):
        fence.publish(directory, raw, owner=OWNER)


@pytest.mark.parametrize("change", ["missing", "negated", "trigger", "wrong-phase"])
def test_effective_systemd_condition_must_require_the_real_completion_record(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    condition: list[object] = [
        "ConditionPathExists",
        False,
        False,
        str(wire.ROOT / "converged.json"),
        0,
    ]
    if change == "negated":
        condition[2] = True
    elif change == "trigger":
        condition[1] = True
    elif change == "wrong-phase":
        condition[3] = str(wire.ROOT / "converged.started.json")

    def run(args: list[str], *, stop: bool = False) -> bytes:
        assert not stop
        if args[0] == "/usr/bin/systemctl":
            return b"loaded\n"
        if "LoadUnit" in args:
            return b'{"type":"o","data":["/unit"]}'
        return json.dumps(
            {"type": "a(sbbsi)", "data": [] if change == "missing" else [condition]}
        ).encode()

    monkeypatch.setattr(fence, "run", run)
    with pytest.raises(ValueError, match="required migration condition"):
        fence.conditions("lowerduckpond-backup.service", "converged")


@pytest.fixture
def predecessor(
    tmp_path: Path, records: list[tuple[str, bytes]], monkeypatch: pytest.MonkeyPatch
) -> Path:
    original = json.loads(records[0][1])
    parent, units = tmp_path / "convergence", tmp_path / "units"
    parent.mkdir(mode=0o700)
    units.mkdir(mode=0o755)
    root = parent / "m3-11"
    for name, raw in records[:2]:
        wire.operate(root, ["publish", name], raw, owner=OWNER)
    selected = tmp_path / original["predecessor"].split()[0]
    selected.mkdir()
    current = tmp_path / "current"
    current.symlink_to(selected, target_is_directory=True)
    completion, publication = tmp_path / "m3-10", tmp_path / "publication"
    completion.write_text(original["predecessor"])
    publication.write_text(
        json.dumps(
            {
                "format": "lowerduckpond-static-publication-gate-v1",
                "static_publication_enabled": False,
            }
        )
    )
    completion.chmod(0o400)
    publication.chmod(0o400)
    monkeypatch.setattr(wire, "ROOT", root)
    monkeypatch.setattr(probe, "COMPLETION", completion)
    monkeypatch.setattr(probe, "SELECTION", current)
    monkeypatch.setattr(probe, "PUBLICATION", publication)
    monkeypatch.setattr(fence, "UNITS", units)
    return units


@pytest.mark.parametrize("fault", ["zero", "duplicate"])
def test_drain_requires_one_boolean_false_publication_value(predecessor: Path, fault: str) -> None:
    raw = probe.PUBLICATION.read_bytes()
    if fault == "zero":
        raw = raw.replace(b"false", b"0")
    else:
        raw = raw.replace(b"{", b'{"static_publication_enabled":false,', 1)
    probe.PUBLICATION.chmod(0o600)
    probe.PUBLICATION.write_bytes(raw)
    probe.PUBLICATION.chmod(0o400)
    with pytest.raises(ValueError):
        fence.drain(owner=OWNER)
    assert not list(predecessor.iterdir())


@pytest.mark.parametrize("fault", ["none", "live-unit", "external-process", "stop-failed"])
def test_drain_cannot_complete_until_all_old_execution_is_absent(
    predecessor: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    calls: list[list[str]] = []

    def run(args: list[str], *, stop: bool = False) -> bytes:
        calls.append(args)
        if stop:
            # Durable conditions must exist before any stop operation.
            assert all((predecessor / (u + ".d") / fence.NAME).exists() for u in fence.FENCES)
            if fault == "stop-failed":
                raise ValueError("stop failed")
        if "--property=LoadState" in args:
            return b"not-found\n"
        if "list-units" in args:
            active_query = any(a.startswith("--state=") for a in args)
            return json.dumps(
                []
                if active_query and fault != "live-unit"
                else [{"unit": "lowerduckpond-backup.service"}]
            ).encode()
        return b""

    def processes(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            ["pgrep"], 0 if fault == "external-process" else 1, b"", b""
        )

    monkeypatch.setattr(fence, "run", run)
    monkeypatch.setattr(subprocess, "run", processes)
    if fault != "none":
        with pytest.raises(ValueError):
            fence.drain(owner=OWNER)
    else:
        result = json.loads(fence.drain(owner=OWNER))
        assert (
            result["active_units"]
            == result["external_commands"]
            == result["populated_groups"]
            == []
        )
        assert set(result["fences"]) == set(fence.FENCES)
        assert any("stop" in args for args in calls)
    assert all((predecessor / (u + ".d") / fence.NAME).exists() for u in fence.FENCES)


@pytest.mark.parametrize("phase", ["", "converged.started", "rotation-enabled.started"])
def test_backup_role_defers_work_only_during_the_two_original_converges(phase: str) -> None:
    tasks = yaml.safe_load((ROOT / "config/ansible/roles/backup/tasks/main.yml").read_text())
    variables: dict[str, object] = {
        "host_recovery_bootstrap_enabled": False,
        "backup_static_recovery_enabled": True,
        "backup_run_initial": True,
        "backup_run_initial_maintenance": True,
        "backup_local_health_status": {},
        "backup_initial_maintenance_status": {},
        "backup_status_scope": "fixture",
        "backup_maintenance_status_scope": "fixture",
        "m3_11_production_phase": {"stdout": phase},
        "omit": "fixture-omit",
    }
    templar = Templar(variables=variables)
    for name in ("Create the first encrypted off-host backup", "Apply backup retention initially"):
        task = next(t for t in tasks if t["name"] == name)
        enabled = all(
            templar.template(trust_as_template("{{ " + condition + " }}"))
            for condition in task["when"]
        )
        assert enabled is (phase != "converged.started")
    for name in (
        "Enable backup schedules",
        "Configure protected audit verification at boot and daily",
    ):
        task = next(t for t in tasks if t["name"] == name)
        state = templar.template(
            trust_as_template(task["ansible.builtin.systemd_service"]["state"])
        )
        assert state == ("fixture-omit" if phase == "converged.started" else "started")
