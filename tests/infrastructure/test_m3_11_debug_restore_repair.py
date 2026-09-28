"""Diagnostic instrumentation keeps native recovery authority and reports stalls."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jinja2 import Environment
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_gate import close_gate, open_gate
from lowerduckpond_static_host_agent.host_restore_history import (
    require_backup_provenance,
    seal_provenance,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)

from scripts import m3_11_debug_restore_repair as repair
from scripts import m3_11_debug_trace as trace

RESTORE = "0198d17f-6f4a-7000-8000-000000000001"


@pytest.fixture
def launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    path = tmp_path / "host-restore-coordinator"
    original = ("# original administrative launcher\n" + repair.TAIL + "\n").encode()
    path.write_bytes(original)
    path.chmod(0o755)
    monkeypatch.setattr(repair, "ROOT", root)
    monkeypatch.setattr(repair, "LAUNCHER", path)
    return original


def legacy_launcher(original: bytes) -> Path:
    directory = repair.ROOT / "diagnostic-launcher"
    directory.mkdir(mode=0o700)
    saved = directory / "original.py"
    saved.write_bytes(original)
    saved.chmod(0o600)
    repair.LAUNCHER.write_bytes(repair.instrument(original))
    return saved


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("phase", [RestorePhase.INSTALLED, RestorePhase.VERIFIED])
def test_diagnostic_backup_preserves_evidence_and_allows_native_completion(
    launcher: bytes, legacy: bool, phase: RestorePhase
) -> None:
    formats = {
        "backupDescriptor": "lowerduckpond-static-backup-v1",
        "repository": "lowerduckpond-backup-repository-binding-v1",
        "originalArtifact": "lowerduckpond-static-host-agent-artifact-v1",
        "trustedInputs": "lowerduckpond-host-restore-inputs-v1",
        "destination": "lowerduckpond-host-restore-destination-v1",
        "sourceFence": "lowerduckpond-host-restore-source-fence-v1",
    }
    journal = RestoreJournal(
        RESTORE,
        "a" * 64,
        "0198d17f-6f4a-7000-8000-000000000002",
        "0198d17f-6f4a-7000-8000-000000000003",
        {key: framed_digest(value, b"synthetic bound input") for key, value in formats.items()},
    )
    with RestoreStore.locked(repair.ROOT, owner=os.geteuid()) as store:
        close_gate(store, RESTORE)
        store.begin(journal)
        for step in PHASES[1 : PHASES.index(phase) + 1]:
            journal = store.advance(
                journal, step, {"decisions": []} if step is RestorePhase.RECONCILED else {}
            )
        before = {path.name: path.read_bytes() for path in repair.ROOT.iterdir()}
        inode = legacy_launcher(launcher).stat().st_ino if legacy else None
        if legacy and phase is RestorePhase.VERIFIED:
            with pytest.raises(HostRestoreError, match="restore_provenance_file_unsafe"):
                seal_provenance(store)
        assert repair.preserve_launcher(RESTORE, owner=os.geteuid()) == launcher
        repair.LAUNCHER.write_bytes(repair.instrument(launcher))
        assert repair.preserve_launcher(RESTORE, owner=os.geteuid()) == launcher
        assert {path.name: path.read_bytes() for path in repair.ROOT.iterdir()} == before
        saved = repair.ROOT.with_name("recovery-diagnostic-launcher-" + RESTORE) / "original.py"
        assert saved.read_bytes() == launcher
        if legacy:
            assert saved.stat().st_ino == inode
        if journal.phase is RestorePhase.INSTALLED:
            journal = store.advance(journal, RestorePhase.VERIFIED, {})
        digest = seal_provenance(store)
        store.advance(journal, RestorePhase.COMPLETE, {"provenanceInventory": digest})
        open_gate(store)
    require_backup_provenance(repair.ROOT, owner=os.geteuid())


@pytest.mark.parametrize(
    "damage", ["unknown-file", "symlink", "hardlink", "mode", "launcher", "collision"]
)
def test_legacy_migration_refuses_ambiguous_or_changed_backup(
    launcher: bytes, tmp_path: Path, damage: str
) -> None:
    saved = legacy_launcher(launcher)
    if damage == "unknown-file":
        (saved.parent / "unclassified-evidence").write_bytes(b"preserve")
    elif damage == "symlink":
        saved.rename(tmp_path / "original.py")
        saved.symlink_to(tmp_path / "original.py")
    elif damage == "hardlink":
        os.link(saved, tmp_path / "original.py")
    elif damage == "mode":
        saved.chmod(0o666)
    elif damage == "launcher":
        repair.LAUNCHER.write_bytes(b"changed launcher")
    else:
        repair.ROOT.with_name("recovery-diagnostic-launcher-" + RESTORE).mkdir(mode=0o700)
    before = repair.LAUNCHER.read_bytes()
    with pytest.raises((ValueError, FileExistsError)):
        repair.preserve_launcher(RESTORE, owner=os.geteuid())
    assert saved.read_bytes() == launcher
    assert repair.LAUNCHER.read_bytes() == before


def test_migration_resumes_after_rename_before_directory_sync(
    launcher: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = legacy_launcher(launcher)
    original_inode = saved.stat().st_ino
    original_sync = os.fsync

    def interrupted(fd: int) -> None:
        raise OSError("injected interruption after rename")

    monkeypatch.setattr(os, "fsync", interrupted)
    with pytest.raises(OSError, match="injected interruption"):
        repair.preserve_launcher(RESTORE, owner=os.geteuid())
    assert not saved.parent.exists()
    monkeypatch.setattr(os, "fsync", original_sync)
    assert repair.preserve_launcher(RESTORE, owner=os.geteuid()) == launcher
    destination = repair.ROOT.with_name("recovery-diagnostic-launcher-" + RESTORE) / "original.py"
    assert destination.stat().st_ino == original_inode


def test_original_launcher_verification_and_argument_binding_are_preserved() -> None:
    source = Path("config/ansible/roles/host_recovery/templates/host-restore-agent.j2").read_text()
    original = (
        Environment(autoescape=False)  # noqa: S701 - Python source, not HTML
        .from_string(source)
        .render(item={"mode": "coordinator", "function": "restore_coordinator_main"})
        .encode()
    )
    updated = repair.instrument(original)
    assert (
        updated[: updated.index(repair.MARKER.encode())]
        == original[: original.index(repair.TAIL.encode())]
    )
    assert updated.rstrip().endswith(repair.TAIL.encode())
    assert b"selected_artifact()" in updated[: updated.index(repair.MARKER.encode())]
    with pytest.raises(ValueError):
        repair.instrument(updated)
    with pytest.raises(ValueError):
        repair.instrument(b"print('unrelated launcher')\n")


@pytest.mark.parametrize("failure", [False, True])
def test_real_observer_keeps_exceptions_drains_health_and_reports_waiting_stack(
    tmp_path: Path, failure: bool
) -> None:
    # A fast sampler exercises the same bounded loop without a 30-second test.
    observer = repair.OBSERVER.replace("time.sleep(30)", "time.sleep(0.02)")
    driver = """import json, time
from types import SimpleNamespace
from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent import host_restore_coordinator as coordinator
for name in ("ORDINARY_ACTIVATORS", "ORDINARY_SERVICES", "_PATTERNS"):
    setattr(services, name, tuple(unit for unit in getattr(services, name) if "health" not in unit))
commands = []
def command(args, **kwargs):
    commands.append(args)
    return b""
services.require_command = command
services._units = lambda: {"lowerduckpond-health.service": "inactive"}
_SELECTION_FD, _ARTIFACT = 123, SimpleNamespace(name="original-artifact")
def restore_coordinator_main(fd, artifact):
    assert fd == 123 and artifact == "original-artifact"
    secret = "private-local-canary"
    services.quiesce_host(caddy=False)
    with coordinator.verification_step("installed-audit"):
        time.sleep(0.12)
        if FAILURE:
            raise RuntimeError("private-exception-canary")
    services.restore_schedules(audit_rotation=True)
    print(json.dumps(commands))
    return 0
""".replace("FAILURE", str(failure))
    script = tmp_path / "host-restore-coordinator"
    script.write_bytes(
        repair.instrument((driver + repair.TAIL).encode()).replace(
            repr(repair.OBSERVER).encode(), repr(observer).encode()
        )
    )
    invocation = "a" * 32
    result = subprocess.run(  # noqa: S603 - local instrumented fixture, no providers
        [sys.executable, str(script)],
        env={**os.environ, "INVOCATION_ID": invocation},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == int(failure)
    events = [
        trace.event(line.removeprefix(trace.PREFIX), invocation)
        for line in result.stderr.splitlines()
        if line.startswith(trace.PREFIX)
    ]
    assert events and all(event is not None for event in events)
    assert any(
        event and event["event"] == "sample" and event["step"] == "installed-audit"
        for event in events
    )
    assert "private-local-canary" not in json.dumps(events)
    assert "private-exception-canary" not in json.dumps(events)
    if failure:
        assert "RuntimeError: private-exception-canary" in result.stderr
        assert "host_restore_step_failed step=installed-audit" in result.stderr
    else:
        commands = json.loads(result.stdout)
        assert any(
            row[:2] == ["/usr/bin/systemctl", "stop"] and "lowerduckpond-health.service" in row
            for row in commands
        )
        assert any(
            row[:2] == ["/usr/bin/systemctl", "start"] and "lowerduckpond-health.timer" in row
            for row in commands
        )


@pytest.mark.parametrize("unit", repair.UNITS)
def test_health_admission_preserves_merged_gate_requirements(unit: str) -> None:
    source = Path(
        "config/ansible/roles/host_recovery/templates/restore-admission.conf.j2"
    ).read_text()
    native = Environment(autoescape=False).from_string(source).render(item=unit)  # noqa: S701 - systemd configuration
    lines = [line for line in native.splitlines() if line and not line.startswith("#")]
    assert repair.admission(unit).decode().splitlines() == lines
