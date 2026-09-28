"""Diagnostic instrumentation keeps native recovery authority and reports stalls."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jinja2 import Environment

from scripts import m3_11_debug_restore_repair as repair
from scripts import m3_11_debug_trace as trace


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
