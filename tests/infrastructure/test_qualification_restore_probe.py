"""Restore failure labels are bounded, invocation-bound, and contain no raw log."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.host_restore_diagnostics import VERIFICATION_STEPS

from scripts import qualification_restore_probe as probe
from scripts.qualification_probe import CATEGORIES


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("host_restore_step_failed step=installed-audit\n", "installed-audit"),
        ("host_restore_step_failed step=caddy-start\n", "caddy-start"),
        ("host_restore_step_failed step=private-secret\n", "unknown"),
        ("host_restore_step_failed step=tls private-content\n", "unknown"),
        ("host_restore_step_failed step=tls\nprivate-content\n", "unknown"),
        ("", "unknown"),
    ],
)
def test_failure_step_requires_exact_label_from_original_invocation(
    message: str, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert "_SYSTEMD_INVOCATION_ID=" + "a" * 32 in args
        assert "--unit=lowerduckpond-host-restore.service" in args
        assert "--lines=1" in args
        assert kwargs["timeout"] == 3  # noqa: PLR2004 - fixed read-only command deadline
        assert next(arg for arg in args if arg.startswith("--grep=")).endswith(")$")
        return subprocess.CompletedProcess(args, 0, message, "private stderr")

    assert probe.VERIFICATION_STEPS == VERIFICATION_STEPS
    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe.failed_step("a" * 32) == expected
    assert probe.failed_step("private invocation") == "unknown"
    assert len(calls) == 1


def test_journal_unavailability_stays_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("private command", 3, output="private output")

    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe.failed_step("a" * 32) == "unknown"


@pytest.mark.parametrize("state", ["failed", "activating", "inactive"])
def test_observation_reports_helpers_and_uses_only_the_current_failed_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    (tmp_path / "host-restore.json").write_text(json.dumps({"phase": "installed"}))
    (tmp_path / "restore-gate.json").touch()
    monkeypatch.setattr(probe, "Path", lambda value: tmp_path / Path(value).name)
    monkeypatch.setattr(probe.signal, "alarm", lambda _: 0)
    observed = []
    monkeypatch.setattr(
        probe, "failed_step", lambda invocation: observed.append(invocation) or "installed-archives"
    )

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[0] == "/usr/bin/journalctl":
            assert "--unit=" + probe.UNITS[1] in args
            assert "_SYSTEMD_INVOCATION_ID=" + "b" * 32 in args
            return subprocess.CompletedProcess(
                args, 0, "restore_archive_unverified restore_unverified category=state_busy", ""
            )
        assert args[0] == "/usr/bin/systemctl" and all(unit in args for unit in probe.UNITS)
        assert kwargs["timeout"] == 3  # noqa: PLR2004 - batch stays within original probe alarm
        rows = [
            f"Id={probe.UNITS[0]}\nLoadState=loaded\nActiveState={state}\nResult=exit-code\n"
            f"ExecMainStatus=1\nInvocationID={'a' * 32}\nExecMainStartTimestampMonotonic=10",
            f"Id={probe.UNITS[1]}\nLoadState=loaded\nActiveState=failed\nResult=oom-kill\n"
            f"ExecMainStatus=9\nInvocationID={'b' * 32}\nExecMainStartTimestampMonotonic=20",
            f"Id={probe.UNITS[2]}\nLoadState=not-found\nActiveState=inactive\nResult=success\n"
            "ExecMainStatus=0",
            f"Id={probe.UNITS[3]}\nLoadState=loaded\nActiveState=private-state\n"
            "Result=private-result\nExecMainStatus=private-exit",
        ]
        return subprocess.CompletedProcess(args, 0, "\n\n".join(rows), "private stderr")

    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.observe()
    assert result["phase"] == "installed" and result["gate_present"] is True
    assert result["failed_step"] == ("installed-archives" if state == "failed" else "unknown")
    assert observed == (["a" * 32] if state == "failed" else [])
    units = result["units"]
    assert isinstance(units, dict)
    assert units[probe.UNITS[1]] == {
        "state": "failed",
        "result": "oom-kill",
        "exit_status": 9,
        "failure_category": "state_busy",
    }
    for unit in probe.UNITS[2:]:
        assert units[unit] == {
            "state": "unknown",
            "result": "unknown",
            "exit_status": "unknown",
            "failure_category": "unknown",
        }
    for canary in ("private-state", "private-result", "private-exit", "private stderr"):
        assert canary not in json.dumps(result)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("restore_archive_unverified restore_unverified category=local_io", "local_io"),
        (
            "restore_archive_unverified restore_unverified category=provider_response "
            "operation=get_object code=access_denied http_status=403",
            "provider_response",
        ),
        ("restore_archive_unverified restore_unverified category=unexpected", "unexpected"),
        ("restore_archive_unverified restore_unverified category=private-value", "unknown"),
        (
            "restore_archive_unverified restore_unverified category=local_io private-value",
            "unknown",
        ),
        (
            "restore_archive_unverified restore_unverified category=local_io\nprivate-value",
            "unknown",
        ),
        ("", "unknown"),
    ],
)
def test_archive_category_is_allowlisted_and_bound_to_helper_invocation(
    message: str, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert "--unit=" + probe.UNITS[2] in args
        assert "_SYSTEMD_INVOCATION_ID=" + "b" * 32 in args
        assert "--lines=1" in args
        assert kwargs["timeout"] == 3  # noqa: PLR2004 - bounded journal collection
        return subprocess.CompletedProcess(args, 0, message, "private stderr")

    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe.ARCHIVE_CATEGORIES == CATEGORIES
    assert (
        probe.archive_failure_category(
            probe.UNITS[2],
            {
                "ActiveState": "failed",
                "InvocationID": "b" * 32,
                "ExecMainStartTimestampMonotonic": "20",
            },
            {"ExecMainStartTimestampMonotonic": "10"},
        )
        == expected
    )


@pytest.mark.parametrize(
    "override",
    [
        {"ActiveState": "activating"},
        {"InvocationID": "private-value"},
        {"ExecMainStartTimestampMonotonic": "9"},
        {"ExecMainStartTimestampMonotonic": "0"},
        {"ExecMainStartTimestampMonotonic": "private-value"},
    ],
)
def test_old_or_unbound_archive_failure_cannot_be_attributed_to_current_restore(
    override: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe.subprocess, "run", lambda *_a, **_k: pytest.fail("unbound journal"))
    helper = {
        "ActiveState": "failed",
        "InvocationID": "b" * 32,
        "ExecMainStartTimestampMonotonic": "20",
        **override,
    }
    assert (
        probe.archive_failure_category(
            probe.UNITS[2], helper, {"ExecMainStartTimestampMonotonic": "10"}
        )
        == "unknown"
    )
