"""Secret-free failure projection for the installed successor audit unit."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.m3_12_audit_failure import PROPERTIES, SOURCE, UNIT, unit_failure, validated


def property_output(*values: object) -> str:
    return "\n".join(f"{key}={value}" for key, value in zip(PROPERTIES, values, strict=True))


def test_report_contains_only_failed_unit_status_and_fresh_category() -> None:
    report = unit_failure(
        property_output("loaded", "exit-code", 1, 42, 20, 30),
        10_000,
        (25_500, "archive-unavailable"),
        (499, 501),
    )
    assert report == {
        "observation": "correlated",
        "Result": "exit-code",
        "ExecMainCode": 1,
        "ExecMainStatus": 42,
        "protectionCategory": "archive-unavailable",
    }
    report["InvocationID"] = "synthetic-private-canary"
    report["protectionCategory"] = "another-synthetic-private-canary"
    assert validated(report) == {
        "observation": "correlated",
        "Result": "exit-code",
        "ExecMainCode": 1,
        "ExecMainStatus": 42,
    }


def test_old_context_and_unloaded_oneshot_cannot_supply_status() -> None:
    assert unit_failure(
        property_output("loaded", "exit-code", 1, 42, 20, 30),
        20_001,
        (25_500, "archive-unavailable"),
        (499, 501),
    ) == {"observation": "unattributed"}
    assert unit_failure(property_output("loaded", "success", 0, 0, 0, 0), 1, None, (0, 0)) == {
        "observation": "unloaded"
    }
    assert unit_failure("LoadState=not-found", 1, None, (0, 0)) == {"observation": "unloaded"}


def test_stale_too_new_or_unvalidated_protection_does_not_obscure_exit() -> None:
    raw = property_output("loaded", "exit-code", 1, 9, 20, 30)
    for protection in (
        (20_500, "verified"),
        (30_500, "protection"),
        (25_500, "synthetic-private-canary"),
        None,
    ):
        assert unit_failure(raw, 10_000, protection, (499, 501)) == {
            "observation": "correlated",
            "Result": "exit-code",
            "ExecMainCode": 1,
            "ExecMainStatus": 9,
        }
    assert validated({"observation": "correlated", "Result": "synthetic-private-canary"}) == {
        "observation": "unavailable"
    }


def test_callback_marks_only_the_fixed_audit_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The fixed task identity enables the readback without publishing private args."""
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path))
    plugin = import_module("config.ansible.plugins.callback.ldp_m3_12_successor")
    reports: list[dict[str, object]] = []

    def retain(kind: str, report: dict[str, object]) -> bool:
        assert kind == "failure"
        reports.append(report)
        return True

    task = SimpleNamespace(
        action="ansible.builtin.systemd_service",
        args={"name": UNIT, "state": "started", "_private": "synthetic-private-canary"},
        get_path=lambda: "source.yml:291",
        no_log=False,
    )
    result = SimpleNamespace(_task=task, _result={"msg": "another-synthetic-private-canary"})
    monkeypatch.setattr(plugin, "task_source", lambda _path: (SOURCE, 291))
    for state in ("started", "stopped"):
        task.args["state"] = state
        callback = plugin.CallbackModule()
        monkeypatch.setattr(callback, "_retain", retain)
        callback.v2_runner_on_failed(result)
    assert reports[0]["auditInitialization"] is True
    assert "auditInitialization" not in reports[1]
    assert "synthetic-private-canary" not in repr(reports)
