from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

_SUPPORT = (
    Path(__file__).parents[2] / "config/ansible/molecule/m3_8/tests/archive_capture_support.py"
)


@pytest.mark.parametrize(
    "failure",
    [None, "convergence", "closed gate", "reconcile", "failed result", "unvalidated result"],
)
def test_capture_waits_for_convergence_and_validated_recovery(  # noqa: PLR0915 - coordinated boundaries
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    # Load the real coordinator with boundary doubles, without importing the
    # installed pytest modules (whose names overlap the ordinary unit suite).
    manifest = {"source": "unchanged archived tenant"}
    events: list[str] = []
    host = Mock()
    process = Mock(returncode=0)
    process.poll.return_value = 0

    def communicate(*, timeout: int) -> tuple[str, str]:
        assert timeout > 0
        events.append("capture released")
        return json.dumps({"manifest": manifest}), ""

    process.communicate.side_effect = communicate
    host.file.return_value.exists = False
    support = Mock(STATE_ROOT="/state", PUBLICATION_GATE="/gate")
    support._issue_without_handoff.return_value = "job"

    def read_state(_host: object, path: str) -> dict[str, object]:
        if path.endswith("/jobs/job.json"):
            return {
                "phase": "completed",
                "executionValidated": failure != "unvalidated result",
            }
        return manifest

    support._read_state.side_effect = read_state

    def host_run(command: str, *_args: object) -> SimpleNamespace:
        rc = 0
        if command == "%s job-issuance":
            assert events[-1] == "convergence completed"
            events.append("gate checked")
            rc = int(failure == "closed gate")
        elif command == "systemctl start --wait lowerduckpond-static-reconcile.service":
            assert events[-1] == "gate checked"
            events.append("reconcile")
            rc = int(failure == "reconcile")
        return SimpleNamespace(rc=rc, stderr=failure or "")

    host.run.side_effect = host_run

    def converge_result(*, timeout: int) -> subprocess.CompletedProcess[str]:
        assert timeout > 0
        assert events[-1] == "capture released"
        events.append("convergence completed")
        return subprocess.CompletedProcess(
            ["molecule", "converge"],
            int(failure == "convergence"),
            "convergence output",
            "convergence failure" if failure == "convergence" else "",
        )

    future = Mock()
    future.done.return_value = False
    future.result.side_effect = converge_result
    pool = Mock()
    pool.submit.return_value = future
    executor = Mock()
    executor.__enter__ = Mock(return_value=pool)
    executor.__exit__ = Mock(return_value=False)

    def await_result(_host: object, _job: str) -> dict[str, object]:
        # Model convergence outlasting the ordinary 60-second result deadline:
        # no durable result exists while publication is deliberately closed.
        assert "convergence completed" in events, "result deadline preceded convergence"
        assert events[-1] == "reconcile"
        events.append("durable result")
        return {"status": "failed" if failure == "failed result" else "succeeded"}

    recovery = Mock()
    recovery._await_result.side_effect = await_result
    for name, module in (
        ("test_export_import", Mock()),
        ("test_lifecycle", support),
        ("test_transport_recovery", recovery),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    namespace = runpy.run_path(str(_SUPPORT))
    exercise = namespace["exercise_capture_exclusion"]
    monkeypatch.setitem(exercise.__globals__, "_archived_capture", Mock(return_value=process))
    monkeypatch.setitem(exercise.__globals__, "ThreadPoolExecutor", Mock(return_value=executor))
    monkeypatch.setitem(exercise.__globals__, "time", Mock())

    if failure is None:
        assert exercise(host, {"tenantId": "tenant"}, archived=True, ansible_overlap=True) == {
            "status": "succeeded"
        }
        assert events == [
            "capture released",
            "convergence completed",
            "gate checked",
            "reconcile",
            "durable result",
        ]
        recovery._await_authorization_quiescent.assert_called_once_with(host, "job")
    else:
        with pytest.raises(AssertionError, match=failure if failure == "convergence" else None):
            exercise(host, {"tenantId": "tenant"}, archived=True, ansible_overlap=True)
        if failure in {"convergence", "closed gate", "reconcile"}:
            recovery._await_result.assert_not_called()
