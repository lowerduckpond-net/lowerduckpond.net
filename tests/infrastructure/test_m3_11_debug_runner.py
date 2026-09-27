"""Collect independent failures in one cycle and preserve private subprocess evidence."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_debug_runner as runner
from scripts.m3_11_private_inputs import PRIVATE_FILE_MODE, read_private, write_private


def stage_results(result: dict[str, object]) -> dict[str, dict[str, object]]:
    return cast("dict[str, dict[str, object]]", result["stages"])


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "attempts").mkdir(mode=0o700)
    return tmp_path


def test_multiple_failures_are_collected_before_stopping(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    visited = []

    def execute(command: list[str], log: Path, environment: dict[str, str], seconds: int) -> int:
        stage = command[-1]
        visited.append(stage)
        if stage in {"reconstruction", "reboot"}:
            write_private(log.with_suffix(".error.json"), {"exception": "AssertionError"})
            return 1
        return 0

    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(root, {}, start=None, guard=Mock(), prepare=Mock(), capture=Mock())
    assert visited == list(runner.STAGES)
    assert result["outcome"] == "diagnostic-incomplete"
    assert stage_results(result)["reconstruction"]["error"] == {"exception": "AssertionError"}
    assert stage_results(result)["public-ca"]["outcome"] == "passed"
    (attempt,) = (root / "attempts").iterdir()
    assert read_private(attempt / "summary.json") == result


def test_failed_restore_blocks_unsafe_downstream_stages(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock(return_value=1)
    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(root, {}, start=None, guard=Mock(), prepare=Mock(), capture=Mock())
    assert execute.call_count == 1
    assert stage_results(result)["replay"] == {"outcome": "blocked", "dependencies": ["restore"]}


def test_rerun_begins_at_first_failure_and_keeps_earlier_logs(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock(side_effect=[0, 1, 0, 0, 0, 0, 0])
    monkeypatch.setattr(runner, "execute", execute)
    runner.run(root, {}, start=None, guard=Mock(), prepare=Mock(), capture=Mock())
    (original,) = (root / "attempts").iterdir()
    original_bytes = (original / "summary.json").read_bytes()
    execute.reset_mock(side_effect=True)
    execute.return_value = 0
    result = runner.run(root, {}, start=None, guard=Mock(), prepare=Mock(), capture=Mock())
    assert execute.call_args_list[0].args[0][-1] == "reconstruction"
    assert stage_results(result)["restore"]["reused_diagnostic_observation"] is True
    assert result["outcome"] == "diagnostic-complete"
    assert result["qualification_authority"] == "none"
    assert (original / "summary.json").read_bytes() == original_bytes


def test_binding_loss_stops_mutation_but_still_emits_all_statuses(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock(return_value=0)
    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(
        root,
        {},
        start=None,
        guard=Mock(side_effect=[None, None, ValueError("secret")]),
        prepare=Mock(),
        capture=Mock(),
    )
    assert execute.call_count == 1
    assert "secret" not in str(result)
    assert stage_results(result)["replay"]["outcome"] == "blocked"
    assert result["controller_error"]


def test_collection_failure_does_not_hide_test_results(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "execute", Mock(return_value=0))
    result = runner.run(
        root,
        {},
        start=None,
        guard=Mock(),
        prepare=Mock(),
        capture=Mock(side_effect=OSError("private")),
    )
    assert result["outcome"] == "diagnostic-complete"
    (attempt,) = (root / "attempts").iterdir()
    assert (attempt / "before.collection-error.json").exists()


def test_timed_out_guest_action_prevents_overlapping_mutations(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock(return_value=124)
    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(root, {}, start=None, guard=Mock(), prepare=Mock(), capture=Mock())
    assert execute.call_count == 1
    assert result["outcome"] == "diagnostic-incomplete"


def test_subprocess_keeps_failure_output_private(root: Path) -> None:
    path = root / "failed.log"
    result = runner.execute(
        [sys.executable, "-c", "raise ValueError('private-canary')"], path, dict(os.environ), 10
    )
    assert result == 1
    assert "private-canary" in path.read_text()
    assert path.stat().st_mode & 0o777 == PRIVATE_FILE_MODE


def test_real_subprocess_timeout_is_bounded(root: Path) -> None:
    result = runner.execute(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        root / "timed-out.log",
        dict(os.environ),
        1,
    )
    assert result == runner.TIMED_OUT
