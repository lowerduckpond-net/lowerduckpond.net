"""Test-run-only timing; no task parameters, results, host names, or exceptions."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from ansible.plugins.callback import CallbackBase  # type: ignore[import-untyped]

# The controller loads callbacks outside the repository's Python import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from scripts.qualification_timing import EVENT_ENV, record_span

if TYPE_CHECKING:
    from ansible.executor.stats import AggregateStats  # type: ignore[import-untyped]
    from ansible.playbook import Playbook  # type: ignore[import-untyped]
    from ansible.playbook.task import Task  # type: ignore[import-untyped]

DOCUMENTATION = """
name: ldp_timing
type: aggregate
short_description: Allowlisted qualification timings
version_added: '1.0'
description: Monotonic diagnostic spans for explicitly instrumented test runs.
requirements:
  - Enabled only by the qualification timing entry point.
"""
REBOOT_TASKS = {
    "Reboot the disposable systemd host": "reboot",
    "Wait for immutable Caddy to return after reboot": "reboot-caddy",
    "Wait for startup reconciliation to complete after reboot": "reboot-reconcile",
}
PHASES = frozenset({"create", "prepare", "converge", "verify", "destroy", "cleanup"})


class CallbackModule(CallbackBase):  # type: ignore[misc]
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "ldp_timing"
    CALLBACK_NEEDS_ENABLED = True

    def v2_playbook_on_start(self, playbook: Playbook) -> None:
        self._timing_start = time.monotonic_ns()
        name = Path(playbook._file_name).stem
        self._timing_phase = name if name in PHASES else "other-playbook"
        if name == "converge" and any("molecule-idempotence-notest" in arg for arg in sys.argv):
            self._timing_phase = "idempotence"
        self._reboot_timing: tuple[str, int] | None = None

    def v2_playbook_on_task_start(self, task: Task, is_conditional: bool) -> None:
        self._reboot_timing = None
        name = task.get_name().strip()
        if name in REBOOT_TASKS and os.environ.get(EVENT_ENV):
            self._reboot_timing = REBOOT_TASKS[name], time.monotonic_ns()

    def _finish_reboot(self, outcome: str) -> None:
        if self._reboot_timing:
            label, start = self._reboot_timing
            record_span(label, start, outcome)
            self._reboot_timing = None

    def v2_runner_on_ok(self, result: object) -> None:
        self._finish_reboot("completed")

    def v2_runner_on_failed(self, result: object, ignore_errors: bool = False) -> None:
        self._finish_reboot("failed")

    def v2_runner_on_skipped(self, result: object) -> None:
        self._reboot_timing = None

    def v2_runner_on_unreachable(self, result: object) -> None:
        self._finish_reboot("failed")

    def v2_playbook_on_stats(self, stats: AggregateStats) -> None:
        failed = any(stats.failures.values()) or any(stats.dark.values())
        record_span(self._timing_phase, self._timing_start, "failed" if failed else "completed")
