"""Retain only the installed successor's nested task identity and counters."""

from __future__ import annotations

import os
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ansible.plugins.callback import CallbackBase  # type: ignore[import-untyped]

# Callback discovery may execute outside the checkout's Python import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from scripts.m3_11_production_converge import COUNTERS
from scripts.m3_12_diagnostic_store import publish
from scripts.m3_12_installed import (
    APPLY_STAGE_ENV,
    APPLY_STAGES,
    PROGRESS_DIRECTORY,
    PROGRESS_ROOT_ENV,
)
from scripts.qualification_failure import ansible_failure_category
from scripts.qualification_task_timing import ACTIONS, task_source

if TYPE_CHECKING:
    from ansible.executor.stats import AggregateStats  # type: ignore[import-untyped]
    from ansible.playbook.task import Task  # type: ignore[import-untyped]


class CallbackResult(Protocol):
    _task: Task
    _result: dict[str, object]


DOCUMENTATION = """
name: ldp_m3_12_successor
type: aggregate
short_description: Installed successor convergence diagnostics
version_added: '1.0'
description: Retain only the first failed task identity and aggregate counts.
requirements:
  - Enabled only by the owned installed successor verifier.
"""
LAUNCH_DENIAL = ("launch_authority_unavailable", "launch_authority_unavailable\n")


class CallbackModule(CallbackBase):  # type: ignore[misc]
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "ldp_m3_12_successor"
    CALLBACK_NEEDS_ENABLED = True
    _failure_retained = False

    def _retain(self, kind: str, fields: dict[str, object]) -> bool:
        stage = os.environ.get(APPLY_STAGE_ENV)
        root = os.environ.get(PROGRESS_ROOT_ENV)
        if stage not in APPLY_STAGES or not root:
            return False
        directory = Path(root) / PROGRESS_DIRECTORY
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            publish(
                directory,
                f"{stage}-ansible-{kind}.json",
                {
                    "format": "lowerduckpond-m3-12-successor-ansible-v1",
                    "authority": "diagnostic-only",
                    "stage": stage,
                    **fields,
                },
            )
        except OSError, ValueError:
            with suppress(OSError):
                print("Installed successor Ansible diagnostic unavailable.", file=sys.stderr)
            return False
        return True

    def _first_failure(self, result: CallbackResult, outcome: str) -> None:
        if self._failure_retained:
            return
        source, line = task_source(result._task.get_path())
        full_action: str = result._task.action
        action = full_action.rsplit(".", 1)[-1]
        values = (
            {} if result._task.no_log or result._result.get("_ansible_no_log") else result._result
        )
        category = (
            "launch-authority-unavailable"
            if values.get("stderr") in LAUNCH_DENIAL
            else ansible_failure_category(full_action, values, outcome)
        )
        self._failure_retained = self._retain(
            "failure",
            {
                "task": {
                    "source": source,
                    "line": line,
                    "action": action
                    if action in ACTIONS | {"assert", "fail", "systemd_service"}
                    else "other",
                    "category": category,
                }
            },
        )

    def v2_runner_on_failed(self, result: CallbackResult, ignore_errors: bool = False) -> None:
        if not ignore_errors:
            self._first_failure(result, "failed")

    def v2_runner_on_unreachable(self, result: CallbackResult) -> None:
        self._first_failure(result, "unreachable")

    def v2_playbook_on_stats(self, stats: AggregateStats) -> None:
        hosts = [stats.summarize(host) for host in stats.processed]
        counts = {key: sum(row[key] for row in hosts) for key in COUNTERS}
        self._retain("recap", {"counts": counts})
