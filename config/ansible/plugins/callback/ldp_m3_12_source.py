"""Keep the last start and first reported task failure for the leased source play."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ansible.plugins.callback import CallbackBase  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent.durable import DurableDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from scripts.m3_12_diagnostic_store import encode
from scripts.qualification_task_timing import task_source

if TYPE_CHECKING:
    from ansible.playbook.task import Task  # type: ignore[import-untyped]


class CallbackResult(Protocol):
    _task: Task


DOCUMENTATION = """
name: ldp_m3_12_source
type: aggregate
short_description: Private source operator task observation
version_added: '1.0'
description: Record only checkout task locations and callback outcomes for the source operator.
"""


class CallbackModule(CallbackBase):  # type: ignore[misc]
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "ldp_m3_12_source"
    CALLBACK_NEEDS_ENABLED = True

    _last_started: dict[str, object] | None = None
    _first_failure: dict[str, object] | None = None

    def _observe(self, task: Task, event: str) -> None:
        if event != "started" and self._first_failure is not None:
            return
        source, line = task_source(task.get_path())
        location: dict[str, object] = {"source": source, "line": line}
        if event == "started":
            self._last_started = location
        else:
            self._first_failure = {**location, "outcome": event}
        path = Path(os.environ["LDP_M3_12_SOURCE_TASK_RECEIPT"])
        with DurableDirectory.open(
            path.parent, expected_owner=os.geteuid(), expected_directory_mode=0o700
        ) as retained:
            retained.replace(
                (path.name,),
                encode(
                    {
                        "contextSha256": os.environ["LDP_M3_11_PLAYBOOK_CONTEXT"],
                        "lastStarted": self._last_started,
                        "firstReportedFailure": self._first_failure,
                    }
                ),
            )

    def v2_runner_on_start(self, host: object, task: Task) -> None:
        self._observe(task, "started")

    def v2_runner_on_failed(self, result: CallbackResult, ignore_errors: bool = False) -> None:
        if not ignore_errors:
            self._observe(result._task, "failed")

    def v2_runner_on_unreachable(self, result: CallbackResult) -> None:
        if not result._task.ignore_unreachable:
            self._observe(result._task, "unreachable")
