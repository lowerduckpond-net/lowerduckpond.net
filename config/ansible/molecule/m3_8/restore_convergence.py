"""Bound destination convergence, including children of the tool launcher."""

from __future__ import annotations

import os
import signal
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO


def run(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log: BinaryIO,
    timeout: float = 600,
) -> int:
    with subprocess.Popen(  # noqa: S603 - fixed playbook and owned fixture inventory
        arguments,
        cwd=cwd,
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    ) as process:
        try:
            return process.wait(timeout=timeout)
        finally:
            # Killing only uv leaves Ansible able to mutate a failed fixture
            # after the controller releases its qualification lease.
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
