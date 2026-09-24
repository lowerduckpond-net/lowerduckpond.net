"""Bounded fixed-command children; provider or credential output stays private."""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from dataclasses import dataclass

from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError


@dataclass(frozen=True)
class RestoreCommandResult:
    status: int
    output: bytes


def run_bounded(
    command: tuple[str, ...],
    *,
    descriptors: tuple[int, ...] = (),
    timeout: int = 30,
    maximum: int = 256 * 1024,
) -> RestoreCommandResult:
    """Only internal, fixed commands call this; there is no shell interface."""
    with subprocess.Popen(  # noqa: S603 - fixed executable and validated internal arguments
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        pass_fds=descriptors,
    ) as process:
        assert process.stdout is not None  # noqa: S101 - PIPE supplied above
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        output = bytearray()
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(descriptor, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise HostRestoreError("restore_helper_deadline")
                    try:
                        data = os.read(descriptor, min(65536, maximum + 1 - len(output)))
                    except BlockingIOError:
                        continue
                    if not data:
                        break
                    output.extend(data)
                    if len(output) > maximum:
                        raise HostRestoreError("restore_helper_output_limit")
            return RestoreCommandResult(
                process.wait(timeout=max(0.0, deadline - time.monotonic())), bytes(output)
            )
        except subprocess.TimeoutExpired as error:
            raise HostRestoreError("restore_helper_deadline") from error
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def require_command(
    command: tuple[str, ...],
    *,
    descriptors: tuple[int, ...] = (),
    timeout: int = 30,
    maximum: int = 256 * 1024,
    failure: str = "restore_helper_failed",
) -> bytes:
    result = run_bounded(command, descriptors=descriptors, timeout=timeout, maximum=maximum)
    if result.status:
        raise HostRestoreError(failure)
    return result.output
