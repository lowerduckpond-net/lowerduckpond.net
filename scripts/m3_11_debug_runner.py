"""Run independent diagnostic stages, retaining every attempt and raw log privately."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
import traceback
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

from scripts.m3_11_debug_capture import exception
from scripts.m3_11_debug_files import FORMAT, replace_private
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_storage_lease import FD_ENV

STAGES = {
    "restore": (),
    "reconstruction": ("restore",),
    "reboot": ("restore",),
    "replay": ("restore",),
    "public-ca": ("restore",),
    "accounting": ("restore",),
    "teardown-check": ("replay", "public-ca", "accounting"),
}
TIMEOUTS = {
    **dict.fromkeys(STAGES, 1900),
    "replay": 5400,
    "accounting": 600,
    "teardown-check": 600,
    "repair": 300,
}
TIMED_OUT = 124


def execute(command: list[str], log: Path, environment: Mapping[str, str], seconds: int) -> int:
    """Drain the local process group before any subsequent stage starts."""
    with log.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        child = subprocess.Popen(  # noqa: S603 - fixed diagnostic stage entry point
            command,
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
            pass_fds=(int(environment[FD_ENV]),) if FD_ENV in environment else (),
        )
        try:
            return child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=15)
            return TIMED_OUT
        finally:
            # A subprocess may exit while a helper remains in its process group.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=15)


def run(  # noqa: PLR0913, PLR0915 - explicit injectable stage runner and final report
    root: Path,
    environment: dict[str, str],
    *,
    start: str | None,
    guard: Callable[[], object],
    prepare: Callable[[Path], None],
    capture: Callable[[Path, str], None],
    repair: bool = False,
) -> dict[str, object]:
    attempt = root / "attempts" / uuid.uuid7().hex
    attempt.mkdir(mode=0o700)
    print(f"Private diagnostic logs: {attempt}", flush=True)
    progress: dict[str, dict[str, object]] = {}
    fatal: dict[str, object] = {}
    active = False

    def checkpoint(label: str) -> None:
        try:
            capture(attempt, label)
        except Exception as error:
            write_private(attempt / (label + ".collection-error.json"), exception(error))

    try:
        prepare(attempt)
        guard()
        checkpoint("before")
        stages = {"repair": (), **STAGES} if repair else STAGES
        for stage, dependencies in stages.items():
            previous = root / (stage + ".latest.json")
            prior = read_private(previous) if previous.exists() else {"outcome": "unknown"}
            active = active or stage == start or (start is None and prior["outcome"] != "passed")
            if not active and stage != "repair":
                progress[stage] = {**prior, "reused_diagnostic_observation": True}
                continue
            guard()
            blocked = [name for name in dependencies if progress[name]["outcome"] != "passed"]
            if blocked:
                progress[stage] = {"outcome": "blocked", "dependencies": blocked}
                continue
            opening = time.monotonic()
            print(f"Diagnostic stage: {stage}", flush=True)
            status = execute(
                [
                    sys.executable,
                    "-m",
                    "scripts.m3_11_debug_stages",
                    str(root),
                    str(attempt),
                    stage,
                ],
                attempt / (stage + ".log"),
                environment,
                TIMEOUTS[stage],
            )
            value: dict[str, object] = {
                "outcome": "passed" if status == 0 else "failed",
                "exit_status": status,
                "elapsed_seconds": round(time.monotonic() - opening, 1),
            }
            for suffix in ("error", "details"):
                path = attempt / (stage + "." + suffix + ".json")
                if path.exists():
                    value[suffix] = read_private(path)
                    if suffix == "details" and read_private(path).get("coverage_gaps"):
                        value["outcome"] = "failed"
            progress[stage] = value
            guard()
            checkpoint(stage)
            diagnostics = attempt / (stage + ".diagnostics.json")
            if diagnostics.exists() and value["outcome"] != "passed":
                value["diagnostics"] = read_private(diagnostics)
            write_private(attempt / (stage + ".json"), value)
            replace_private(root / (stage + ".latest.json"), value)
            if status == TIMED_OUT or (stage == "repair" and status):
                # A timed out docker exec can leave a guest process behind.
                # Retain its checkpoint; do not overlap a new mutating stage.
                raise TimeoutError("diagnostic action must be settled before continuation")
    except Exception as error:
        fatal = exception(error)
        with (attempt / "controller-error.log").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            traceback.print_exc(file=stream)
    finally:
        for stage in STAGES:
            progress.setdefault(stage, {"outcome": "blocked", "dependencies": ["controller"]})
        result: dict[str, object] = {
            "format": FORMAT,
            "qualification_authority": "none",
            "stages": progress,
            "controller_error": fatal,
            "outcome": "diagnostic-complete"
            if not fatal and all(row["outcome"] == "passed" for row in progress.values())
            else "diagnostic-incomplete",
        }
        write_private(attempt / "summary.json", result)
    return result
