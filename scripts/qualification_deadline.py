"""Supervise the live M3.11 journey and retain diagnostics after bounded shutdown."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from types import FrameType

from scripts import qualification_budget as budget
from scripts import qualification_failure as failure
from scripts import qualification_timing as timing
from scripts.qualification_storage_lease import FD_ENV

ROOT = Path(__file__).resolve().parents[1]
CONTEXT_ENV = "LDP_QUALIFICATION_SUPERVISOR_CONTEXT"
LIVE_SECONDS = budget.LIVE_SECONDS
GRACE_SECONDS = 30
REPORT_SECONDS = 300
INTERRUPT_POLL_SECONDS = 1
MAX_CONTEXT_BYTES = 8192


@dataclass(frozen=True)
class Exit:
    status: int
    reason: str
    elapsed_seconds: float
    direct_child_reaped: bool


@dataclass
class Interruption:
    signum: int | None = None

    def result(self) -> tuple[int, str] | None:
        return (128 + self.signum, "interrupted") if self.signum is not None else None


@contextlib.contextmanager
def interrupts() -> Iterator[Interruption]:
    pending = Interruption()

    def stop(signum: int, _frame: FrameType | None) -> None:
        # Never unwind Popen before its handle is assigned, or interrupt cleanup.
        # Recording instead of masking also leaves the child's signal mask intact.
        if pending.signum is None:
            pending.signum = signum

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield pending
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _kill_group(child: subprocess.Popen[bytes], signum: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(child.pid, signum)


def _wait(
    child: subprocess.Popen[bytes], deadline_at: float, pending: Interruption
) -> tuple[int, str]:
    while True:
        if interrupted := pending.result():
            return interrupted
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            return 124, "deadline-exceeded"
        try:
            status = child.wait(timeout=min(remaining, INTERRUPT_POLL_SECONDS))
        except subprocess.TimeoutExpired:
            continue
        if interrupted := pending.result():
            return interrupted
        return (128 - status, "interrupted") if status < 0 else (status, "command-exit")


def execute(
    command: list[str],
    environment: Mapping[str, str],
    *,
    seconds: float,
    grace: float = GRACE_SECONDS,
) -> Exit:
    """Bound controller shutdown without replacing its result if reaping fails."""
    started = time.monotonic()
    reaped = True
    with interrupts() as pending:
        try:
            child = subprocess.Popen(  # noqa: S603 - fixed workflow or diagnostic reporter
                command,
                env=environment,
                cwd=ROOT,
                start_new_session=True,
                pass_fds=(int(environment[FD_ENV]),) if FD_ENV in environment else (),
            )
        except OSError:
            print("Qualification process could not be started.", file=sys.stderr)
            status, reason = pending.result() or (1, "command-exit")
            return Exit(status, reason, round(time.monotonic() - started, 3), True)
        try:
            status, reason = _wait(child, started + seconds, pending)
        finally:
            # A terminating shell can exit zero or leave children behind. Neither
            # changes the result. Further signals are recorded without unwinding
            # these bounded waits. Do not signal our caller.
            _kill_group(child, signal.SIGTERM)
            try:
                child.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
            finally:
                _kill_group(child, signal.SIGKILL)
                try:
                    child.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    reaped = False
                    print(
                        "Qualification child could not be reaped after SIGKILL; "
                        "original exit retained.",
                        file=sys.stderr,
                    )
    return Exit(status, reason, round(time.monotonic() - started, 3), reaped)


def record(directory: Path, phase: str) -> None:
    """Publish the allocated run and last entered phase through a private parent-owned channel."""
    if phase not in failure.PHASES:
        raise ValueError("unknown live qualification phase")
    path = Path(os.environ[CONTEXT_ENV])
    directory = directory.resolve(strict=True)
    raw = json.dumps(
        {"directory": str(directory), "phase": phase, "docker_host": os.environ["DOCKER_HOST"]}
    ).encode("ascii")
    if len(raw) > MAX_CONTEXT_BYTES:
        raise ValueError("live qualification context exceeds its bound")
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def context(path: Path) -> tuple[Path, str, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004
            or metadata.st_nlink != 1
        ):
            raise ValueError("unsafe live qualification context")
        raw = stream.read(MAX_CONTEXT_BYTES + 1)
    if len(raw) > MAX_CONTEXT_BYTES:
        raise ValueError("live qualification context exceeds its bound")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"directory", "phase", "docker_host"}
        or not isinstance(value["directory"], str)
        or not isinstance(value["phase"], str)
        or value["phase"] not in failure.PHASES
        or not isinstance(value["docker_host"], str)
        or not value["docker_host"].startswith("unix:///")
    ):
        raise ValueError("invalid live qualification context")
    directory = Path(value["directory"])
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise ValueError("live qualification context is redirected")
    return directory, value["phase"], value["docker_host"]


def report(directory: Path, phase: str, status: int, reason: str) -> None:
    os.environ[timing.EVENT_ENV] = str(directory / "timing-events.jsonl")
    if reason == "deadline-exceeded":
        failure.record_controller_stage("full-run-deadline")
        failure.record_controller_failure(
            subprocess.TimeoutExpired("live-qualification", LIVE_SECONDS)
        )
    try:
        if not (directory / "timing.json").exists():
            timing.finish_run(directory, status, interrupted=reason != "command-exit")
    except Exception:
        print("Qualification timing summary unavailable.", file=sys.stderr)
    if status:
        failure.collect(directory, status=status, phase=phase)


def run() -> int:
    """The fixed deadline includes setup; the separate diagnostic allowance grants no pass."""
    with contextlib.ExitStack() as stack:
        retained = os.environ.get("LDP_QUALIFICATION_CONTEXT_DIRECTORY")
        if retained:
            from scripts.m3_11_unattended.state import private_directory  # noqa: PLC0415

            private_directory(Path(retained))
            if (Path(retained) / "context.json").exists():
                raise ValueError("an interrupted qualification context cannot be replayed")
            temporary = retained
        else:
            temporary = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="ldp-qualification-supervisor-")
            )
        path = Path(temporary) / "context.json"
        environment = {**os.environ, CONTEXT_ENV: str(path)}
        result = execute(
            [str(ROOT / "scripts/m3-10-spaces-qualification"), "--milestone", "3.11"],
            environment,
            seconds=LIVE_SECONDS,
        )
        if result.reason == "deadline-exceeded":
            print(
                f"Qualification exceeded its {LIVE_SECONDS // 60}-minute full-run deadline.",
                flush=True,
            )
        try:
            directory, phase, endpoint = context(path)
            # The wrapper resolves and pins a local endpoint before allocation.
            # Its child-only exports cannot update this parent's environment.
            environment["DOCKER_HOST"] = endpoint
            environment.pop("DOCKER_CONTEXT", None)
            # Written before diagnostic collection, with the actual supervised
            # duration. Later read-only collection cannot extend this measurement.
            receipt = {
                "format": "lowerduckpond-qualification-exit-v1",
                "authority": "diagnostic-only",
                "limit_seconds": LIVE_SECONDS,
                "phase": phase,
                **asdict(result),
            }
            with (directory / "qualification-exit.json").open("x", encoding="ascii") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(receipt, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            observed = execute(
                [
                    sys.executable,
                    "-m",
                    "scripts.qualification_deadline",
                    "report",
                    str(directory),
                    phase,
                    str(result.status),
                    result.reason,
                ],
                environment,
                seconds=REPORT_SECONDS,
            )
            if observed.status or not observed.direct_child_reaped:
                print(
                    "Qualification diagnostic collection incomplete; original exit retained.",
                    file=sys.stderr,
                )
            if result.status:
                print(
                    "Qualification failed; no passing report was created.\n"
                    f"Private run logs: {directory}",
                    flush=True,
                )
        except Exception:
            print(
                "Qualification final diagnostics unavailable; original exit retained.",
                file=sys.stderr,
            )
        return result.status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action")
    record_parser = sub.add_parser("record")
    record_parser.add_argument("directory", type=Path)
    record_parser.add_argument("phase", choices=sorted(failure.PHASES))
    report_parser = sub.add_parser("report")
    report_parser.add_argument("directory", type=Path)
    report_parser.add_argument("phase", choices=sorted(failure.PHASES))
    report_parser.add_argument("status", type=int)
    report_parser.add_argument(
        "reason", choices=("command-exit", "deadline-exceeded", "interrupted")
    )
    args = parser.parse_args()
    if args.action == "record":
        record(args.directory, args.phase)
        return 0
    if args.action == "report":
        report(args.directory, args.phase, args.status, args.reason)
        return 0
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
