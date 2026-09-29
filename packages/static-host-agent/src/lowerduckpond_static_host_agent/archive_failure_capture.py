"""Best-effort, bounded private failure evidence for installed qualification.

Disabled outside explicitly configured fixtures. Never format exception messages,
source lines, locals, requests, or provider values, and never authorize recovery.
"""

from __future__ import annotations

import json
import os
import re
import stat
import traceback
from collections import deque
from contextvars import ContextVar
from pathlib import Path

ROOT = Path("/var/log/lowerduckpond-archive-failures")
MAX_BYTES = 64 * 1024
MAX_EVENTS = 8
OPERATIONS = ("construction", "cleanup", "export")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,99}")
_JOB: ContextVar[tuple[str, str]] = ContextVar(
    "archive_failure_job", default=("unknown", "unknown")
)


def reset() -> None:
    _JOB.set(("unknown", "unknown"))


def bind_job(document: dict[str, object], job_id: str) -> None:
    """Identify a decoded durable job, without implying permission to execute it."""
    request = document.get("request")
    correlation = request.get("correlationId") if isinstance(request, dict) else None
    if (
        document.get("jobId") == job_id
        and UUID.fullmatch(job_id)
        and isinstance(correlation, str)
        and UUID.fullmatch(correlation)
    ):
        _JOB.set((job_id, correlation))


def _chain(error: BaseException) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen and len(result) < 4:  # noqa: PLR2004
        seen.add(id(current))
        locations: deque[dict[str, object]] = deque(maxlen=12)
        for frame, line in traceback.walk_tb(current.__traceback__):
            name = Path(frame.f_code.co_filename).name
            if name.endswith(".py") and IDENTIFIER.fullmatch(name[:-3]) and 0 < line <= 1000000:  # noqa: PLR2004
                locations.append({"file": name, "line": line})
        exception = type(current).__name__
        result.append(
            {
                "exception": exception if IDENTIFIER.fullmatch(exception) else "unknown",
                "locations": list(locations),
            }
        )
        current = current.__cause__ or (
            None if current.__suppress_context__ else current.__context__
        )
    return result


def _metadata(item: os.stat_result) -> None:
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o600  # noqa: PLR2004
        or item.st_nlink != 1
        or item.st_size > MAX_BYTES
    ):
        raise ValueError("unsafe private archive failure file")


def _read(directory: int, name: str) -> list[object]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return []
    with os.fdopen(fd, "rb") as stream:
        _metadata(os.fstat(stream.fileno()))
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("oversized archive failure file")
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) > MAX_EVENTS:
        raise ValueError("invalid archive failure file")
    return value


def _write(operation: str, record: dict[str, object]) -> None:
    if ROOT.resolve() != ROOT:
        raise ValueError("redirected archive failure directory")
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        item = os.fstat(directory)
        if item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700:  # noqa: PLR2004
            raise ValueError("unsafe archive failure directory")
        name = operation + ".json"
        records = _read(directory, name)
        raw = json.dumps([*records[-(MAX_EVENTS - 1) :], record], sort_keys=True).encode() + b"\n"
        if len(raw) > MAX_BYTES:
            raise ValueError("oversized archive failure capture")
        # One service per operation is serialized by socket activation. The fixed
        # staging name bounds storage even after crashes; rename preserves the last
        # complete failure through an interrupted write. Successful calls do not
        # open or truncate these files. Cleanup has its own separate history.
        temporary = operation + ".next"
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(fd, "wb") as stream:
            _metadata(os.fstat(stream.fileno()))
            stream.truncate(0)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)


def capture(
    operation: str, error: BaseException, *, diagnostic: str = "category=unexpected"
) -> None:
    """Preserve the helper's original failure even if diagnostics are unavailable."""
    if os.environ.get("LDP_ARCHIVE_FAILURE_CAPTURE") != "1" or operation not in OPERATIONS:
        return
    try:
        invocation = os.environ.get("INVOCATION_ID", "")
        artifact = Path(__file__).resolve().parents[2].name
        job, correlation = _JOB.get()
        _write(
            operation,
            {
                "helper": operation,
                "invocation": invocation
                if re.fullmatch(r"[0-9a-f]{32}", invocation)
                else "unknown",
                "artifact_sha256": artifact
                if re.fullmatch(r"[0-9a-f]{64}", artifact)
                else "unknown",
                "job_id": job,
                "correlation_id": correlation,
                "chain": _chain(error),
                "diagnostic": diagnostic,
            },
        )
    except Exception:  # noqa: S110 - diagnostics must not expose or replace the original failure
        # No secondary error, retry, or changed service result on evidence failure.
        pass
