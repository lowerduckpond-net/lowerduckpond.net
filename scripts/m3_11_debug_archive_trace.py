"""Collect direct private helper logs and expose only invocation-bound locations."""

from __future__ import annotations

import json
import re
from pathlib import Path

OPERATIONS = ("construction", "cleanup", "export")
PREFIX = "ldp_debug_archive "
MAXIMUM = 256 * 1024
PROBE = b"""
import os, stat, sys
from pathlib import Path
root = Path('/var/log/lowerduckpond-debug-archive')
if root.exists() or root.is_symlink():
    item = root.lstat()
    if (root.resolve() != root or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != 0 or stat.S_IMODE(item.st_mode) != 0o700):
        raise ValueError('unsafe diagnostic log directory')
    for name in ('construction', 'cleanup', 'export'):
        fd = os.open(root / (name + '.log'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            item = os.fstat(stream.fileno())
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != 0
                    or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600):
                raise ValueError('unsafe diagnostic log file')
            stream.seek(max(0, item.st_size - 65536))
            raw = stream.read(65536)
        sys.stdout.buffer.write(name.encode() + b'\\n' + raw + b'\\n')
"""


def event(raw: str, invocation: str) -> dict[str, object] | None:
    try:
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"helper", "invocation", "chain"}
            or value["helper"] not in OPERATIONS
            or value["invocation"] != invocation
            or not isinstance(value["chain"], list)
            or not 1 <= len(value["chain"]) <= 4  # noqa: PLR2004 - bounded exception chain
        ):
            return None
        for cause in value["chain"]:
            if (
                not isinstance(cause, dict)
                or set(cause) != {"exception", "locations"}
                or not isinstance(cause["exception"], str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", cause["exception"]) is None
                or not isinstance(cause["locations"], list)
                or len(cause["locations"]) > 12  # noqa: PLR2004 - bounded traceback
            ):
                return None
            for frame in cause["locations"]:
                if (
                    not isinstance(frame, dict)
                    or set(frame) != {"file", "line"}
                    or not isinstance(frame["file"], str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}\.py", frame["file"]) is None
                    or type(frame["line"]) is not int
                    or not 0 < frame["line"] <= 1000000  # noqa: PLR2004
                ):
                    return None
        return {"helper": value["helper"], "chain": value["chain"]}
    except ValueError, TypeError, KeyError:
        return None


def summarize(log: Path, journal: Path) -> dict[str, object]:
    invocations = {}
    selected = ""
    with journal.open("rb") as stream:
        status = stream.read(2 * 1024 * 1024 + 1)
    if len(status) > 2 * 1024 * 1024:
        return {"collection": "oversized"}
    for line in status.decode(errors="replace").splitlines():
        if line.startswith("lowerduckpond-"):
            selected = next(
                (op for op in OPERATIONS if line == f"lowerduckpond-archive-{op}@request.service"),
                "",
            )
        if selected and re.fullmatch(r"InvocationID=[0-9a-f]{32}", line):
            invocations[selected] = line.removeprefix("InvocationID=")
    with log.open("rb") as stream:
        raw = stream.read(MAXIMUM + 1)
    if len(raw) > MAXIMUM:
        return {"collection": "oversized"}
    failures = {}
    for line in raw.decode(errors="replace").splitlines():
        if not line.startswith(PREFIX):
            continue
        for operation, invocation in invocations.items():
            value = event(line.removeprefix(PREFIX), invocation)
            if value and value["helper"] == operation:
                failures[operation] = value["chain"]
    return {"collection": "observed" if failures else "unavailable", "failures": failures}
