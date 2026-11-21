"""Root-owned systemd checkpoint writer and fixed, secret-free export on installed guests."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

# The installed copy runs with Python isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.m3_12_diagnostic_store import (
    MAX_BYTES,
    UUID7,
    Attempt,
    clock,
    encode,
    failure,
    process_status,
    projection,
)

ROOT = Path(__file__).resolve().parents[1]
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
DIGEST = re.compile(r"[0-9a-f]{64}")
CAUSES = frozenset(
    {
        "timeout",
        "connection",
        "process",
        "protocol",
        "schema",
        "permission",
        "integrity",
        "conflict",
        "unsafe-state",
        "capacity",
        "missing",
        "unexpected",
    }
)


def guest_attempt(run: str, invocation: str, *, create: bool) -> Attempt:
    if not UUID7.fullmatch(run) or not UUID7.fullmatch(invocation) or invocation != ROOT.name:
        raise ValueError("guest diagnostic identity changed")
    directory = ROOT / "evidence" / run / invocation
    if create:
        directory.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
        directory.mkdir(mode=0o700)
        for parent in (ROOT, directory.parent.parent, directory.parent):
            descriptor = os.open(parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    return Attempt(directory)


def observe(run: str, invocation: str, action: Callable[[], None]) -> int:
    attempt = guest_attempt(run, invocation, create=True)
    start = clock()
    attempt.append("bootstrap", "systemd", start)
    try:
        action()
    except Exception as error:
        incident = failure("primary", "process", "systemd", error)
        attempt.append("bootstrap", "systemd", start, status=1, incident=incident, original=True)
        return 1
    attempt.append("bootstrap", "systemd", start, status=0, original=True)
    return 0


def numeric(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def causes(items: object) -> bool:
    if not isinstance(items, list) or not 1 <= len(items) <= 32:  # noqa: PLR2004 - contract bound
        return False
    return all(
        isinstance(item, dict)
        and set(item) <= {"type", "operation", "frames", "errno"}
        and isinstance(item.get("type"), str)
        and item["type"] in CAUSES
        and item.get("operation") == "systemd"
        and ("errno" not in item or numeric(item["errno"], 1, 4095))
        and isinstance(item.get("frames"), list)
        and len(item["frames"]) <= 32  # noqa: PLR2004 - contract bound
        and all(
            isinstance(frame, dict)
            and set(frame) == {"sourceSha256", "symbolId", "line"}
            and isinstance(frame["sourceSha256"], str)
            and DIGEST.fullmatch(frame["sourceSha256"])
            and numeric(frame["symbolId"], 1, 65535)
            and numeric(frame["line"], 1, 1_000_000)
            for frame in item["frames"]
        )
        for item in items
    )


def export_record(attempt: Attempt, slot: str) -> dict[str, Any]:
    if slot not in {"start", "result"}:
        raise ValueError("invalid guest checkpoint kind")
    record = attempt.record("0000000000.json" if slot == "start" else "original.json")
    summary = projection(record)
    if record.get("operation") != "systemd" or record.get("stage") != "bootstrap":
        raise ValueError("invalid native guest checkpoint")
    # Reconstruct the exact emitted subset before this record crosses transport.
    started, started_ms = record.get("startedAt"), record.get("startedMonotonicMs")
    if (
        not isinstance(started, str)
        or not STAMP.fullmatch(started)
        or type(started_ms) is not int
        or not numeric(started_ms, 0, 2**53 - 1)
    ):
        raise ValueError("invalid checkpoint clock")
    expected: dict[str, Any] = {
        "format": record["format"],
        "runId": record["runId"],
        "invocationId": record["invocationId"],
        "stage": "bootstrap",
        "operation": "systemd",
        "sequence": summary["checkpoint"],
        "startedAt": started,
        "startedMonotonicMs": started_ms,
        "attempts": 1,
        "inspection": "inspect",
        "failures": [],
        "terminalEvidence": "missing",
        "outcome": "uncertain",
        "result": "unknown",
        "omissions": ["no-terminal-evidence"],
    }
    if slot == "result":
        finished, ended = record.get("finishedAt"), record.get("finishedMonotonicMs")
        process = record.get("process")
        if (
            not isinstance(finished, str)
            or not STAMP.fullmatch(finished)
            or finished < started
            or not numeric(ended, started_ms, 2**53 - 1)
            or not isinstance(process, dict)
            or not numeric(process.get("exit"), 0, 255)
        ):
            raise ValueError("invalid terminal guest checkpoint")
        code = process["exit"]
        expected.update(
            finishedAt=finished,
            finishedMonotonicMs=ended,
            terminalEvidence="recorded",
            outcome="known",
            result="failed" if code else "passed",
            process=process_status(code),
            omissions=[],
        )
        if code:
            failures = record.get("failures")
            if (
                not isinstance(failures, list)
                or len(failures) != 1
                or not isinstance(incident := failures[0], dict)
                or set(incident) != {"role", "category", "prerequisite", "causes"}
                or incident.get("role") != "primary"
                or incident.get("category") != "process"
                or incident.get("prerequisite") != "other"
                or not causes(incident.get("causes"))
            ):
                raise ValueError("invalid native guest causes")
            expected["failures"] = failures
    if record != expected or len(encode(expected)) > MAX_BYTES:
        raise ValueError("invalid guest checkpoint")
    return expected


def main() -> int:
    try:
        mode, run, invocation, slot = sys.argv[1:]
        if mode != "export":
            raise ValueError("unsupported guest action")
        record = export_record(guest_attempt(run, invocation, create=False), slot)
        sys.stdout.buffer.write(encode(record))
        return 0
    except Exception:
        print("M3.12 guest checkpoint unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
