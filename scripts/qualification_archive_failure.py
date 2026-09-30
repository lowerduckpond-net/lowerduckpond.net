"""Read bounded first-run archive evidence from each independently owned host."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from scripts import qualification_restore as owned
from scripts.m3_11_debug_archive_trace import OPERATIONS, event
from scripts.qualification_context import host_name
from scripts.qualification_probe import (
    DIGEST,
    UUID,
    bounded_command,
    diagnostic,
    document,
    safe_diagnostic,
)

MAX_EVENTS = 8
MAX_BYTES = 64 * 1024
PROBE = b"""
import json, os, stat
from pathlib import Path
root = Path('/var/log/lowerduckpond-archive-failures')
result = None
if root.exists() or root.is_symlink():
    result = {}
    item = root.lstat()
    if (root.resolve() != root or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != 0 or stat.S_IMODE(item.st_mode) != 0o700):
        raise ValueError('unsafe archive failure directory')
    for name in ('construction', 'cleanup', 'export'):
        try:
            fd = os.open(root / (name + '.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, 'rb') as stream:
            item = os.fstat(stream.fileno())
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_nlink != 1
                    or stat.S_IMODE(item.st_mode) != 0o600 or item.st_size > 65536):
                raise ValueError('unsafe archive failure file')
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('oversized archive failure file')
        result[name] = json.loads(raw)
print(json.dumps(result))
"""


def _diagnostic(detail: object) -> dict[str, object]:
    if isinstance(detail, str):
        return diagnostic(detail)
    if isinstance(detail, dict):
        return safe_diagnostic(detail)
    raise ValueError("invalid archive failure classification")


def sanitize(raw: bytes, correlation: str) -> dict[str, object]:
    if len(raw) > len(OPERATIONS) * MAX_BYTES + 1024:
        raise ValueError("oversized archive failure observation")
    document = json.loads(raw)
    if document is None:
        return {"collection": "unavailable"}
    if not isinstance(document, dict) or set(document) - set(OPERATIONS):
        raise ValueError("invalid archive failure observation")
    failures = []
    for helper, records in document.items():
        if not isinstance(records, list) or len(records) > MAX_EVENTS:
            raise ValueError("invalid archive failure history")
        for record in records:
            if not isinstance(record, dict) or set(record) != {
                "helper",
                "invocation",
                "artifact_sha256",
                "job_id",
                "correlation_id",
                "chain",
                "diagnostic",
            }:
                raise ValueError("invalid archive failure record")
            if record["helper"] != helper:
                raise ValueError("archive failure helper mismatch")
            for key, pattern in (
                ("invocation", re.compile(r"[0-9a-f]{32}")),
                ("artifact_sha256", DIGEST),
                ("job_id", UUID),
                ("correlation_id", UUID),
            ):
                value = record[key]
                if not isinstance(value, str) or (
                    value != "unknown" and not pattern.fullmatch(value)
                ):
                    raise ValueError("invalid archive failure identity")
            if (record["job_id"] == "unknown") != (record["correlation_id"] == "unknown"):
                raise ValueError("incomplete archive failure job identity")
            if (
                event(
                    json.dumps({key: record[key] for key in ("helper", "invocation", "chain")}),
                    record["invocation"],
                )
                is None
            ):
                raise ValueError("invalid archive failure locations")
            failures.append(
                {
                    **record,
                    "diagnostic": _diagnostic(record["diagnostic"]),
                    "matches_last_submission": correlation != "unknown"
                    and record["correlation_id"] == correlation,
                }
            )
    return {"collection": "observed", "failures": failures}


def collect(run: Path, correlation: str) -> dict[str, object]:
    """No journal, service InvocationID retention, or source/destination inference."""
    result: dict[str, object] = {}
    try:
        environment = owned.environment_for(run)
    except Exception:
        return {"collection": "unavailable"}
    for kind in ("source", "destination"):
        try:
            if kind == "source":
                identity = str(document(run / "failure-fixture.json").get("container_id"))
                if not DIGEST.fullmatch(identity):
                    raise ValueError("archive failure source is unbound")
                current = owned.inspect(environment, identity)
                if current["id"] != identity or current["name"] != "/" + host_name(environment):
                    raise ValueError("archive failure source identity changed")
            else:
                receipt = document(owned.directory(environment) / "destination.json")
                identity = str(receipt["id"])
                current = owned.inspect(environment, identity)
                if any(current[key] != receipt[key] for key in ("id", "name", "owner", "image")):
                    raise ValueError("archive failure destination identity changed")
            raw = bounded_command(
                ["docker", "exec", "-i", identity, "/usr/bin/python3", "-I", "-B", "-"],
                environment=environment,
                stdin=PROBE,
                timeout=15,
                maximum=len(OPERATIONS) * MAX_BYTES + 1024,
            )
            if raw is None:
                raise ValueError("archive failure evidence unavailable")
            result[kind] = sanitize(raw, correlation)
        except Exception:
            result[kind] = {"collection": "unavailable"}
    return result


def before_teardown(run: Path, correlation: str) -> dict[str, object]:
    """Revalidate a saved observation; do not present it as current host state."""
    try:
        snapshot = document(run / "failure-snapshot.json")
        start, end = snapshot["started_at"], snapshot["completed_at"]
        if not isinstance(start, str) or not isinstance(end, str):
            raise ValueError("invalid archive failure timestamps")
        started = datetime.fromisoformat(start)
        completed = datetime.fromisoformat(end)
        if (
            started.tzinfo != UTC
            or completed.tzinfo != UTC
            or not started <= completed <= datetime.now(UTC)
            or snapshot["correlation_id"] != correlation
        ):
            raise ValueError("unbound archive failure snapshot")
        reports = snapshot["archive_failures"]
        if not isinstance(reports, dict):
            raise ValueError("invalid archive failure snapshot")
        result: dict[str, object] = {}
        for kind in ("source", "destination"):
            report = reports.get(kind, {})
            if report.get("collection") != "observed":
                continue
            grouped: dict[str, list[object]] = {}
            for failure in report["failures"]:
                item = dict(failure)
                item.pop("matches_last_submission")
                grouped.setdefault(item["helper"], []).append(item)
            result[kind] = sanitize(json.dumps(grouped).encode(), correlation)
        return {
            "observation_origin": "captured-before-teardown",
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "hosts": result,
        }
    except Exception:
        return {"collection": "unavailable"}
