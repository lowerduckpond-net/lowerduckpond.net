"""Bounded Ansible task observations that survive an interrupted playbook."""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from functools import cache
from pathlib import Path
from typing import TypedDict, cast

from scripts import qualification_timing as timing

JOURNAL = "timing-tasks.jsonl"
MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 30
MAX_SOURCE_LINE = 100000
MAX_DOWNLOAD_SECONDS = 24 * 60 * 60
PHASES = frozenset(
    {
        "create",
        "prepare",
        "converge",
        "idempotence",
        "verify",
        "destroy",
        "cleanup",
        "other-playbook",
    }
)
ACTIONS = frozenset(
    {
        "apt",
        "command",
        "shell",
        "copy",
        "file",
        "template",
        "get_url",
        "uri",
        "git",
        "unarchive",
        "synchronize",
        "docker_image",
        "docker_container",
        "docker_image_info",
        "async_status",
        "setup",
        "other",
    }
)
OUTCOMES = frozenset({"started", "completed", "failed", "skipped"})


class TaskEvent(TypedDict):
    process: int
    phase: str
    group: str
    action: str
    source: str
    line: int
    start_ns: int
    elapsed_ns: int
    outcome: str
    apt_download_seconds: int | None


@cache
def _checkout_sources(root: Path) -> frozenset[str]:
    git = shutil.which("git")
    if git is None:
        return frozenset()
    try:
        result = subprocess.run(  # noqa: S603 - fixed read-only checkout inventory
            [git, "-C", str(root), "ls-files", "--", "config/ansible"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except OSError, subprocess.SubprocessError:
        # Cache an unavailable inventory too, rather than delay every task again.
        return frozenset()
    return frozenset(result.stdout.splitlines())


def _known_source(path: Path) -> str:
    path = path.resolve()
    root = timing.ROOT / "config/ansible"
    if path.is_relative_to(root) and path.is_file():
        relative = path.relative_to(timing.ROOT).as_posix()
        if re.fullmatch(
            r"config/ansible/[a-zA-Z0-9_./-]{1,400}\.ya?ml", relative
        ) and relative in _checkout_sources(timing.ROOT):
            return relative
    # Molecule's create/build tasks live outside the checkout. Never serialize
    # that absolute path or a dynamically generated private playbook name.
    from molecule_plugins import docker  # noqa: PLC0415

    for name in ("create", "destroy"):
        if path == Path(docker.__file__).parent / "playbooks" / f"{name}.yml":
            return f"molecule-plugins/docker/{name}.yml"
    return "unknown"


def _source(source: object) -> tuple[str, int]:
    match = re.fullmatch(r"(.+\.ya?ml):([0-9]{1,6})", source if isinstance(source, str) else "")
    if match and 0 < int(match[2]) <= MAX_SOURCE_LINE:
        path = _known_source(Path(match[1]))
        if path != "unknown":
            return path, int(match[2])
    return "unknown", 0


def _append(event: TaskEvent) -> None:
    destination = Path(os.environ[timing.EVENT_ENV]).with_name(JOURNAL)
    raw = (json.dumps(event, separators=(",", ":")) + "\n").encode("ascii")
    descriptor = os.open(
        destination, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size + len(raw) > MAX_BYTES:
            raise ValueError("task timing budget exhausted")
        os.write(descriptor, raw)
    finally:
        os.close(descriptor)


def start_task(phase: str, action: object, source: object) -> TaskEvent | None:
    if not os.environ.get(timing.EVENT_ENV):
        return None
    try:
        path, line = _source(source)
        module = action.rsplit(".", 1)[-1] if isinstance(action, str) else "other"
        group = os.environ.get(timing.CONTEXT_ENV, "unclassified")
        event: TaskEvent = {
            "process": os.getpid(),
            "phase": phase if phase in PHASES else "other-playbook",
            "group": group if group in timing.GROUPS else "unclassified",
            "action": module if module in ACTIONS else "other",
            "source": path,
            "line": line,
            "start_ns": time.monotonic_ns(),
            "elapsed_ns": 0,
            "outcome": "started",
            "apt_download_seconds": None,
        }
        _append(event)
        return event
    except Exception:
        print("Qualification task timing unavailable.", file=sys.stderr)
        return None


def observe_result(event: TaskEvent | None, result: object) -> None:
    """Keep only APT's numeric fetch duration; never retain its output or URLs."""
    if event is None or event["action"] != "apt" or not isinstance(result, dict):
        return
    if result.get("_ansible_no_log"):
        return
    output = result.get("stdout")
    if not isinstance(output, str) or len(output) > 1024 * 1024:
        return
    match = re.search(
        r"^Fetched [0-9.]+ [kMGT]?B in ((?:[0-9]{1,5}(?:h|min|s) ?){1,3}) \(",
        output,
        re.MULTILINE,
    )
    if match:
        duration = sum(
            int(number) * {"h": 3600, "min": 60, "s": 1}[unit]
            for number, unit in re.findall(r"([0-9]+)(h|min|s)", match[1])
        )
        if duration <= MAX_DOWNLOAD_SECONDS:
            event["apt_download_seconds"] = duration


def finish_task(event: TaskEvent | None, outcome: str) -> None:
    if event is None:
        return
    try:
        if outcome not in OUTCOMES - {"started"}:
            raise ValueError("invalid task outcome")
        _append(
            {**event, "elapsed_ns": time.monotonic_ns() - event["start_ns"], "outcome": outcome}
        )
    except Exception:
        print("Qualification task timing unavailable.", file=sys.stderr)


def _validated(value: object, started: int, ended: int) -> TaskEvent:
    if not isinstance(value, dict) or set(value) != set(TaskEvent.__annotations__):
        raise ValueError("invalid task fields")
    source = value["source"]
    if (
        type(value["process"]) is not int
        or value["process"] <= 0
        or value["phase"] not in PHASES
        or value["group"] not in timing.GROUPS
        or value["action"] not in ACTIONS
        or value["outcome"] not in OUTCOMES
        or not isinstance(source, str)
        or (
            source
            not in {
                "unknown",
                "molecule-plugins/docker/create.yml",
                "molecule-plugins/docker/destroy.yml",
            }
            and _known_source(timing.ROOT / source) != source
        )
        or type(value["line"]) is not int
        or not 0 <= value["line"] <= MAX_SOURCE_LINE
        or (source == "unknown") != (value["line"] == 0)
        or type(value["start_ns"]) is not int
        or type(value["elapsed_ns"]) is not int
        or not started <= value["start_ns"] <= ended
        or not 0 <= value["elapsed_ns"] <= ended - value["start_ns"]
        or (value["outcome"] == "started" and value["elapsed_ns"] != 0)
        or (
            value["apt_download_seconds"] is not None
            and (
                value["action"] != "apt"
                or type(value["apt_download_seconds"]) is not int
                or not 0 <= value["apt_download_seconds"] <= MAX_DOWNLOAD_SECONDS
                or value["outcome"] == "started"
            )
        )
    ):
        raise ValueError("invalid task values")
    return cast(TaskEvent, value)


def summarize(directory: Path, started: int, ended: int) -> dict[str, object]:
    """A missing/corrupt diagnostic cannot suppress the original phase report."""
    try:
        return _summarize(directory, started, ended)
    except FileNotFoundError:
        return {"status": "unavailable"}
    except Exception:
        return {"status": "invalid-or-incomplete"}


def _summarize(directory: Path, started: int, ended: int) -> dict[str, object]:
    raw = timing._read(directory / JOURNAL, MAX_BYTES)
    read_ended = time.monotonic_ns()
    truncated = not raw.endswith(b"\n")
    if truncated:
        raw = raw[: raw.rfind(b"\n") + 1]
    pending: dict[tuple[int, int], TaskEvent] = {}
    completed: list[TaskEvent] = []
    for line in raw.splitlines():
        event = _validated(json.loads(line), started, read_ended)
        # A cancelled runner may collect before all child processes have died.
        # Validate concurrent appends, but retain the report's observation time:
        # a completion after that instant cannot close an in-flight task in it.
        if event["start_ns"] + event["elapsed_ns"] > ended:
            continue
        key = event["process"], event["start_ns"]
        if event["outcome"] == "started":
            if key in pending:
                raise ValueError("duplicate task start")
            pending[key] = event
        else:
            begin = pending.pop(key)
            if any(
                event[field] != begin[field]
                for field in ("phase", "group", "action", "source", "line")
            ):
                raise ValueError("changed task identity")
            completed.append(event)
    return {
        "status": "observed",
        "scope": "task-start-through-next-task-or-playbook-stats; overlaps-phase-spans",
        "partial_final_append": truncated,
        "completed_count": len(completed),
        "longest_completed": [
            {
                **{k: e[k] for k in ("phase", "group", "action", "source", "line", "outcome")},
                "seconds": e["elapsed_ns"] / 1e9,
                "apt_download_seconds": e["apt_download_seconds"],
            }
            for e in sorted(completed, key=lambda e: e["elapsed_ns"], reverse=True)[:MAX_ROWS]
        ],
        "unfinished_count": len(pending),
        "unfinished": [
            {
                **{k: e[k] for k in ("phase", "group", "action", "source", "line")},
                "seconds_until_collection": (ended - e["start_ns"]) / 1e9,
            }
            for e in sorted(pending.values(), key=lambda e: e["start_ns"])[:MAX_ROWS]
        ],
    }
