"""Allowlisted, invocation-bound summaries of private diagnostic restore traces."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from scripts.qualification_restore_probe import UNITS, VERIFICATION_STEPS

PREFIX = "ldp_debug_restore "
MAX_LOG = 2 * 1024 * 1024
MAX_SECONDS = 86400
MAX_FRAMES = 12
MAX_LINE = 1000000


def event(raw: str, invocation: str) -> dict[str, object] | None:
    try:
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value)
            != {"event", "step", "invocation", "elapsed_seconds", "cpu_seconds", "stack"}
            or value["invocation"] != invocation
            or value["event"] not in {"start", "begin", "end", "sample"}
            or value["step"] not in {"startup", *VERIFICATION_STEPS}
        ):
            return None
        for key in ("elapsed_seconds", "cpu_seconds"):
            if (
                type(value[key]) not in (int, float)
                or not math.isfinite(value[key])
                or not 0 <= value[key] <= MAX_SECONDS
            ):
                return None
        stack = value["stack"]
        if not isinstance(stack, list) or len(stack) > MAX_FRAMES:
            return None
        for frame in stack:
            if (
                not isinstance(frame, dict)
                or set(frame) != {"file", "line", "function"}
                or not isinstance(frame["file"], str)
                or re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]{0,99}\.py|host-restore-coordinator", frame["file"]
                )
                is None
                or not isinstance(frame["function"], str)
                or re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]{0,99}|<(module|listcomp|dictcomp|setcomp|genexpr|lambda)>",
                    frame["function"],
                )
                is None
                or type(frame["line"]) is not int
                or not 0 < frame["line"] <= MAX_LINE
            ):
                return None
        return value
    except ValueError, TypeError, KeyError:
        return None


def summarize(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_LOG + 1)
    if len(raw) > MAX_LOG:
        return {"collection": "oversized"}
    lines = raw.decode(errors="replace").splitlines()
    active = False
    invocation = ""
    events = []
    for line in lines:
        if line in UNITS or line == "lowerduckpond-m3-11-public-caddy.service":
            active = line == UNITS[0]
        if not active:
            continue
        if line.startswith("InvocationID="):
            invocation = line.removeprefix("InvocationID=")
        if re.fullmatch(r"[0-9a-f]{32}", invocation) is None or PREFIX not in line:
            continue
        parsed = event(line.partition(PREFIX)[2], invocation)
        if parsed is not None:
            events.append(parsed)
    if not events:
        return {"collection": "unavailable"}
    last = events[-1]
    # Raw events stay in the private journal. Expose only compact locations and
    # counters, never source lines, local variables, exception messages or IDs.
    locations: Counter[tuple[str, int, str]] = Counter()
    for value in events:
        frames = value["stack"]
        if value["event"] == "sample" and isinstance(frames, list) and frames:
            frame = frames[0]
            locations[(frame["file"], frame["line"], frame["function"])] += 1
    return {
        "collection": "observed",
        "events": len(events),
        "last": {
            key: last[key] for key in ("event", "step", "elapsed_seconds", "cpu_seconds", "stack")
        },
        "sample_locations": [
            {"file": file, "line": line, "function": function, "samples": count}
            for (file, line, function), count in locations.most_common(5)
        ],
    }
