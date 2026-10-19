"""A frozen fixture's disposition fences execution, never shared lease cleanup.

Presence is deliberately sufficient: incomplete, damaged or dangling retirement
state cannot reopen the old fixture. Read-only run/credential observers do not
use this execution gate. Original tenant, job and audit records remain unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from scripts.m3_11_private_inputs import read_private

DIRECTORY = "frozen-archive-retirement"
ORIGIN = "diagnostic-origin.json"


def original_run(run: Path) -> Path:
    marker = run / ORIGIN
    if not marker.exists() and not marker.is_symlink():
        return run
    value = read_private(marker)
    original = value.get("original_run")
    if (
        value.get("format") != "lowerduckpond-m3-11-debug-v1"
        or value.get("qualification_authority") != "none"
        or not isinstance(original, str)
    ):
        raise ValueError("fixture diagnostic origin is invalid")
    root = Path(original)
    if (
        not root.is_absolute()
        or root.resolve(strict=True) != root
        or run not in {root, root / "diagnostics/workspace"}
        or read_private(root / ORIGIN) != value
    ):
        raise ValueError("fixture diagnostic origin differs from its original")
    return root


def require_available(run: Path) -> None:
    """Check again under the original run lock immediately before execution."""
    root = original_run(run)
    for base in {run, root}:
        marker = base / DIRECTORY
        if marker.exists() or marker.is_symlink():
            raise ValueError("frozen fixture retirement permanently excludes execution")


def require_environment(environment: Mapping[str, str]) -> None:
    artifact = environment.get("LDP_QUALIFICATION_ARTIFACT")
    if not artifact:
        if environment.get("LDP_QUALIFICATION_RUN_ID"):
            raise ValueError("owned fixture artifact is missing")
        return
    path = Path(artifact)
    if (
        not path.is_absolute()
        or path.name != "static-host-agent.tar"
        or path.parent.name != "fixture"
    ):
        raise ValueError("owned fixture artifact location is invalid")
    require_available(path.parent.parent)
