"""Sanitized, read-only progress reporting for an interrupted M3.0 run."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.report import QualificationReport, UnsafeReportError
from lowerduckpond_m3_qualification.session import QualificationSession, UnsafeSessionError

FRAGMENT_LABELS: Final = frozenset(
    {
        "libraries",
        "host",
        "domains",
        "browser",
        "edge-primary",
        "edge-replacement",
        "edge-rollback",
        "edge-forward",
        "edge-retired-primary",
        "edge-final",
        "assembled",
    }
)
FRAGMENT_ARGUMENT_PATTERN: Final = re.compile(r"^([a-z-]+)=(.+)$")


def report_status(*, session_path: Path, source_revision: str, fragments: tuple[str, ...]) -> int:
    """Print only validated identities, labels, check IDs, and status words."""
    try:
        session = QualificationSession.read(session_path)
        if session.source_revision != source_revision:
            raise UnsafeSessionError("source revision changed")
    except OSError, ValueError, UnsafeSessionError:
        print("session: invalid-or-stale")
        return 2
    print(f"session: active {session.run_id} {session.source_revision}")

    next_action: str | None = None
    for raw in fragments:
        match = FRAGMENT_ARGUMENT_PATTERN.fullmatch(raw)
        if match is None or match.group(1) not in FRAGMENT_LABELS:
            print("evidence: invalid-argument")
            return 2
        label, raw_path = match.groups()
        path = Path(raw_path)
        if not path.is_file():
            print(f"{label}: absent")
            next_action = next_action or label
            continue
        try:
            report = QualificationReport.from_json(path.read_text(encoding="utf-8"))
        except OSError, ValueError, UnsafeReportError:
            print(f"{label}: invalid")
            next_action = next_action or label
            continue
        if report.run_id != session.run_id or report.source_revision != session.source_revision:
            print(f"{label}: stale")
            next_action = next_action or label
            continue
        failures = tuple(check.check_id for check in report.checks if check.status == "failed")
        if failures:
            print(f"{label}: failed {','.join(failures)}")
            next_action = next_action or label
        else:
            print(f"{label}: passed")
    print(f"next: {next_action or 'complete'}")
    return 0
