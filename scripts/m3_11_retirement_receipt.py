"""Allowlisted diagnostic receipt; never qualification or production evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from scripts.m3_11_qualification_evidence import count, digest, fields
from scripts.m3_11_retirement_files import RetirementError

FORMAT = "lowerduckpond-m3-11-failed-fixture-archive-retirement-v1"
RETAINED = ["containers", "state", "backup-prefix", "private-copies", "original-failure"]


def timestamp(value: object) -> str:
    if not isinstance(value, str) or len(value) > 40:  # noqa: PLR2004
        raise RetirementError("retirement timestamp is invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed > datetime.now(UTC):
        raise RetirementError("retirement timestamp is invalid")
    return value


def receipt(value: object) -> dict[str, object]:
    result = fields(
        value,
        {
            "format",
            "outcome",
            "plan_sha256",
            "authorization_sha256",
            "original_failure_preserved",
            "qualification_authority",
            "versions_retired",
            "final_absence_at",
            "retained",
        },
    )
    if (
        result["format"] != FORMAT
        or result["outcome"] != "archives-retired-fixture-retained"
        or result["original_failure_preserved"] is not True
        or result["qualification_authority"] != "none"
        or result["retained"] != RETAINED
    ):
        raise RetirementError("retirement receipt is invalid")
    digest(result["plan_sha256"])
    digest(result["authorization_sha256"])
    count(result["versions_retired"], minimum=1, maximum=25)
    timestamp(result["final_absence_at"])
    return result
