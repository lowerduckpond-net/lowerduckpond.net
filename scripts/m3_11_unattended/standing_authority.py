"""Standing consent provenance and one exact retained-lease execution assessment.

These records preserve externally established authority; they do not grant it.
The launcher rereads the current assessment. A daemon payload is only a bound
snapshot, not a cross-host withdrawal subscription.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import (
    LifecycleError,
    Targets,
    digest,
    fingerprint,
    identity,
    instant,
)

FORMAT = "lowerduckpond-m3-11-standing-authorization-v1"
ASSESSMENT_FORMAT = "lowerduckpond-m3-11-authority-assessment-v1"
EXECUTION_FORMAT = "lowerduckpond-m3-11-execution-readiness-v1"
MAXIMUM_AGE = timedelta(days=1)
MAX_REFERENCE = 256
FIRST_PRINTABLE = 32
SCOPE = {"action", "lease_id", "policy_sha256", "targets", "modes", "not_after"}
EXECUTION_FIELDS = {
    "format",
    "prepared",
    "targets",
    "qualification_inputs_sha256",
    "modes",
    "policy_sha256",
    "lease_id",
    "authority",
    "assessment",
    "assessment_path",
    "readiness",
}


def reference(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_REFERENCE
        or any(ord(char) < FIRST_PRINTABLE for char in value)
    ):
        raise LifecycleError("authentic bounded authority/evidence reference is required")
    return value


def authority(value: object, *, now: datetime) -> dict[str, object]:
    document = fields(value, {"format", "consent", "scope"})
    consent = fields(document["consent"], {"approval_reference", "approved_at", "evidence_sha256"})
    reference(consent["approval_reference"])
    fingerprint(consent["evidence_sha256"])
    # Missing native chronology is represented honestly, never replaced by now.
    if consent["approved_at"] is not None and instant(consent["approved_at"]) > now:
        raise LifecycleError("standing consent is future dated")
    scope = fields(document["scope"], SCOPE)
    identity(scope["lease_id"])
    fingerprint(scope["policy_sha256"])
    Targets.parse(scope["targets"])
    if scope["not_after"] is not None and now >= instant(scope["not_after"]):
        raise LifecycleError("owner-imposed standing authority deadline has expired")
    modes = scope["modes"]
    if (
        document["format"] != FORMAT
        or scope["action"] != "reuse-retained-lease"
        or not isinstance(modes, list)
        or not modes
        or any(
            not isinstance(item, str) or item not in {"rehearsal", "qualification"}
            for item in modes
        )
        or len(modes) != len(set(modes))
    ):
        raise LifecycleError("standing authority scope is invalid")
    return document


def assessment(value: object, *, authorized: dict[str, object], now: datetime) -> dict[str, object]:
    document = fields(
        value,
        {
            "format",
            "authority_sha256",
            "scope_sha256",
            "action_id",
            "status",
            "checked_at",
            "check_reference",
        },
    )
    identity(document["action_id"])
    reference(document["check_reference"])
    checked = instant(document["checked_at"])
    if (
        document["format"] != ASSESSMENT_FORMAT
        or document["authority_sha256"] != digest(authorized)
        or document["scope_sha256"] != digest(authorized["scope"])
        or document["status"] != "active"
        or not checked <= now < checked + MAXIMUM_AGE
    ):
        raise LifecycleError("standing authority is withdrawn, stale or scope-mismatched")
    consent = cast(dict[str, object], authorized["consent"])
    if consent["approved_at"] is not None and instant(consent["approved_at"]) > checked:
        raise LifecycleError("authority assessment predates original consent")
    return document


def validate(value: object, *, mode: str, now: datetime) -> dict[str, object]:
    document = fields(value, EXECUTION_FIELDS)
    path = document["assessment_path"]
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise LifecycleError("execution readiness lacks its current assessment path")
    authorized = authority(document["authority"], now=now)
    checked = assessment(document["assessment"], authorized=authorized, now=now)
    scope = cast(dict[str, object], authorized["scope"])
    readiness = fields(
        document["readiness"],
        {
            "checked_at",
            "expires_at",
            "learning_reference",
            "review_reference",
        },
    )
    reference(readiness["learning_reference"])
    reference(readiness["review_reference"])
    start, stop = instant(readiness["checked_at"]), instant(readiness["expires_at"])
    modes = document["modes"]
    if (
        document["format"] != EXECUTION_FORMAT
        or any(document[key] != scope[key] for key in ("lease_id", "policy_sha256", "targets"))
        or not isinstance(modes, list)
        or not modes
        or any(item not in cast(list[str], scope["modes"]) for item in modes)
        or len(modes) != len(set(modes))
        or mode not in modes
        or not instant(checked["checked_at"]) <= start <= now < stop
        or stop - start > MAXIMUM_AGE
    ):
        raise LifecycleError("execution readiness expired or exceeds standing authority scope")
    return document


def require_current(value: dict[str, object], path: Path | None, *, now: datetime) -> None:
    """Reread operator-maintained assessment; never accept a historical active copy."""
    if value.get("format") != EXECUTION_FORMAT:
        if path is not None:
            raise LifecycleError("current standing assessment cannot alter a legacy approval")
        return
    if (
        path is None
        or str(path) != value["assessment_path"]
        or not path.is_absolute()
        or path.resolve(strict=True) != path
    ):
        raise LifecycleError("current authority assessment requires its canonical private path")
    current = read_private(path)
    authorized = authority(value["authority"], now=now)
    assessment(current, authorized=authorized, now=now)
    if current != value["assessment"]:
        raise LifecycleError("current authority assessment changed; retain the exact candidate")


def action(value: object) -> tuple[str, str] | None:
    """Historical identity only; callers separately validate retained records."""
    if not isinstance(value, dict) or value.get("format") != EXECUTION_FORMAT:
        return None
    checked = cast(dict[str, object], value["assessment"])
    return digest(value["authority"]), identity(checked["action_id"])
