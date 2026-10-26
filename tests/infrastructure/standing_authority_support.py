"""Entirely synthetic standing consent, current assessment and execution records."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from scripts.m3_11_unattended import standing_authority as standing
from scripts.m3_11_unattended.model import digest, stamp


def execution(
    original: dict[str, object], now: datetime, *, action_id: str | None = None
) -> dict[str, object]:
    scope = {
        **{key: original[key] for key in ("lease_id", "policy_sha256", "targets", "modes")},
        "action": "reuse-retained-lease",
        "not_after": None,
    }
    authority = {
        "format": standing.FORMAT,
        "consent": {
            "approved_at": stamp(now - timedelta(days=30)),
            "approval_reference": "SYNTHETIC original standing consent",
            "evidence_sha256": "1" * 64,
        },
        "scope": scope,
    }
    assessment = {
        "format": standing.ASSESSMENT_FORMAT,
        "authority_sha256": digest(authority),
        "scope_sha256": digest(scope),
        "action_id": action_id or str(uuid.uuid7()),
        "status": "active",
        "checked_at": stamp(now),
        "check_reference": "SYNTHETIC latest scope and withdrawal review",
    }
    return {
        **{
            key: value
            for key, value in original.items()
            if key not in {"format", "approved_at", "expires_at", "approval_reference"}
        },
        "format": standing.EXECUTION_FORMAT,
        "authority": authority,
        "assessment": assessment,
        "assessment_path": "/synthetic/current-authority.json",
        "readiness": {
            "checked_at": stamp(now),
            "expires_at": stamp(now + timedelta(hours=1)),
            "learning_reference": "SYNTHETIC corrected failure and test evidence",
            "review_reference": "SYNTHETIC exact source and CI review",
        },
    }
