"""Evidence-based retirement of obligations belonging to fenced legacy issuers.

Only the approved legacy import uses this rule. Ordinary lifecycle cleanup still
performs fresh provider checks. Original status labels never establish closure.
"""

from __future__ import annotations

from typing import cast

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import audit_policy_recovery, cleanup_expiry, historical_absence
from scripts.m3_11_unattended.creation_outcome import is_abort, select_abort, valid_resolution
from scripts.m3_11_unattended.journal import validate
from scripts.m3_11_unattended.lifecycle import (
    CleanupResult,
    _intents,
    _known_id,
    pending_authentication,
)
from scripts.m3_11_unattended.model import Credential, Intent, LifecycleError, digest, instant
from scripts.production_qualification_inputs import revision


def terminal(  # noqa: PLR0912 - independent evidence gates
    intent: Intent,
    records: list[dict[str, object]],
    credential: Credential | None = None,
) -> CleanupResult | None:
    """Return a preserved outcome only when all available facts support it.

    Missing evidence leaves live cleanup work. Contradictory evidence cannot be
    repaired by selecting one favorable resolution or by omitting a retained key.
    """
    related = [
        row
        for row in records
        if isinstance(row["payload"], dict) and row["payload"].get("intent_sha256") == intent.sha256
    ]
    for row in related:
        validate(row)
        if row["run_id"] != intent.run_id:
            raise LifecycleError("legacy terminal evidence belongs to another run")
    known = _known_id(records, intent)
    if credential is not None and credential.identifier != known:
        raise LifecycleError("retained credential conflicts with legacy identity")
    observations = [row for row in related if row["kind"] in {"cleanup", "resolved"}]
    resolutions = [row for row in observations if row["kind"] == "resolved"]
    accepted = [row for row in related if historical_absence.is_receipt(row)]
    if accepted:
        if credential is not None or not historical_absence.receipts(intent, records):
            raise LifecycleError("legacy uncertainty acceptance conflicts with creation evidence")
        return CleanupResult(intent.sha256, historical_absence.STATUS, "unavailable")
    abort = select_abort(intent, records)
    if abort is not None:
        if (
            known is not None
            or credential is not None
            or any(row["kind"] == "cleanup" for row in observations)
        ):
            raise LifecycleError("legacy pre-creation abort conflicts with creation evidence")
        if any(not valid_resolution(row, intent, records) for row in resolutions):
            raise LifecycleError("legacy pre-creation resolution differs from its original abort")
        return CleanupResult(intent.sha256, "verified", "not-tested")
    if any(is_abort(row) for row in related):
        raise LifecycleError("legacy abort is not bound to its original attempt")
    for row in resolutions:
        value = cast(dict[str, object], row["payload"])
        fields(
            value,
            {"intent_sha256", "credential_id", "provider_readback", "negative_authentication"}
            | (
                {"negative_authentication_markers"}
                if "negative_authentication_markers" in value
                else set()
            ),
        )
        if (
            known is None
            or value["credential_id"] != known
            or value["provider_readback"] != "absent"
            or value["negative_authentication"] not in {"denied", "unavailable"}
            or (
                "negative_authentication_markers" in value
                and value["negative_authentication"] != "denied"
            )
        ):
            raise LifecycleError("legacy resolution lacks matching creation and removal evidence")
    pending = pending_authentication(observations)
    if not resolutions or pending:
        return None
    denied = any(
        cast(dict[str, object], row["payload"])["negative_authentication"] == "denied"
        for row in resolutions
    )
    if credential is not None and not denied:
        return None  # A retained key still requires its outstanding rejection check.
    return CleanupResult(intent.sha256, "verified", "denied" if denied else "unavailable")


def validate_claims(mapping: dict[str, object], records: list[dict[str, object]]) -> None:
    """Check imported labels against their original evidence before publication."""
    restored(records)
    for update in cast(list[object], mapping.get("expiry_updates", [])):
        cleanup_expiry.terminal_update(update, records=records)
    obligations = cast(dict[str, dict[str, object]], mapping["obligations"])
    for intent in _intents(records):
        result = terminal(intent, records)
        claimed = obligations[intent.sha256]["original_status"]
        if claimed == "unresolved":
            continue
        expected = "verified" if claimed == "not-submitted" else claimed
        if (
            result is None
            or result.status != expected
            or (claimed == "not-submitted" and result.negative_authentication != "not-tested")
        ):
            raise LifecycleError("legacy terminal status lacks its original evidence")


def restored(records: list[dict[str, object]]) -> bool:
    """A fenced diagnostic grant may retire only with its exact restoration proof."""
    plans = audit_policy_recovery.plans(records)
    if len(plans) != 1:
        return not plans
    plan = plans[0]
    approved = audit_policy_recovery.plan(plan)
    bound = [
        intent
        for intent in _intents(records)
        if intent.sha256 == approved["intent_sha256"]
        and intent.run_id == plan["run_id"]
        and intent.provider == "cloudflare-account"
        and intent.role == "audit"
    ]
    if len(bound) != 1:
        return False
    proofs = []
    for row in records:
        value = row["payload"]
        if not isinstance(value, dict) or value.get("format") != audit_policy_recovery.PROOF_FORMAT:
            continue
        validate(row)
        fields(
            value,
            {"format", "plan_sha256", "status", "cleanup_actor", "observed_at", "helper_revision"},
        )
        revision(value["helper_revision"])
        if (
            row["kind"] != "heartbeat"
            or row["run_id"] != plan["run_id"]
            or value["plan_sha256"] != digest(plan)
            or value["cleanup_actor"] not in {"controller", "watchdog", "github", "legacy-cleanup"}
            or value["status"]
            not in {
                "original-policy-verified",
                "policy-metadata-verified",
                "restoration-unresolved",
            }
            or instant(value["observed_at"]) < instant(plan["recorded_at"])
        ):
            raise LifecycleError("legacy audit restoration proof differs from its original plan")
        proofs.append(value)
    if not proofs:
        return False
    latest = max(instant(value["observed_at"]) for value in proofs)
    return latest >= instant(approved["restore_after"]) and all(
        value["status"] == "original-policy-verified"
        for value in proofs
        if instant(value["observed_at"]) == latest
    )
