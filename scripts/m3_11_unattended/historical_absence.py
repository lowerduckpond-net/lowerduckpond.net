"""One operator-approved historical uncertainty; never proof of revocation.

The operator accepted this exact legacy obligation on 2026-10-06 after repeated
provider/UI absence checks and a same-process positive control with verified
revocation. No expiry wait was required. There is no configurable waiver list.
Fresh inventory and all ordinary ownership/negative-authentication checks still
precede admission; an observed identity immediately leaves this exception path.
"""

from __future__ import annotations

from scripts.m3_11_unattended.creation_outcome import is_abort
from scripts.m3_11_unattended.journal import Journal, event, validate
from scripts.m3_11_unattended.model import Intent, LifecycleError, instant

FORMAT = "lowerduckpond-m3-11-accepted-historical-absence-v1"
STATUS = "operator-accepted-uncertainty"
INTENT = "ccdc7926243530cf6dd6615745f8520440d29531f28869a226f432b31a64b574"
RUN = "01a11021-76d1-775a-adb1-fe00b6fd6152"
APPROVED_AT = "2026-10-06T20:02:56.424655Z"
BINDING = {
    "managed_run_id": RUN,
    "source_revision": "71421f7f32dddbe0965afd67fd89fb563b46a616",
    "helper_revision": "71421f7f32dddbe0965afd67fd89fb563b46a616",
    "artifact_sha256": "4feb9c45b59380bcd1ea98fa8fa61232003cc6418f9901042aac1a5023e71970",
    "qualification_inputs_sha256": (
        "f9066d281fdeff6c52bccc1e05b7ddd63bf01b8e0d3a8746ee12156772d9b8e4"
    ),
    "storage_target_sha256": "e982ace39c2cae07de0899170481058051db3cf12c2a03d42c9e3bf0400d1528",
}
PAYLOAD: dict[str, object] = {
    "format": FORMAT,
    "intent_sha256": INTENT,
    "decision": STATUS,
    "operator_approval_recorded_at": APPROVED_AT,
    "provider_readback": "absent",
    "creation_outcome": "unavailable",
    "negative_authentication": "unavailable",
}


def is_receipt(record: dict[str, object]) -> bool:
    value = record.get("payload")
    return (
        record.get("kind") == "heartbeat"
        and isinstance(value, dict)
        and value.get("format") == FORMAT
    )


def eligible(intent: Intent, records: list[dict[str, object]]) -> bool:
    """The full digest binds scope, provider, baseline, authority and original times."""
    return (
        intent.sha256 == INTENT
        and intent.run_id == RUN
        and not any(
            (row["kind"] in {"created", "cleanup", "resolved"} or is_abort(row))
            and isinstance(row["payload"], dict)
            and row["payload"].get("intent_sha256") == INTENT
            for row in records
        )
    )


def receipts(intent: Intent, records: list[dict[str, object]]) -> list[dict[str, object]]:
    if not eligible(intent, records):
        return []
    selected = []
    for row in records:
        if not is_receipt(row):
            continue
        validate(row)
        if (
            row["run_id"] != RUN
            or row["payload"] != PAYLOAD
            or instant(row["recorded_at"]) < instant(APPROVED_AT)
        ):
            raise LifecycleError("historical absence acceptance differs from its authorization")
        selected.append(row)
    return selected


def record_absence(journal: Journal, intent: Intent) -> bool:
    """Called only after a successful complete inventory with no matching child."""
    records = journal.records()
    if not eligible(intent, records):
        return False
    prior = receipts(intent, records)
    # Preserve an interrupted persistence attempt and never create a resolution.
    journal.persist(prior[0] if prior else event("heartbeat", RUN, dict(PAYLOAD)))
    return True


def admits(intent_sha256: object, status: object) -> bool:
    """Aggregate admission only; each new run still requires verified revocation."""
    return status == "verified" or (intent_sha256 == INTENT and status == STATUS)


def retained_failure(run_id: str, status: object, binding: object) -> bool:
    """Skip only the old local guard; independent global clearance still follows."""
    return (
        run_id == RUN
        and binding == BINDING
        and isinstance(status, dict)
        and status.get("phase") == "finished"
        and status.get("qualification") == "failed"
        and status.get("exit_status") == 1
        and status.get("credential_cleanup") == "unresolved"
        and status.get("closure") == "unresolved"
    )
