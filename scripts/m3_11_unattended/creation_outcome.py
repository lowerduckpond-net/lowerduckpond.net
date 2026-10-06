"""Original controller attestations for failures strictly before provider invocation.

Independent cleanup preserves and checks the attestation; it did not witness the
controller's control flow. Missing attestations, including legacy attempts, never
prove non-submission. Recovery transports exact existing records only.
"""

from __future__ import annotations

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.journal import event, validate
from scripts.m3_11_unattended.model import Intent, LifecycleError, digest

FORMAT = "lowerduckpond-m3-11-before-creation-abort-v1"
RUN_FIELDS = {"binding", "mode", "approval_sha256"}


def run_payload(value: object) -> dict[str, object]:
    names = RUN_FIELDS | (
        {"creation_protocol"} if isinstance(value, dict) and "creation_protocol" in value else set()
    )
    selected = fields(value, names)
    if "creation_protocol" in selected and selected["creation_protocol"] != FORMAT:
        raise LifecycleError("credential creation protocol is unrecognized")
    return selected


def is_abort(record: dict[str, object]) -> bool:
    payload = record.get("payload")
    return (
        record.get("kind") == "heartbeat"
        and isinstance(payload, dict)
        and payload.get("format") == FORMAT
    )


def original_abort(
    intent: Intent, intent_record: dict[str, object], run: dict[str, object]
) -> dict[str, object]:
    """Called only by the original execution's pre-provider exception handler."""
    payload = run_payload(run["payload"])
    if payload.get("creation_protocol") != FORMAT:
        raise LifecycleError("original attempt did not select the creation outcome protocol")
    record = event(
        "heartbeat",
        intent.run_id,
        {
            "format": FORMAT,
            "reason": "before-provider-call",
            "intent_sha256": intent.sha256,
            "intent_event_id": intent_record["event_id"],
            "intent_event_sha256": digest(intent_record),
            "run_event_id": run["event_id"],
            "run_event_sha256": digest(run),
            "binding": payload["binding"],
        },
    )
    validate_abort(record, intent, [intent_record, run])
    return record


def validate_abort(
    record: dict[str, object], intent: Intent, observed: list[dict[str, object]]
) -> None:
    validate(record)
    value = fields(
        record["payload"],
        {
            "format",
            "reason",
            "intent_sha256",
            "intent_event_id",
            "intent_event_sha256",
            "run_event_id",
            "run_event_sha256",
            "binding",
        },
    )
    binding = fields(value["binding"], BINDING)
    if (
        not is_abort(record)
        or record["run_id"] != intent.run_id
        or value["intent_sha256"] != intent.sha256
        or value["reason"] != "before-provider-call"
        or binding["managed_run_id"] != intent.run_id
        or binding["source_revision"] != intent.source_revision
        or binding["helper_revision"] != intent.helper_revision
        or binding["storage_target_sha256"] != intent.targets.storage_digest
    ):
        raise LifecycleError("pre-creation outcome differs from its exact attempt")
    for kind in ("intent", "run"):
        originals = [
            candidate
            for candidate in observed
            if candidate["event_id"] == value[kind + "_event_id"]
        ]
        if (
            len(originals) != 1
            or originals[0]["run_id"] != intent.run_id
            or originals[0]["kind"] != kind
            or digest(originals[0]) != value[kind + "_event_sha256"]
        ):
            raise LifecycleError("pre-creation outcome has no exact original event")
        original = originals[0]
        if kind == "intent" and original["payload"] != intent.document():
            raise LifecycleError("pre-creation outcome changed its original intent")
        if kind == "run":
            payload = run_payload(original["payload"])
            if payload.get("creation_protocol") != FORMAT or payload["binding"] != binding:
                raise LifecycleError("legacy attempts cannot acquire pre-creation attestations")


def select_abort(intent: Intent, observed: list[dict[str, object]]) -> dict[str, object] | None:
    selected = [
        record
        for record in observed
        if is_abort(record)
        and record["run_id"] == intent.run_id
        and isinstance(record["payload"], dict)
        and record["payload"].get("intent_sha256") == intent.sha256
    ]
    if not selected:
        return None
    if len(selected) != 1:
        raise LifecycleError("pre-creation outcomes are ambiguous")
    validate_abort(selected[0], intent, observed)
    return selected[0]


def valid_resolution(
    record: dict[str, object], intent: Intent, observed: list[dict[str, object]]
) -> bool:
    """A read-only status cannot treat contradictory non-creation as closure."""
    payload = record["payload"]
    if not isinstance(payload, dict) or "creation_outcome" not in payload:
        return True  # Existing provider-revocation receipts keep their interpretation.
    try:
        abort = select_abort(intent, observed)
        if abort is None or payload != {
            "intent_sha256": intent.sha256,
            "credential_id": None,
            "provider_readback": "absent",
            "negative_authentication": "not-tested",
            "creation_outcome": "not-submitted",
            "abort_event_id": abort["event_id"],
            "abort_event_sha256": digest(abort),
        }:
            return False
        return not any(
            candidate["run_id"] == intent.run_id
            and candidate["kind"] in {"created", "cleanup"}
            and isinstance(candidate["payload"], dict)
            and candidate["payload"].get("intent_sha256") == intent.sha256
            for candidate in observed
        )
    except LifecycleError, ValueError, KeyError, TypeError:
        return False
