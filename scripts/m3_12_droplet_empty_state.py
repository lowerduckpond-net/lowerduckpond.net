"""Retain version and lineage evidence from authenticated role-state snapshots."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256
from uuid import UUID

from lowerduckpond_static_contracts import ContractError, decode_json_object

from scripts.m3_12_contracts import MAX_RECORD_BYTES, Document, ValidationError, require

COMPACT_EMPTY_STATE = {"format_version": "1.0"}
PINNED_OPENTOFU_VERSION = "1.12.6"
STATE_FILE_VERSION = 4
EVIDENCE_FORMAT = "lowerduckpond-m3-12-empty-role-state-evidence-v1"
FINGERPRINT = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AuthenticatedStateSnapshot:
    """A trusted reader supplies the exact role key, ciphertext and its authenticated decode."""

    state_key: str
    display: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    decoded: bytes = field(repr=False)


def _document(raw: bytes) -> Document:
    try:
        return decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError:
        raise ValidationError("droplet-cleanup-empty-state-evidence-invalid") from None


def _snapshot(snapshot: AuthenticatedStateSnapshot) -> tuple[Document, Document]:
    raw = _document(snapshot.decoded)
    envelope = _document(snapshot.ciphertext)
    require(
        type(raw.get("version")) is int
        and raw["version"] == STATE_FILE_VERSION
        and envelope.get("encryption_version") == "v0"
        and isinstance(envelope.get("encrypted_data"), str)
        and bool(envelope["encrypted_data"]),
        "droplet-cleanup-state-snapshot-invalid",
    )
    return raw, {
        "lineage": raw.get("lineage"),
        "serial": raw.get("serial"),
        "ciphertextSha256": sha256(snapshot.ciphertext).hexdigest(),
        "displaySha256": sha256(snapshot.display).hexdigest(),
    }


def capture_empty_state_evidence(
    before: AuthenticatedStateSnapshot, after: AuthenticatedStateSnapshot
) -> Document:
    """Project independently captured snapshots without retaining the raw state or its checks."""
    _, prior = _snapshot(before)
    raw, current = _snapshot(after)
    require(
        before.state_key == after.state_key
        and set(raw)
        <= {
            "version",
            "terraform_version",
            "serial",
            "lineage",
            "resources",
            "outputs",
            "check_results",
        }
        and raw.get("resources") == []
        and raw.get("outputs") == {}
        and _passing_variable_checks(raw.get("check_results")),
        "droplet-cleanup-state-snapshot-not-empty",
    )
    evidence = {
        "format": EVIDENCE_FORMAT,
        "stateKey": after.state_key,
        "terraformVersion": raw.get("terraform_version"),
        "before": prior,
        "after": current,
    }
    verify_empty_state_evidence(after.display, evidence)
    return evidence


def _passing_variable_checks(checks: object) -> bool:
    return checks is None or (
        isinstance(checks, list)
        and all(
            isinstance(check, dict)
            and check.get("object_kind") == "var"
            and check.get("status") == "pass"
            for check in checks
        )
    )


def _valid_snapshot(snapshot: object) -> bool:
    if not isinstance(snapshot, dict) or snapshot.keys() != {
        "lineage",
        "serial",
        "ciphertextSha256",
        "displaySha256",
    }:
        return False
    lineage = snapshot["lineage"]
    try:
        canonical = isinstance(lineage, str) and str(UUID(lineage)) == lineage
    except ValueError:
        return False
    return bool(
        canonical
        and type(snapshot["serial"]) is int
        and snapshot["serial"] >= 0
        and all(
            isinstance(snapshot[key], str) and FINGERPRINT.fullmatch(snapshot[key])
            for key in ("ciphertextSha256", "displaySha256")
        )
    )


def verify_empty_state_evidence(raw: bytes, evidence: Document) -> None:
    """Admit only the pinned compact display with the separately retained snapshot evidence."""
    display = _document(raw)
    require(
        display == COMPACT_EMPTY_STATE
        and isinstance(evidence, dict)
        and evidence.keys() == {"format", "stateKey", "terraformVersion", "before", "after"}
        and evidence["format"] == EVIDENCE_FORMAT
        and evidence["terraformVersion"] == PINNED_OPENTOFU_VERSION
        and isinstance(evidence["stateKey"], str)
        and bool(evidence["stateKey"])
        and _valid_snapshot(evidence["before"])
        and _valid_snapshot(evidence["after"]),
        "droplet-cleanup-empty-state-evidence-invalid",
    )
    before, after = evidence["before"], evidence["after"]
    require(
        before["lineage"] == after["lineage"]
        and before["serial"] < after["serial"]
        and before["ciphertextSha256"] != after["ciphertextSha256"]
        and after["displaySha256"] == sha256(raw).hexdigest(),
        "droplet-cleanup-empty-state-evidence-changed",
    )
