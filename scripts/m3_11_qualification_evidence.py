"""Strict, shareable combined evidence consumed by the existing qualification gate.

This validates receipts, never runs a fixture or promotes local diagnostics to
live evidence. The live producer must inspect the private bytes behind every
hash and emit a receipt only after its installed assertions have passed.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

FORMAT = "lowerduckpond-m3-11-combined-spaces-v1"
REPORT_FORMAT = "lowerduckpond-m3-11-installed-spaces-v1"
CONTEXT_FORMAT = "lowerduckpond-m3-11-combined-context-v1"
NAMES_FORMAT = "lowerduckpond-m3-11-private-names-v1"
ENVIRONMENT = "secure-workstation-live-spaces-public-ca"
ISSUER = "https://acme-v02.api.letsencrypt.org/directory"
MAX_BYTES = 256 * 1024
MAX_COUNT = 1_000_000
PHASE_CHECKS = {
    "backup-mutation-overlap": ("coherent-boundary", "excluded-secrets", "concurrent-mutation"),
    "protected-rotation": ("retention-guard", "interrupted-rotation", "historical-replay"),
    "reconstruction": (
        "full-restore",
        "exact-archive-versions",
        "release-digests",
        "audit-continuity",
        "excluded-input-outcomes",
        "interrupted-restore",
        "regenerated-runtime",
    ),
    "reboot": ("journal-resume", "ingress-gate", "ordinary-result-replay"),
    "public-ca-cold-recovery": (
        "empty-certificate-store",
        "public-trust-chain",
        "loopback-certificates",
        "dns01-both-zones",
        "interrupted-issuance",
        "reboot-with-gate-closed",
        "gate-opens-after-verification",
        "challenge-cleanup",
    ),
    "paired-accounting": (
        "source-fenced",
        "destination-quiescent",
        "independent-archive-absence",
        "protected-history-verified",
    ),
    "owned-teardown": (
        "backup-prefix-removed",
        "independent-backup-absence",
        "archive-absence",
        "dns-challenges-absent",
        "all-owned-resources-removed",
    ),
}
BINDING_FIELDS = (
    "source_revision",
    "artifact_sha256",
    "input_policy",
    "qualification_inputs_sha256",
    "storage_target_sha256",
    "storage_run_id",
    "storage_report_sha256",
)
IDENTITY_FIELDS = (
    "source_fixture_sha256",
    "destination_fixture_sha256",
    "backup_repository_sha256",
    "caddy_binary_sha256",
    "subject_set_sha256",
)
RECOVERY_FIELDS = ("snapshot_sha256", "descriptor_sha256", "index_sha256", "journal_sha256")
ZERO_ACCOUNTING = (
    "destination_pending_intents",
    "destination_pending_intake",
    "destination_pending_exports",
    "destination_pending_staging",
    "remote_archive_versions_and_markers",
    "remote_archive_multipart_uploads",
)
ZERO_TEARDOWN = (
    "remaining_owned_resources",
    "remaining_backup_objects",
    "remaining_archive_versions_and_markers",
    "remaining_archive_multipart_uploads",
    "remaining_dns_challenges",
)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("qualification evidence contains duplicate fields")
        result[key] = value
    return result


def read_document(path: Path) -> tuple[bytes, dict[str, object]]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("qualification evidence exceeds its byte bound")
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("qualification evidence is not an object")
    return raw, value


def fields(value: object, expected: tuple[str, ...] | set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("combined qualification fields are incomplete or unknown")
    return cast(dict[str, object], value)


def digest(value: object) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("combined qualification digest is invalid")


def count(value: object, *, minimum: int = 0, maximum: int = MAX_COUNT) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("combined qualification count is invalid")


def timestamp(value: object, *, now: datetime, maximum_age: timedelta) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value
        )
        is None
    ):
        raise ValueError("combined qualification timestamp is invalid")
    result = datetime.fromisoformat(value)
    if not timedelta(0) <= now - result <= maximum_age:
        raise ValueError("combined qualification evidence is stale or future-dated")
    return result


def uuid7(value: object) -> uuid.UUID:
    if not isinstance(value, str) or str(uuid.UUID(value, version=7)) != value:
        raise ValueError("combined qualification run identity is invalid")
    return uuid.UUID(value)


def subjects(nonce: object) -> tuple[str, ...]:
    # These are disposable subdomains, never the production serving names.
    # The nonce stays private so the shareable run ID cannot reveal the names.
    prefix = "m3-11-" + uuid7(nonce).hex
    return tuple(
        sorted(
            f"{wildcard}{prefix}.{zone}"
            for zone in ("lowerduckpond.net", "lowerduckpond.com")
            for wildcard in ("", "*.")
        )
    )


def subject_digest(nonce: object) -> str:
    return hashlib.sha256(canonical_bytes(subjects(nonce))).hexdigest()


def validate_names(path: Path, context: dict[str, object]) -> None:
    raw, names = read_document(path)
    fields(names, {"format", "run_id", "nonce", "subjects"})
    if (
        raw != canonical_bytes(names)
        or names["format"] != NAMES_FORMAT
        or names["run_id"] != context["run_id"]
        or names["nonce"] == names["run_id"]
        or names["subjects"] != list(subjects(names["nonce"]))
        or context["subject_set_sha256"] != subject_digest(names["nonce"])
    ):
        raise ValueError("public-CA subjects are not bound to the private disposable run")


@dataclass(frozen=True)
class EvidenceTimes:
    captured_at: datetime
    started_at: datetime
    completed_at: datetime


def validate(
    value: object,
    *,
    binding: dict[str, object],
    maximum_age: timedelta,
) -> EvidenceTimes:
    proof = fields(
        value,
        {
            "format",
            "environment",
            "context",
            "phases",
            "recovery",
            "public_ca",
            "accounting",
            "teardown",
        },
    )
    if proof["format"] != FORMAT or proof["environment"] != ENVIRONMENT:
        raise ValueError("combined qualification requires live Spaces and public-CA evidence")
    context = fields(
        proof["context"], {"format", "run_id", "captured_at", *BINDING_FIELDS, *IDENTITY_FIELDS}
    )
    if context["format"] != CONTEXT_FORMAT or any(
        context[key] != binding[key] for key in BINDING_FIELDS
    ):
        raise ValueError("combined qualification identity does not match the enclosing run")
    uuid7(context["storage_run_id"])
    digest(context["storage_report_sha256"])
    for key in IDENTITY_FIELDS:
        digest(context[key])
    uuid7(context["run_id"])
    if context["source_fixture_sha256"] == context["destination_fixture_sha256"]:
        raise ValueError("combined qualification requires distinct source and destination hosts")
    started, completed = _phases(proof["phases"], maximum_age=maximum_age)
    captured = timestamp(context["captured_at"], now=datetime.now(UTC), maximum_age=maximum_age)
    if captured > started:
        raise ValueError("combined qualification context was captured after proof began")
    _recovery(proof["recovery"])
    _public_ca(proof["public_ca"])
    _accounting(proof["accounting"], proof["teardown"])
    return EvidenceTimes(captured, started, completed)


def _phases(value: object, *, maximum_age: timedelta) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    phases = fields(value, set(PHASE_CHECKS))
    times: list[datetime] = []
    for name, checks in PHASE_CHECKS.items():
        phase = fields(phases[name], {"started_at", "completed_at", "checks", "evidence_sha256"})
        if phase["checks"] != dict.fromkeys(checks, "passed"):
            raise ValueError("combined qualification requires every declared check to pass")
        digest(phase["evidence_sha256"])
        started = timestamp(phase["started_at"], now=now, maximum_age=maximum_age)
        completed = timestamp(phase["completed_at"], now=now, maximum_age=maximum_age)
        if completed < started or (times and started < times[-1]):
            raise ValueError("combined qualification phase chronology is invalid")
        times.extend((started, completed))
    return times[0], times[-1]


def _recovery(value: object) -> None:
    recovery = fields(
        value,
        {*RECOVERY_FIELDS, "protected_segments", "retained_releases", "tenant_states"},
    )
    for key in RECOVERY_FIELDS:
        digest(recovery[key])
    count(recovery["protected_segments"], minimum=2)
    count(recovery["retained_releases"], minimum=2)
    states = fields(recovery["tenant_states"], {"active", "suspended", "archived", "undeployed"})
    for number in states.values():
        count(number, minimum=1)


def _public_ca(value: object) -> None:
    public_ca = fields(
        value,
        {"issuer", "trust", "subject_count", "zone_count", "certificates_sha256"},
    )
    if public_ca["issuer"] != ISSUER or public_ca["trust"] != "system-public-roots":
        raise ValueError("a local or staging CA cannot qualify public cold recovery")
    count(public_ca["subject_count"], minimum=4, maximum=4)
    count(public_ca["zone_count"], minimum=2, maximum=2)
    digest(public_ca["certificates_sha256"])


def _accounting(value: object, removal: object) -> None:
    # The original source may still own deliberately excluded pending input.
    # Preserve and fence that authority; only the destination must be empty.
    accounting = fields(
        value,
        {
            *ZERO_ACCOUNTING,
            "source_state",
            "source_fence_sha256",
            "source_pending_inputs_sha256",
            "destination_quarantine",
        },
    )
    if accounting["source_state"] != "fenced" or accounting["destination_quarantine"] is not False:
        raise ValueError("combined source or destination accounting is unresolved")
    for key in ("source_fence_sha256", "source_pending_inputs_sha256"):
        digest(accounting[key])
    for key in ZERO_ACCOUNTING:
        count(accounting[key], maximum=0)
    teardown = fields(removal, set(ZERO_TEARDOWN))
    for number in teardown.values():
        count(number, maximum=0)
