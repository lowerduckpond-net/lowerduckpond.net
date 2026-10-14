"""Evidence-based retirement of obligations belonging to fenced legacy issuers.

Only the approved legacy import uses this rule. Ordinary lifecycle cleanup still
performs fresh provider checks. Original status labels never establish closure.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import audit_policy_recovery, cleanup_expiry, historical_absence
from scripts.m3_11_unattended.creation_outcome import is_abort, select_abort, valid_resolution
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.journal import validate
from scripts.m3_11_unattended.lifecycle import (
    CleanupResult,
    _intents,
    _known_id,
    pending_authentication,
)
from scripts.m3_11_unattended.model import (
    Credential,
    Intent,
    LifecycleError,
    Targets,
    digest,
    fingerprint,
    identity,
    instant,
    strings,
)
from scripts.m3_11_unattended.state import journey_result
from scripts.production_qualification_inputs import revision


def retained_bytes(mapping: dict[str, object], path: Path) -> bytes:
    """Read an original, or its exact embedded nonsecret expiry result on another host.

    Detached result bytes do not claim that the original path exists on this host.
    Existing files still have to agree; never hide a changed file or unsafe link.
    """
    try:
        return read_private_bytes(path)
    except FileNotFoundError:
        if path.is_symlink():
            raise
        matches = []
        for raw in cast(list[object], mapping.get("expiry_updates", [])):
            row = cleanup_expiry.imported_update(raw)
            contents = strings(row.get("result_contents", {}))
            if str(path) in contents:
                matches.append(contents[str(path)].encode())
        if len(matches) != 1:
            raise
        return matches[0]


def original_run(  # noqa: PLR0912 - original request, attempt, local and external intent bindings
    directory: Path,
    records: list[dict[str, object]],
    retained: dict[str, str],
    *,
    allow_empty: bool = False,
) -> dict[str, object]:
    """Bind an original run without synthesizing a journey result or status."""
    request_path = directory / "request.json"
    attempt_path = directory / "attempt.json"
    for path in (request_path, attempt_path):
        if retained.get(str(path)) != hashlib.sha256(read_private_bytes(path)).hexdigest():
            raise LifecycleError("original legacy run binding is missing or changed")
    result_path = directory / "journey-result.json"
    if result_path.exists() or result_path.is_symlink():
        if (
            retained.get(str(result_path))
            != hashlib.sha256(read_private_bytes(result_path)).hexdigest()
        ):
            raise LifecycleError("existing legacy result is outside the reviewed inventory")
        journey_result(directory)
    request = fields(
        read_private(request_path),
        {"format", "binding", "mode", "approval_sha256", "controller_image", "daemon"},
    )
    if request["format"] != "lowerduckpond-m3-11-unattended-request-v1":
        raise LifecycleError("migration admission applies only to an original legacy run")
    binding = fields(request["binding"], BINDING)
    if identity(binding["managed_run_id"]) != directory.name:
        raise LifecycleError("original legacy run identity differs")
    revision(binding["source_revision"])
    revision(binding["helper_revision"])
    for key in BINDING - {"managed_run_id", "source_revision", "helper_revision"}:
        fingerprint(binding[key])
    fingerprint(request["approval_sha256"])
    attempt = fields(read_private(attempt_path), {"format", "binding", "started_at"})
    if (
        attempt["format"] != "lowerduckpond-m3-11-unattended-attempt-v1"
        or attempt["binding"] != binding
    ):
        raise LifecycleError("original legacy attempt binding differs")
    instant(attempt["started_at"])
    owned = {item.sha256: item for item in _intents(records) if item.run_id == directory.name}
    local = {}
    for path in (directory / "credential-intents").glob("*.json"):
        if retained.get(str(path)) != hashlib.sha256(read_private_bytes(path)).hexdigest():
            raise LifecycleError("original legacy intent is outside the reviewed inventory")
        intent = Intent.parse(read_private(path))
        if path.stem != intent.sha256 or intent.sha256 in local:
            raise LifecycleError("original legacy intent identity differs")
        local[intent.sha256] = intent
    if (
        (not owned and not allow_empty)
        or local != owned
        or any(
            item.source_revision != binding["source_revision"]
            or item.helper_revision != binding["helper_revision"]
            or item.targets.storage_digest != binding["storage_target_sha256"]
            for item in owned.values()
        )
    ):
        raise LifecycleError("original legacy intent coverage is incomplete or misbound")
    if not owned and (
        not result_path.is_file()
        or journey_result(directory)["status"] == 0
        or any(
            list((directory / kind).glob("*.json"))
            for kind in ("credential-created", "credential-aborted", "credential-cleanup")
        )
        or any(
            row["run_id"] == directory.name
            and (
                row["kind"] in {"created", "cleanup", "resolved"}
                or (isinstance(row["payload"], dict) and "intent_sha256" in row["payload"])
            )
            for row in records
        )
    ):
        raise LifecycleError("empty legacy attempt has issuance evidence or no original result")
    for row in records:
        if row["run_id"] == directory.name and row["kind"] == "run":
            payload = cast(dict[str, object], row["payload"])
            if (
                payload.get("binding") != binding
                or payload.get("approval_sha256") != request["approval_sha256"]
                or payload.get("mode") != request["mode"]
            ):
                raise LifecycleError("original external run binding differs")
    return request


def require_terminal_run(  # noqa: PLR0912 - retained evidence and all terminal obligations
    directory: Path,
    mapping: dict[str, object],
    records: list[dict[str, object]],
    *,
    targets: Targets,
) -> dict[str, object]:
    """Read-only migration closure; retained keys require original denial proof."""
    retained = strings(mapping["retained_files"])
    request = original_run(
        directory,
        records,
        retained,
        allow_empty=mapping.get("format") == "lowerduckpond-m3-11-legacy-import-v2",
    )
    from scripts.m3_11_unattended.legacy_actors import credential_intents  # noqa: PLC0415

    keys = credential_intents(mapping, records)
    owned = {
        intent.sha256: intent for intent in _intents(records) if intent.run_id == directory.name
    }
    for kind in ("credential-created", "credential-aborted", "credential-cleanup"):
        if any(str(path) not in retained for path in (directory / kind).glob("*.json")):
            raise LifecycleError("unreviewed legacy local evidence appeared")
    expected_secrets = set()
    for filename, expected in retained.items():
        path = Path(filename)
        is_secret = filename in keys
        if is_secret:
            expected_secrets.add(keys[filename].sha256)
        if not path.exists() and is_secret:
            proof = terminal(keys[filename], records, credential_expected=True)
            if proof is None or proof.negative_authentication != "denied":
                raise LifecycleError("missing retained secret lacks original denial proof")
            continue
        if hashlib.sha256(retained_bytes(mapping, path)).hexdigest() != expected:
            raise LifecycleError("reviewed legacy retained file changed")
        if is_secret:
            manual = path.parent.parent.name == "manual-page-rules"
            raw = fields(
                read_private(path),
                {"identifier", "secret"} | (set() if manual else {"intent_sha256"}),
            )
            if (not manual and raw["intent_sha256"] != path.stem) or raw["identifier"] != _known_id(
                records, keys[filename]
            ):
                raise LifecycleError("retained legacy credential identity differs")
    required = (
        _intents(records)
        if mapping.get("format") == "lowerduckpond-m3-11-legacy-import-v2"
        else list(owned.values())
    )
    for intent in required:
        if terminal(intent, records, credential_expected=intent.sha256 in expected_secrets) is None:
            raise LifecycleError("legacy terminal removal or negative authentication is unresolved")
    issuers = cast(list[dict[str, object]], mapping["issuers"])
    fenced_after = max((instant(row["stopped_at"]) for row in issuers), default=None)
    if not restored(records, fenced_after=fenced_after):
        raise LifecycleError("legacy auxiliary policy restoration is unresolved")
    if any(
        not cleanup_expiry.terminal_update(row, records=records, targets=targets)
        for row in cast(list[object], mapping["expiry_updates"])
    ):
        raise LifecycleError("legacy expiry update closure is unresolved")
    return request


def terminal(  # noqa: PLR0912 - independent evidence gates
    intent: Intent,
    records: list[dict[str, object]],
    credential: Credential | None = None,
    *,
    credential_expected: bool = False,
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
        if (
            credential is not None
            or credential_expected
            or not historical_absence.receipts(intent, records)
        ):
            raise LifecycleError("legacy uncertainty acceptance conflicts with creation evidence")
        return CleanupResult(intent.sha256, historical_absence.STATUS, "unavailable")
    abort = select_abort(intent, records)
    if abort is not None:
        if (
            known is not None
            or credential is not None
            or credential_expected
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
    if (credential is not None or credential_expected) and not denied:
        return None  # A retained key still requires its outstanding rejection check.
    return CleanupResult(intent.sha256, "verified", "denied" if denied else "unavailable")


def validate_claims(mapping: dict[str, object], records: list[dict[str, object]]) -> None:
    """Check imported labels against their original evidence before publication."""
    restored(records)
    for update in cast(list[object], mapping.get("expiry_updates", [])):
        cleanup_expiry.terminal_update(update, records=records)
    obligations = cast(dict[str, dict[str, object]], mapping["obligations"])
    for intent in _intents(records):
        row = obligations[intent.sha256]
        if (
            "cleanup_authority_sha256" in row
            and row["cleanup_authority_sha256"] != intent.cleanup_authority_sha256
        ):
            raise LifecycleError("legacy authority differs from its original intent")
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


def restored(
    records: list[dict[str, object]],
    *,
    fenced_after: datetime | None = None,
    now: datetime | None = None,
) -> bool:
    """A fenced diagnostic grant may retire only with its exact restoration proof."""
    now = now or datetime.now(UTC)
    plans = audit_policy_recovery.plans(records)
    if len(plans) != 1:
        return not plans
    plan = plans[0]
    approved = audit_policy_recovery.plan(plan)
    intents = _intents(records)
    trigger = [
        intent
        for intent in intents
        if intent.sha256 == approved["intent_sha256"]
        and intent.run_id == plan["run_id"] == audit_policy_recovery.RUN_ID
        and intent.provider == "cloudflare-user"
        and intent.role == "page-rules"
    ]
    authority = [
        intent
        for intent in intents
        if intent.run_id == plan["run_id"]
        and intent.provider == "cloudflare-account"
        and intent.role == "audit"
    ]
    candidate = audit_policy_recovery.candidate(approved["candidate"])
    if (
        len(trigger) != 1
        or len(authority) != 1
        or authority[0].targets != trigger[0].targets
        or authority[0].targets.account_id != candidate["account_id"]
        or authority[0].cleanup_authority_sha256 == candidate["credential_sha256"]
    ):
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
            or instant(value["observed_at"]) > now
        ):
            raise LifecycleError("legacy audit restoration proof differs from its original plan")
        proofs.append(value)
    if not proofs:
        return False
    latest = max(instant(value["observed_at"]) for value in proofs)
    return (
        latest >= instant(approved["restore_after"])
        and (fenced_after is None or latest > fenced_after)
        and all(
            value["status"] == "original-policy-verified"
            for value in proofs
            if instant(value["observed_at"]) == latest
        )
    )
