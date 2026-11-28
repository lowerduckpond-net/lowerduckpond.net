"""Pure M3.12 contract validation for an independently authenticated evidence store."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import cache
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from jsonschema import Draft202012Validator
from lowerduckpond_static_contracts import (
    ContractError,
    ContractKind,
    canonical_json_bytes,
    decode_contract,
    decode_json_object,
)

type Document = dict[str, Any]

MAX_RECORD_BYTES = 256 * 1024
CLOCK_TOLERANCE = timedelta(minutes=5)
LIVE_EVIDENCE_AGE = timedelta(days=7)
SCHEMA = Path(__file__).resolve().parents[1] / "schemas/m3-12/v1/contracts.schema.json"
FIRST_CANARY = "lowerduckpond-m3-12-first-production-canary-v1"
CANARY_TRANSACTION = "01a21d1c-672f-7111-83be-f9a37c3bc632"
CANARY_DROPLET = 593949487
CANARY_COUNT = 2
CANARY_PROJECT_SHA = sha256(b"2d1c1a69-d3dd-4eca-bb3f-cea6a9d7f158").hexdigest()
CANARY_PREDECESSOR = "01a19b8a-4ad9-70c1-b831-11e3dd65bcc0"
CANARY_PREDECESSOR_HEAD = "43f6b4eade5d945c1b299d65075a4cefd1de3091fe60adc201bf3c8d86f3fc5d"
PRODUCTION = "production-host"
DISPOSABLE = "disposable-droplet"
INSTALLED = "installed-fixture"
COMMON_SLOTS = {
    "component": "component",
    "transportBootstrap": "transport-bootstrap",
    "darkStage": "dark-stage",
    "darkRepeat": "dark-repeat",
    "targetSafety": "target-safety",
}
PRODUCTION_SLOTS = {
    **COMMON_SLOTS,
    "livePreflight": "live-preflight",
    "predecessor": "accepted-predecessor",
    "successor": "successor-lease",
    "backupRestore": "final-backup-restore",
}
PRODUCTION_IDENTITY = (
    "enrollmentSha256",
    "allocationSha256",
    "inventorySha256",
    "stateSha256",
    "transactionNamespaceSha256",
    "addressSetSha256",
    "leaseDomainSha256",
)


class ValidationError(ValueError):
    """Reject a record with a fixed code that can be emitted without its values."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValidationError(code)


@cache
def _validator(name: str) -> Draft202012Validator:
    schema = decode_json_object(SCHEMA.read_bytes(), maximum_bytes=MAX_RECORD_BYTES)
    return Draft202012Validator(
        {"$defs": schema["$defs"], "$ref": f"#/$defs/{name}"},
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def encode(document: object) -> bytes:
    try:
        return canonical_json_bytes(document, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError, RecursionError, OverflowError:
        raise ValidationError("invalid-record") from None


def digest(document: object) -> str:
    return sha256(encode(document)).hexdigest()


def decode(raw: bytes, name: str) -> Document:
    """Load one closed, canonical record; values never enter a rejection message."""
    try:
        document = decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
        canonical = encode(document)
    except ContractError:
        raise ValidationError("invalid-record") from None
    require(raw == canonical and _validator(name).is_valid(document), "invalid-record")
    return document


def decode_launch_admission(raw: bytes) -> Document:
    try:
        record = decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError:
        raise ValidationError("invalid-record") from None
    schema = "first-canary-admission" if record.get("format") == FIRST_CANARY else "admission"
    return decode(raw, schema)


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class Evidence:
    """Canonical, allowlisted records authenticated outside the contract parser.

    The caller derives this store from independent reads and durable receipts.
    It must never populate it from the admission request, transport arguments,
    an imported report by itself, or any diagnostic artifact.
    """

    records: Mapping[str, bytes]

    def read(self, key: str, name: str) -> Document:
        raw = self.records.get(key)
        if raw is None or sha256(raw).hexdigest() != key:
            raise ValidationError("untrusted-evidence")
        return decode(raw, name)


@dataclass(frozen=True)
class AdmissionContext:
    """Current verified enrollment, reviewed selection and scoped execution authority."""

    now: datetime
    invocation_id: str
    enrolled_target: Mapping[str, Any]
    candidate_sha256: str
    platform_sha256: str
    authority_sha256: str
    lease_sha256: str
    run_id: str
    active_authority: bool
    revoked: bool
    tenant_history: bool
    tenant_generation: bool
    unfinished_lifecycle: bool
    # Include enrolled and reserved aliases, even when their addresses overlap only partly.
    production_identifiers: frozenset[str | int]
    observed_disposable_identifiers: frozenset[str | int] = frozenset()
    qualified_disposable_platform_sha256: str | None = None
    transaction_id: str | None = None
    predecessor_transaction: str | None = None
    predecessor_head: str | None = None


def _binding(admission: Document) -> Document:
    binding = cast(Document, admission["binding"])
    target = admission["target"]
    require(
        binding["targetKind"] == target["targetKind"]
        and binding["purpose"] == target["purpose"]
        and binding["targetSha256"] == digest(target)
        and binding["candidateSha256"] == digest(admission["candidate"])
        and binding["platformSha256"] == digest(admission["platform"]),
        "binding-mismatch",
    )
    backend = "minio" if binding["targetKind"] == INSTALLED else "spaces"
    require(admission["platform"]["storageBackend"] == backend, "wrong-backend")
    if backend == "minio":
        docker = target["docker"]
        host, archive = docker["roles"]["host"], docker["roles"]["archive"]
        run_label = UUID(binding["runId"]).hex
        require(
            host["id"] != archive["id"]
            and host["runLabel"] == archive["runLabel"] == docker["runLabel"] == run_label,
            "invalid-fixture-roles",
        )
    else:
        require(target["transport"]["kind"] == "ssh", "wrong-transport")
    return binding


def _receipt(
    evidence: Evidence, key: str, kind: str, binding: Document, latest: datetime
) -> tuple[Document, datetime, datetime]:
    receipt = evidence.read(key, "receipt")
    require(receipt["kind"] == kind and receipt["binding"] == binding, "wrong-receipt")
    start, end = instant(receipt["startedAt"]), instant(receipt["finishedAt"])
    require(instant(receipt["oldestSupportingAt"]) <= start <= end <= latest, "invalid-chronology")
    return receipt, start, end


def _prerequisites(admission: Document, evidence: Evidence) -> tuple[datetime, datetime]:
    binding = _binding(admission)
    production = binding["targetKind"] == PRODUCTION
    slots = PRODUCTION_SLOTS if production else COMMON_SLOTS
    supplied = admission["prerequisites"]
    require(
        supplied.keys()
        == slots.keys()
        | ({"completeDisposable"} if production and admission["format"] != FIRST_CANARY else set()),
        "wrong-prerequisites",
    )
    prepared = instant(admission["preparedAt"])
    checks = {
        key: _receipt(evidence, supplied[key], kind, binding, prepared)
        for key, kind in slots.items()
    }
    require(
        max(checks["component"][2], checks["transportBootstrap"][2]) <= checks["darkStage"][1]
        and checks["darkStage"][2] <= checks["darkRepeat"][1],
        "invalid-stage-order",
    )
    require(
        checks["targetSafety"][0]["invocationId"] == admission["invocationId"]
        and checks["targetSafety"][2] >= checks["darkRepeat"][2],
        "stale-target-safety",
    )
    if production:
        target = admission["target"]
        invocation = admission["invocationId"]
        preflight, preflight_start, preflight_end = checks["livePreflight"]
        mutations = (checks["darkStage"], checks["darkRepeat"], checks["backupRestore"])
        require(
            preflight["invocationId"] == invocation
            and all(
                preflight_end <= start
                if receipt["invocationId"] == invocation
                else end <= preflight_start
                for receipt, start, end in mutations
            )
            and checks["backupRestore"][1] >= checks["darkRepeat"][2],
            "invalid-production-stage-order",
        )
        require(
            checks["predecessor"][0]["observationSha256"] == target["predecessorSha256"]
            and checks["successor"][0]["observationSha256"] == target["successorProposalSha256"]
            and checks["successor"][0]["invocationId"] == admission["invocationId"],
            "wrong-predecessor-or-successor",
        )
    return min(instant(item[0]["oldestSupportingAt"]) for item in checks.values()), max(
        item[2] for item in checks.values()
    )


def require_canary_decision(
    decision: Document, target: Document, binding: Document, context: AdmissionContext
) -> None:
    require(
        context.transaction_id == CANARY_TRANSACTION
        and context.predecessor_transaction == CANARY_PREDECESSOR
        and context.predecessor_head == CANARY_PREDECESSOR_HEAD,
        "first-canary-authority-changed",
    )
    require_canary_binding(decision, target, binding)


def require_canary_binding(decision: Document, target: Document, binding: Document) -> None:
    require(
        target["targetKind"] == PRODUCTION
        and target["droplet"]["projectIdSha256"] == CANARY_PROJECT_SHA
        and target["droplet"]["dropletId"] == CANARY_DROPLET
        and decision["binding"] == binding
        and decision["predecessorSha256"] == target["predecessorSha256"]
        and decision["successorProposalSha256"] == target["successorProposalSha256"]
        and len({item["correlationId"] for item in decision["creates"]}) == CANARY_COUNT
        and len({item["requestSha256"] for item in decision["creates"]}) == CANARY_COUNT,
        "first-canary-authority-changed",
    )


def validate_admission(raw: bytes, context: AdmissionContext, evidence: Evidence) -> Document:
    """Check a first-launch bundle against the current independent authority."""
    admission = decode_launch_admission(raw)
    binding = _binding(admission)
    target = admission["target"]
    require(
        context.now.tzinfo is not None
        and instant(admission["preparedAt"]) <= context.now + CLOCK_TOLERANCE,
        "invalid-admission-time",
    )
    require(
        context.active_authority
        and not context.revoked
        and admission["authoritySha256"] == context.authority_sha256
        and admission["leaseSha256"] == context.lease_sha256,
        "inactive-authority",
    )
    require(
        target == context.enrolled_target
        and binding["runId"] == context.run_id
        and binding["candidateSha256"] == context.candidate_sha256
        and binding["platformSha256"] == context.platform_sha256
        and admission["invocationId"] == context.invocation_id,
        "enrollment-mismatch",
    )
    require(
        not (context.tenant_history or context.tenant_generation or context.unfinished_lifecycle),
        "tenant-history-or-work",
    )
    if binding["targetKind"] != PRODUCTION:
        identifiers = {target[field] for field in PRODUCTION_IDENTITY}
        if binding["targetKind"] == DISPOSABLE:
            identifiers.add(target["droplet"]["dropletId"])
        require(
            bool(context.production_identifiers)
            and not context.production_identifiers.intersection(
                identifiers | context.observed_disposable_identifiers
            ),
            "production-crossover",
        )
    first, _ = _prerequisites(admission, evidence)
    if admission["format"] == FIRST_CANARY:
        decision = evidence.read(context.authority_sha256, "first-canary-decision")
        require(decision == admission["decision"], "first-canary-authority-changed")
        require_canary_decision(decision, target, binding, context)
        require(context.now - first <= LIVE_EVIDENCE_AGE, "stale-canary-evidence")
    elif binding["targetKind"] == PRODUCTION:
        require(context.transaction_id != CANARY_TRANSACTION, "first-canary-admission-required")
        _validate_qualification(admission, context, evidence)
    return admission


def validate_launch(
    admission_raw: bytes, intent_raw: bytes, launch_raw: bytes, receipt_raw: bytes
) -> Document:
    """Verify immutable links and the existing on-host launch-record contract."""
    admission = decode_launch_admission(admission_raw)
    intent = decode(intent_raw, "launch-intent")
    receipt = decode(receipt_raw, "launch-receipt")
    binding = _binding(admission)
    try:
        launch = launch_document(launch_raw)
    except ContractError:
        raise ValidationError("invalid-launch-record") from None
    require(
        intent["binding"] == receipt["binding"] == binding
        and intent["invocationId"] == admission["invocationId"]
        and intent["leaseSha256"] == admission["leaseSha256"]
        and intent["admissionSha256"] == receipt["admissionSha256"] == digest(admission)
        and receipt["intentSha256"] == digest(intent)
        and receipt["launchRecordSha256"] == digest(launch)
        and launch["acceptanceEvidenceDigest"]["value"] == digest(admission),
        "wrong-launch-binding",
    )
    platform = admission["platform"]
    require(
        launch["configurationVersion"] == admission["candidate"]["revision"]
        and launch["cloudflareNetworkSetDigest"]["value"] == platform["cloudflareNetworkSetSha256"]
        and all(
            launch[field] == platform[field]
            for field in (
                "trustedPlatformDomain",
                "aliasSuffix",
                "tenantOriginSuffix",
                "cookiePolicyVersion",
                "edgePolicyVersion",
            )
        ),
        "wrong-launch-policy",
    )
    require(
        instant(admission["preparedAt"]) <= instant(intent["intendedAt"])
        and intent["intendedAt"] == receipt["launchedAt"] == launch["launchedAt"],
        "wrong-launch-time",
    )
    return receipt


def launch_document(raw: bytes) -> Document:
    launch = decode_contract(raw, expected_kind=ContractKind.LAUNCH_RECORD)
    require(encode(launch) == raw, "invalid-launch-record")
    return launch


def validate_report(raw: bytes, evidence: Evidence, now: datetime) -> tuple[Document, Document]:
    """Verify original evidence and chronology independent of packaging delay."""
    report = decode(raw, "report")
    seal = evidence.read(report["sealSha256"], "seal")
    completion = report["completion"]
    require(seal["completion"] == completion, "wrong-seal")
    admission = evidence.read(seal["admissionSha256"], "admission")
    binding = _binding(admission)
    launch = evidence.read(seal["launchReceiptSha256"], "launch-receipt")
    require(
        binding == launch["binding"] == completion["binding"]
        and launch["admissionSha256"] == seal["admissionSha256"],
        "wrong-completion-binding",
    )
    key = launch["launchRecordSha256"]
    launch_raw = evidence.records.get(key)
    if launch_raw is None or sha256(launch_raw).hexdigest() != key:
        raise ValidationError("untrusted-evidence")
    intent = evidence.read(launch["intentSha256"], "launch-intent")
    validate_launch(encode(admission), encode(intent), launch_raw, encode(launch))
    first, _ = _prerequisites(admission, evidence)
    if binding["targetKind"] == PRODUCTION:
        _, prior_seal = _disposable_report(admission, evidence, now)
        first = min(first, instant(prior_seal["oldestEvidenceAt"]))
    previous = instant(launch["launchedAt"])
    kinds = (
        ("canary", "accounting", "acceptance")
        if binding["targetKind"] == PRODUCTION
        else ("functional", "accounting", "teardown")
    )
    finished = instant(seal["finishedAt"])
    for kind in kinds:
        receipt, start, end = _receipt(
            evidence, completion["receipts"][kind], kind, binding, finished
        )
        first = min(first, instant(receipt["oldestSupportingAt"]))
        require(previous <= start, "invalid-completion-order")
        previous = end
    require(
        instant(seal["oldestEvidenceAt"]) == first
        and finished == previous
        and finished
        <= instant(seal["sealedAt"])
        <= instant(report["packagedAt"])
        <= now + CLOCK_TOLERANCE,
        "invalid-report-time",
    )
    return report, seal


def _disposable_report(
    admission: Document, evidence: Evidence, now: datetime
) -> tuple[Document, Document]:
    key = admission["prerequisites"]["completeDisposable"]
    report = evidence.read(key, "report")
    completion = report["completion"]
    require(completion["kind"] == "complete-disposable", "wrong-disposable-proof")
    disposable = completion["binding"]
    require(
        disposable["candidateSha256"] == admission["binding"]["candidateSha256"]
        and disposable["runId"] != admission["binding"]["runId"],
        "wrong-disposable-proof",
    )
    report, seal = validate_report(encode(report), evidence, now)
    original_admission = evidence.read(seal["admissionSha256"], "admission")
    require(
        original_admission["platform"]["cloudflareNetworkSetSha256"]
        == admission["platform"]["cloudflareNetworkSetSha256"],
        "wrong-disposable-policy",
    )
    preflight = evidence.read(admission["prerequisites"]["livePreflight"], "receipt")
    require(
        instant(report["packagedAt"]) <= instant(preflight["startedAt"])
        and instant(preflight["startedAt"]) - instant(seal["oldestEvidenceAt"])
        <= LIVE_EVIDENCE_AGE,
        "stale-disposable-proof",
    )
    return report, seal


def _validate_qualification(
    admission: Document, context: AdmissionContext, evidence: Evidence
) -> None:
    report, seal = _disposable_report(admission, evidence, context.now)
    require(
        report["completion"]["binding"]["platformSha256"]
        == context.qualified_disposable_platform_sha256,
        "wrong-disposable-proof",
    )
    require(
        context.now - instant(seal["oldestEvidenceAt"]) <= LIVE_EVIDENCE_AGE,
        "stale-disposable-proof",
    )


def validate_diagnostic(raw: bytes) -> Document:
    """Validate one bounded checkpoint. The checkpoint carries zero mutation authority."""
    record = decode(raw, "diagnostic")
    has_terminal = record["terminalEvidence"] == "recorded"
    known = record["outcome"] == "known"
    require(
        ("finishedAt" in record) == ("finishedMonotonicMs" in record)
        and has_terminal == ("finishedAt" in record)
        and (has_terminal or "no-terminal-evidence" in record["omissions"])
        and (not known or has_terminal)
        and (record["result"] == "unknown") == (not known),
        "diagnostic-terminal-mismatch",
    )
    if has_terminal:
        require(
            instant(record["startedAt"]) <= instant(record["finishedAt"])
            and record["startedMonotonicMs"] <= record["finishedMonotonicMs"],
            "invalid-diagnostic-time",
        )
    failures = record["failures"]
    primary = sum(item["role"] == "primary" for item in failures)
    require(
        primary <= 1
        and (record["result"] != "failed" or primary == 1)
        and (record["result"] != "passed" or not failures)
        and ("process" not in record or len(record["process"]) == 1),
        "invalid-diagnostic-result",
    )
    return record
