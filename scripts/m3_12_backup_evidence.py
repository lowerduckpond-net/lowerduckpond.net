"""Bind a native successor's independently verified restore to its phase receipt."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent.host_restore_journal import full_id

from scripts.m3_12_contracts import (
    Document,
    ValidationError,
    decode,
    digest,
    encode,
    instant,
    require,
)
from scripts.m3_12_transaction import Reconciliation

if TYPE_CHECKING:
    from lowerduckpond_static_host_agent.production_backup import BackupAuthority

    from scripts.m3_12_contracts import AdmissionContext
    from scripts.m3_12_successor_journal import Snapshot, SuccessorJournal

PHASE = "final-backup-verification"
RESULT_FIELDS = {
    "snapshot_id",
    "descriptor_sha256",
    "index_sha256",
    "restored_tree_sha256",
    "report_sha256",
}


def seal_verified_restore(  # noqa: PLR0913 - phase and independent restore identities are explicit
    journal: SuccessorJournal,
    context: AdmissionContext,
    authority: BackupAuthority,
    verified: Mapping[str, str],
    *,
    started: datetime,
    finished: datetime,
    expected_index_sha256: str,
) -> tuple[Document, Reconciliation]:
    """Retain content-addressed readback before committing the native phase.

    The caller holds the original action lock, verifies dark health, and reads
    the durable result from the exact post-capture private restoration.
    """
    current = journal.snapshot()
    binding = _require_pending(journal, current, context, authority)
    history = current.history
    pending = current.phases[-1]
    _require_result(verified, authority, expected_index_sha256)
    earlier = [
        row
        for row in current.phases
        if row["phase"] == "dark-repeat" and row["transition"] == "committed"
    ]
    require(len(earlier) == 1, "native-backup-order-invalid")
    dark_repeat = instant(earlier[0]["recordedAt"])
    require(
        dark_repeat <= history.recorded_at <= started <= finished <= context.now,
        "native-backup-order-invalid",
    )
    observation = {
        "format": "lowerduckpond-m3-12-final-backup-observation-v1",
        "transactionSha256": history.transaction_sha256,
        "phaseSha256": history.head_sha256,
        "candidateSha256": context.candidate_sha256,
        "artifactSha256": authority.artifact_sha256,
        "repositoryBinding": authority.repository_binding,
        "lineageSha256": authority.lineage_sha256,
        "proof": dict(verified),
    }
    observation_sha = digest(observation)
    start, end = (
        value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") for value in (started, finished)
    )
    receipt = {
        "format": "lowerduckpond-m3-12-receipt-v1",
        "binding": binding,
        "invocationId": context.invocation_id,
        "kind": "final-backup-restore",
        "startedAt": start,
        "finishedAt": end,
        "oldestSupportingAt": start,
        "observationSha256": observation_sha,
        "outcome": "passed",
    }
    receipt_raw = encode(receipt)
    decode(receipt_raw, "receipt")
    journal.immutable(
        f"backup-proof-{authority.phase_sha256}.json",
        encode({"receiptSha256": digest(receipt), "observationSha256": observation_sha}),
    )
    journal.immutable(f"evidence-{observation_sha}.json", encode(observation))
    journal.immutable(f"evidence-{digest(receipt)}.json", receipt_raw)
    return receipt, Reconciliation(
        evidence_sha256=observation_sha,
        outcome="committed",
        drained=True,
        preconditions_hold=True,
        stage_configuration_sha256=pending["stageConfigurationSha256"],
    )


def _require_pending(
    journal: SuccessorJournal,
    current: Snapshot,
    context: AdmissionContext,
    authority: BackupAuthority,
) -> Document:
    authority.document()
    history = current.history
    require(
        history.phase == PHASE
        and history.pending
        and len(current.rollbacks) % 2 == 0
        and context.active_authority
        and not (context.revoked or context.tenant_history or context.tenant_generation)
        and not context.unfinished_lifecycle
        and authority.launch is None
        and authority.original_sha256 == history.transaction_sha256
        and authority.phase_sha256 == history.head_sha256
        and authority.report_sha256 == context.authority_sha256,
        "native-backup-not-current",
    )
    pending = current.phases[-1]
    transaction = decode(current.original, "transaction")
    binding = cast(Document, transaction["binding"])
    candidate = decode(journal.read("candidate.json"), "candidate")
    require(
        pending["invocationId"] == context.invocation_id
        and pending["leaseSha256"] == context.lease_sha256
        and binding["runId"] == context.run_id
        and binding["candidateSha256"] == digest(candidate) == context.candidate_sha256
        and binding["platformSha256"] == context.platform_sha256
        and binding["targetSha256"] == digest(dict(context.enrolled_target))
        and binding["targetKind"] == "production-host"
        and transaction["authorizationSha256"] == context.authority_sha256
        and candidate["hostAgentSha256"] == authority.artifact_sha256,
        "native-backup-binding-changed",
    )
    return binding


def _require_result(
    verified: Mapping[str, str], authority: BackupAuthority, expected_index_sha256: str
) -> None:
    require(
        verified.keys() == RESULT_FIELDS
        and verified["report_sha256"] == authority.report_sha256
        and verified["index_sha256"] == expected_index_sha256,
        "native-backup-result-changed",
    )
    for value in verified.values():
        full_id(value)


def capture_verified_restore(  # noqa: PLR0913 - explicit fresh authority, exact capture and clock
    journal: SuccessorJournal,
    reopen_authority: Callable[[], AdmissionContext],
    authority: BackupAuthority,
    verify_exact_restore: Callable[[], Mapping[str, str]],
    *,
    now: Callable[[], datetime],
    expected_index_sha256: str,
) -> tuple[Document, Reconciliation]:
    """Preserve the first start and verified finish for retries of the same phase.

    The supplied operation must use the durable exact-snapshot capture and
    inert restore implementation, not take an uncontrolled new snapshot on
    retry. The wrapping native action must hold both resource locks.
    """
    initial = reopen_authority()
    current = journal.snapshot()
    _require_pending(journal, current, initial, authority)
    key = authority.phase_sha256
    start_file = f"backup-start-{key}.json"
    finish_file = f"backup-finish-{key}.json"
    try:
        start = decode_json_object(journal.read(start_file))
    except FileNotFoundError:
        started = now()
        require(started >= current.history.recorded_at, "native-backup-order-invalid")
        start = {"startedAt": started.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
        journal.immutable(start_file, encode(start))
    start_value = start["startedAt"]
    if not isinstance(start_value, str):
        raise ValueError("native-backup-order-invalid")
    started = instant(start_value)
    try:
        completed = decode_json_object(journal.read(finish_file))
    except FileNotFoundError:
        verified = dict(verify_exact_restore())
        _require_result(verified, authority, expected_index_sha256)
        refreshed = reopen_authority()
        _require_pending(journal, journal.snapshot(), refreshed, authority)
        require(
            refreshed.invocation_id == initial.invocation_id
            and refreshed.lease_sha256 == initial.lease_sha256,
            "native-backup-binding-changed",
        )
        completed = {
            "startedAt": start["startedAt"],
            "finishedAt": now().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verified": verified,
        }
        journal.immutable(finish_file, encode(completed))
    finish_value = completed["finishedAt"]
    result = completed["verified"]
    if not isinstance(finish_value, str) or completed["startedAt"] != start_value:
        raise ValueError("native-backup-order-invalid")
    if not isinstance(result, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in result.items()
    ):
        raise ValueError("native-backup-result-changed")
    return seal_verified_restore(
        journal,
        reopen_authority(),
        authority,
        result,
        started=started,
        finished=instant(finish_value),
        expected_index_sha256=expected_index_sha256,
    )


def require_committed_restore(
    journal: SuccessorJournal, current: Snapshot, receipt: Document, context: AdmissionContext
) -> None:
    """Reopen the original byte-bound restore observation, not only the receipt's label."""
    completed = [
        row for row in current.phases if row["phase"] == PHASE and row["transition"] == "committed"
    ]
    require(len(completed) == 1, "native-successor-final-backup-changed")
    committed = completed[0]
    pending_sha = committed["previousSha256"]
    observation_sha = receipt["observationSha256"]
    full_id(pending_sha)
    full_id(observation_sha)
    require(
        committed["evidenceSha256"] == observation_sha
        and committed["invocationId"] == receipt["invocationId"],
        "native-successor-final-backup-changed",
    )
    try:
        binding = journal.read(f"backup-proof-{pending_sha}.json")
        observation = journal.read(f"evidence-{observation_sha}.json")
    except FileNotFoundError:
        raise ValidationError("native-successor-final-backup-record-missing") from None
    require(
        binding == encode({"receiptSha256": digest(receipt), "observationSha256": observation_sha}),
        "native-successor-final-backup-changed",
    )
    data = decode_json_object(observation)
    candidate = decode(journal.read("candidate.json"), "candidate")
    verified = data.get("proof")
    require(
        observation == encode(data)
        and digest(data) == observation_sha
        and data.get("format") == "lowerduckpond-m3-12-final-backup-observation-v1"
        and data.get("transactionSha256") == current.history.transaction_sha256
        and data.get("phaseSha256") == pending_sha
        and data.get("candidateSha256") == context.candidate_sha256 == digest(candidate)
        and data.get("artifactSha256") == candidate["hostAgentSha256"]
        and isinstance(verified, dict)
        and verified.keys() == RESULT_FIELDS
        and verified.get("report_sha256") == context.authority_sha256,
        "native-successor-final-backup-changed",
    )
