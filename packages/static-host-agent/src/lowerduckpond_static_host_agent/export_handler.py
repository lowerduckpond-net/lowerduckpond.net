"""State-preserving export construction and replay-safe terminal commitment."""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    Digest,
    canonical_json_bytes,
    manifest_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityRejectedError,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.execution import (
    ExecutionError,
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
)
from lowerduckpond_static_host_agent.export_snapshot import ExportSnapshot, capture_export_snapshot
from lowerduckpond_static_host_agent.export_spool import (
    EXPORT_WORKSPACE_BUNDLE_NAME,
    ExportSpool,
    ExportSpoolCapacityError,
    ExportSpoolError,
    ExportSpoolOccupiedError,
)
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName, StateBusyError
from lowerduckpond_static_host_agent.portable_bundle import (
    MAXIMUM_PORTABLE_BUNDLE_BYTES,
    PortableBundleError,
    PortableBundleInspection,
    build_portable_bundle,
    inspect_portable_bundle,
)
from lowerduckpond_static_host_agent.release_tree import ReleaseTreeError
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class ExportLifecycleError(ExecutionError):
    """An export cannot prove its exact durable source, bundle, or terminal state."""


class ExportCommitBoundary(StrEnum):
    SNAPSHOT_CAPTURED = "snapshot-captured"
    BUNDLE_VERIFIED = "bundle-verified"
    INTENT_SYNC = "intent-sync"
    BUNDLE_PUBLISHED = "bundle-published"
    AUDIT_SYNC = "audit-sync"
    RESULT_SYNC = "result-sync"
    JOB_SYNC = "job-sync"
    INTENT_REMOVED = "intent-removed"


@dataclass(frozen=True, slots=True)
class _ExportIntent:
    record: StoredContract
    path: StateRecordPath
    token: IntentRemovalToken


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


class ExportLifecycleHandler:
    """Capture and build from one exact source without changing tenant state."""

    def __init__(  # noqa: PLR0913 - root-configured dependencies remain explicit
        self,
        repository: StateRepository,
        spool: ExportSpool,
        gate: PublicationGate,
        *,
        release_root: Path,
        expected_owner: int,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
        now: Callable[[], datetime] = _utc_now,
        hook: Callable[[ExportCommitBoundary], None] | None = None,
    ) -> None:
        self._repository = repository
        self._spool = spool
        self._gate = gate
        self._releases = release_root
        self._owner = expected_owner
        self._capacity_limits = capacity_limits
        self._now = now
        self._hook = hook

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        canonical = validate_uuid7(job_id)
        if claim is not None:
            raise LifecycleJobRejectionError("invalid_artifact")
        with self._spool.locks.acquire(LockName.EXPORT, blocking=blocking):
            recovered = self._recover(canonical, blocking=blocking)
            if recovered is not None:
                return recovered
            self._gate.require_enabled()
            try:
                self._spool.prepare_workspace()
            except (ExportSpoolCapacityError, CapacityRejectedError) as error:
                raise LifecycleJobRejectionError("capacity_exceeded") from error
            except ExportSpoolOccupiedError as error:
                raise LifecycleJobRejectionError("conflict") from error
            try:
                snapshot, job = self._capture(canonical, blocking=blocking)
                self._notify(ExportCommitBoundary.SNAPSHOT_CAPTURED)
                inspection = self._build(snapshot)
                self._notify(ExportCommitBoundary.BUNDLE_VERIFIED)
                return self._publish(job, inspection, blocking=blocking)
            except (ExportSpoolCapacityError, CapacityRejectedError) as error:
                raise LifecycleJobRejectionError("capacity_exceeded") from error
            finally:
                self._spool.discard_workspace()

    def _capture(self, job_id: str, *, blocking: bool) -> tuple[ExportSnapshot, StoredContract]:
        with self._repository.transaction(mode=LockMode.SHARED, blocking=blocking) as transaction:
            job = _read_job(transaction, job_id)
            request = cast(dict[str, object], job.document["request"])
            expected = cast(dict[str, object], job.document["expectedSource"])
            if expected["lifecycle"] == "archived":
                raise LifecycleJobRejectionError("not_implemented")
            if expected["lifecycle"] not in {"active", "suspended"}:
                raise LifecycleJobRejectionError("invalid_request")
            if build_expected_source(transaction, request) != expected:
                raise LifecycleJobRejectionError("state_drift")
            try:
                snapshot = capture_export_snapshot(
                    self._spool,
                    transaction,
                    release_root=self._releases,
                    tenant_id=request["tenantId"],
                    expected_manifest_digest=_digest(expected["manifestDigest"]),
                    expected_deployment_digest=_digest(expected["deploymentDigest"]),
                    expected_owner=self._owner,
                )
            except ExportSpoolCapacityError as error:
                raise LifecycleJobRejectionError("capacity_exceeded") from error
            except (
                ExportSpoolError,
                ReleaseTreeError,
                FileNotFoundError,
                NotADirectoryError,
                PermissionError,
            ) as error:
                raise LifecycleJobRejectionError("state_drift") from error
            return snapshot, job

    def _build(self, snapshot: ExportSnapshot) -> PortableBundleInspection:
        self._spool.reserve(CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES, 2))
        parent = os.open(self._spool.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with self._spool.accounting() as accounting:

                def check_capacity(descriptor: int, byte_count: int) -> None:
                    accounting.record(parent)
                    accounting.record(descriptor)
                    fragment = self._spool.fragment_size()
                    allocation = ((byte_count + fragment - 1) // fragment) * fragment
                    accounting.reserve(CapacityReservation(allocation + fragment, 0))

                bundle = build_portable_bundle(
                    snapshot.content,
                    snapshot.manifest,
                    output_parent=self._spool.workspace,
                    output_name=EXPORT_WORKSPACE_BUNDLE_NAME,
                    lock_manager=self._spool.locks,
                    expected_owner=self._owner,
                    read_only_snapshot=True,
                    check_capacity=check_capacity,
                )
            self._spool.reserve(CapacityReservation(0, 0))
            inspection = inspect_portable_bundle(
                self._spool.workspace / bundle.output_name, expected_owner=self._owner
            )
            if (
                inspection.bundle_size != bundle.bundle_size
                or inspection.bundle_digest != bundle.bundle_digest
                or inspection.provenance_manifest != snapshot.manifest
                or inspection.release_tree_digest != snapshot.measurement.digest
            ):
                raise ExportLifecycleError("completed export disagrees with its captured source")
            return inspection
        finally:
            os.close(parent)

    def _publish(
        self,
        captured_job: StoredContract,
        inspection: PortableBundleInspection,
        *,
        blocking: bool,
    ) -> ExecutionOutcome:
        job_id = validate_uuid7(captured_job.document["jobId"])
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE, blocking=blocking
        ) as transaction:
            job = _read_job(transaction, job_id)
            if job.document != captured_job.document:
                raise ExportLifecycleError("export authorization changed during construction")
            if transaction.measure_intent_records().records:
                raise StateBusyError("export commitment waits for the active lifecycle intent")
            request = cast(dict[str, object], job.document["request"])
            if build_expected_source(transaction, request) != job.document["expectedSource"]:
                raise LifecycleJobRejectionError("state_drift")
            intent = _make_intent(job.document, inspection.provenance_manifest, self._now())
            result = _make_result(job.document, inspection)
            _admit_commit(transaction, job, result, intent, self._capacity_limits)
            path = StateRecordPath.transaction_intent(intent["intentId"])
            transaction.create_immutable(path, intent)
            self._notify(ExportCommitBoundary.INTENT_SYNC)
            self._spool.publish_bundle(job_id)
            self._notify(ExportCommitBoundary.BUNDLE_PUBLISHED)
            # No result can outlive its intent while private work still makes
            # the completed slot ambiguous to terminal validation.
            self._spool.discard_workspace()
            bound = _find_intent(transaction, job)
            if bound is None:
                raise ExportLifecycleError("export intent disappeared after publication")
            return self._commit(transaction, job, bound, inspection)

    def _recover(self, job_id: str, *, blocking: bool) -> ExecutionOutcome | None:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE, blocking=blocking
        ) as transaction:
            job = _read_job(transaction, job_id)
            intent = _find_intent(transaction, job)
            result = _existing_result(transaction, job_id)
            if intent is None:
                if result is not None:
                    return ExecutionOutcome(
                        result.document,
                        False,
                        replay_existing=result.document.get("failurePublisher")
                        == "authorization-executor",
                    )
                return None
            completed = self._spool.completed_job_id()
            if completed is None:
                audit = transaction.inspect_audit_correlation(
                    cast(dict[str, object], job.document["request"])["correlationId"]
                )
                if result is not None or audit.entry is not None:
                    raise ExportLifecycleError("committed export lost its bound bundle")
                # No authoritative tenant write belongs to an export intent.
                # An interruption before bundle publication may discard and
                # recapture only while neither result nor audit exists.
                transaction.remove_reconciled_intent(intent.path, intent.token)
                return None
            if completed != job_id:
                raise ExportLifecycleError("export intent disagrees with the completed slot")
            try:
                inspection = inspect_portable_bundle(
                    self._spool.completed_path(job_id), expected_owner=self._owner
                )
            except PortableBundleError as error:
                raise ExportLifecycleError("export recovery bundle is invalid") from error
            self._spool.discard_workspace()
            return self._commit(transaction, job, intent, inspection)

    def _commit(
        self,
        transaction: _StateTransaction,
        job: StoredContract,
        intent: _ExportIntent,
        inspection: PortableBundleInspection,
    ) -> ExecutionOutcome:
        source = intent.record.document["sourceManifest"]
        request = cast(dict[str, object], job.document["request"])
        if (
            inspection.provenance_manifest != source
            or inspection.release_tree_digest.to_dict()
            != job.document.get("dispatchSourceReleaseTreeDigest")
            or build_expected_source(transaction, request) != job.document["expectedSource"]
        ):
            raise ExportLifecycleError("export commitment disagrees with its source authority")
        result = _make_result(job.document, inspection)
        existing = _existing_result(transaction, validate_uuid7(job.document["jobId"]))
        if existing is not None and existing.document != result:
            raise ExportLifecycleError("export terminal result disagrees with the bound bundle")
        _admit_commit(transaction, job, result, intent.record.document, self._capacity_limits)
        audit = transaction.inspect_audit_correlation(request["correlationId"])
        if audit.entry is None:
            entry = _make_audit(
                job.document,
                result,
                intent.record.document,
                audit.state.entry_count,
                audit.state.terminal_digest,
            )
            transaction.append_audit(entry)
        elif (
            audit.entry["resultDigest"] != result_digest(result).to_dict()
            or audit.entry["operatorPrincipal"] != job.document["operatorPrincipal"]
            or audit.entry["timestamp"] != intent.record.document["createdAt"]
        ):
            raise ExportLifecycleError("export audit disagrees with the bound result")
        self._notify(ExportCommitBoundary.AUDIT_SYNC)
        if existing is None:
            transaction.create_immutable(
                StateRecordPath.authorization_result(job.document["jobId"]), result
            )
        self._notify(ExportCommitBoundary.RESULT_SYNC)
        if job.document["phase"] != "completed":
            completed = job.document
            completed["phase"] = "completed"
            transaction.compare_and_swap(
                StateRecordPath.authorization_job(completed["jobId"]), job.revision, completed
            )
        self._notify(ExportCommitBoundary.JOB_SYNC)
        transaction.remove_reconciled_intent(intent.path, intent.token)
        self._notify(ExportCommitBoundary.INTENT_REMOVED)
        return ExecutionOutcome(result, existing is None)

    def _notify(self, boundary: ExportCommitBoundary) -> None:
        if self._hook is not None:
            self._hook(boundary)


def _read_job(transaction: _StateTransaction, job_id: str) -> StoredContract:
    job = transaction.read(StateRecordPath.authorization_job(job_id))
    document = job.document
    validate_contract(document, expected_kind=ContractKind.AUTHORIZATION_JOB)
    request = cast(dict[str, object], document["request"])
    if (
        document["jobId"] != job_id
        or document["compatibilityVersion"] != "static-job-v2"
        or document["phase"] not in {"claimed", "completed", "failed"}
        or request["operation"] != "export"
        or document["artifact"] is not None
    ):
        raise ExportLifecycleError("export handler requires one claimed export authorization")
    return job


def _find_intent(transaction: _StateTransaction, job: StoredContract) -> _ExportIntent | None:
    request = cast(dict[str, object], job.document["request"])
    found: _ExportIntent | None = None
    for identity in transaction.measure_intent_records().records:
        path, record = transaction.read_intent(identity.intent_id)
        document = record.document
        if document["correlationId"] != request["correlationId"]:
            raise StateBusyError("export waits for another lifecycle intent")
        source_authority = cast(dict[str, object], job.document["sourceAuthority"])
        if (
            found is not None
            or document["kind"] != "TransactionIntent"
            or document["operation"] != "export"
            or document["tenantId"] != request["tenantId"]
            or document["sourceManifest"] != source_authority["manifest"]
            or document["candidateManifest"] != source_authority["manifest"]
        ):
            raise ExportLifecycleError("export recovery intent disagrees with its job")
        found = _ExportIntent(
            record, path, IntentRemovalToken(record.revision, identity.metadata_generation)
        )
    return found


def _existing_result(transaction: _StateTransaction, job_id: str) -> StoredContract | None:
    try:
        return transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        return None


def _digest(value: object) -> Digest:
    if type(value) is not dict:
        raise ExportLifecycleError("export authorization omitted a source digest")
    return Digest(
        cast(str, value["format"]), cast(str, value["algorithm"]), cast(str, value["value"])
    )


def _make_intent(
    job: dict[str, object], manifest: dict[str, object], now: datetime
) -> dict[str, object]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ExportLifecycleError("export clock is not timezone-aware")
    request = cast(dict[str, object], job["request"])
    digest = manifest_digest(manifest).to_dict()
    document: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TransactionIntent",
        "compatibilityVersion": "static-intent-v2",
        "intentId": generate_uuid7(
            clock=lambda: time.time_ns() // 1_000_000,
            entropy=_entropy,
        ),
        "tenantId": request["tenantId"],
        "correlationId": request["correlationId"],
        "operation": "export",
        "archiveRecovery": None,
        "lifecycleRecovery": None,
        "sourceManifest": manifest,
        "sourceManifestDigest": digest,
        "candidateManifest": manifest,
        "candidateManifestDigest": digest,
        "phase": "prepared",
        "restartFence": None,
        "createdAt": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }
    validate_contract(document, expected_kind=ContractKind.TRANSACTION_INTENT)
    return document


def _make_result(job: dict[str, object], inspection: PortableBundleInspection) -> dict[str, object]:
    request = cast(dict[str, object], job["request"])
    manifest = inspection.provenance_manifest
    metadata = cast(dict[str, object], manifest["metadata"])
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "operation": "export",
        "correlationId": request["correlationId"],
        "tenantId": request["tenantId"],
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": manifest,
        "status": "succeeded",
        "exportBundle": {
            "digest": inspection.bundle_digest.to_dict(),
            "size": inspection.bundle_size,
        },
    }
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    return result


def _make_audit(
    job: dict[str, object],
    result: dict[str, object],
    intent: dict[str, object],
    sequence: int,
    previous: dict[str, str] | None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": sequence,
        "previousEntryDigest": previous,
        "timestamp": intent["createdAt"],
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": "export",
        "tenantId": result["tenantId"],
        "correlationId": result["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "succeeded",
    }
    validate_contract(entry, expected_kind=ContractKind.AUDIT_ENTRY)
    return entry


def _admit_commit(
    transaction: _StateTransaction,
    job: StoredContract,
    result: dict[str, object],
    intent: dict[str, object],
    limits: HostCapacityLimits,
) -> None:
    existing = _existing_result(transaction, validate_uuid7(job.document["jobId"]))
    if existing is None:
        transaction.admit_inventory(
            StateInventoryReservation(
                authorization_records=1,
                authorization_allocated_bytes=transaction.allocation_upper_bound(
                    len(canonical_json_bytes(result))
                ),
            )
        )
    audit = transaction.inspect_audit_correlation(result["correlationId"])
    if audit.entry is None:
        entry = _make_audit(
            job.document, result, intent, audit.state.entry_count, audit.state.terminal_digest
        )
        transaction.admit_audit_append(entry)
    documents = (job.document, result, intent)
    transient = sum(
        transaction.allocation_upper_bound(len(canonical_json_bytes(item))) for item in documents
    )
    if audit.entry is None:
        transient += transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(transient + transaction.namespace_allocation_upper_bound(4), 4),
        transaction.measure_filesystem_capacity(),
        limits=limits,
    )
