"""Ordered private reconciliation before runtime preparation or public admission."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.archive_abort import finalize_failed_construction
from lowerduckpond_static_host_agent.archive_journal import ArchiveRetirementJournal
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.backup_descriptor import INTENT_DIGEST_FORMAT
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.execution import (
    _capture_replay_authority,
    _repair_executor_failure_audit,
    _repair_terminal_phase_transaction,
    _require_same_authority,
    _validate_handler_result_state,
    _validate_request_integrity,
    _validate_result_audit,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_archive import reconcile_archive
from lowerduckpond_static_host_agent.host_restore_create import reconcile_create
from lowerduckpond_static_host_agent.host_restore_delete import reconcile_delete
from lowerduckpond_static_host_agent.host_restore_deployments import reconcile_deployment
from lowerduckpond_static_host_agent.host_restore_emergency import reconcile_emergency
from lowerduckpond_static_host_agent.host_restore_exports import (
    abandon_uncommitted_export,
    finish_export_intent,
    retire_restored_export,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.host_restore_pending import finish_missing_input
from lowerduckpond_static_host_agent.host_restore_retirement import reconcile_unstarted_retirement
from lowerduckpond_static_host_agent.host_restore_routes import reconcile_route
from lowerduckpond_static_host_agent.host_restore_tenant_restore import reconcile_tenant_restore
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository

WORK_SCHEMA = "lowerduckpond-host-restore-local-work-v1"
DONE_SCHEMA = "lowerduckpond-host-restore-local-done-v1"


def _require_saved_work(store: RestoreStore, work: dict[str, object]) -> None:
    if canonical_json_bytes(work, maximum_bytes=MAX_RESTORE_BYTES) != store.read_bytes(
        "local-work.json"
    ):
        raise HostRestoreError("restore_local_work_changed")


def _validated(store: RestoreStore) -> dict[str, str]:
    current = store.read()
    if current is None or current.phase is not RestorePhase.VALIDATED:
        raise HostRestoreError("restore_local_requires_validated")
    return current.digest


def local_work(
    store: RestoreStore, repository: StateRepository, descriptor: dict[str, object]
) -> dict[str, object]:
    """Freeze identities before finalizers remove their original durable intents."""
    validated = _validated(store)
    try:
        raw = store.read_bytes("local-work.json")
    except FileNotFoundError:
        with repository.publication_transaction() as transaction:
            intents = [
                transaction.read_intent(row.intent_id)[1].document
                for row in transaction.measure_intent_records().records
            ]
            observed = [
                {
                    "intentId": intent["intentId"],
                    "tenantId": intent["tenantId"],
                    "kind": intent["kind"],
                    "digest": framed_digest(INTENT_DIGEST_FORMAT, canonical_json_bytes(intent)),
                }
                for intent in intents
            ]
            expected = cast(list[dict[str, object]], descriptor["intents"])
            if sorted(observed, key=lambda row: str(row["intentId"])) != sorted(
                expected, key=lambda row: str(row["intentId"])
            ):
                raise HostRestoreError("restore_local_capture_changed") from None
            rows = []
            for intent in intents:
                kind = intent["kind"]
                operation = intent.get("operation")
                if kind == "ArchiveConstructionIntent":
                    # A successful bound construction needs only remote cleanup.
                    bound = any(
                        transaction.read(
                            StateRecordPath.tenant_archive(tenant, deployment)
                        ).document["key"]
                        == intent["key"]
                        for tenant in transaction.measure_inventory().tenant_ids
                        for deployment in transaction.tenant_archive_ids(tenant)
                    )
                    operation = "bound-construction" if bound else "unbound-construction"
                elif kind == "ArchiveRetirementIntent":
                    provenance = cast(dict[str, object], intent["provenance"])
                    result_id = provenance.get("jobId", intent["correlationId"])
                    try:
                        path = (
                            StateRecordPath.authorization_result(result_id)
                            if provenance["kind"] == "authorization-job"
                            else StateRecordPath.emergency_result(result_id)
                        )
                        transaction.read(path)
                    except FileNotFoundError:
                        operation = "unstarted-retirement"
                    else:
                        operation = "terminal-retirement"
                job_id = intent.get("jobId")
                if operation == "export":
                    matches = [
                        identity
                        for identity in transaction.measure_authorization_records().job_ids
                        if cast(
                            dict[str, object],
                            transaction.read(StateRecordPath.authorization_job(identity)).document[
                                "request"
                            ],
                        )["correlationId"]
                        == intent["correlationId"]
                    ]
                    if len(matches) != 1:
                        raise HostRestoreError("restore_export_job_ambiguous") from None
                    job_id = matches[0]
                rows.append(
                    {
                        "intentId": intent["intentId"],
                        "kind": kind,
                        "operation": operation,
                        "jobId": job_id,
                    }
                )
            document = {
                "schema": WORK_SCHEMA,
                "validatedJournalDigest": validated,
                "jobs": list(transaction.measure_authorization_records().job_ids),
                "intents": rows,
            }
        raw = canonical_json_bytes(document, maximum_bytes=MAX_RESTORE_BYTES)
        store.immutable("local-work.json", raw)
    work = exact_object(
        decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES),
        {"schema", "validatedJournalDigest", "jobs", "intents"},
    )
    if (
        canonical_json_bytes(work, maximum_bytes=MAX_RESTORE_BYTES) != raw
        or work["schema"] != WORK_SCHEMA
        or work["validatedJournalDigest"] != validated
        or type(work["jobs"]) is not list
        or type(work["intents"]) is not list
    ):
        raise HostRestoreError("restore_local_work_unbound")
    for identity in work["jobs"]:
        validate_uuid7(identity)
    with repository.publication_transaction() as transaction:
        if work["jobs"] != list(transaction.measure_authorization_records().job_ids):
            raise HostRestoreError("restore_local_jobs_changed")
    return work


@dataclass(frozen=True)
class LocalRecovery:
    store: RestoreStore
    repository: StateRepository
    spool: ExportSpool
    releases: DeploymentReleaseStore
    evidence: CaddyBackupEvidence
    original_ca: tuple[bytes, ...]
    bucket: str

    def reconcile(self, work: dict[str, object], proof: dict[str, object]) -> tuple[str, ...]:
        """The credential helper's complete inventory/bundle proof precedes this call."""
        self.spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
        _require_saved_work(self.store, work)
        validated = _validated(self.store)
        binding = framed_digest(
            WORK_SCHEMA, canonical_json_bytes(work, maximum_bytes=MAX_RESTORE_BYTES)
        )
        try:
            raw = self.store.read_bytes("local-done.json")
        except FileNotFoundError:
            self._exports(work)
            rows = cast(list[dict[str, object]], work["intents"])
            local = [
                row
                for row in rows
                if row["kind"] in {"TransactionIntent", "EmergencyDeletionIntent"}
            ]
            if len(local) > 1:
                raise HostRestoreError("restore_local_intents_ambiguous") from None
            if local:
                self._lifecycle(local[0], proof)
            elif rows:
                if len(rows) != 1:
                    raise HostRestoreError("restore_remote_intents_ambiguous") from None
                row = rows[0]
                if row["operation"] == "unstarted-retirement":
                    reconcile_unstarted_retirement(
                        self.store,
                        ArchiveRetirementJournal(self.repository, self.spool, bucket=self.bucket),
                        str(row["intentId"]),
                        proof,
                    )
                elif row["operation"] == "unbound-construction":
                    finalize_failed_construction(self.repository, self.spool, str(row["jobId"]))
                elif row["operation"] not in {"bound-construction", "terminal-retirement"}:
                    raise HostRestoreError("restore_local_unknown_operation") from None
            with self.repository.publication_transaction() as transaction:
                remaining = [
                    transaction.read_intent(row.intent_id)[1].document
                    for row in transaction.measure_intent_records().records
                ]
                if any(
                    row["kind"] not in {"ArchiveConstructionIntent", "ArchiveRetirementIntent"}
                    for row in remaining
                ):
                    raise HostRestoreError("restore_local_intent_remains") from None
            raw = canonical_json_bytes(
                {
                    "schema": DONE_SCHEMA,
                    "validatedJournalDigest": validated,
                    "workDigest": binding,
                    "remoteIntents": sorted(str(row["intentId"]) for row in remaining),
                }
            )
            self.store.immutable("local-done.json", raw)
        done = exact_object(
            decode_json_object(raw),
            {"schema", "validatedJournalDigest", "workDigest", "remoteIntents"},
        )
        if (
            done["schema"] != DONE_SCHEMA
            or done["validatedJournalDigest"] != validated
            or done["workDigest"] != binding
            or canonical_json_bytes(done) != raw
            or type(done["remoteIntents"]) is not list
        ):
            raise HostRestoreError("restore_local_completion_changed")
        return tuple(validate_uuid7(identity) for identity in done["remoteIntents"])

    def _exports(self, work: dict[str, object]) -> None:
        if self.spool.completed_job_id() is not None:
            raise HostRestoreError("restore_export_delivery_not_excluded")
        with self.repository.publication_transaction() as transaction:
            for identity in cast(list[str], work["jobs"]):
                job = transaction.read(StateRecordPath.authorization_job(identity)).document
                request = cast(dict[str, object], job["request"])
                if request["operation"] != "export" or job.get("exportDelivery") in {
                    "acknowledged",
                    "expired",
                }:
                    continue
                try:
                    result = transaction.read(
                        StateRecordPath.authorization_result(identity)
                    ).document
                except FileNotFoundError:
                    continue
                if result["status"] == "succeeded":
                    retire_restored_export(self.store, transaction, job, result)

    def _lifecycle(self, row: dict[str, object], proof: dict[str, object]) -> None:
        identity = validate_uuid7(row["intentId"])
        operation = row["operation"]
        if operation == "archive":
            reconcile_archive(
                self.store,
                self.repository,
                self.spool,
                self.releases,
                identity,
                self.evidence,
                self.original_ca,
                proof,
            )
            return
        with self.repository.publication_transaction() as transaction:
            if row["kind"] == "EmergencyDeletionIntent":
                reconcile_emergency(
                    self.store,
                    transaction,
                    self.spool,
                    self.releases,
                    identity,
                    self.evidence,
                    self.original_ca,
                    proof,
                )
            elif operation == "create":
                reconcile_create(self.store, transaction, identity, self.evidence, self.original_ca)
            elif operation in {"suspend", "resume", "rename", "reconcile"}:
                reconcile_route(self.store, transaction, identity, self.evidence, self.original_ca)
            elif operation in {"deploy", "import", "rollback"}:
                reconcile_deployment(
                    self.store,
                    transaction,
                    self.releases,
                    identity,
                    self.evidence,
                    self.original_ca,
                )
            elif operation in {"restore", "delete"}:
                function = reconcile_tenant_restore if operation == "restore" else reconcile_delete
                function(
                    self.store,
                    transaction,
                    self.spool,
                    self.releases,
                    identity,
                    self.evidence,
                    self.original_ca,
                    proof,
                )
            elif operation == "export":
                job_id = validate_uuid7(row["jobId"])
                try:
                    transaction.read(StateRecordPath.authorization_result(job_id))
                except FileNotFoundError:
                    abandon_uncommitted_export(self.store, transaction, job_id, identity)
                else:
                    finish_export_intent(transaction, job_id)
            else:
                raise HostRestoreError("restore_local_unknown_operation")


def finish_restored_jobs(
    store: RestoreStore, repository: StateRepository, work: dict[str, object]
) -> None:
    """Remote barriers must be gone before unrelated missing-input failures append."""
    _validated(store)
    _require_saved_work(store, work)
    with repository.publication_transaction() as transaction:
        if transaction.measure_intent_records().records:
            raise HostRestoreError("restore_remote_cleanup_incomplete")
        for identity in cast(list[str], work["jobs"]):
            job = transaction.read(StateRecordPath.authorization_job(identity))
            _validate_request_integrity(job.document)
            request = cast(dict[str, object], job.document["request"])
            correlation = transaction.read(
                StateRecordPath.authorization_correlation(request["correlationId"])
            )
            _require_same_authority(job.document, correlation.document)
            if (
                correlation.document["jobId"] != identity
                or correlation.document["requestDigest"] != job.document["requestDigest"]
            ):
                raise HostRestoreError("restore_job_correlation_changed")
            finish_missing_input(transaction, identity)
            job = transaction.read(StateRecordPath.authorization_job(identity))
            try:
                result = transaction.read(StateRecordPath.authorization_result(identity))
            except FileNotFoundError:
                if job.document["phase"] not in {"pending", "claimed"}:
                    raise HostRestoreError("restore_terminal_job_missing_result") from None
                if (
                    transaction.inspect_audit_correlation(request["correlationId"]).entry
                    is not None
                ):
                    raise HostRestoreError("restore_job_audit_missing_result") from None
                continue
            _validate_result_binding(job.document, result.document)
            if result.document.get("failurePublisher") == "authorization-executor":
                _repair_executor_failure_audit(
                    transaction, job.document, result.document, limits=DEFAULT_HOST_CAPACITY_LIMITS
                )
            latest = _validate_result_audit(transaction, job.document, result.document)
            if job.document["compatibilityVersion"] == "static-job-v2":
                authority = _capture_replay_authority(
                    transaction,
                    job.document,
                    result.document,
                    validation_was_committed=job.document["executionValidated"] is True,
                    audit_is_latest_for_tenant=latest,
                )
                _validate_handler_result_state(
                    transaction,
                    job.document,
                    result.document,
                    authority=authority,
                    audit_is_latest_for_tenant=latest,
                )
            _repair_terminal_phase_transaction(transaction, job, result)
