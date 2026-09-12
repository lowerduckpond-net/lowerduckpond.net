"""Root-owned remote construction and retirement barriers under export exclusion.

Lifecycle code must commit its own manifest, routes, audit, and immutable result
before finishing either journal. A journal never grants lifecycle authority.
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractKind,
    archive_record_digest,
    deployment_record_digest,
    manifest_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.archive_bundle import require_archive_inspection
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteError,
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
    archive_key,
)
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    FilesystemCapacity,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.export_snapshot import ExportSnapshot
from lowerduckpond_static_host_agent.export_spool import EXPORT_WORKSPACE_BUNDLE_NAME, ExportSpool
from lowerduckpond_static_host_agent.intents import DiscoveredIntent, IntentDiscovery
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.portable_bundle import inspect_portable_bundle
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)


class ArchiveJournalError(ArchiveRemoteError):
    """Remote journal recovery cannot prove the required lifecycle authority."""


class ArchiveJournalBoundary(StrEnum):
    CONSTRUCTION_SYNC = "construction-sync"
    REMOTE_ADMITTED = "remote-admitted"
    REMOTE_PUT = "remote-put"
    REMOTE_VERIFIED = "remote-verified"
    UPLOADED_SYNC = "uploaded-sync"
    RETIREMENT_SYNC = "retirement-sync"
    ABSENCE_VERIFIED = "absence-verified"
    INTENT_REMOVED = "intent-removed"


@dataclass(frozen=True, slots=True)
class UploadedArchive:
    construction: StoredContract
    record: dict[str, object]


class ArchiveJournal:
    """Persist authority before upload and retain it through exact remote cleanup.

    The injected quarantine sink must durably close admission and retain known
    inventory before returning. It is required, including for malformed or
    unavailable listings (represented by None), rather than an optional log.
    """

    def __init__(  # noqa: PLR0913 - trusted boundaries stay explicit
        self,
        repository: StateRepository,
        spool: ExportSpool,
        remote: ArchiveRemoteStore,
        *,
        expected_owner: int,
        quarantine: Callable[[RemoteInventory | None], None],
        require_quarantine_empty: Callable[[], None],
        hook: Callable[[ArchiveJournalBoundary], None] | None = None,
    ) -> None:
        self.repository = repository
        self.spool = spool
        self.remote = remote
        self.owner = expected_owner
        self.quarantine = quarantine
        self.require_quarantine_empty = require_quarantine_empty
        self.hook = hook

    def construct(  # noqa: PLR0915 - durable and remote barriers remain visible
        self, job_id: str, snapshot: ExportSnapshot, *, now: datetime
    ) -> UploadedArchive:
        """Create one fresh intent and send exactly one complete portable bundle.

        An existing intent always rejects this fresh path, including prepared
        intents whose PutObject response was lost. Recovery discovers that key;
        it never retries its PutObject.
        """
        self._require_lock()
        self.require_quarantine_empty()
        bundle = self.spool.workspace / EXPORT_WORKSPACE_BUNDLE_NAME
        inspection = inspect_portable_bundle(bundle, expected_owner=self.owner)
        if (
            snapshot.source_manifest is None
            or inspection.provenance_manifest != snapshot.manifest
            or inspection.release_tree_digest != snapshot.measurement.digest
            or inspection.release_tree_digest.to_dict() != snapshot.deployment["releaseTreeDigest"]
        ):
            raise ArchiveJournalError("archive bundle did not bind its separate source snapshot")
        candidate = deepcopy(snapshot.source_manifest)
        cast(dict[str, object], candidate["spec"])["desiredState"] = "archived"
        if candidate != snapshot.manifest:
            raise ArchiveJournalError(
                "archive candidate changed fields outside lifecycle authority"
            )
        with self.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id))
            request = cast(dict[str, object], job.document["request"])
            expected = cast(dict[str, object], job.document["expectedSource"])
            if (
                job.document["phase"] != "claimed"
                or request["operation"] != "archive"
                or expected["lifecycle"] not in {"active", "suspended"}
                or build_expected_source(transaction, request) != expected
                or expected["manifestDigest"] != manifest_digest(snapshot.source_manifest).to_dict()
                or expected["deploymentDigest"]
                != deployment_record_digest(snapshot.deployment).to_dict()
            ):
                raise ArchiveJournalError("archive construction source is not job-authorized")
            if transaction.measure_intent_records().records:
                raise ArchiveJournalError("archive construction requires reconciled intents")
            intent: dict[str, object] = {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "ArchiveConstructionIntent",
                "intentId": _identity(),
                "uploadAttemptId": _identity(),
                "jobId": job_id,
                "operatorPrincipal": job.document["operatorPrincipal"],
                "tenantId": request["tenantId"],
                "correlationId": request["correlationId"],
                "sourceManifestDigest": expected["manifestDigest"],
                "candidateManifestDigest": inspection.provenance_manifest_digest.to_dict(),
                "deploymentRecordDigest": expected["deploymentDigest"],
                "releaseTreeDigest": inspection.release_tree_digest.to_dict(),
                "bundleDigest": inspection.bundle_digest.to_dict(),
                "bundleSize": inspection.bundle_size,
                "bucket": self.remote.bucket,
                "key": "",
                "versionId": None,
                "phase": "prepared",
                "createdAt": _timestamp(now),
            }
            intent["key"] = archive_key(intent["uploadAttemptId"])
            path = StateRecordPath.archive_construction_intent(intent["intentId"])
            _reserve_journal(transaction.measure_filesystem_capacity)
            stored = transaction.create_immutable(path, intent)
        self._notify(ArchiveJournalBoundary.CONSTRUCTION_SYNC)
        inventory: RemoteInventory | None = None
        try:
            inventory = self.remote.inventory()
            inventory.require_reservation(self.bound_versions())
            self.remote.require_absent(cast(str, intent["key"]))
        except Exception:
            self.quarantine(inventory)
            raise
        self._notify(ArchiveJournalBoundary.REMOTE_ADMITTED)
        parent = os.open(self.spool.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(
                EXPORT_WORKSPACE_BUNDLE_NAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
        finally:
            os.close(parent)
        version: str | None = None
        try:
            with os.fdopen(descriptor, "rb") as body:
                version = self.remote.put_once(
                    cast(str, intent["key"]),
                    body,
                    size=inspection.bundle_size,
                    sha256=inspection.bundle_digest.value,
                )
            self._notify(ArchiveJournalBoundary.REMOTE_PUT)
            self.remote.read_verified(
                cast(str, intent["key"]),
                version,
                size=inspection.bundle_size,
                sha256=inspection.bundle_digest.value,
            )
            self._notify(ArchiveJournalBoundary.REMOTE_VERIFIED)
        except Exception:
            self.quarantine(
                None
                if version is None
                else RemoteInventory(
                    (
                        RemoteVersion(
                            cast(str, intent["key"]), version, inspection.bundle_size, False
                        ),
                    ),
                    (),
                )
            )
            raise
        intent.update(versionId=version, phase="uploaded")
        stored = self.repository.compare_and_swap(path, stored.revision, intent)
        self._notify(ArchiveJournalBoundary.UPLOADED_SYNC)
        record = _archive_record(intent, snapshot.deployment)
        require_archive_inspection(inspection, record, snapshot.manifest)
        return UploadedArchive(stored, record)

    def prepare_retirement(self, job_id: str, *, now: datetime) -> StoredContract:
        """Bind the complete current archive before restore or ordinary deletion."""
        self._require_lock()
        with self.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id)).document
            request = cast(dict[str, object], job["request"])
            expected = cast(dict[str, object], job["expectedSource"])
            if (
                job["phase"] != "claimed"
                or request["operation"] not in {"restore", "delete"}
                or expected["lifecycle"] != "archived"
                or build_expected_source(transaction, request) != expected
                or transaction.measure_intent_records().records
            ):
                raise ArchiveJournalError("retirement requires current distinct archived authority")
            manifest = transaction.read(
                StateRecordPath.tenant_desired(request["tenantId"])
            ).document
            desired = cast(
                dict[str, object], cast(dict[str, object], manifest["spec"])["desiredDeployment"]
            )
            archive = transaction.read(
                StateRecordPath.tenant_archive(request["tenantId"], desired["id"])
            ).document
            if archive["bucket"] != self.remote.bucket:
                raise ArchiveJournalError("retirement archive belongs to another configured bucket")
            intent: dict[str, object] = {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "ArchiveRetirementIntent",
                "compatibilityVersion": "static-retirement-v2",
                "intentId": _identity(),
                "provenance": {"kind": "authorization-job", "jobId": job_id},
                "operatorPrincipal": job["operatorPrincipal"],
                "tenantId": request["tenantId"],
                "correlationId": request["correlationId"],
                "transition": request["operation"],
                "sourceManifestDigest": expected["manifestDigest"],
                "archiveRecord": archive,
                "archiveRecordDigest": archive_record_digest(archive).to_dict(),
                "phase": "prepared",
                "createdAt": _timestamp(now),
                **{
                    key: archive[key]
                    for key in ("bucket", "key", "versionId", "bundleDigest", "bundleSize")
                },
            }
            _reserve_journal(transaction.measure_filesystem_capacity)
            stored = transaction.create_immutable(
                StateRecordPath.archive_retirement_intent(intent["intentId"]), intent
            )
        self._notify(ArchiveJournalBoundary.RETIREMENT_SYNC)
        return stored

    def bound_versions(self) -> frozenset[RemoteVersion]:
        """Charge every authoritative record, including incomplete local retirement."""
        self._require_lock()
        versions: set[RemoteVersion] = set()
        with self.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            for tenant_id in transaction.measure_inventory().tenant_ids:
                for deployment_id in transaction.tenant_archive_ids(tenant_id):
                    record = transaction.read(
                        StateRecordPath.tenant_archive(tenant_id, deployment_id)
                    ).document
                    if record["bucket"] != self.remote.bucket:
                        raise ArchiveJournalError(
                            "authoritative archive bucket disagrees with configuration"
                        )
                    entry = RemoteVersion(
                        cast(str, record["key"]),
                        cast(str, record["versionId"]),
                        cast(int, record["bundleSize"]),
                        False,
                    )
                    if any(previous.key == entry.key for previous in versions):
                        raise ArchiveJournalError("archive key has multiple authoritative bindings")
                    versions.add(entry)
        return frozenset(versions)

    def purge_unbound_construction(self, intent_id: str) -> None:
        """Discover a lost upload response and purge, retaining the journal for audit.

        Caller must durably publish the failed lifecycle result before finish.
        Prepared recovery never repeats PutObject, even after an empty listing.
        """
        intent = self._remote_intent(intent_id)
        if intent.kind is not ContractKind.ARCHIVE_CONSTRUCTION_INTENT:
            raise ArchiveJournalError("construction cleanup received other authority")
        self._purge(intent.record.document)

    def finish(self, intent_id: str) -> None:
        """Clear only after audited terminal state and independent remote proof."""
        intent = self._remote_intent(intent_id)
        document = intent.record.document
        result = self._terminal_result(document)
        key = cast(str, document["key"])
        bound = tuple(version for version in self.bound_versions() if version.key == key)
        construction = intent.kind is ContractKind.ARCHIVE_CONSTRUCTION_INTENT
        preserve = result["status"] == "succeeded" if construction else result["status"] == "failed"
        if preserve:
            archive = result.get("archiveRecord") if construction else document["archiveRecord"]
            if (
                type(archive) is not dict
                or not _same_object(document, archive)
                or archive["tenantId"] != document["tenantId"]
                or bound
                != (
                    RemoteVersion(
                        key,
                        cast(str, archive["versionId"]),
                        cast(int, archive["bundleSize"]),
                        False,
                    ),
                )
            ):
                raise ArchiveJournalError("terminal state does not retain its exact archive")
            if construction and (
                archive["manifestDigest"] != document["candidateManifestDigest"]
                or archive["releaseTreeDigest"] != document["releaseTreeDigest"]
            ):
                raise ArchiveJournalError("terminal archive exceeds construction evidence")
            self.verify_retained(archive)
        else:
            if bound:
                raise ArchiveJournalError(
                    "terminal cleanup still has authoritative archive bindings"
                )
            self._purge(document)
        self.repository.remove_reconciled_intent(intent.path, intent.removal_token)
        self._notify(ArchiveJournalBoundary.INTENT_REMOVED)

    def verify_retained(self, archive: dict[str, object]) -> bool:
        validate_contract(archive, expected_kind=ContractKind.ARCHIVE_RECORD)
        if archive["bucket"] != self.remote.bucket:
            raise ArchiveJournalError("archive verification selected another bucket")
        digest = cast(dict[str, object], archive["bundleDigest"])
        self.remote.read_verified(
            cast(str, archive["key"]),
            cast(str, archive["versionId"]),
            size=cast(int, archive["bundleSize"]),
            sha256=cast(str, digest["value"]),
        )
        return True

    def _remote_intent(self, intent_id: str) -> DiscoveredIntent:
        self._require_lock()
        discovery = IntentDiscovery(self.repository).discover()
        if len(discovery.intents) != 1:
            raise ArchiveJournalError("reconcile lifecycle authority before remote cleanup")
        intent = discovery.intents[0]
        if (
            intent.path.record_id != validate_uuid7(intent_id)
            or intent.kind
            not in {
                ContractKind.ARCHIVE_CONSTRUCTION_INTENT,
                ContractKind.ARCHIVE_RETIREMENT_INTENT,
            }
            or intent.record.document["bucket"] != self.remote.bucket
        ):
            raise ArchiveJournalError("remote cleanup journal identity is inconsistent")
        return intent

    def _terminal_result(self, intent: dict[str, object]) -> dict[str, object]:
        job_id = intent.get("jobId")
        if job_id is None:
            provenance = cast(dict[str, object], intent["provenance"])
            if provenance["kind"] != "authorization-job":
                raise ArchiveJournalError("ordinary cleanup cannot consume emergency provenance")
            job_id = provenance["jobId"]
        with self.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id)).document
            result = transaction.read(StateRecordPath.authorization_result(job_id)).document
            request = cast(dict[str, object], job["request"])
            audit = transaction.inspect_audit_correlation(intent["correlationId"])
            expected = cast(dict[str, object], job["expectedSource"])
            if (
                job["phase"] != "completed"
                or job["operatorPrincipal"] != intent["operatorPrincipal"]
                or request["correlationId"] != intent["correlationId"]
                or request["tenantId"] != intent["tenantId"]
                or request["operation"] != intent.get("transition", "archive")
                or result["operation"] != request["operation"]
                or result["provenance"] != {"kind": "authorization-job", "jobId": job_id}
                or result["correlationId"] != intent["correlationId"]
                or result["tenantId"] != intent["tenantId"]
                or expected["manifestDigest"] != intent["sourceManifestDigest"]
                or audit.entry is None
                or audit.entry["resultDigest"] != result_digest(result).to_dict()
                or audit.entry["operatorPrincipal"] != intent["operatorPrincipal"]
            ):
                raise ArchiveJournalError("remote cleanup has no exact audited terminal result")
            if (
                intent["kind"] == "ArchiveRetirementIntent"
                and expected["archiveRecordDigest"] != intent["archiveRecordDigest"]
            ):
                raise ArchiveJournalError("retirement exceeds its job's archive authority")
            _require_terminal_local_state(transaction, job, result, intent, audit.entry)
            return result

    def _purge(self, document: dict[str, object]) -> None:
        def require_unbound(key: str) -> None:
            if any(version.key == key for version in self.bound_versions()):
                raise ArchiveJournalError("remote key remains bound by authoritative state")

        try:
            self.remote.purge_unbound(cast(str, document["key"]), require_unbound=require_unbound)
            self.remote.require_absent(cast(str, document["key"]))
        except Exception:
            self.quarantine(None)
            raise
        self._notify(ArchiveJournalBoundary.ABSENCE_VERIFIED)

    def _require_lock(self) -> None:
        self.spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)

    def _notify(self, boundary: ArchiveJournalBoundary) -> None:
        if self.hook is not None:
            self.hook(boundary)


def _identity() -> str:
    return generate_uuid7(
        clock=lambda: time.time_ns() // 1_000_000,
        entropy=_entropy,
    )


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


def _timestamp(now: datetime) -> str:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ArchiveJournalError("archive journal requires a timezone-aware clock")
    return now.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _archive_record(intent: dict[str, object], deployment: dict[str, object]) -> dict[str, object]:
    record: dict[str, object] = {
        "apiVersion": intent["apiVersion"],
        "kind": "ArchiveRecord",
        "tenantId": intent["tenantId"],
        "deploymentId": deployment["id"],
        "manifestDigest": intent["candidateManifestDigest"],
        **{
            key: intent[key]
            for key in (
                "releaseTreeDigest",
                "bundleDigest",
                "bundleSize",
                "bucket",
                "key",
                "versionId",
                "createdAt",
                "correlationId",
            )
        },
    }
    validate_contract(record, expected_kind=ContractKind.ARCHIVE_RECORD)
    return record


def _same_object(intent: dict[str, object], record: dict[str, object]) -> bool:
    return all(
        intent[key] == record[key]
        for key in ("bucket", "key", "versionId", "bundleSize", "bundleDigest")
    )


def _require_terminal_local_state(
    transaction: _StateTransaction,
    job: dict[str, object],
    result: dict[str, object],
    intent: dict[str, object],
    audit: dict[str, object],
) -> None:
    tenant = intent["tenantId"]
    if result["operation"] == "delete" and result["status"] == "succeeded":
        expected = cast(dict[str, object], job["expectedSource"])
        if tenant in transaction.measure_inventory().tenant_ids or audit.get(
            "deletionEvidence"
        ) != expected.get("deletionEvidence"):
            raise ArchiveJournalError("deletion has not committed its exact tombstone and absence")
        return
    authority = cast(dict[str, object], job["sourceAuthority"])
    expected_manifest = (
        result.get("manifest") if result["status"] == "succeeded" else authority["manifest"]
    )
    manifest = transaction.read(StateRecordPath.tenant_desired(tenant)).document
    observed = transaction.read(StateRecordPath.tenant_observed(tenant)).document
    spec = cast(dict[str, object], manifest["spec"])
    desired = cast(dict[str, object], spec["desiredDeployment"])
    if (
        manifest != expected_manifest
        or observed["desiredManifestDigest"] != manifest_digest(manifest).to_dict()
        or observed["observedState"] != spec["desiredState"]
    ):
        raise ArchiveJournalError("archive cleanup precedes complete terminal local state")
    if spec["desiredState"] == "archived":
        archive = transaction.read(StateRecordPath.tenant_archive(tenant, desired["id"])).document
        expected_archive = (
            result.get("archiveRecord")
            if result["operation"] == "archive"
            else intent["archiveRecord"]
        )
        if (
            archive != expected_archive
            or observed["activeDeploymentId"] is not None
            or observed["runtimeGenerationId"] is not None
            or archive["manifestDigest"] != manifest_digest(manifest).to_dict()
        ):
            raise ArchiveJournalError("archived terminal state lost its complete source record")
    elif result["operation"] == "restore" and result["status"] == "succeeded":
        archive = cast(dict[str, object], intent["archiveRecord"])
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant, desired["id"])
        ).document
        if (
            spec["desiredState"] != "active"
            or desired["id"] == archive["deploymentId"]
            or observed["activeDeploymentId"] != desired["id"]
            or observed["runtimeGenerationId"] is None
            or deployment["releaseTreeDigest"] != archive["releaseTreeDigest"]
            or deployment["archiveSha256"]
            != cast(dict[str, object], archive["bundleDigest"])["value"]
        ):
            raise ArchiveJournalError("restoration has not committed a new bound deployment")


def _reserve_journal(filesystem: Callable[[], FilesystemCapacity]) -> None:
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(4 * MAX_CANONICAL_BYTES, 4),
        filesystem(),
    )
