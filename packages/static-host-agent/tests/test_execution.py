from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import zipfile
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    archive_record_digest,
    audit_entry_digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    request_digest,
    result_digest,
)
from lowerduckpond_static_host_agent import (
    ArtifactClaim,
    ArtifactIntake,
    AuditError,
    AuthorizationExecutor,
    AuthorizationIssuer,
    CapacityProjection,
    CapacityReservation,
    ExecutionError,
    ExecutionOutcome,
    FilesystemCapacity,
    IntakeArtifactUnavailableError,
    IntentRemovalToken,
    IssuedAuthorization,
    LifecycleArtifact,
    LifecycleJobHandler,
    LockManager,
    LockName,
    StateRecordPath,
    StateRepository,
    StoredContract,
    VerifiedArtifact,
    build_portable_bundle,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT_ID = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_TENANT_ROOTED_RECORD_COMPONENTS = 3
_RESULT_AND_AUDIT_INODES = 2


class _OpenGate:
    def require_enabled(self) -> None:
        return


class _Entropy:
    def __call__(self, length: int) -> bytes:
        return b"\x08" * length


class _CompletingCreateHandler:
    def __init__(  # noqa: PLR0913 - test handler toggles independent corruption boundaries
        self,
        repository: StateRepository,
        *,
        persist_result: bool = True,
        commit_job: bool = True,
        state_root: Path | None = None,
        result_slug: str | None = None,
        write_observed: bool = True,
    ) -> None:
        self._repository = repository
        self._persist_result = persist_result
        self._commit_job = commit_job
        self._state_root = state_root
        self._result_slug = result_slug
        self._write_observed = write_observed
        self.phases: list[object] = []
        self.claims: list[LifecycleArtifact | None] = []

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        self.phases.append(job.document["phase"])
        self.claims.append(claim)
        created = False
        try:
            result = self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=blocking,
            ).document
        except FileNotFoundError:
            request = job.document["request"]
            assert type(request) is dict
            result = _fixture("operation-result.json")
            provenance = result["provenance"]
            manifest = result["manifest"]
            assert type(provenance) is dict
            assert type(manifest) is dict
            provenance["jobId"] = job_id
            result["correlationId"] = request["correlationId"]
            committed_manifest = json.loads(json.dumps(manifest))
            if self._result_slug is not None:
                metadata = manifest["metadata"]
                assert type(metadata) is dict
                metadata["slug"] = self._result_slug
            if result["status"] == "succeeded" and self._state_root is not None:
                _write(
                    self._state_root,
                    StateRecordPath.tenant_desired(result["tenantId"]),
                    committed_manifest,
                )
                if self._write_observed:
                    _write_observed_for_manifest(self._state_root, committed_manifest)
            if self._persist_result:
                self._repository.create_immutable(
                    StateRecordPath.authorization_result(job_id),
                    result,
                    blocking=blocking,
                )
                if result["status"] == "succeeded":
                    _append_result_audit(self._repository, job.document, result)
                created = True
        if result["status"] == "failed":
            _append_result_audit_if_absent(self._repository, job.document, result)
        if self._commit_job:
            current = self._repository.read(
                StateRecordPath.authorization_job(job_id),
                blocking=blocking,
            )
            completed = current.document
            completed["phase"] = "completed" if result["status"] == "succeeded" else "failed"
            self._repository.compare_and_swap(
                StateRecordPath.authorization_job(job_id),
                current.revision,
                completed,
                blocking=blocking,
            )
        return ExecutionOutcome(result, created)


class _CompletingFailureHandler:
    def __init__(  # noqa: PLR0913 - test handler toggles independent failure residue
        self,
        repository: StateRepository,
        *,
        append_audit: bool = True,
        claim_executor_publication: bool = False,
        retained_archive_id: str | None = None,
        retained_deployment_id: str | None = None,
        state_root: Path | None = None,
    ) -> None:
        self._repository = repository
        self._append_audit = append_audit
        self._claim_executor_publication = claim_executor_publication
        self._retained_archive_id = retained_archive_id
        self._retained_deployment_id = retained_deployment_id
        self._state_root = state_root
        self.claims: list[LifecycleArtifact | None] = []

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        self.claims.append(claim)
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        request = job.document["request"]
        assert type(request) is dict
        candidate: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "correlationId": request["correlationId"],
            "operation": request["operation"],
            "status": "failed",
            "errorCode": "not_implemented",
            "tenantId": None if request["operation"] == "create" else request["tenantId"],
        }
        if self._claim_executor_publication:
            candidate["failurePublisher"] = "authorization-executor"
        try:
            result = self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=blocking,
            ).document
            created = False
        except FileNotFoundError:
            result = candidate
            self._repository.create_immutable(
                StateRecordPath.authorization_result(job_id),
                result,
                blocking=blocking,
            )
            created = True
        if self._state_root is not None:
            _write(
                self._state_root,
                StateRecordPath.tenant_desired(_TENANT_ID),
                _fixture("site.json"),
            )
            if self._retained_deployment_id is not None:
                deployment = _fixture("deployment-record.json")
                deployment["id"] = self._retained_deployment_id
                _write(
                    self._state_root,
                    StateRecordPath.tenant_deployment(
                        _TENANT_ID,
                        self._retained_deployment_id,
                    ),
                    deployment,
                )
            if self._retained_archive_id is not None:
                archive = _fixture("archive-record.json")
                archive["deploymentId"] = self._retained_archive_id
                _write(
                    self._state_root,
                    StateRecordPath.tenant_archive(
                        _TENANT_ID,
                        self._retained_archive_id,
                    ),
                    archive,
                )
        if self._append_audit:
            _append_result_audit_if_absent(self._repository, job.document, result)
        if job.document["phase"] != "failed":
            failed = job.document
            failed["phase"] = "failed"
            self._repository.compare_and_swap(
                StateRecordPath.authorization_job(job_id),
                job.revision,
                failed,
                blocking=blocking,
            )
        return ExecutionOutcome(result, created)


class _CompletingDeployHandler:
    def __init__(  # noqa: PLR0913 - test handler toggles independent durable records
        self,
        repository: StateRepository,
        root: Path,
        *,
        deployment_record: bool = True,
        deployment_archive_sha256: str | None = None,
        deployment_release_tree_digest: dict[str, object] | None = None,
        write_observed: bool = True,
    ) -> None:
        self._repository = repository
        self._root = root
        self._deployment_record = deployment_record
        self._deployment_archive_sha256 = deployment_archive_sha256
        self._deployment_release_tree_digest = deployment_release_tree_digest
        self._write_observed = write_observed
        self.claims: list[LifecycleArtifact | None] = []

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert claim is not None
        self.claims.append(claim)
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        request = job.document["request"]
        assert type(request) is dict
        artifact = request["artifact"]
        assert type(artifact) is dict
        manifest = _fixture("site.json")
        spec = manifest["spec"]
        metadata = manifest["metadata"]
        assert type(spec) is dict
        assert type(metadata) is dict
        selected = spec["desiredDeployment"]
        assert type(selected) is dict
        selected.update(
            {
                "id": "0198d17f-6f4a-7000-8000-000000000009",
                "archiveSha256": artifact["sha256"],
            }
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "correlationId": request["correlationId"],
            "operation": request["operation"],
            "status": "succeeded",
            "tenantId": request["tenantId"],
            "canonicalOrigin": metadata["canonicalOrigin"],
            "manifest": manifest,
        }
        _write(
            self._root,
            StateRecordPath.tenant_desired(request["tenantId"]),
            manifest,
        )
        if self._write_observed:
            _write_observed_for_manifest(self._root, manifest)
        if self._deployment_record:
            deployment = _fixture("deployment-record.json")
            release_tree_digest = job.document["dispatchArtifactReleaseTreeDigest"]
            assert type(release_tree_digest) is dict
            deployment.update(
                {
                    "id": selected["id"],
                    "tenantId": request["tenantId"],
                    "archiveSha256": (
                        artifact["sha256"]
                        if self._deployment_archive_sha256 is None
                        else self._deployment_archive_sha256
                    ),
                    "correlationId": request["correlationId"],
                    "releaseTreeDigest": (
                        release_tree_digest
                        if self._deployment_release_tree_digest is None
                        else self._deployment_release_tree_digest
                    ),
                }
            )
            _write(
                self._root,
                StateRecordPath.tenant_deployment(request["tenantId"], selected["id"]),
                deployment,
            )
        self._repository.create_immutable(
            StateRecordPath.authorization_result(job_id),
            result,
            blocking=blocking,
        )
        _append_result_audit(self._repository, job.document, result)
        completed = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        terminal = completed.document
        terminal["phase"] = "completed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(job_id),
            completed.revision,
            terminal,
            blocking=blocking,
        )
        return ExecutionOutcome(result, True)


class _ArtifactConsumingHandler:
    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert job_id
        assert claim is not None
        assert blocking is False
        claim.consume()  # type: ignore[attr-defined]
        raise AssertionError("read-only lifecycle artifact unexpectedly exposed consume")


class _CompletingRollbackHandler:
    def __init__(
        self,
        repository: StateRepository,
        root: Path,
        *,
        remove_deployment_record: bool,
        extra_archive: dict[str, object] | None = None,
        extra_deployment: dict[str, object] | None = None,
    ) -> None:
        self._repository = repository
        self._root = root
        self._remove_deployment_record = remove_deployment_record
        self._extra_archive = extra_archive
        self._extra_deployment = extra_deployment

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert claim is None
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        request = job.document["request"]
        assert type(request) is dict
        deployment_path = StateRecordPath.tenant_deployment(
            request["tenantId"],
            request["deploymentId"],
        )
        deployment = self._repository.read(deployment_path, blocking=blocking).document
        manifest = _fixture("site.json")
        spec = manifest["spec"]
        metadata = manifest["metadata"]
        assert type(spec) is dict
        assert type(metadata) is dict
        selected = spec["desiredDeployment"]
        assert type(selected) is dict
        selected.update(
            {
                "id": deployment["id"],
                "archiveSha256": deployment["archiveSha256"],
            }
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "correlationId": request["correlationId"],
            "operation": "rollback",
            "status": "succeeded",
            "tenantId": request["tenantId"],
            "canonicalOrigin": metadata["canonicalOrigin"],
            "manifest": manifest,
        }
        _write(
            self._root,
            StateRecordPath.tenant_desired(request["tenantId"]),
            manifest,
        )
        _write_observed_for_manifest(self._root, manifest)
        if self._remove_deployment_record:
            self._root.joinpath(*deployment_path.components).unlink()
        if self._extra_archive is not None:
            _write(
                self._root,
                StateRecordPath.tenant_archive(
                    request["tenantId"],
                    self._extra_archive["deploymentId"],
                ),
                self._extra_archive,
            )
        if self._extra_deployment is not None:
            _write(
                self._root,
                StateRecordPath.tenant_deployment(
                    request["tenantId"],
                    self._extra_deployment["id"],
                ),
                self._extra_deployment,
            )
        self._repository.create_immutable(
            StateRecordPath.authorization_result(job_id),
            result,
            blocking=blocking,
        )
        _append_result_audit(self._repository, job.document, result)
        current = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        terminal = current.document
        terminal["phase"] = "completed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(job_id),
            current.revision,
            terminal,
            blocking=blocking,
        )
        return ExecutionOutcome(result, True)


class _CompletingTransitionHandler:
    def __init__(  # noqa: PLR0913 - test handler toggles independent durable records
        self,
        repository: StateRepository,
        root: Path,
        *,
        manifest: dict[str, object],
        deployment: dict[str, object] | None = None,
        archive: dict[str, object] | None = None,
        write_archive: bool = True,
        write_export: bool = False,
    ) -> None:
        self._repository = repository
        self._root = root
        self._manifest = manifest
        self._deployment = deployment
        self._archive = archive
        self._write_archive = write_archive
        self._write_export = write_export

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert claim is None
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        request = job.document["request"]
        metadata = self._manifest["metadata"]
        spec = self._manifest["spec"]
        assert type(request) is dict
        assert type(metadata) is dict
        assert type(spec) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "correlationId": request["correlationId"],
            "operation": request["operation"],
            "status": "succeeded",
            "tenantId": request["tenantId"],
            "canonicalOrigin": metadata["canonicalOrigin"],
            "manifest": self._manifest,
        }
        if request["operation"] == "archive" and self._archive is not None:
            result["archiveRecord"] = self._archive
        if request["operation"] == "export":
            payload = b"authorized exported bundle"
            result["exportBundle"] = {
                "size": len(payload),
                "digest": {
                    "format": "lowerduckpond-archive-v1",
                    "algorithm": "sha256",
                    "value": hashlib.sha256(payload).hexdigest(),
                },
            }
            if self._write_export:
                export = self._root / "exports" / f"{job_id}.zip"
                export.write_bytes(payload)
                export.chmod(0o600)
        _write(
            self._root,
            StateRecordPath.tenant_desired(request["tenantId"]),
            self._manifest,
        )
        _write_observed_for_manifest(self._root, self._manifest)
        if self._deployment is not None:
            _write(
                self._root,
                StateRecordPath.tenant_deployment(
                    request["tenantId"],
                    self._deployment["id"],
                ),
                self._deployment,
            )
        if self._archive is not None and self._write_archive:
            _write(
                self._root,
                StateRecordPath.tenant_archive(
                    request["tenantId"],
                    self._archive["deploymentId"],
                ),
                self._archive,
            )
        self._repository.create_immutable(
            StateRecordPath.authorization_result(job_id),
            result,
            blocking=blocking,
        )
        _append_result_audit(self._repository, job.document, result)
        current = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        terminal = current.document
        terminal["phase"] = "completed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(job_id),
            current.revision,
            terminal,
            blocking=blocking,
        )
        return ExecutionOutcome(result, True)


class _SupersedingTransitionHandler:
    """Append a later same-tenant commit before executor validation."""

    def __init__(
        self,
        repository: StateRepository,
        root: Path,
        delegate: _CompletingTransitionHandler,
    ) -> None:
        self._repository = repository
        self._root = root
        self._delegate = delegate

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        outcome = self._delegate.execute(job_id, claim=claim, blocking=blocking)
        later = json.loads(json.dumps(outcome.result))
        provenance = later["provenance"]
        manifest = later["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        metadata = manifest["metadata"]
        assert type(metadata) is dict
        provenance["jobId"] = "0198d17f-6f4a-7000-8000-000000000007"
        later["correlationId"] = "0198d17f-6f4a-7000-8000-000000000008"
        later["operation"] = "rename"
        later.pop("exportBundle", None)
        metadata["slug"] = "later-authorized-operation"
        _write(
            self._root,
            StateRecordPath.tenant_desired(later["tenantId"]),
            manifest,
        )
        _write_observed_for_manifest(self._root, manifest)
        job = self._repository.read(StateRecordPath.authorization_job(job_id)).document
        _append_result_audit(self._repository, job, later)
        return outcome


class _SupersedingCreateHandler:
    """Model a later audited lifecycle commit before executor validation."""

    def __init__(
        self,
        repository: StateRepository,
        root: Path,
        *,
        audit_tenant_id: str | None = None,
    ) -> None:
        self._repository = repository
        self._root = root
        self._audit_tenant_id = audit_tenant_id

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        outcome = _CompletingCreateHandler(
            self._repository,
            state_root=self._root,
        ).execute(job_id, claim=claim, blocking=blocking)
        later = json.loads(json.dumps(outcome.result))
        later_provenance = later["provenance"]
        later_manifest = later["manifest"]
        assert type(later_provenance) is dict
        assert type(later_manifest) is dict
        later_metadata = later_manifest["metadata"]
        assert type(later_metadata) is dict
        later_provenance["jobId"] = "0198d17f-6f4a-7000-8000-000000000007"
        later["correlationId"] = "0198d17f-6f4a-7000-8000-000000000008"
        later["operation"] = "rename"
        later_metadata["slug"] = "later-authorized-operation"
        _write(
            self._root,
            StateRecordPath.tenant_desired(later["tenantId"]),
            later_manifest,
        )
        _write_observed_for_manifest(self._root, later_manifest)
        audit_result = json.loads(json.dumps(later))
        if self._audit_tenant_id is not None:
            audit_manifest = audit_result["manifest"]
            assert type(audit_manifest) is dict
            audit_metadata = audit_manifest["metadata"]
            assert type(audit_metadata) is dict
            audit_origin = f"t-{self._audit_tenant_id.replace('-', '')}.lowerduckpond.com"
            audit_result["tenantId"] = self._audit_tenant_id
            audit_result["canonicalOrigin"] = audit_origin
            audit_metadata["id"] = self._audit_tenant_id
            audit_metadata["canonicalOrigin"] = audit_origin
        job = self._repository.read(StateRecordPath.authorization_job(job_id)).document
        _append_result_audit(
            self._repository,
            {
                "acceptedAt": job["acceptedAt"],
                "operatorPrincipal": job["operatorPrincipal"],
            },
            audit_result,
        )
        return outcome


class _CompletingDeleteHandler:
    def __init__(
        self,
        repository: StateRepository,
        root: Path,
        *,
        deletion_evidence: dict[str, object],
        remove_namespace: bool = True,
    ) -> None:
        self._repository = repository
        self._root = root
        self._deletion_evidence = deletion_evidence
        self._remove_namespace = remove_namespace

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert claim is None
        job = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        request = job.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "correlationId": request["correlationId"],
            "operation": "delete",
            "status": "succeeded",
            "tenantId": request["tenantId"],
        }
        self._repository.create_immutable(
            StateRecordPath.authorization_result(job_id),
            result,
            blocking=blocking,
        )
        _append_result_audit(
            self._repository,
            job.document,
            result,
            deletion_evidence=self._deletion_evidence,
        )
        tenant_root = self._root / "tenants" / str(request["tenantId"])
        if self._remove_namespace:
            shutil.rmtree(tenant_root)
        else:
            desired_path = StateRecordPath.tenant_desired(request["tenantId"])
            self._root.joinpath(*desired_path.components).unlink()
            observed_path = StateRecordPath.tenant_observed(request["tenantId"])
            self._root.joinpath(*observed_path.components).unlink(missing_ok=True)
        current = self._repository.read(
            StateRecordPath.authorization_job(job_id),
            blocking=blocking,
        )
        completed = current.document
        completed["phase"] = "completed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(job_id),
            current.revision,
            completed,
            blocking=blocking,
        )
        return ExecutionOutcome(result, True)


class _CompletingIntentHandler:
    def __init__(
        self,
        repository: StateRepository,
        *,
        intent_path: StateRecordPath,
        delegate: _CompletingCreateHandler | _CompletingFailureHandler,
    ) -> None:
        self._repository = repository
        self._intent_path = intent_path
        self._delegate = delegate

    @property
    def claims(self) -> list[LifecycleArtifact | None]:
        return self._delegate.claims

    @property
    def phases(self) -> list[object]:
        assert isinstance(self._delegate, _CompletingCreateHandler)
        return self._delegate.phases

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        outcome = self._delegate.execute(job_id, claim=claim, blocking=blocking)
        intent = self._repository.read(self._intent_path, blocking=blocking)
        inventory = self._repository.measure_intent_records(blocking=blocking)
        generation = next(
            record.metadata_generation
            for record in inventory.records
            if record.intent_id == self._intent_path.record_id
        )
        self._repository.remove_reconciled_intent(
            self._intent_path,
            IntentRemovalToken(intent.revision, generation),
            blocking=blocking,
        )
        return outcome


class _ClearingIntentHandler:
    def __init__(
        self,
        repository: StateRepository,
        *,
        intent_paths: tuple[StateRecordPath, ...],
        delegate: LifecycleJobHandler | None = None,
    ) -> None:
        self._repository = repository
        self._intent_paths = intent_paths
        self._delegate = delegate
        self.dispatched = False

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        self.dispatched = True
        if self._delegate is None:
            result = self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=blocking,
            ).document
            outcome = ExecutionOutcome(result, False)
        else:
            outcome = self._delegate.execute(job_id, claim=claim, blocking=blocking)
        for path in self._intent_paths:
            intent = self._repository.read(path, blocking=blocking)
            inventory = self._repository.measure_intent_records(blocking=blocking)
            generation = next(
                record.metadata_generation
                for record in inventory.records
                if record.intent_id == path.record_id
            )
            self._repository.remove_reconciled_intent(
                path,
                IntentRemovalToken(intent.revision, generation),
                blocking=blocking,
            )
        return outcome


class _UnavailableArtifactHandler:
    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        assert job_id
        assert claim is not None
        assert blocking is False
        raise IntakeArtifactUnavailableError("handler recovery requires its artifact")


class _CompletingUnavailableClaim(AbstractContextManager[ArtifactClaim]):
    def __init__(
        self,
        repository: StateRepository,
        *,
        job_id: str,
        intent_id: str,
    ) -> None:
        self._repository = repository
        self._job_id = job_id
        self._intent_id = intent_id

    def __enter__(self) -> ArtifactClaim:
        path = StateRecordPath.transaction_intent(self._intent_id)
        intent = self._repository.read(path)
        inventory = self._repository.measure_intent_records()
        generation = next(
            record.metadata_generation
            for record in inventory.records
            if record.intent_id == self._intent_id
        )
        self._repository.remove_reconciled_intent(
            path,
            IntentRemovalToken(intent.revision, generation),
        )
        job = self._repository.read(StateRecordPath.authorization_job(self._job_id))
        result = self._repository.read(StateRecordPath.authorization_result(self._job_id)).document
        _append_result_audit_if_absent(self._repository, job.document, result)
        failed = job.document
        failed["phase"] = "failed"
        self._repository.compare_and_swap(
            StateRecordPath.authorization_job(self._job_id),
            job.revision,
            failed,
        )
        raise IntakeArtifactUnavailableError("concurrent replay consumed the artifact")

    def __exit__(self, *_exception: object) -> None:
        return


class _CompletingUnavailableIntake:
    def __init__(
        self,
        repository: StateRepository,
        *,
        job_id: str,
        intent_id: str,
    ) -> None:
        self._repository = repository
        self._job_id = job_id
        self._intent_id = intent_id

    def claim(
        self,
        *,
        correlation_id: object,
        declared: VerifiedArtifact,
        blocking: bool = False,
    ) -> AbstractContextManager[ArtifactClaim]:
        assert correlation_id
        assert declared.size > 0
        assert blocking is True
        return _CompletingUnavailableClaim(
            self._repository,
            job_id=self._job_id,
            intent_id=self._intent_id,
        )


@pytest.fixture(autouse=True)
def _capacity_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _transaction: FilesystemCapacity(
            device=1,
            fragment_size=4096,
            total_blocks=100_000_000,
            available_blocks=80_000_000,
            total_inodes=1_000_000,
            available_inodes=900_000,
        ),
    )
    for module in ("correlations", "execution", "intake"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.admit_release_capacity",
            lambda *_args, **_kwargs: CapacityProjection(
                projected_allocated_bytes=0,
                projected_unique_inodes=0,
                remaining_available_bytes=1,
                remaining_available_inodes=1,
                required_available_bytes=0,
                required_available_inodes=0,
            ),
        )


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _mapping(value: object) -> dict[str, object]:
    assert type(value) is dict
    return value


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(0o700)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root)
    for components in (
        ("platform",),
        ("tenants",),
        ("authorization",),
        ("authorization", "correlations"),
        ("authorization", "jobs"),
        ("authorization", "results"),
        ("audit",),
        ("intents",),
        ("intake",),
        ("locks",),
        ("exports",),
    ):
        _mkdir(root.joinpath(*components))
    LockManager.initialize(root / "locks", expected_owner=os.geteuid()).close()
    return root


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    if (
        path.components[:1] == ("tenants",)
        and len(path.components) == _TENANT_ROOTED_RECORD_COMPONENTS
    ):
        for name in ("archives", "deployments"):
            child = target.parent / name
            child.mkdir(exist_ok=True)
            child.chmod(0o700)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def _write_observed_for_manifest(root: Path, manifest: dict[str, object]) -> None:
    metadata = manifest["metadata"]
    spec = manifest["spec"]
    assert type(metadata) is dict
    assert type(spec) is dict
    lifecycle = spec["desiredState"]
    deployment = spec.get("desiredDeployment")
    active_deployment_id = None
    runtime_generation_id = None
    if lifecycle in {"active", "suspended"}:
        assert type(deployment) is dict
        active_deployment_id = deployment["id"]
    if lifecycle == "active":
        runtime_generation_id = "0198d17f-6f4a-7000-8000-000000000006"
    observed = _fixture("tenant-observed-state.json")
    observed.update(
        {
            "tenantId": metadata["id"],
            "desiredManifestDigest": manifest_digest(manifest).to_dict(),
            "observedState": lifecycle,
            "activeDeploymentId": active_deployment_id,
            "runtimeGenerationId": runtime_generation_id,
        }
    )
    _write(root, StateRecordPath.tenant_observed(metadata["id"]), observed)


def _append_result_audit(
    repository: StateRepository,
    job: dict[str, object],
    result: dict[str, object],
    *,
    deletion_evidence: dict[str, object] | None = None,
) -> None:
    state = repository.inspect_audit()
    entry: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": state.entry_count,
        "previousEntryDigest": state.terminal_digest,
        "timestamp": job["acceptedAt"],
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": result["operation"],
        "tenantId": result["tenantId"],
        "correlationId": result["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": result["status"],
    }
    if deletion_evidence is not None:
        entry["deletionEvidence"] = deletion_evidence
    repository.append_audit(entry)


def _append_result_audit_if_absent(
    repository: StateRepository,
    job: dict[str, object],
    result: dict[str, object],
) -> None:
    snapshot = repository.inspect_audit_correlation(result["correlationId"])
    if snapshot.entry is None:
        _append_result_audit(repository, job, result)


def _deleted_tenant_routes_absent(_tenant_id: str) -> bool:
    return True


def _deleted_tenant_routes_present(_tenant_id: str) -> bool:
    return False


def _deleted_tenant_releases_absent(_tenant_id: str) -> bool:
    return True


def _deleted_tenant_releases_present(_tenant_id: str) -> bool:
    return False


def _write_deployment_record(
    root: Path,
    deployment_id: object,
    archive_sha256: object,
) -> None:
    record = _fixture("deployment-record.json")
    record["id"] = deployment_id
    record["archiveSha256"] = archive_sha256
    _mkdir(root / "tenants" / _TENANT_ID)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, deployment_id),
        record,
    )


def _create_request() -> bytes:
    return canonical_json_bytes(_fixture("operation-request.json"))


def _issue_create(repository: StateRepository) -> IssuedAuthorization:
    return AuthorizationIssuer(
        repository,
        gate=_OpenGate(),
        entropy=_Entropy(),
    ).issue(
        _create_request(),
        operator_principal="operator@example.test",
        now=_NOW,
        artifact=None,
    )


def _issue_delete(repository: StateRepository) -> IssuedAuthorization:
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "delete",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
    }
    return AuthorizationIssuer(
        repository,
        gate=_OpenGate(),
        entropy=_Entropy(),
    ).issue(
        canonical_json_bytes(request),
        operator_principal="operator@example.test",
        now=_NOW,
        artifact=None,
    )


def _deployment_zip_payload(content: bytes = b"authorized deployment") -> bytes:
    stream = BytesIO()
    member = zipfile.ZipInfo("index.html", date_time=(1980, 1, 1, 0, 0, 0))
    member.create_system = 3
    member.external_attr = (stat.S_IFREG | 0o644) << 16
    member.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(stream, mode="w") as archive:
        archive.writestr(member, content)
    return stream.getvalue()


def _portable_bundle_payload(tmp_path: Path) -> tuple[bytes, dict[str, str]]:
    release = tmp_path / "portable-release"
    release.mkdir()
    release.chmod(0o755)
    index = release / "index.html"
    index.write_bytes(b"authorized import")
    index.chmod(0o644)
    lock_root = tmp_path / "portable-locks"
    output_root = tmp_path / "portable-output"
    for directory in (lock_root, output_root):
        directory.mkdir()
        directory.chmod(0o700)
    with (
        LockManager.initialize(lock_root, expected_owner=os.geteuid()) as manager,
        manager.acquire(LockName.EXPORT),
    ):
        bundle = build_portable_bundle(
            release,
            _fixture("site.json"),
            output_parent=output_root,
            output_name="import.zip",
            lock_manager=manager,
            expected_owner=os.geteuid(),
        )
    return (output_root / "import.zip").read_bytes(), bundle.release_tree.digest.to_dict()


def _issue_deploy(
    repository: StateRepository,
    intake: ArtifactIntake,
    *,
    payload: bytes | None = None,
    operation: str = "deploy",
) -> tuple[IssuedAuthorization, VerifiedArtifact, str]:
    if payload is None:
        payload = _deployment_zip_payload()
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }
    with intake.admit(
        operation=operation,
        correlation_id=correlation_id,
        declared=artifact,
        read=BytesIO(payload).read,
    ) as lease:
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        lease.commit()
    return issued, artifact, correlation_id


def _create_intent(correlation_id: object) -> dict[str, object]:
    intent = _fixture("transaction-intent.json")
    result = _fixture("operation-result.json")
    candidate_manifest = result["manifest"]
    assert type(candidate_manifest) is dict
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    intent["correlationId"] = correlation_id
    intent["operation"] = "create"
    intent["sourceManifest"] = None
    intent["sourceManifestDigest"] = None
    intent["candidateManifest"] = candidate_manifest
    intent["candidateManifestDigest"] = candidate_digest
    candidate = _fixture("tenant-observed-state.json")
    candidate.update(
        {
            "desiredManifestDigest": candidate_digest,
            "observedState": "undeployed",
            "activeDeploymentId": None,
            "runtimeGenerationId": None,
        }
    )
    intent["lifecycleRecovery"] = {
        "sourceObservedState": None,
        "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
        "sourceRouteSet": "absent",
        "candidateObservedState": candidate,
        "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
        "candidateRouteSet": "absent",
    }
    return intent


def _archive_transaction_intent(
    construction: dict[str, object],
) -> dict[str, object]:
    intent = _fixture("transaction-intent.json")
    source = _fixture("site.json")
    candidate = json.loads(json.dumps(source))
    source_spec = source["spec"]
    candidate_spec = candidate["spec"]
    assert type(source_spec) is dict
    assert type(candidate_spec) is dict
    source_deployment = source_spec["desiredDeployment"]
    assert type(source_deployment) is dict
    candidate_spec["desiredState"] = "archived"
    source_digest = manifest_digest(source).to_dict()
    candidate_digest = manifest_digest(candidate).to_dict()
    construction["sourceManifestDigest"] = source_digest
    construction["candidateManifestDigest"] = candidate_digest
    observed = _fixture("tenant-observed-state.json")
    observed["desiredManifestDigest"] = source_digest
    archive = _fixture("archive-record.json")
    archive.update(
        {
            "tenantId": construction["tenantId"],
            "deploymentId": source_deployment["id"],
            "releaseTreeDigest": construction["releaseTreeDigest"],
            "manifestDigest": candidate_digest,
            "bundleDigest": construction["bundleDigest"],
            "bundleSize": construction["bundleSize"],
            "bucket": construction["bucket"],
            "key": construction["key"],
            "versionId": construction["versionId"],
            "correlationId": construction["correlationId"],
        }
    )
    intent.update(
        {
            "operation": "archive",
            "tenantId": construction["tenantId"],
            "correlationId": construction["correlationId"],
            "sourceManifest": source,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate,
            "candidateManifestDigest": candidate_digest,
            "archiveRecovery": {
                "sourceManifest": source,
                "sourceObservedState": observed,
                "sourceRuntimeGenerationId": observed["runtimeGenerationId"],
                "sourceRouteSet": "both",
                "candidateManifest": candidate,
                "candidateArchiveRecord": archive,
                "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                "candidateRouteSet": "absent",
            },
            "lifecycleRecovery": None,
        }
    )
    return intent


def _write_committed_archive_replay(
    root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    namespace = _fixture("platform-namespace.json")
    construction = _fixture("archive-construction-intent.json")
    source = _write_archive_source_authority(root, construction)
    transaction_intent = _archive_transaction_intent(construction)
    candidate = _mapping(transaction_intent["candidateManifest"])
    recovery = _mapping(transaction_intent["archiveRecovery"])
    archive = _mapping(recovery["candidateArchiveRecord"])
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(construction["tenantId"]), candidate)
    _write_observed_for_manifest(root, candidate)
    _write(
        root,
        StateRecordPath.tenant_archive(construction["tenantId"], archive["deploymentId"]),
        archive,
    )

    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": construction["correlationId"],
        "tenantId": construction["tenantId"],
    }
    job = _fixture("authorization-job.json")
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "completed"
    expected = _mapping(job["expectedSource"])
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": _mapping(source["spec"])["desiredState"],
            "manifestDigest": manifest_digest(source).to_dict(),
            "deploymentDigest": construction["deploymentRecordDigest"],
            "archiveRecordDigest": None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    metadata = _mapping(candidate["metadata"])
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": construction["correlationId"],
        "operation": "archive",
        "status": "succeeded",
        "tenantId": construction["tenantId"],
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": candidate,
        "archiveRecord": archive,
    }
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(construction["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    _write(
        root,
        StateRecordPath.archive_construction_intent(construction["intentId"]),
        construction,
    )
    return job, construction, result


def _write_committed_restore_replay(
    root: Path,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    namespace = _fixture("platform-namespace.json")
    transaction_intent, retirement_intent = _restore_intents()
    source = _mapping(transaction_intent["sourceManifest"])
    candidate = _mapping(transaction_intent["candidateManifest"])
    source_spec = _mapping(source["spec"])
    candidate_spec = _mapping(candidate["spec"])
    source_reference = _mapping(source_spec["desiredDeployment"])
    candidate_reference = _mapping(candidate_spec["desiredDeployment"])
    archive = _mapping(retirement_intent["archiveRecord"])
    bundle_digest = _mapping(archive["bundleDigest"])

    source_deployment = _fixture("deployment-record.json")
    source_deployment["id"] = source_reference["id"]
    restored_deployment = json.loads(json.dumps(source_deployment))
    restored_deployment.update(
        {
            "id": candidate_reference["id"],
            "archiveSha256": bundle_digest["value"],
            "correlationId": retirement_intent["correlationId"],
        }
    )

    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "restore",
        "correlationId": retirement_intent["correlationId"],
        "tenantId": retirement_intent["tenantId"],
    }
    job = _fixture("authorization-job.json")
    job.update(
        {
            "compatibilityVersion": "static-job-v2",
            "executionValidated": False,
            "sourceAuthority": {"manifest": source, "archiveRecord": archive},
            "request": request,
            "requestDigest": request_digest(request).to_dict(),
            "phase": "completed",
        }
    )
    expected = _mapping(job["expectedSource"])
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "archived",
            "manifestDigest": retirement_intent["sourceManifestDigest"],
            "deploymentDigest": deployment_record_digest(source_deployment).to_dict(),
            "archiveRecordDigest": retirement_intent["archiveRecordDigest"],
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
    )
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "restore",
        "status": "succeeded",
        "tenantId": request["tenantId"],
        "canonicalOrigin": _mapping(candidate["metadata"])["canonicalOrigin"],
        "manifest": candidate,
    }

    previous = _fixture("authorization-job.json")
    previous_request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000008",
        "tenantId": retirement_intent["tenantId"],
    }
    previous.update(
        {
            "jobId": "0198d17f-6f4a-7000-8000-000000000007",
            "request": previous_request,
            "requestDigest": request_digest(previous_request).to_dict(),
            "phase": "completed",
        }
    )
    previous_source = json.loads(json.dumps(source))
    _mapping(previous_source["spec"])["desiredState"] = "active"
    _mapping(previous["expectedSource"]).update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": manifest_digest(previous_source).to_dict(),
            "deploymentDigest": deployment_record_digest(source_deployment).to_dict(),
            "archiveRecordDigest": None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
    )
    previous_result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": previous["jobId"]},
        "correlationId": previous_request["correlationId"],
        "operation": "archive",
        "status": "succeeded",
        "tenantId": previous_request["tenantId"],
        "canonicalOrigin": result["canonicalOrigin"],
    }

    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(request["tenantId"]), candidate)
    _write_observed_for_manifest(root, candidate)
    _write(
        root,
        StateRecordPath.tenant_deployment(request["tenantId"], source_deployment["id"]),
        source_deployment,
    )
    _write(
        root,
        StateRecordPath.tenant_deployment(request["tenantId"], restored_deployment["id"]),
        restored_deployment,
    )
    for authority, authority_result in ((previous, previous_result), (job, result)):
        authority_request = _mapping(authority["request"])
        correlation = json.loads(json.dumps(authority))
        correlation["phase"] = "pending"
        _write(root, StateRecordPath.authorization_job(authority["jobId"]), authority)
        _write(
            root,
            StateRecordPath.authorization_correlation(authority_request["correlationId"]),
            correlation,
        )
        _write(
            root,
            StateRecordPath.authorization_result(authority["jobId"]),
            authority_result,
        )
    return job, result, previous, previous_result


def _write_committed_transition_replay(
    root: Path,
    *,
    operation: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    namespace = _fixture("platform-namespace.json")
    source = _fixture("site.json")
    candidate = json.loads(json.dumps(source))
    candidate_metadata = _mapping(candidate["metadata"])
    candidate_spec = _mapping(candidate["spec"])
    if operation == "rename":
        candidate_metadata["slug"] = "authorized-rename"
        candidate_route_set = "both"
        candidate_runtime = "0198d17f-6f4a-7000-8000-000000000006"
    elif operation == "suspend":
        candidate_spec["desiredState"] = "suspended"
        candidate_route_set = "absent"
        candidate_runtime = None
    else:  # pragma: no cover - tests call only the explicit lifecycle matrix
        raise AssertionError("unsupported transition fixture")
    source_digest = manifest_digest(source).to_dict()
    candidate_digest = manifest_digest(candidate).to_dict()
    source_observed = _fixture("tenant-observed-state.json")
    source_observed["desiredManifestDigest"] = source_digest
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed.update(
        {
            "desiredManifestDigest": candidate_digest,
            "observedState": candidate_spec["desiredState"],
            "runtimeGenerationId": candidate_runtime,
        }
    )

    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
    }
    if operation == "rename":
        request["slug"] = candidate_metadata["slug"]
    job = _fixture("authorization-job.json")
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "completed"
    expected = _mapping(job["expectedSource"])
    deployment = _fixture("deployment-record.json")
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": source_digest,
            "deploymentDigest": deployment_record_digest(deployment).to_dict(),
            "archiveRecordDigest": None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    intent = _fixture("transaction-intent.json")
    intent.update(
        {
            "tenantId": _TENANT_ID,
            "correlationId": request["correlationId"],
            "operation": operation,
            "sourceManifest": source,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate,
            "candidateManifestDigest": candidate_digest,
            "archiveRecovery": None,
            "lifecycleRecovery": {
                "sourceObservedState": source_observed,
                "sourceRuntimeGenerationId": source_observed["runtimeGenerationId"],
                "sourceRouteSet": "both",
                "candidateObservedState": candidate_observed,
                "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                "candidateRouteSet": candidate_route_set,
            },
        }
    )
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": operation,
        "status": "succeeded",
        "tenantId": _TENANT_ID,
        "canonicalOrigin": candidate_metadata["canonicalOrigin"],
        "manifest": candidate,
    }
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), candidate)
    _write(root, StateRecordPath.tenant_observed(_TENANT_ID), candidate_observed)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, deployment["id"]),
        deployment,
    )
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    _write(root, StateRecordPath.transaction_intent(intent["intentId"]), intent)
    return job, intent, result


def _write_archive_source_authority(
    root: Path,
    construction: dict[str, object],
) -> dict[str, object]:
    source = _fixture("site.json")
    deployment = _fixture("deployment-record.json")
    construction["sourceManifestDigest"] = manifest_digest(source).to_dict()
    construction["deploymentRecordDigest"] = deployment_record_digest(deployment).to_dict()
    construction["releaseTreeDigest"] = deployment["releaseTreeDigest"]
    _write(root, StateRecordPath.tenant_desired(construction["tenantId"]), source)
    _write(
        root,
        StateRecordPath.tenant_deployment(construction["tenantId"], deployment["id"]),
        deployment,
    )
    return source


def _restore_intents() -> tuple[dict[str, object], dict[str, object]]:
    retirement = _fixture("archive-retirement-intent.json")
    retirement["transition"] = "restore"
    archive = retirement["archiveRecord"]
    assert type(archive) is dict

    source = _fixture("site.json")
    source_spec = source["spec"]
    assert type(source_spec) is dict
    source_spec["desiredState"] = "archived"
    source_deployment = source_spec["desiredDeployment"]
    assert type(source_deployment) is dict
    source_deployment["id"] = archive["deploymentId"]
    source_digest = manifest_digest(source).to_dict()
    archive["manifestDigest"] = source_digest
    retirement["sourceManifestDigest"] = source_digest
    retirement["archiveRecordDigest"] = archive_record_digest(archive).to_dict()

    candidate = json.loads(json.dumps(source))
    candidate_spec = candidate["spec"]
    assert type(candidate_spec) is dict
    candidate_spec["desiredState"] = "active"
    candidate_deployment = candidate_spec["desiredDeployment"]
    bundle_digest = retirement["bundleDigest"]
    assert type(candidate_deployment) is dict
    assert type(bundle_digest) is dict
    candidate_deployment.update(
        {
            "id": "0198d17f-6f4a-7000-8000-000000000009",
            "archiveSha256": bundle_digest["value"],
        }
    )
    candidate_digest = manifest_digest(candidate).to_dict()

    source_observed = _fixture("tenant-observed-state.json")
    source_observed.update(
        {
            "desiredManifestDigest": source_digest,
            "observedState": "archived",
            "activeDeploymentId": None,
            "runtimeGenerationId": None,
        }
    )
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed.update(
        {
            "desiredManifestDigest": candidate_digest,
            "observedState": "active",
            "activeDeploymentId": candidate_deployment["id"],
            "runtimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
        }
    )
    transaction = _fixture("transaction-intent.json")
    transaction.update(
        {
            "operation": "restore",
            "tenantId": retirement["tenantId"],
            "correlationId": retirement["correlationId"],
            "sourceManifest": source,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate,
            "candidateManifestDigest": candidate_digest,
            "archiveRecovery": None,
            "lifecycleRecovery": {
                "sourceObservedState": source_observed,
                "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                "sourceRouteSet": "absent",
                "candidateObservedState": candidate_observed,
                "candidateRuntimeGenerationId": candidate_observed["runtimeGenerationId"],
                "candidateRouteSet": "both",
            },
        }
    )
    return transaction, retirement


def test_executor_publishes_one_immutable_mutation_free_terminal_result(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    before_tenants = list((root / "tenants").iterdir())

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        first = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        second = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document

    assert first.created is True
    assert first.result["status"] == "failed"
    assert first.result["errorCode"] == "not_implemented"
    assert first.result["failureAuditPredecessorDigest"] is None
    assert first.result["failureAuditSequence"] == 0
    assert second.created is False
    assert second.result == first.result == stored
    assert job["phase"] == "failed"
    assert list((root / "tenants").iterdir()) == before_tenants


def test_executor_reserves_result_and_worst_case_failure_audit_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    reservations: list[CapacityReservation] = []

    def capture_capacity(
        _usage: object,
        reservation: CapacityReservation,
        _filesystem: object,
        **_kwargs: object,
    ) -> CapacityProjection:
        reservations.append(reservation)
        return CapacityProjection(
            projected_allocated_bytes=0,
            projected_unique_inodes=0,
            remaining_available_bytes=1,
            remaining_available_inodes=1,
            required_available_bytes=0,
            required_available_inodes=0,
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.execution.admit_release_capacity",
        capture_capacity,
    )
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        AuthorizationExecutor(repository, intake).execute(issued.job_id)

    assert len(reservations) == 1
    assert reservations[0].allocated_bytes > 8 * 1024 * 1024
    assert reservations[0].unique_inodes == _RESULT_AND_AUDIT_INODES


def test_executor_preserves_a_claimed_job_when_its_handler_is_unavailable(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = claimed["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

        with pytest.raises(RuntimeError, match="handler is unavailable"):
            AuthorizationExecutor(repository, intake).execute(issued.job_id)

        preserved = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        preserved_intent = repository.read(
            StateRecordPath.transaction_intent(intent["intentId"])
        ).document
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(issued.job_id))

    assert preserved["phase"] == "claimed"
    assert preserved_intent == intent


def test_executor_finishes_intent_free_claimed_fallback_without_a_handler(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )

        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        replay = AuthorizationExecutor(repository, intake).execute(issued.job_id)

    assert outcome.created is True
    assert outcome.result["errorCode"] == "not_implemented"
    assert terminal["phase"] == "failed"
    assert replay.created is False
    assert replay.result == outcome.result


def test_executor_finishes_intent_free_claimed_fallback_after_artifact_loss(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = b"claimed fallback artifact"
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        for path in (root / "intake").iterdir():
            path.unlink()

        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert outcome.created is True
    assert outcome.result["errorCode"] == "not_implemented"
    assert terminal["phase"] == "failed"


def test_executor_preserves_result_bearing_recovery_without_its_handler(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = claimed["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        intent = _create_intent(request["correlationId"])
        candidate_digest = manifest_digest(manifest).to_dict()
        intent["candidateManifest"] = manifest
        intent["candidateManifestDigest"] = candidate_digest
        recovery = intent["lifecycleRecovery"]
        assert type(recovery) is dict
        candidate_observed = recovery["candidateObservedState"]
        assert type(candidate_observed) is dict
        candidate_observed["desiredManifestDigest"] = candidate_digest
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        _append_result_audit(repository, issued.document, result)

        with pytest.raises(RuntimeError, match=r"result-bearing.*handler is unavailable"):
            AuthorizationExecutor(repository, intake).execute(issued.job_id)

        preserved = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        preserved_result = repository.read(
            StateRecordPath.authorization_result(issued.job_id)
        ).document
        preserved_intent = repository.read(
            StateRecordPath.transaction_intent(intent["intentId"])
        ).document

    assert preserved["phase"] == "claimed"
    assert preserved_result == result
    assert preserved_intent == intent


def test_executor_dispatches_claimed_create_and_replays_its_handler(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        handler = _CompletingCreateHandler(repository, state_root=root)
        executor = AuthorizationExecutor(repository, intake, handlers={"create": handler})

        first = executor.execute(issued.job_id)
        assert (
            repository.read(StateRecordPath.authorization_job(issued.job_id)).document[
                "executionValidated"
            ]
            is True
        )
        second = executor.execute(issued.job_id)

        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document
        phase = repository.read(StateRecordPath.authorization_job(issued.job_id)).document["phase"]

    assert first.created is True
    assert second.created is False
    assert first.result == second.result == stored
    assert first.result["status"] == "succeeded"
    assert phase == "completed"
    assert handler.phases == ["claimed"]
    assert handler.claims == [None]


def test_executor_rejects_success_without_observed_tenant_state(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(ExecutionError, match="no observed tenant state"),
    ):
        issued = _issue_create(repository)
        AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "create": _CompletingCreateHandler(
                    repository,
                    state_root=root,
                    write_observed=False,
                ),
            },
        ).execute(issued.job_id)


def test_executor_repairs_a_lagging_job_phase_without_handler_replay(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        manifest = result["manifest"]
        assert type(manifest) is dict
        _write(
            root,
            StateRecordPath.tenant_desired(result["tenantId"]),
            manifest,
        )
        _write_observed_for_manifest(root, manifest)
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        _append_result_audit(repository, issued.document, result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
            tenant_runtime_validator=lambda *_arguments: True,
        ).execute(issued.job_id)

    assert outcome.created is False
    assert outcome.result == result
    assert handler.phases == []


def test_executor_replays_an_audited_historical_success_after_later_state_change(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        _append_result_audit(repository, issued.document, result)
        desired = json.loads(json.dumps(manifest))
        metadata = desired["metadata"]
        assert type(metadata) is dict
        metadata["slug"] = "later-duck"
        _write(root, StateRecordPath.tenant_desired(result["tenantId"]), desired)
        _write_observed_for_manifest(root, desired)
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(ExecutionError, match="authoritative tenant state"),
    ):
        AuthorizationExecutor(repository, intake).execute(issued.job_id)


def test_executor_replays_audited_legacy_manifestless_success(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        job = _fixture("authorization-job.json")
        request: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationRequest",
            "operation": "rename",
            "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
            "tenantId": _TENANT_ID,
            "slug": "renamed-duck",
        }
        job["request"] = request
        job["requestDigest"] = request_digest(request).to_dict()
        expected = job["expectedSource"]
        assert type(expected) is dict
        expected.update(
            {
                "expectsTenantAbsent": False,
                "lifecycle": "active",
                "manifestDigest": manifest_digest(_fixture("site.json")).to_dict(),
                "deploymentDigest": deployment_record_digest(
                    _fixture("deployment-record.json")
                ).to_dict(),
                "archiveRecordDigest": None,
            }
        )
        result = _fixture("operation-result.json")
        result["operation"] = "rename"
        del result["manifest"]
        _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
        _write(
            root,
            StateRecordPath.authorization_correlation(request["correlationId"]),
            job,
        )
        _append_result_audit(repository, job, result)
        _write(root, StateRecordPath.authorization_result(job["jobId"]), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = AuthorizationExecutor(repository, intake).execute(job["jobId"])

    assert outcome.result == result
    assert outcome.created is False


def test_executor_rejects_an_intent_free_success_without_matching_audit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        _append_result_audit(repository, issued.document, result)
        metadata = manifest["metadata"]
        assert type(metadata) is dict
        metadata["slug"] = "forged-after-audit"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(ExecutionError, match="durable audit authority"),
    ):
        AuthorizationExecutor(repository, intake).execute(issued.job_id)


def test_executor_translates_invalid_audit_authority_to_an_execution_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        _write(root, StateRecordPath.tenant_desired(result["tenantId"]), manifest)
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    def reject_audit(*_args: object, **_kwargs: object) -> object:
        raise AuditError("synthetic malformed audit chain")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.inspect_audit_correlation",
        reject_audit,
    )
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(ExecutionError, match="audit authority is invalid"),
    ):
        AuthorizationExecutor(repository, intake).execute(issued.job_id)


def test_executor_rejects_a_handler_failure_without_durable_audit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "create": _CompletingFailureHandler(repository, append_audit=False),
            },
        )
        with pytest.raises(ExecutionError, match="no durable audit authority"):
            executor.execute(issued.job_id)
        with pytest.raises(ExecutionError, match="no durable audit authority"):
            executor.execute(issued.job_id)


def test_executor_rejects_a_handler_claiming_executor_failure_publication(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "create": _CompletingFailureHandler(
                    repository,
                    claim_executor_publication=True,
                ),
            },
        )

        with pytest.raises(ExecutionError, match="claimed executor failure publication"):
            executor.execute(issued.job_id)


def test_executor_rejects_a_handler_failure_that_retains_candidate_state(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        with pytest.raises(ExecutionError, match="did not restore its authorized source"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "create": _CompletingFailureHandler(repository, state_root=root),
                },
            ).execute(issued.job_id)

        retained = repository.read(StateRecordPath.tenant_desired(_TENANT_ID)).document

    assert retained == _fixture("site.json")


def test_executor_rejects_a_legacy_handler_failure_that_retains_candidate_state(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        correlation = repository.read(
            StateRecordPath.authorization_correlation(request["correlationId"])
        ).document

    for document in (job, correlation):
        document["compatibilityVersion"] = "static-job-v1"
        document.pop("sourceAuthority")
    _write(root, StateRecordPath.authorization_job(issued.job_id), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(ExecutionError, match="did not restore its authorized source"),
    ):
        AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "create": _CompletingFailureHandler(repository, state_root=root),
            },
        ).execute(issued.job_id)


@pytest.mark.parametrize("operation", ["deploy", "import"])
@pytest.mark.parametrize(("deployment_record", "archive_sha256"), [(False, None), (True, "e" * 64)])
def test_executor_rejects_an_incomplete_successful_deployment_commit(
    tmp_path: Path,
    operation: str,
    deployment_record: bool,
    archive_sha256: str | None,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    source = _fixture("site.json")
    if operation == "import":
        source_spec = source["spec"]
        assert type(source_spec) is dict
        source_spec["desiredState"] = "undeployed"
        del source_spec["desiredDeployment"]
    else:
        _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        payload = None
        if operation == "import":
            payload, _release_digest = _portable_bundle_payload(tmp_path)
        issued, _artifact, correlation_id = _issue_deploy(
            repository,
            intake,
            payload=payload,
            operation=operation,
        )
        with pytest.raises(ExecutionError, match="deployment record"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    operation: _CompletingDeployHandler(
                        repository,
                        root,
                        deployment_record=deployment_record,
                        deployment_archive_sha256=archive_sha256,
                    ),
                },
            ).execute(issued.job_id)

    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_accepts_a_complete_successful_deployment_commit(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, artifact, _correlation_id = _issue_deploy(repository, intake)
        handler = _CompletingDeployHandler(repository, root)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
        ).execute(issued.job_id)

    assert outcome.result["status"] == "succeeded"
    assert handler.claims[0] is not None
    assert handler.claims[0].artifact.verified == artifact
    assert list((root / "intake").iterdir()) == []


def test_executor_derives_import_content_from_the_portable_envelope(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    source = _fixture("site.json")
    source_spec = _mapping(source["spec"])
    source_spec["desiredState"] = "undeployed"
    source_spec.pop("desiredDeployment")
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    payload, release_digest = _portable_bundle_payload(tmp_path)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, _correlation_id = _issue_deploy(
            repository,
            intake,
            payload=payload,
            operation="import",
        )
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"import": _CompletingDeployHandler(repository, root)},
        ).execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert outcome.result["status"] == "succeeded"
    assert job["dispatchArtifactReleaseTreeDigest"] == release_digest


@pytest.mark.parametrize("operation", ["deploy", "import"])
def test_executor_terminally_rejects_malformed_artifact_content(
    tmp_path: Path,
    operation: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, _correlation_id = _issue_deploy(
            repository,
            intake,
            payload=b"hash-valid but structurally invalid artifact",
            operation=operation,
        )
        handler = _CompletingDeployHandler(repository, root)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={operation: handler},
        ).execute(issued.job_id)
        replay = AuthorizationExecutor(
            repository,
            intake,
            handlers={operation: handler},
        ).execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert outcome.created is True
    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "invalid_artifact"
    assert replay.created is False
    assert replay.result == outcome.result
    assert job["phase"] == "failed"
    assert job["executionValidated"] is True
    assert handler.claims == []
    assert list((root / "intake").iterdir()) == []


def test_executor_rejects_a_deployment_digest_not_derived_from_its_artifact(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    forged_digest: dict[str, object] = {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": "e" * 64,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, correlation_id = _issue_deploy(repository, intake)
        with pytest.raises(ExecutionError, match="unbound deployment record"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "deploy": _CompletingDeployHandler(
                        repository,
                        root,
                        deployment_release_tree_digest=forged_digest,
                    )
                },
            ).execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert job["dispatchArtifactReleaseTreeDigest"] != forged_digest
    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_requires_selected_release_validation_after_successful_deploy(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    source = _fixture("site.json")
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    calls: list[tuple[str, dict[str, object]]] = []

    def reject_unselected_release(
        tenant_id: str,
        manifest: dict[str, object],
    ) -> bool:
        calls.append((tenant_id, manifest))
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, _correlation_id = _issue_deploy(repository, intake)
        with pytest.raises(ExecutionError, match="authorized release"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"deploy": _CompletingDeployHandler(repository, root)},
                tenant_release_validator=reject_unselected_release,
            ).execute(issued.job_id)

    assert len(calls) == 1
    assert calls[0][0] == _TENANT_ID
    candidate_spec = _mapping(calls[0][1]["spec"])
    candidate_deployment = _mapping(candidate_spec["desiredDeployment"])
    assert candidate_deployment["id"] == "0198d17f-6f4a-7000-8000-000000000009"


def test_executor_rejects_a_failed_deploy_that_retains_deployment_history(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    candidate_deployment_id = "0198d17f-6f4a-7000-8000-000000000009"
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, correlation_id = _issue_deploy(repository, intake)
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "deploy": _CompletingFailureHandler(
                    repository,
                    retained_deployment_id=candidate_deployment_id,
                    state_root=root,
                ),
            },
            tenant_runtime_validator=lambda *_arguments: True,
        )

        with pytest.raises(ExecutionError, match="unauthorized deployment history"):
            executor.execute(issued.job_id)
        with pytest.raises(ExecutionError, match="unauthorized deployment history"):
            executor.execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert job["dispatchDeploymentIds"] == [_DEPLOYMENT_ID]
    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_rejects_a_failed_archive_that_retains_archive_history(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "archive": _CompletingFailureHandler(
                    repository,
                    retained_archive_id=_DEPLOYMENT_ID,
                    state_root=root,
                ),
            },
            tenant_runtime_validator=lambda *_arguments: True,
        )

        with pytest.raises(ExecutionError, match="unauthorized archive history"):
            executor.execute(issued.job_id)
        with pytest.raises(ExecutionError, match="unauthorized archive history"):
            executor.execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert job["dispatchArchiveDeploymentIds"] == []
    assert job["dispatchDeploymentIds"] == [_DEPLOYMENT_ID]


def test_executor_requires_source_release_validation_after_failed_deploy(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    source = _fixture("site.json")
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    calls: list[tuple[str, dict[str, object]]] = []

    def reject_unrestored_release(
        tenant_id: str,
        manifest: dict[str, object],
    ) -> bool:
        calls.append((tenant_id, manifest))
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, _correlation_id = _issue_deploy(repository, intake)
        with pytest.raises(ExecutionError, match="authorized release"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"deploy": _CompletingFailureHandler(repository)},
                tenant_release_validator=reject_unrestored_release,
            ).execute(issued.job_id)

    assert calls == [(_TENANT_ID, source)]


@pytest.mark.parametrize("include_archive", [False, True])
def test_executor_requires_the_archive_record_for_an_archived_commit(
    tmp_path: Path,
    include_archive: bool,
) -> None:
    root = _state_root(tmp_path)
    source = _fixture("site.json")
    deployment = _fixture("deployment-record.json")
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    _write(root, StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID), deployment)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
    }
    candidate = json.loads(json.dumps(source))
    candidate_spec = candidate["spec"]
    assert type(candidate_spec) is dict
    candidate_spec["desiredState"] = "archived"
    archive = _fixture("archive-record.json")
    archive.update(
        {
            "manifestDigest": manifest_digest(candidate).to_dict(),
            "releaseTreeDigest": deployment["releaseTreeDigest"],
            "correlationId": request["correlationId"],
        }
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "archive": _CompletingTransitionHandler(
                    repository,
                    root,
                    manifest=candidate,
                    archive=archive,
                    write_archive=include_archive,
                )
            },
        )
        if include_archive:
            outcome = executor.execute(issued.job_id)
            assert outcome.result["status"] == "succeeded"
        else:
            with pytest.raises(ExecutionError, match="no archive record"):
                executor.execute(issued.job_id)


@pytest.mark.parametrize("include_deployment", [False, True])
def test_executor_requires_the_new_deployment_record_for_a_restore_commit(
    tmp_path: Path,
    include_deployment: bool,
) -> None:
    root = _state_root(tmp_path)
    source = _fixture("site.json")
    source_spec = source["spec"]
    deployment = _fixture("deployment-record.json")
    archive = _fixture("archive-record.json")
    assert type(source_spec) is dict
    source_spec["desiredState"] = "archived"
    archive["manifestDigest"] = manifest_digest(source).to_dict()
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    _write(root, StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID), deployment)
    _write(root, StateRecordPath.tenant_archive(_TENANT_ID, _DEPLOYMENT_ID), archive)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "restore",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
    }
    candidate = json.loads(json.dumps(source))
    candidate_spec = candidate["spec"]
    bundle_digest = archive["bundleDigest"]
    assert type(candidate_spec) is dict
    assert type(bundle_digest) is dict
    candidate_spec["desiredState"] = "active"
    candidate_reference = candidate_spec["desiredDeployment"]
    assert type(candidate_reference) is dict
    candidate_reference.update(
        {
            "id": "0198d17f-6f4a-7000-8000-000000000009",
            "archiveSha256": bundle_digest["value"],
        }
    )
    restored = json.loads(json.dumps(deployment))
    restored.update(
        {
            "id": candidate_reference["id"],
            "archiveSha256": candidate_reference["archiveSha256"],
            "releaseTreeDigest": archive["releaseTreeDigest"],
            "correlationId": request["correlationId"],
        }
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            retired_archive_validator=lambda _archive: True,
            handlers={
                "restore": _CompletingTransitionHandler(
                    repository,
                    root,
                    manifest=candidate,
                    deployment=restored if include_deployment else None,
                )
            },
        )
        if include_deployment:
            outcome = executor.execute(issued.job_id)
            assert outcome.result["status"] == "succeeded"
        else:
            with pytest.raises(ExecutionError, match="no deployment record"):
                executor.execute(issued.job_id)


@pytest.mark.parametrize("write_export", [False, True])
def test_executor_requires_the_exact_export_bundle_for_success(
    tmp_path: Path,
    write_export: bool,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    deployment = _fixture("deployment-record.json")
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(root, StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID), deployment)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "export",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "export": _CompletingTransitionHandler(
                    repository,
                    root,
                    manifest=manifest,
                    write_export=write_export,
                )
            },
        )
        if write_export:
            outcome = executor.execute(issued.job_id)
            assert outcome.result["status"] == "succeeded"
        else:
            with pytest.raises(ExecutionError, match="no exact bundle"):
                executor.execute(issued.job_id)


def test_executor_rejects_a_successful_export_that_adds_archive_history(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    deployment = _fixture("deployment-record.json")
    extra_archive = _fixture("archive-record.json")
    extra_archive["deploymentId"] = "0198d17f-6f4a-7000-8000-000000000009"
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(root, StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID), deployment)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "export",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        with pytest.raises(ExecutionError, match="changed retained history"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "export": _CompletingTransitionHandler(
                        repository,
                        root,
                        manifest=manifest,
                        archive=extra_archive,
                        write_export=True,
                    )
                },
            ).execute(issued.job_id)


def test_executor_requires_export_bundle_after_a_later_tenant_commit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "export",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        handler = _SupersedingTransitionHandler(
            repository,
            root,
            _CompletingTransitionHandler(
                repository,
                root,
                manifest=manifest,
                write_export=False,
            ),
        )
        with pytest.raises(ExecutionError, match="no exact bundle"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"export": handler},
            ).execute(issued.job_id)


def test_executor_rejects_a_manifest_that_exceeds_rename_authority(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    source = _fixture("site.json")
    candidate = json.loads(json.dumps(source))
    metadata = _mapping(candidate["metadata"])
    spec = _mapping(candidate["spec"])
    quotas = _mapping(spec["quotas"])
    metadata["slug"] = "authorized-rename"
    quotas["entries"] = 4999
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "rename",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
        "slug": "authorized-rename",
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        with pytest.raises(ExecutionError, match="exceeds its request authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "rename": _CompletingTransitionHandler(
                        repository,
                        root,
                        manifest=candidate,
                    )
                },
            ).execute(issued.job_id)


def test_executor_does_not_expose_artifact_consumption_to_handlers(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, _DEPLOYMENT_ID, "0" * 64)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, correlation_id = _issue_deploy(repository, intake)
        with pytest.raises(AttributeError, match="consume"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"deploy": _ArtifactConsumingHandler()},
            ).execute(issued.job_id)

    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_rejects_a_rollback_that_loses_its_selected_deployment(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    current = spec["desiredDeployment"]
    assert type(current) is dict
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write_deployment_record(root, current["id"], current["archiveSha256"])
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    rollback_id = "0198d17f-6f4a-7000-8000-000000000009"
    rollback = _fixture("deployment-record.json")
    rollback.update(
        {
            "id": rollback_id,
            "archiveSha256": "e" * 64,
            "correlationId": "0198d17f-6f4a-7000-8000-000000000002",
        }
    )
    _write(root, StateRecordPath.tenant_deployment(_TENANT_ID, rollback_id), rollback)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "rollback",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
        "deploymentId": rollback_id,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(ExecutionError, match="changed retained history"),
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "rollback": _CompletingRollbackHandler(
                    repository,
                    root,
                    remove_deployment_record=True,
                ),
            },
        ).execute(issued.job_id)


@pytest.mark.parametrize("history_kind", [None, "archive", "deployment"])
def test_executor_requires_a_rollback_to_preserve_retained_history(
    tmp_path: Path,
    history_kind: str | None,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    spec = _mapping(manifest["spec"])
    current = _mapping(spec["desiredDeployment"])
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write_deployment_record(root, current["id"], current["archiveSha256"])
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    rollback_id = "0198d17f-6f4a-7000-8000-000000000009"
    rollback = _fixture("deployment-record.json")
    rollback.update(
        {
            "id": rollback_id,
            "archiveSha256": "e" * 64,
            "correlationId": "0198d17f-6f4a-7000-8000-000000000002",
        }
    )
    _write(root, StateRecordPath.tenant_deployment(_TENANT_ID, rollback_id), rollback)
    extra_id = "0198d17f-6f4a-7000-8000-000000000010"
    extra_archive = _fixture("archive-record.json")
    extra_archive["deploymentId"] = extra_id
    extra_deployment = _fixture("deployment-record.json")
    extra_deployment["id"] = extra_id
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "rollback",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000003",
        "tenantId": _TENANT_ID,
        "deploymentId": rollback_id,
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "rollback": _CompletingRollbackHandler(
                    repository,
                    root,
                    remove_deployment_record=False,
                    extra_archive=(extra_archive if history_kind == "archive" else None),
                    extra_deployment=(extra_deployment if history_kind == "deployment" else None),
                )
            },
        )
        if history_kind is None:
            assert executor.execute(issued.job_id).result["status"] == "succeeded"
        else:
            with pytest.raises(ExecutionError, match="changed retained history"):
                executor.execute(issued.job_id)


def test_executor_accepts_a_handler_result_superseded_by_a_later_audited_commit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": _SupersedingCreateHandler(repository, root)},
        ).execute(issued.job_id)
        current = repository.read(
            StateRecordPath.tenant_desired(outcome.result["tenantId"])
        ).document

    assert outcome.result["status"] == "succeeded"
    assert current != outcome.result["manifest"]


def test_executor_rejects_a_handler_result_followed_only_by_another_tenants_audit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        with pytest.raises(
            ExecutionError,
            match="disagrees with authoritative tenant state",
        ):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "create": _SupersedingCreateHandler(
                        repository,
                        root,
                        audit_tenant_id="0198d17f-6f4a-7000-8000-000000000099",
                    ),
                },
            ).execute(issued.job_id)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_executor_rejects_an_ineligible_delete_before_handler_dispatch(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = lifecycle
    deployment = _fixture("deployment-record.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        deployment,
    )
    job = _fixture("authorization-job.json")
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "delete",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["expectedSource"] = {
        "expectsTenantAbsent": False,
        "lifecycle": lifecycle,
        "manifestDigest": manifest_digest(manifest).to_dict(),
        "deploymentDigest": deployment_record_digest(deployment).to_dict(),
        "archiveRecordDigest": None,
        "platformStateDigest": platform_state_digest(namespace).to_dict(),
        "deletionEvidence": None,
    }
    job["phase"] = "pending"
    correlation = json.loads(json.dumps(job))
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={
                "delete": _CompletingDeleteHandler(
                    repository,
                    root,
                    deletion_evidence={"mode": "never-deployed"},
                )
            },
            deleted_tenant_route_validator=_deleted_tenant_routes_absent,
        ).execute(job["jobId"])

    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "state_drift"
    assert root.joinpath(*StateRecordPath.tenant_desired(_TENANT_ID).components).exists()


def test_executor_decodes_but_never_mutates_for_a_legacy_delete_job(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_delete(repository)
        request = issued.document["request"]
        assert type(request) is dict
        correlation_id = request["correlationId"]
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        correlation = repository.read(
            StateRecordPath.authorization_correlation(correlation_id)
        ).document

    for document in (job, correlation):
        document["compatibilityVersion"] = "static-job-v1"
        document.pop("sourceAuthority")
        expected = document["expectedSource"]
        assert type(expected) is dict
        del expected["deletionEvidence"]
    _write(root, StateRecordPath.authorization_job(issued.job_id), job)
    _write(root, StateRecordPath.authorization_correlation(correlation_id), correlation)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        retained = repository.read(StateRecordPath.tenant_desired(_TENANT_ID)).document

    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "state_drift"
    assert retained == manifest


@pytest.mark.parametrize("lifecycle", ["undeployed", "archived"])
def test_executor_binds_delete_audit_evidence_to_its_exact_source(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = lifecycle
    archive: dict[str, object] | None = None
    if lifecycle == "undeployed":
        del spec["desiredDeployment"]
        deletion_evidence: dict[str, object] = {
            "mode": "never-deployed",
            "releasedSlugs": ["wrong-duck"],
            "archiveRecordDigest": None,
            "bucket": None,
            "key": None,
            "versionId": None,
            "emergencyReason": None,
        }
    else:
        deployment = _fixture("deployment-record.json")
        archive = _fixture("archive-record.json")
        archive["manifestDigest"] = manifest_digest(manifest).to_dict()
        _write(
            root,
            StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
            deployment,
        )
        _write(
            root,
            StateRecordPath.tenant_archive(_TENANT_ID, _DEPLOYMENT_ID),
            archive,
        )
        deletion_evidence = {
            "mode": "archived",
            "releasedSlugs": ["duck-repair"],
            "archiveRecordDigest": archive_record_digest(archive).to_dict(),
            "bucket": archive["bucket"],
            "key": "archives/0198d17f-6f4a-7000-8000-000000000004.zip",
            "versionId": archive["versionId"],
            "emergencyReason": None,
        }
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_delete(repository)
        handler = _CompletingDeleteHandler(
            repository,
            root,
            deletion_evidence=deletion_evidence,
        )
        with pytest.raises(ExecutionError, match="source authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"delete": handler},
                deleted_tenant_route_validator=_deleted_tenant_routes_absent,
            ).execute(issued.job_id)
        with pytest.raises(ExecutionError, match="source authority"):
            AuthorizationExecutor(
                repository,
                intake,
                deleted_tenant_route_validator=_deleted_tenant_routes_absent,
            ).execute(issued.job_id)


def test_executor_accepts_exact_durable_delete_evidence_and_replays_it(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_delete(repository)
        expected = issued.document["expectedSource"]
        assert type(expected) is dict
        deletion_evidence = expected["deletionEvidence"]
        assert type(deletion_evidence) is dict
        handler = _CompletingDeleteHandler(
            repository,
            root,
            deletion_evidence=deletion_evidence,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={"delete": handler},
            deleted_tenant_release_validator=_deleted_tenant_releases_absent,
            deleted_tenant_route_validator=_deleted_tenant_routes_absent,
        )
        outcome = executor.execute(issued.job_id)
        replay = executor.execute(issued.job_id)
        with pytest.raises(ExecutionError, match="retained an active tenant route"):
            AuthorizationExecutor(
                repository,
                intake,
                deleted_tenant_release_validator=_deleted_tenant_releases_absent,
                deleted_tenant_route_validator=_deleted_tenant_routes_present,
            ).execute(issued.job_id)

    assert outcome.result["status"] == "succeeded"
    assert replay.result == outcome.result
    assert replay.created is False


def test_executor_rejects_delete_that_retains_the_tenant_namespace(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_delete(repository)
        expected = issued.document["expectedSource"]
        assert type(expected) is dict
        deletion_evidence = expected["deletionEvidence"]
        assert type(deletion_evidence) is dict
        with pytest.raises(ExecutionError, match="retained its tenant namespace"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "delete": _CompletingDeleteHandler(
                        repository,
                        root,
                        deletion_evidence=deletion_evidence,
                        remove_namespace=False,
                    )
                },
                deleted_tenant_route_validator=_deleted_tenant_routes_absent,
            ).execute(issued.job_id)


def test_executor_rejects_delete_that_retains_an_active_route(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_delete(repository)
        expected = issued.document["expectedSource"]
        assert type(expected) is dict
        deletion_evidence = expected["deletionEvidence"]
        assert type(deletion_evidence) is dict
        with pytest.raises(ExecutionError, match="retained an active tenant route"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "delete": _CompletingDeleteHandler(
                        repository,
                        root,
                        deletion_evidence=deletion_evidence,
                    )
                },
                deleted_tenant_release_validator=_deleted_tenant_releases_absent,
                deleted_tenant_route_validator=_deleted_tenant_routes_present,
            ).execute(issued.job_id)


def test_executor_rejects_delete_that_retains_tenant_release_bytes(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _fixture("site.json")
    spec = _mapping(manifest["spec"])
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_delete(repository)
        expected = _mapping(issued.document["expectedSource"])
        deletion_evidence = _mapping(expected["deletionEvidence"])
        with pytest.raises(ExecutionError, match="retained tenant release bytes"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={
                    "delete": _CompletingDeleteHandler(
                        repository,
                        root,
                        deletion_evidence=deletion_evidence,
                    )
                },
                deleted_tenant_release_validator=_deleted_tenant_releases_present,
                deleted_tenant_route_validator=_deleted_tenant_routes_absent,
            ).execute(issued.job_id)


def test_executor_rejects_a_misbound_result_before_handler_dispatch(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = "0198d17f-6f4a-7000-8000-000000000099"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="does not match its authorization job"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


@pytest.mark.parametrize("drift", ["tenant", "candidate"])
def test_executor_binds_a_successful_create_result_to_its_active_intent(
    tmp_path: Path,
    drift: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        intent = _create_intent(request["correlationId"])
        metadata = manifest["metadata"]
        assert type(metadata) is dict
        if drift == "tenant":
            other_tenant = "0198d17f-6f4a-7000-8000-000000000099"
            other_origin = f"t-{other_tenant.replace('-', '')}.lowerduckpond.com"
            result["tenantId"] = other_tenant
            result["canonicalOrigin"] = other_origin
            metadata["id"] = other_tenant
            metadata["canonicalOrigin"] = other_origin
        if drift == "candidate":
            metadata["slug"] = "different-duck"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="result disagrees with its lifecycle intent"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


def test_executor_binds_a_handler_result_after_its_intent_is_cleared(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        candidate = intent["candidateManifest"]
        intent_id = intent["intentId"]
        assert type(candidate) is dict
        assert type(intent_id) is str
        intent_path = StateRecordPath.transaction_intent(intent_id)
        repository.create_immutable(intent_path, intent)
        handler = _CompletingIntentHandler(
            repository,
            intent_path=intent_path,
            delegate=_CompletingCreateHandler(
                repository,
                state_root=root,
                result_slug="different-duck",
            ),
        )

        with pytest.raises(ExecutionError, match="request target"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document
        assert repository.read(StateRecordPath.tenant_desired(_TENANT_ID)).document == candidate
        with pytest.raises(FileNotFoundError):
            repository.read(intent_path)

    stored_manifest = stored["manifest"]
    assert type(stored_manifest) is dict
    stored_metadata = stored_manifest["metadata"]
    assert type(stored_metadata) is dict
    assert stored_metadata["slug"] == "different-duck"


@pytest.mark.parametrize("drift", ["slug", "quotas"])
def test_executor_binds_a_successful_create_candidate_to_its_request(
    tmp_path: Path,
    drift: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        metadata = manifest["metadata"]
        spec = manifest["spec"]
        assert type(metadata) is dict
        assert type(spec) is dict
        if drift == "slug":
            metadata["slug"] = "different-duck"
        else:
            quotas = spec["quotas"]
            assert type(quotas) is dict
            quotas["storageMiB"] = 99
        candidate_digest = manifest_digest(manifest).to_dict()
        intent = _create_intent(request["correlationId"])
        intent["candidateManifest"] = manifest
        intent["candidateManifestDigest"] = candidate_digest
        recovery = intent["lifecycleRecovery"]
        assert type(recovery) is dict
        candidate_observed = recovery["candidateObservedState"]
        assert type(candidate_observed) is dict
        candidate_observed["desiredManifestDigest"] = candidate_digest
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="request target"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


def test_executor_binds_a_successful_rename_result_to_its_active_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    source_manifest = _fixture("site.json")
    source_digest = manifest_digest(source_manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(source_manifest))
    candidate_metadata = candidate_manifest["metadata"]
    assert type(candidate_metadata) is dict
    candidate_metadata["slug"] = "different-duck"
    candidate_digest = manifest_digest(candidate_manifest).to_dict()

    job = _fixture("authorization-job.json")
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "rename",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
        "slug": "renamed-duck",
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": source_digest,
            "deploymentDigest": deployment_record_digest(
                _fixture("deployment-record.json")
            ).to_dict(),
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"

    intent = _fixture("transaction-intent.json")
    source_observed = _fixture("tenant-observed-state.json")
    source_observed["desiredManifestDigest"] = source_digest
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed["desiredManifestDigest"] = candidate_digest
    candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
    intent.update(
        {
            "tenantId": _TENANT_ID,
            "correlationId": request["correlationId"],
            "operation": "rename",
            "sourceManifest": source_manifest,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate_manifest,
            "candidateManifestDigest": candidate_digest,
            "lifecycleRecovery": {
                "sourceObservedState": source_observed,
                "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                "sourceRouteSet": "both",
                "candidateObservedState": candidate_observed,
                "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
                "candidateRouteSet": "both",
            },
        }
    )
    result = _fixture("operation-result.json")
    provenance = result["provenance"]
    assert type(provenance) is dict
    provenance["jobId"] = job["jobId"]
    result.update(
        {
            "correlationId": request["correlationId"],
            "operation": "rename",
            "tenantId": _TENANT_ID,
            "manifest": candidate_manifest,
        }
    )
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.transaction_intent(intent["intentId"]), intent)
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="request target"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"rename": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


def test_executor_rejects_an_unauthorized_claimed_candidate_before_dispatch(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    source_manifest = _fixture("site.json")
    source_digest = manifest_digest(source_manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(source_manifest))
    candidate_metadata = candidate_manifest["metadata"]
    assert type(candidate_metadata) is dict
    candidate_metadata["slug"] = "different-duck"
    candidate_digest = manifest_digest(candidate_manifest).to_dict()

    job = _fixture("authorization-job.json")
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "rename",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
        "slug": "renamed-duck",
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": source_digest,
            "deploymentDigest": deployment_record_digest(
                _fixture("deployment-record.json")
            ).to_dict(),
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"

    source_observed = _fixture("tenant-observed-state.json")
    source_observed["desiredManifestDigest"] = source_digest
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed["desiredManifestDigest"] = candidate_digest
    candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
    intent = _fixture("transaction-intent.json")
    intent.update(
        {
            "tenantId": _TENANT_ID,
            "correlationId": request["correlationId"],
            "operation": "rename",
            "sourceManifest": source_manifest,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate_manifest,
            "candidateManifestDigest": candidate_digest,
            "lifecycleRecovery": {
                "sourceObservedState": source_observed,
                "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                "sourceRouteSet": "both",
                "candidateObservedState": candidate_observed,
                "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
                "candidateRouteSet": "both",
            },
        }
    )
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.transaction_intent(intent["intentId"]), intent)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(ExecutionError, match="request target"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"rename": handler},
            ).execute(job["jobId"])
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job["jobId"]))

    assert handler.phases == []


@pytest.mark.parametrize("operation", ["deploy", "rollback"])
def test_executor_binds_a_deployment_candidate_to_its_request(
    tmp_path: Path,
    operation: str,
) -> None:
    root = _state_root(tmp_path)
    source_manifest = _fixture("site.json")
    source_digest = manifest_digest(source_manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(source_manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = "e" * 64
    candidate_digest = manifest_digest(candidate_manifest).to_dict()

    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": _TENANT_ID,
    }
    if operation == "deploy":
        request["artifact"] = {"size": 32, "sha256": "d" * 64}
    else:
        request["deploymentId"] = "0198d17f-6f4a-7000-8000-000000000007"

    job = _fixture("authorization-job.json")
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["artifact"] = request.get("artifact")
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": source_digest,
            "deploymentDigest": deployment_record_digest(
                _fixture("deployment-record.json")
            ).to_dict(),
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"

    source_observed = _fixture("tenant-observed-state.json")
    source_observed["desiredManifestDigest"] = source_digest
    candidate_observed = json.loads(json.dumps(source_observed))
    candidate_observed["desiredManifestDigest"] = candidate_digest
    candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
    candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
    intent = _fixture("transaction-intent.json")
    intent.update(
        {
            "tenantId": _TENANT_ID,
            "correlationId": request["correlationId"],
            "operation": operation,
            "sourceManifest": source_manifest,
            "sourceManifestDigest": source_digest,
            "candidateManifest": candidate_manifest,
            "candidateManifestDigest": candidate_digest,
            "lifecycleRecovery": {
                "sourceObservedState": source_observed,
                "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                "sourceRouteSet": "both",
                "candidateObservedState": candidate_observed,
                "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                "candidateRouteSet": "both",
            },
        }
    )
    result = _fixture("operation-result.json")
    provenance = result["provenance"]
    assert type(provenance) is dict
    provenance["jobId"] = job["jobId"]
    result.update(
        {
            "correlationId": request["correlationId"],
            "operation": operation,
            "tenantId": _TENANT_ID,
            "manifest": candidate_manifest,
        }
    )

    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.transaction_intent(intent["intentId"]), intent)
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    if operation == "rollback":
        _write_deployment_record(
            root,
            request["deploymentId"],
            candidate_deployment["archiveSha256"],
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="request target"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={operation: handler},
            ).execute(job["jobId"])

    assert handler.phases == []


@pytest.mark.parametrize(
    ("persist_result", "commit_job", "message"),
    [
        (False, True, "result is not durably exact"),
        (True, False, "before terminal job commit"),
    ],
)
def test_executor_rejects_an_incomplete_handler_commit(
    tmp_path: Path,
    persist_result: bool,
    commit_job: bool,
    message: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        handler = _CompletingCreateHandler(
            repository,
            persist_result=persist_result,
            commit_job=commit_job,
            state_root=root,
        )
        with pytest.raises(RuntimeError, match=message):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)


def test_executor_revalidates_expected_source_before_claiming(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        current = repository.read(StateRecordPath.platform_namespace())
        namespace["initializedAt"] = "2026-08-30T12:01:00Z"
        repository.compare_and_swap(
            StateRecordPath.platform_namespace(),
            current.revision,
            namespace,
        )
        handler = _CompletingCreateHandler(repository)
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        )
        outcome = executor.execute(issued.job_id)
        replay = executor.execute(issued.job_id)

    assert outcome.result["errorCode"] == "state_drift"
    assert replay.result == outcome.result
    assert replay.created is False
    assert handler.phases == []


def test_executor_terminalizes_delete_that_becomes_ineligible(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    desired = _fixture("site.json")
    spec = desired["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "undeployed"
    del spec["desiredDeployment"]
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), desired)
    request = _fixture("operation-request.json")
    request.update({"operation": "delete", "tenantId": _TENANT_ID})
    request.pop("slug", None)
    request.pop("quotas", None)
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        _write(
            root,
            StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
            _fixture("deployment-record.json"),
        )
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        stored = repository.read(StateRecordPath.authorization_result(issued.job_id)).document

    assert outcome.created is True
    assert outcome.result == stored
    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "state_drift"


def test_executor_archive_failure_includes_explicit_absent_record(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    request = _fixture("operation-request.json")
    request.update({"operation": "archive", "tenantId": _TENANT_ID})
    request.pop("slug", None)
    request.pop("quotas", None)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)

    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "not_implemented"
    assert outcome.result["archiveRecord"] is None


def test_executor_uses_bound_intent_not_error_code_to_select_handler_replay(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        intent_id = intent["intentId"]
        assert type(intent_id) is str
        handler = _CompletingIntentHandler(
            repository,
            intent_path=StateRecordPath.transaction_intent(intent_id),
            delegate=_CompletingCreateHandler(repository),
        )
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        ).execute(issued.job_id)

    assert outcome.result == result
    assert outcome.created is False
    assert handler.phases == ["claimed"]


def test_executor_rejects_an_intent_for_another_operation_before_handler_replay(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        intent = _fixture("transaction-intent.json")
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="intent authority does not match"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


def test_executor_rejects_a_misbound_intent_before_claimed_handler_dispatch(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        intent = _fixture("transaction-intent.json")
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="intent authority does not match"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
            ).execute(issued.job_id)

    assert handler.phases == []


@pytest.mark.parametrize(
    ("intent_fixture", "operation", "lifecycle"),
    [
        ("archive-construction-intent.json", "archive", "active"),
        ("archive-retirement-intent.json", "delete", "archived"),
    ],
)
def test_executor_recognizes_archive_intent_paths_for_handler_replay(
    tmp_path: Path,
    intent_fixture: str,
    operation: str,
    lifecycle: str,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    job = _fixture("authorization-job.json")
    intent = _fixture(intent_fixture)
    if intent_fixture == "archive-construction-intent.json":
        _write_archive_source_authority(root, intent)
        deployment_digest = intent["deploymentRecordDigest"]
    else:
        source = _fixture("site.json")
        source_spec = source["spec"]
        archive = intent["archiveRecord"]
        deployment = _fixture("deployment-record.json")
        assert type(source_spec) is dict
        assert type(archive) is dict
        source_spec["desiredState"] = "archived"
        source_digest = manifest_digest(source).to_dict()
        archive["manifestDigest"] = source_digest
        intent["sourceManifestDigest"] = source_digest
        intent["archiveRecordDigest"] = archive_record_digest(archive).to_dict()
        deployment_digest = deployment_record_digest(deployment).to_dict()
        _write(root, StateRecordPath.tenant_desired(intent["tenantId"]), source)
        _write(
            root,
            StateRecordPath.tenant_deployment(intent["tenantId"], deployment["id"]),
            deployment,
        )
        _write(
            root,
            StateRecordPath.tenant_archive(intent["tenantId"], archive["deploymentId"]),
            archive,
        )
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": intent["correlationId"],
        "tenantId": intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "failed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": lifecycle,
            "manifestDigest": intent["sourceManifestDigest"],
            "deploymentDigest": deployment_digest,
            "archiveRecordDigest": intent.get("archiveRecordDigest"),
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
    )
    if operation == "delete":
        archive = intent["archiveRecord"]
        assert type(archive) is dict
        expected["deletionEvidence"] = {
            "mode": "archived",
            "releasedSlugs": ["duck-repair"],
            "archiveRecordDigest": intent["archiveRecordDigest"],
            "bucket": archive["bucket"],
            "key": archive["key"],
            "versionId": archive["versionId"],
            "emergencyReason": None,
        }
    correlation = dict(job)
    correlation["phase"] = "pending"
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": operation,
        "status": "failed",
        "errorCode": "state_drift",
        "tenantId": request["tenantId"],
    }
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    intent_path = (
        StateRecordPath.archive_construction_intent(intent["intentId"])
        if intent_fixture == "archive-construction-intent.json"
        else StateRecordPath.archive_retirement_intent(intent["intentId"])
    )
    _write(root, intent_path, intent)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingIntentHandler(
            repository,
            intent_path=intent_path,
            delegate=_CompletingCreateHandler(repository),
        )
        outcome = AuthorizationExecutor(
            repository,
            intake,
            retained_archive_validator=lambda _archive: True,
            handlers={operation: handler},
        ).execute(job["jobId"])

    assert outcome.result == result
    assert outcome.created is False
    assert handler.phases == ["failed"]


def test_executor_binds_a_successful_archive_result_to_its_construction_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    intent = _fixture("archive-construction-intent.json")
    _write_archive_source_authority(root, intent)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": intent["correlationId"],
        "tenantId": intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": intent["sourceManifestDigest"],
            "deploymentDigest": intent["deploymentRecordDigest"],
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    metadata = manifest["metadata"]
    assert type(spec) is dict
    assert type(metadata) is dict
    spec["desiredState"] = "archived"
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "archive",
        "status": "succeeded",
        "tenantId": request["tenantId"],
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": manifest,
    }
    archive_record = _fixture("archive-record.json")
    archive_record["manifestDigest"] = manifest_digest(manifest).to_dict()
    result["archiveRecord"] = archive_record
    assert manifest_digest(manifest).to_dict() != intent["candidateManifestDigest"]
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.archive_construction_intent(intent["intentId"]),
        intent,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(RuntimeError, match="construction intent"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"archive": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


def test_executor_rejects_disagreeing_archive_intents_before_handler_dispatch(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    construction = _fixture("archive-construction-intent.json")
    _write_archive_source_authority(root, construction)
    transaction_intent = _archive_transaction_intent(construction)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": construction["correlationId"],
        "tenantId": construction["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "active",
            "manifestDigest": transaction_intent["sourceManifestDigest"],
            "deploymentDigest": construction["deploymentRecordDigest"],
            "archiveRecordDigest": None,
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    construction["bundleDigest"] = {
        "format": "lowerduckpond-archive-v1",
        "algorithm": "sha256",
        "value": "f" * 64,
    }
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.transaction_intent(transaction_intent["intentId"]),
        transaction_intent,
    )
    _write(
        root,
        StateRecordPath.archive_construction_intent(construction["intentId"]),
        construction,
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(ExecutionError, match="disagree on candidate authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"archive": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


def test_executor_reconstructs_an_archived_source_for_construction_cleanup(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job, construction, result = _write_committed_archive_replay(root)
    intent_path = StateRecordPath.archive_construction_intent(construction["intentId"])

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        handler = _ClearingIntentHandler(
            repository,
            intent_paths=(intent_path,),
        )
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"archive": handler},
        ).execute(job["jobId"])

    assert handler.dispatched is True
    assert outcome.result == result
    assert outcome.created is False


@pytest.mark.parametrize("archive_matches", [True, False])
def test_executor_revalidates_archive_after_handler_cleared_intents(
    tmp_path: Path,
    archive_matches: bool,
) -> None:
    root = _state_root(tmp_path)
    job, construction, result = _write_committed_archive_replay(root)
    source = json.loads(json.dumps(result["manifest"]))
    source_spec = _mapping(source["spec"])
    source_spec["desiredState"] = "active"

    previous = json.loads(json.dumps(job))
    previous["jobId"] = "0198d17f-6f4a-7000-8000-000000000007"
    previous_request = _mapping(previous["request"])
    previous_request["operation"] = "resume"
    previous_request["correlationId"] = "0198d17f-6f4a-7000-8000-000000000008"
    previous["requestDigest"] = request_digest(previous_request).to_dict()
    previous["phase"] = "pending"
    previous_result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": previous["jobId"]},
        "correlationId": previous_request["correlationId"],
        "operation": "resume",
        "status": "succeeded",
        "tenantId": construction["tenantId"],
        "canonicalOrigin": result["canonicalOrigin"],
        "manifest": source,
    }

    job["compatibilityVersion"] = "static-job-v2"
    job["executionValidated"] = False
    job["sourceAuthority"] = {"manifest": source, "archiveRecord": None}
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(result["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.authorization_correlation(previous_request["correlationId"]),
        previous,
    )
    _write(root, StateRecordPath.authorization_result(previous["jobId"]), previous_result)
    root.joinpath(
        *StateRecordPath.archive_construction_intent(construction["intentId"]).components
    ).unlink()
    if not archive_matches:
        candidate = _mapping(result["manifest"])
        deployment = _mapping(_mapping(candidate["spec"])["desiredDeployment"])
        archive_path = StateRecordPath.tenant_archive(construction["tenantId"], deployment["id"])
        archive = json.loads(root.joinpath(*archive_path.components).read_text(encoding="utf-8"))
        archive["bucket"] = "lowerduckpond-net-production-tenant-archives-wrong"
        _write(root, archive_path, archive)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, previous, previous_result)
        _append_result_audit(repository, job, result)
        executor = AuthorizationExecutor(
            repository,
            intake,
            tenant_runtime_validator=lambda *_arguments: True,
        )
        if not archive_matches:
            with pytest.raises(ExecutionError, match="durable archive authority"):
                executor.execute(job["jobId"])
            return
        outcome = executor.execute(job["jobId"])
        stored = repository.read(StateRecordPath.authorization_job(job["jobId"])).document

    assert outcome.result == result
    assert outcome.created is False
    assert stored["executionValidated"] is True


@pytest.mark.parametrize("deployment_matches", [True, False])
def test_executor_revalidates_restore_after_handler_cleared_intents(
    tmp_path: Path,
    deployment_matches: bool,
) -> None:
    root = _state_root(tmp_path)
    job, result, previous, previous_result = _write_committed_restore_replay(root)
    if not deployment_matches:
        manifest = _mapping(result["manifest"])
        deployment = _mapping(_mapping(manifest["spec"])["desiredDeployment"])
        request = _mapping(job["request"])
        deployment_path = StateRecordPath.tenant_deployment(
            request["tenantId"],
            deployment["id"],
        )
        durable = json.loads(root.joinpath(*deployment_path.components).read_text(encoding="utf-8"))
        durable["archiveSha256"] = "e" * 64
        _write(root, deployment_path, durable)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, previous, previous_result)
        _append_result_audit(repository, job, result)
        executor = AuthorizationExecutor(
            repository,
            intake,
            retired_archive_validator=lambda _archive: True,
            tenant_runtime_validator=lambda *_arguments: True,
        )
        if not deployment_matches:
            with pytest.raises(ExecutionError, match="unbound deployment record"):
                executor.execute(job["jobId"])
            return
        outcome = executor.execute(job["jobId"])
        stored = repository.read(StateRecordPath.authorization_job(job["jobId"])).document

    assert outcome.result == result
    assert outcome.created is False
    assert stored["executionValidated"] is True


def test_executor_requires_remote_absence_for_a_retired_restore_archive(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job, result, previous, previous_result = _write_committed_restore_replay(root)
    checked: list[dict[str, object]] = []

    def reject_retained_archive(archive: dict[str, object]) -> bool:
        checked.append(archive)
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, previous, previous_result)
        _append_result_audit(repository, job, result)
        with pytest.raises(ExecutionError, match="retained its retired archive object"):
            AuthorizationExecutor(
                repository,
                intake,
                retired_archive_validator=reject_retained_archive,
                tenant_runtime_validator=lambda *_arguments: True,
            ).execute(job["jobId"])

    source_authority = _mapping(job["sourceAuthority"])
    assert checked == [source_authority["archiveRecord"]]


def test_executor_requires_remote_presence_after_a_failed_restore(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job, result, _previous, _previous_result = _write_committed_restore_replay(root)
    source_authority = _mapping(job["sourceAuthority"])
    source = _mapping(source_authority["manifest"])
    archive = _mapping(source_authority["archiveRecord"])
    job["phase"] = "failed"
    result.update({"status": "failed", "errorCode": "archive_unavailable"})
    result.pop("canonicalOrigin")
    result.pop("manifest")
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    _write(
        root,
        StateRecordPath.tenant_archive(_TENANT_ID, archive["deploymentId"]),
        archive,
    )
    checked: list[dict[str, object]] = []

    def reject_missing_archive(candidate: dict[str, object]) -> bool:
        checked.append(candidate)
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        with pytest.raises(ExecutionError, match="lost its retained archive object"):
            AuthorizationExecutor(
                repository,
                intake,
                retained_archive_validator=reject_missing_archive,
            ).execute(job["jobId"])

    assert checked == [archive]


def test_executor_rejects_an_archive_record_outside_construction_authority(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job, construction, result = _write_committed_archive_replay(root)
    manifest = _mapping(result["manifest"])
    deployment = _mapping(_mapping(manifest["spec"])["desiredDeployment"])
    archive_path = StateRecordPath.tenant_archive(construction["tenantId"], deployment["id"])
    archive = json.loads(root.joinpath(*archive_path.components).read_text(encoding="utf-8"))
    archive["bucket"] = "lowerduckpond-net-production-tenant-archives-wrong"
    _write(root, archive_path, archive)
    intent_path = StateRecordPath.archive_construction_intent(construction["intentId"])

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        handler = _ClearingIntentHandler(
            repository,
            intent_paths=(intent_path,),
        )
        with pytest.raises(ExecutionError, match="construction authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"archive": handler},
            ).execute(job["jobId"])

    assert handler.dispatched is False


def test_executor_rejects_an_archive_handler_that_commits_another_remote_object(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    construction = _fixture("archive-construction-intent.json")
    source = _write_archive_source_authority(root, construction)
    transaction_intent = _archive_transaction_intent(construction)
    candidate = _mapping(transaction_intent["candidateManifest"])
    recovery = _mapping(transaction_intent["archiveRecovery"])
    authorized_archive = _mapping(recovery["candidateArchiveRecord"])
    wrong_archive = json.loads(json.dumps(authorized_archive))
    wrong_archive["key"] = "archives/0198d17f-6f4a-7000-8000-000000000099.zip"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": construction["correlationId"],
        "tenantId": construction["tenantId"],
    }
    job = _fixture("authorization-job.json")
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = _mapping(job["expectedSource"])
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": _mapping(source["spec"])["desiredState"],
            "manifestDigest": manifest_digest(source).to_dict(),
            "deploymentDigest": construction["deploymentRecordDigest"],
            "archiveRecordDigest": None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    transaction_path = StateRecordPath.transaction_intent(transaction_intent["intentId"])
    construction_path = StateRecordPath.archive_construction_intent(construction["intentId"])
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, transaction_path, transaction_intent)
    _write(root, construction_path, construction)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _ClearingIntentHandler(
            repository,
            intent_paths=(transaction_path, construction_path),
            delegate=_CompletingTransitionHandler(
                repository,
                root,
                manifest=candidate,
                archive=wrong_archive,
            ),
        )
        with pytest.raises(ExecutionError, match="archive record exceeds construction authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"archive": handler},
                tenant_runtime_validator=lambda *_arguments: True,
            ).execute(job["jobId"])

    assert handler.dispatched is True


def test_executor_rejects_observed_runtime_outside_transaction_authority(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job, intent, result = _write_committed_transition_replay(root, operation="rename")
    observed_path = StateRecordPath.tenant_observed(_TENANT_ID)
    observed = json.loads(root.joinpath(*observed_path.components).read_text(encoding="utf-8"))
    observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000007"
    _write(root, observed_path, observed)
    intent_path = StateRecordPath.transaction_intent(intent["intentId"])

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        handler = _ClearingIntentHandler(repository, intent_paths=(intent_path,))
        with pytest.raises(ExecutionError, match="observed state exceeds runtime authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"rename": handler},
                tenant_runtime_validator=lambda *_arguments: True,
            ).execute(job["jobId"])

    assert handler.dispatched is True


@pytest.mark.parametrize(
    ("operation", "route_set"),
    [("rename", "both"), ("suspend", "absent")],
)
def test_executor_requires_the_authorized_selected_runtime_generation(
    tmp_path: Path,
    operation: str,
    route_set: str,
) -> None:
    root = _state_root(tmp_path)
    job, intent, result = _write_committed_transition_replay(root, operation=operation)
    intent_path = StateRecordPath.transaction_intent(intent["intentId"])
    calls: list[tuple[str, str, str | None]] = []

    def reject_unselected(
        tenant_id: str,
        candidate_route_set: str,
        generation_id: str | None,
        _manifest: dict[str, object],
        _observed_state: dict[str, object] | None,
    ) -> bool:
        calls.append((tenant_id, candidate_route_set, generation_id))
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        handler = _ClearingIntentHandler(repository, intent_paths=(intent_path,))
        with pytest.raises(ExecutionError, match="authorized routes"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={operation: handler},
                tenant_runtime_validator=reject_unselected,
            ).execute(job["jobId"])

    assert calls == [
        (
            _TENANT_ID,
            route_set,
            "0198d17f-6f4a-7000-8000-000000000006",
        )
    ]


@pytest.mark.parametrize("operation", ["rename", "suspend"])
def test_executor_requires_the_authorized_source_runtime_after_handler_failure(
    tmp_path: Path,
    operation: str,
) -> None:
    root = _state_root(tmp_path)
    job, intent, result = _write_committed_transition_replay(root, operation=operation)
    source = _mapping(intent["sourceManifest"])
    recovery = _mapping(intent["lifecycleRecovery"])
    source_observed = _mapping(recovery["sourceObservedState"])
    job["compatibilityVersion"] = "static-job-v2"
    job["executionValidated"] = False
    job["sourceAuthority"] = {"manifest": source, "archiveRecord": None}
    job["phase"] = "failed"
    result.update(
        {
            "status": "failed",
            "errorCode": "state_drift",
        }
    )
    result.pop("canonicalOrigin")
    result.pop("manifest")
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    _write(
        root,
        StateRecordPath.authorization_correlation(result["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    _write(root, StateRecordPath.tenant_observed(_TENANT_ID), source_observed)
    intent_path = StateRecordPath.transaction_intent(intent["intentId"])
    calls: list[tuple[str, str, str | None, dict[str, object], dict[str, object]]] = []

    def reject_unrestored(
        tenant_id: str,
        route_set: str,
        generation_id: str | None,
        manifest: dict[str, object],
        observed_state: dict[str, object] | None,
    ) -> bool:
        assert observed_state is not None
        calls.append((tenant_id, route_set, generation_id, manifest, observed_state))
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        handler = _ClearingIntentHandler(repository, intent_paths=(intent_path,))
        with pytest.raises(ExecutionError, match="restore its authorized routes"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={operation: handler},
                tenant_runtime_validator=reject_unrestored,
            ).execute(job["jobId"])

    assert calls == [
        (
            _TENANT_ID,
            "both",
            "0198d17f-6f4a-7000-8000-000000000004",
            source,
            source_observed,
        )
    ]


@pytest.mark.parametrize("execution_validated", [False, True])
def test_executor_revalidates_source_runtime_after_failure_intent_cleanup(
    tmp_path: Path,
    execution_validated: bool,
) -> None:
    root = _state_root(tmp_path)
    job, intent, result = _write_committed_transition_replay(root, operation="rename")
    source = _mapping(intent["sourceManifest"])
    recovery = _mapping(intent["lifecycleRecovery"])
    source_observed = _mapping(recovery["sourceObservedState"])
    job["compatibilityVersion"] = "static-job-v2"
    job["executionValidated"] = execution_validated
    job["sourceAuthority"] = {"manifest": source, "archiveRecord": None}
    job["phase"] = "failed"
    result.update({"status": "failed", "errorCode": "state_drift"})
    result.pop("canonicalOrigin")
    result.pop("manifest")
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    _write(
        root,
        StateRecordPath.authorization_correlation(result["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), source)
    _write(root, StateRecordPath.tenant_observed(_TENANT_ID), source_observed)
    root.joinpath(*StateRecordPath.transaction_intent(intent["intentId"]).components).unlink()
    calls: list[tuple[str, str, str | None]] = []

    def reject_unrestored(
        tenant_id: str,
        route_set: str,
        generation_id: str | None,
        _manifest: dict[str, object],
        _observed_state: dict[str, object] | None,
    ) -> bool:
        calls.append((tenant_id, route_set, generation_id))
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        with pytest.raises(ExecutionError, match="restore its authorized routes"):
            AuthorizationExecutor(
                repository,
                intake,
                tenant_runtime_validator=reject_unrestored,
            ).execute(job["jobId"])

    assert calls == [
        (
            _TENANT_ID,
            "both",
            source_observed["runtimeGenerationId"],
        )
    ]


def test_executor_revalidates_external_state_after_a_validated_failure(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job, intent, result = _write_committed_transition_replay(root, operation="rename")
    source = _mapping(intent["sourceManifest"])
    job["compatibilityVersion"] = "static-job-v2"
    job["executionValidated"] = True
    job["sourceAuthority"] = {"manifest": source, "archiveRecord": None}
    job["phase"] = "failed"
    result.update({"status": "failed", "errorCode": "state_drift"})
    result.pop("canonicalOrigin")
    result.pop("manifest")
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    _write(
        root,
        StateRecordPath.authorization_correlation(result["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)
    root.joinpath(*StateRecordPath.transaction_intent(intent["intentId"]).components).unlink()

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        with pytest.raises(ExecutionError, match="did not restore its authorized routes"):
            AuthorizationExecutor(
                repository,
                intake,
                tenant_runtime_validator=lambda *_arguments: False,
            ).execute(job["jobId"])


def test_executor_requires_the_create_intent_candidate_runtime(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    calls: list[tuple[str, str, str | None, dict[str, object] | None]] = []

    def reject_unselected(
        tenant_id: str,
        route_set: str,
        generation_id: str | None,
        _manifest: dict[str, object],
        observed_state: dict[str, object] | None,
    ) -> bool:
        calls.append((tenant_id, route_set, generation_id, observed_state))
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        current = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = current.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            current.revision,
            claimed,
        )
        request = _mapping(issued.document["request"])
        intent = _create_intent(request["correlationId"])
        intent_path = StateRecordPath.transaction_intent(intent["intentId"])
        repository.create_immutable(intent_path, intent)
        handler = _CompletingIntentHandler(
            repository,
            intent_path=intent_path,
            delegate=_CompletingCreateHandler(repository, state_root=root),
        )
        with pytest.raises(ExecutionError, match="select its authorized routes"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"create": handler},
                tenant_runtime_validator=reject_unselected,
            ).execute(issued.job_id)

    recovery = _mapping(intent["lifecycleRecovery"])
    assert calls == [
        (
            _TENANT_ID,
            "absent",
            "0198d17f-6f4a-7000-8000-000000000006",
            recovery["candidateObservedState"],
        )
    ]


@pytest.mark.parametrize("later_operation", ["rename", "reconcile"])
def test_executor_rechecks_supersession_after_runtime_validation(
    tmp_path: Path,
    later_operation: str,
) -> None:
    root = _state_root(tmp_path)
    job, intent, result = _write_committed_transition_replay(root, operation="rename")
    intent_path = StateRecordPath.transaction_intent(intent["intentId"])

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)

        def supersede_before_recheck(*_arguments: object) -> bool:
            later = json.loads(json.dumps(result))
            provenance = _mapping(later["provenance"])
            manifest = _mapping(later["manifest"])
            metadata = _mapping(manifest["metadata"])
            provenance["jobId"] = "0198d17f-6f4a-7000-8000-000000000007"
            later["correlationId"] = "0198d17f-6f4a-7000-8000-000000000008"
            later["operation"] = later_operation
            if later_operation == "rename":
                metadata["slug"] = "later-authorized-operation"
            _append_result_audit(repository, job, later)
            return False

        handler = _ClearingIntentHandler(repository, intent_paths=(intent_path,))
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"rename": handler},
            tenant_runtime_validator=supersede_before_recheck,
        ).execute(job["jobId"])

    assert outcome.result == result
    assert handler.dispatched is True


def test_executor_binds_restore_candidate_content_to_retirement_authority(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    transaction_intent, retirement_intent = _restore_intents()
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "restore",
        "correlationId": retirement_intent["correlationId"],
        "tenantId": retirement_intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    archive = _mapping(retirement_intent["archiveRecord"])
    source_deployment = _fixture("deployment-record.json")
    source_deployment["id"] = archive["deploymentId"]
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "archived",
            "manifestDigest": retirement_intent["sourceManifestDigest"],
            "deploymentDigest": deployment_record_digest(source_deployment).to_dict(),
            "archiveRecordDigest": retirement_intent["archiveRecordDigest"],
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"

    candidate = transaction_intent["candidateManifest"]
    recovery = transaction_intent["lifecycleRecovery"]
    assert type(candidate) is dict
    assert type(recovery) is dict
    candidate_spec = candidate["spec"]
    candidate_observed = recovery["candidateObservedState"]
    assert type(candidate_spec) is dict
    assert type(candidate_observed) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["archiveSha256"] = "e" * 64
    candidate_digest = manifest_digest(candidate).to_dict()
    transaction_intent["candidateManifestDigest"] = candidate_digest
    candidate_observed["desiredManifestDigest"] = candidate_digest

    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.transaction_intent(transaction_intent["intentId"]),
        transaction_intent,
    )
    _write(
        root,
        StateRecordPath.archive_retirement_intent(retirement_intent["intentId"]),
        retirement_intent,
    )
    source_manifest = _mapping(transaction_intent["sourceManifest"])
    _write(root, StateRecordPath.tenant_desired(request["tenantId"]), source_manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(request["tenantId"], source_deployment["id"]),
        source_deployment,
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(ExecutionError, match="archive retirement authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"restore": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


def test_executor_requires_retirement_authority_for_a_restore_transaction(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    transaction_intent, retirement_intent = _restore_intents()
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "restore",
        "correlationId": retirement_intent["correlationId"],
        "tenantId": retirement_intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "archived",
            "manifestDigest": retirement_intent["sourceManifestDigest"],
            "deploymentDigest": {
                "format": "lowerduckpond-deployment-record-v1",
                "algorithm": "sha256",
                "value": "c" * 64,
            },
            "archiveRecordDigest": retirement_intent["archiveRecordDigest"],
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.transaction_intent(transaction_intent["intentId"]),
        transaction_intent,
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        handler = _CompletingCreateHandler(repository)
        with pytest.raises(ExecutionError, match="no retirement authority"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"restore": handler},
            ).execute(job["jobId"])

    assert handler.phases == []


@pytest.mark.parametrize("restored_release_matches_source", [True, False])
def test_executor_binds_a_lone_restore_retirement_intent_to_its_result(
    tmp_path: Path,
    restored_release_matches_source: bool,
) -> None:
    root = _state_root(tmp_path)
    job = _fixture("authorization-job.json")
    transaction_intent, retirement_intent = _restore_intents()
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "restore",
        "correlationId": retirement_intent["correlationId"],
        "tenantId": retirement_intent["tenantId"],
    }
    job["request"] = request
    job["requestDigest"] = request_digest(request).to_dict()
    job["phase"] = "claimed"
    candidate = _mapping(transaction_intent["candidateManifest"])
    candidate_spec = _mapping(candidate["spec"])
    metadata = _mapping(candidate["metadata"])
    deployment = _mapping(candidate_spec["desiredDeployment"])
    archive = _mapping(retirement_intent["archiveRecord"])
    bundle_digest = _mapping(archive["bundleDigest"])
    deployment["archiveSha256"] = bundle_digest["value"]
    source_deployment = _fixture("deployment-record.json")
    source_deployment["id"] = archive["deploymentId"]
    expected = _mapping(job["expectedSource"])
    expected.update(
        {
            "expectsTenantAbsent": False,
            "lifecycle": "archived",
            "manifestDigest": retirement_intent["sourceManifestDigest"],
            "deploymentDigest": deployment_record_digest(source_deployment).to_dict(),
            "archiveRecordDigest": retirement_intent["archiveRecordDigest"],
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "restore",
        "status": "succeeded",
        "tenantId": request["tenantId"],
        "canonicalOrigin": metadata["canonicalOrigin"],
        "manifest": candidate,
    }
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(
        root,
        StateRecordPath.archive_retirement_intent(retirement_intent["intentId"]),
        retirement_intent,
    )
    _write(root, StateRecordPath.tenant_desired(request["tenantId"]), candidate)
    _write_observed_for_manifest(root, candidate)
    durable_deployment = _fixture("deployment-record.json")
    durable_deployment["id"] = deployment["id"]
    durable_deployment["archiveSha256"] = deployment["archiveSha256"]
    durable_deployment["correlationId"] = request["correlationId"]
    if not restored_release_matches_source:
        release_tree_digest = _mapping(durable_deployment["releaseTreeDigest"])
        release_tree_digest["value"] = "e" * 64
    _write(
        root,
        StateRecordPath.tenant_deployment(request["tenantId"], source_deployment["id"]),
        source_deployment,
    )
    _write(
        root,
        StateRecordPath.tenant_deployment(request["tenantId"], deployment["id"]),
        durable_deployment,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, job, result)
        retirement_id = retirement_intent["intentId"]
        assert type(retirement_id) is str
        handler = _CompletingIntentHandler(
            repository,
            intent_path=StateRecordPath.archive_retirement_intent(retirement_id),
            delegate=_CompletingCreateHandler(repository),
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            retired_archive_validator=lambda _archive: True,
            handlers={"restore": handler},
        )
        if restored_release_matches_source:
            outcome = executor.execute(job["jobId"])
            assert outcome.result == result
            assert outcome.created is False
        else:
            with pytest.raises(ExecutionError, match="unbound deployment record"):
                executor.execute(job["jobId"])

    assert handler.phases == ["claimed"]


def test_executor_dispatches_a_claimed_job_with_an_intent_without_source_recheck(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        intent_id = intent["intentId"]
        assert type(intent_id) is str
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent_id),
            intent,
        )
        current = repository.read(StateRecordPath.platform_namespace())
        namespace["initializedAt"] = "2026-08-30T12:01:00Z"
        repository.compare_and_swap(
            StateRecordPath.platform_namespace(),
            current.revision,
            namespace,
        )
        handler = _CompletingIntentHandler(
            repository,
            intent_path=StateRecordPath.transaction_intent(intent_id),
            delegate=_CompletingCreateHandler(repository, state_root=root),
        )

        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
            tenant_runtime_validator=lambda *_arguments: True,
        ).execute(issued.job_id)

    assert outcome.result["status"] == "succeeded"
    assert handler.phases == ["claimed"]


def test_executor_revalidates_a_claimed_job_without_a_recovery_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        current = repository.read(StateRecordPath.platform_namespace())
        namespace["initializedAt"] = "2026-08-30T12:01:00Z"
        repository.compare_and_swap(
            StateRecordPath.platform_namespace(),
            current.revision,
            namespace,
        )
        handler = _CompletingCreateHandler(repository)

        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"create": handler},
        ).execute(issued.job_id)

    assert outcome.result["status"] == "failed"
    assert outcome.result["errorCode"] == "state_drift"
    assert handler.phases == []


def test_executor_consumes_only_the_artifact_bound_to_the_job(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = _deployment_zip_payload(b"bounded deployment")
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()
        handler = _CompletingFailureHandler(repository)
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
        ).execute(issued.job_id)

    assert outcome.result["errorCode"] == "not_implemented"
    assert len(handler.claims) == 1
    assert handler.claims[0] is not None
    assert handler.claims[0].artifact == lease.artifact
    assert list((root / "intake").iterdir()) == []


def test_executor_retains_artifact_when_handler_leaves_its_intent(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    source_digest = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = _deployment_zip_payload(b"intent-bound deployment")
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    candidate_deployment["archiveSha256"] = artifact.sha256
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = source_digest
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_digest
        candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifest": manifest,
                "sourceManifestDigest": source_digest,
                "candidateManifest": candidate_manifest,
                "candidateManifestDigest": candidate_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000004"),
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                    "candidateRouteSet": "both",
                },
            }
        )
        intent_path = StateRecordPath.transaction_intent(intent["intentId"])
        repository.create_immutable(intent_path, intent)

        with pytest.raises(ExecutionError, match="before clearing its intent"):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"deploy": _CompletingFailureHandler(repository)},
            ).execute(issued.job_id)

        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        repository.read(intent_path)
        repository.read(StateRecordPath.authorization_result(issued.job_id))

    assert terminal["phase"] == "failed"
    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_reacquires_the_bound_artifact_for_lifecycle_replay(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    manifest_digest_value = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = _deployment_zip_payload(b"recoverable replay deployment")
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    candidate_deployment["archiveSha256"] = artifact.sha256
    candidate_manifest_digest = manifest_digest(candidate_manifest).to_dict()
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()

        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = manifest_digest_value
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_manifest_digest
        candidate_observed["activeDeploymentId"] = "0198d17f-6f4a-7000-8000-000000000005"
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifest": manifest,
                "sourceManifestDigest": manifest_digest_value,
                "candidateManifest": candidate_manifest,
                "candidateManifestDigest": candidate_manifest_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
                    "candidateRouteSet": "both",
                },
            }
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation_id,
            "operation": "deploy",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": _TENANT_ID,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        intent_id = intent["intentId"]
        assert type(intent_id) is str
        handler = _CompletingIntentHandler(
            repository,
            intent_path=StateRecordPath.transaction_intent(intent_id),
            delegate=_CompletingCreateHandler(repository),
        )
        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
            tenant_runtime_validator=lambda *_arguments: True,
        ).execute(issued.job_id)

    assert outcome.result == result
    assert outcome.created is False
    assert len(handler.claims) == 1
    assert handler.claims[0] is not None
    assert handler.claims[0].artifact.verified == artifact
    assert list((root / "intake").iterdir()) == []


def test_executor_returns_a_completed_replay_after_losing_the_artifact_race(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    source_digest = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = "d" * 64
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(32, "d" * 64)
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = source_digest
        _write(
            root,
            StateRecordPath.tenant_observed(_TENANT_ID),
            source_observed,
        )
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_digest
        candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifest": manifest,
                "sourceManifestDigest": source_digest,
                "candidateManifest": candidate_manifest,
                "candidateManifestDigest": candidate_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000004"),
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                    "candidateRouteSet": "both",
                },
            }
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation_id,
            "operation": "deploy",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": _TENANT_ID,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        handler = _CompletingFailureHandler(repository)
        intent_id = intent["intentId"]
        assert type(intent_id) is str
        intake = _CompletingUnavailableIntake(
            repository,
            job_id=issued.job_id,
            intent_id=intent_id,
        )

        # The intake double preserves the production claim protocol without
        # constructing a privileged filesystem-backed ArtifactIntake.
        outcome = AuthorizationExecutor(
            repository,
            intake,  # type: ignore[arg-type]
            handlers={"deploy": handler},
            tenant_runtime_validator=lambda *_arguments: True,
        ).execute(issued.job_id, blocking=True)

        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.transaction_intent(intent["intentId"]))

    assert outcome.result == result
    assert outcome.created is False
    assert terminal["phase"] == "failed"
    assert handler.claims == []


def test_executor_does_not_terminalize_handler_artifact_errors(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    payload = _deployment_zip_payload(b"recoverable deployment")
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()

        with pytest.raises(
            IntakeArtifactUnavailableError,
            match="handler recovery requires",
        ):
            AuthorizationExecutor(
                repository,
                intake,
                handlers={"deploy": _UnavailableArtifactHandler()},
            ).execute(issued.job_id)

        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(issued.job_id))

    assert job["phase"] == "claimed"
    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_executor_fails_terminally_when_bound_artifact_is_absent(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(7, "a" * 64)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000004",
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)

    assert outcome.result["errorCode"] == "invalid_artifact"


def test_executor_does_not_publish_artifact_failure_after_a_concurrent_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(7, "a" * 64)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000004",
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        original = AuthorizationExecutor._recover_claimed_lifecycle_without_artifact

        def claim_after_absence(
            executor: AuthorizationExecutor,
            job_id: str,
            initial: StoredContract,
            *,
            handler: LifecycleJobHandler | None,
            blocking: bool,
        ) -> ExecutionOutcome | None:
            recovered = original(
                executor,
                job_id,
                initial,
                handler=handler,
                blocking=blocking,
            )
            assert recovered is None
            job = repository.read(StateRecordPath.authorization_job(job_id))
            claimed = job.document
            claimed["phase"] = "claimed"
            repository.compare_and_swap(
                StateRecordPath.authorization_job(job_id),
                job.revision,
                claimed,
            )
            return None

        monkeypatch.setattr(
            AuthorizationExecutor,
            "_recover_claimed_lifecycle_without_artifact",
            claim_after_absence,
        )

        with pytest.raises(ExecutionError, match="lost pending job authority"):
            AuthorizationExecutor(repository, intake).execute(issued.job_id)

        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(issued.job_id))

    assert job.document["phase"] == "claimed"


def test_executor_returns_artifact_failure_published_by_concurrent_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), _fixture("site.json"))
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(7, "a" * 64)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000004",
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        original = AuthorizationExecutor._recover_claimed_lifecycle_without_artifact

        def fail_after_absence(
            executor: AuthorizationExecutor,
            job_id: str,
            initial: StoredContract,
            *,
            handler: LifecycleJobHandler | None,
            blocking: bool,
        ) -> ExecutionOutcome | None:
            recovered = original(
                executor,
                job_id,
                initial,
                handler=handler,
                blocking=blocking,
            )
            assert recovered is None
            published = AuthorizationExecutor(repository, intake)._fail_without_claim(
                job_id,
                initial,
                error_code="invalid_artifact",
                handler=handler,
                blocking=blocking,
            )
            assert published.created is True
            return None

        monkeypatch.setattr(
            AuthorizationExecutor,
            "_recover_claimed_lifecycle_without_artifact",
            fail_after_absence,
        )

        outcome = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))

    assert outcome.created is False
    assert outcome.result["errorCode"] == "invalid_artifact"
    assert job.document["phase"] == "failed"


@pytest.mark.parametrize("terminal_result", [False, True])
def test_executor_recovers_a_claimed_lifecycle_job_without_its_artifact(  # noqa: PLR0915
    tmp_path: Path,
    terminal_result: bool,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    source_digest = manifest_digest(manifest).to_dict()
    candidate_manifest = json.loads(json.dumps(manifest))
    candidate_spec = candidate_manifest["spec"]
    assert type(candidate_spec) is dict
    candidate_deployment = candidate_spec["desiredDeployment"]
    assert type(candidate_deployment) is dict
    candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
    candidate_deployment["archiveSha256"] = "d" * 64
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    artifact = VerifiedArtifact(32, "d" * 64)
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": _TENANT_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = AuthorizationIssuer(
            repository,
            gate=_OpenGate(),
            entropy=_Entropy(),
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=artifact,
        )
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        claimed["dispatchArchiveDeploymentIds"] = []
        claimed["dispatchArtifactReleaseTreeDigest"] = _fixture("deployment-record.json")[
            "releaseTreeDigest"
        ]
        claimed["dispatchDeploymentIds"] = [_DEPLOYMENT_ID]
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = source_digest
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_digest
        candidate_observed["activeDeploymentId"] = candidate_deployment["id"]
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": _TENANT_ID,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifest": manifest,
                "sourceManifestDigest": source_digest,
                "candidateManifest": candidate_manifest,
                "candidateManifestDigest": candidate_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000004"),
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": ("0198d17f-6f4a-7000-8000-000000000006"),
                    "candidateRouteSet": "both",
                },
            }
        )
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        if terminal_result:
            result: dict[str, object] = {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "OperationResult",
                "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
                "correlationId": correlation_id,
                "operation": "deploy",
                "status": "failed",
                "errorCode": "not_implemented",
                "tenantId": _TENANT_ID,
            }
            repository.create_immutable(
                StateRecordPath.authorization_result(issued.job_id),
                result,
            )
            _append_result_audit(repository, issued.document, result)
            current = repository.read(StateRecordPath.authorization_job(issued.job_id))
            failed = current.document
            failed["phase"] = "failed"
            repository.compare_and_swap(
                StateRecordPath.authorization_job(issued.job_id),
                current.revision,
                failed,
            )
        intent_id = intent["intentId"]
        assert type(intent_id) is str
        handler = _CompletingIntentHandler(
            repository,
            intent_path=StateRecordPath.transaction_intent(intent_id),
            delegate=_CompletingFailureHandler(repository),
        )

        outcome = AuthorizationExecutor(
            repository,
            intake,
            handlers={"deploy": handler},
            tenant_runtime_validator=lambda *_arguments: True,
        ).execute(issued.job_id)
        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document

    assert outcome.result["errorCode"] == "not_implemented"
    assert outcome.created is not terminal_result
    assert terminal["phase"] == "failed"
    assert handler.claims == [None]


@pytest.mark.parametrize("audit_present", [False, True])
def test_executor_repairs_a_result_first_terminal_failure_commit(
    tmp_path: Path,
    audit_present: bool,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "not_implemented",
            "failurePublisher": "authorization-executor",
            "tenantId": None,
        }
        repository.create_immutable(StateRecordPath.authorization_result(issued.job_id), result)
        if audit_present:
            _append_result_audit(repository, issued.document, result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        executor = AuthorizationExecutor(repository, intake)
        outcome = executor.execute(issued.job_id)
        terminal = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        audit = repository.inspect_audit_correlation(result["correlationId"]).entry

    assert outcome.created is False
    assert terminal["phase"] == "failed"
    assert terminal["executionValidated"] is True
    assert audit is not None
    assert audit["resultDigest"] == result_digest(result).to_dict()
    assert audit["resultStatus"] == "failed"


@pytest.mark.parametrize("superseded", [False, True])
def test_executor_preserves_supersession_when_repairing_a_late_failure_audit(
    tmp_path: Path,
    superseded: bool,
) -> None:
    root = _state_root(tmp_path)
    job, intent, later_result = _write_committed_transition_replay(
        root,
        operation="rename",
    )
    source = _mapping(intent["sourceManifest"])
    request = _mapping(job["request"])
    job.update(
        {
            "compatibilityVersion": "static-job-v2",
            "sourceAuthority": {"manifest": source, "archiveRecord": None},
            "executionValidated": False,
            "phase": "failed",
        }
    )
    correlation = json.loads(json.dumps(job))
    correlation["phase"] = "pending"
    later_result = json.loads(json.dumps(later_result))
    later_provenance = _mapping(later_result["provenance"])
    later_provenance["jobId"] = "0198d17f-6f4a-7000-8000-000000000007"
    later_result["correlationId"] = "0198d17f-6f4a-7000-8000-000000000008"
    later_job = {
        # This job was accepted before the failed job even though its audit
        # transition is committed after that failure's publication boundary.
        "acceptedAt": "2026-08-29T11:59:59Z",
        "operatorPrincipal": job["operatorPrincipal"],
    }
    later_entry: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": 0,
        "previousEntryDigest": None,
        "timestamp": later_job["acceptedAt"],
        "operatorPrincipal": later_job["operatorPrincipal"],
        "operation": later_result["operation"],
        "tenantId": later_result["tenantId"],
        "correlationId": later_result["correlationId"],
        "resultDigest": result_digest(later_result).to_dict(),
        "resultStatus": later_result["status"],
    }
    failure: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": "rename",
        "status": "failed",
        "errorCode": "state_drift",
        "failurePublisher": "authorization-executor",
        "failureAuditPredecessorDigest": (
            None if superseded else audit_entry_digest(later_entry).to_dict()
        ),
        "failureAuditSequence": 0 if superseded else 1,
        "tenantId": _TENANT_ID,
    }
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )
    _write(root, StateRecordPath.authorization_result(job["jobId"]), failure)
    root.joinpath(*StateRecordPath.transaction_intent(intent["intentId"]).components).unlink()

    validator_calls: list[str] = []

    def reject_stale_source(*_arguments: object) -> bool:
        validator_calls.append("called")
        return False

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        _append_result_audit(repository, later_job, later_result)
        executor = AuthorizationExecutor(
            repository,
            intake,
            tenant_runtime_validator=reject_stale_source,
            tenant_release_validator=reject_stale_source,
        )
        if superseded:
            outcome = executor.execute(job["jobId"])
            assert outcome.result == failure
            assert outcome.created is False
        else:
            with pytest.raises(
                ExecutionError,
                match="did not restore its authorized source",
            ):
                executor.execute(job["jobId"])
        terminal = repository.read(StateRecordPath.authorization_job(job["jobId"])).document
        snapshot = repository.inspect_audit_correlation(failure["correlationId"])

    assert terminal["phase"] == "failed"
    assert terminal["executionValidated"] is superseded
    assert snapshot.entry is not None
    assert snapshot.entry["sequence"] == 1
    assert snapshot.previous_tenant_state_transition is not None
    assert (
        snapshot.previous_tenant_state_transition["correlationId"] == later_result["correlationId"]
    )
    assert validator_calls == []


def test_executor_repairs_a_successful_create_with_its_generated_tenant(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue_create(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        manifest = result["manifest"]
        assert type(manifest) is dict
        _write(root, StateRecordPath.tenant_desired(result["tenantId"]), manifest)
        _write_observed_for_manifest(root, manifest)
        repository.create_immutable(StateRecordPath.authorization_result(issued.job_id), result)
        _append_result_audit(repository, issued.document, result)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = AuthorizationExecutor(
            repository,
            intake,
            tenant_runtime_validator=lambda *_arguments: True,
        ).execute(issued.job_id)
        phase = repository.read(StateRecordPath.authorization_job(issued.job_id)).document["phase"]

    assert outcome.created is False
    assert outcome.result["status"] == "succeeded"
    assert phase == "completed"
