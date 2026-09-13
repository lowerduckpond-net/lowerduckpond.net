from __future__ import annotations

import io
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

import pytest
from lowerduckpond_static_contracts import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
    deployment_record_digest,
    manifest_digest,
    result_digest,
)
from lowerduckpond_static_host_agent.archive_journal import (
    ArchiveConstructionJournal,
    ArchiveJournal,
    ArchiveJournalBoundary,
    ArchiveJournalError,
    ArchiveRetirementJournal,
    VerifiedArchiveUpload,
)
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteError,
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
)
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.export_snapshot import ExportSnapshot, capture_export_snapshot
from lowerduckpond_static_host_agent.export_spool import EXPORT_WORKSPACE_BUNDLE_NAME, ExportSpool
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.locks import LockManager, LockMode
from lowerduckpond_static_host_agent.portable_bundle import build_portable_bundle
from lowerduckpond_static_host_agent.release_tree import measure_release_tree
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordPath,
    StateRepository,
    StateRevision,
)

_OWNER = os.geteuid()
_TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_DEPLOYMENT = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_CORRELATION = "0198d17f-6f4a-7000-8000-000000000009"
_NOW = datetime(2026, 9, 12, 4, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_BUCKET = "example-tenant-archives"
_OBSERVED_VERSIONS = 2


class MemoryRemote:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.versions: list[dict[str, object]] = []
        self.markers: list[dict[str, object]] = []
        self.body = b""
        self.digest = ""
        self.lose_response = False
        self.fail_purge = False
        self.require_intent = True
        self.uploads: list[dict[str, object]] = []
        self.expected_intent: Path | None = None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        assert self.expected_intent is not None
        if self.require_intent:
            assert tuple(self.expected_intent.glob("*.json")), "remote I/O preceded durable intent"

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, object]:
        self._call("versioning")
        return {"Status": "Enabled"}

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        self._call("list")
        prefix = str(kwargs["Prefix"])
        return {
            "IsTruncated": False,
            "Versions": [entry for entry in self.versions if str(entry["Key"]).startswith(prefix)],
            "DeleteMarkers": [
                entry for entry in self.markers if str(entry["Key"]).startswith(prefix)
            ],
        }

    def list_multipart_uploads(self, **kwargs: object) -> dict[str, object]:
        self._call("multipart")
        return {"IsTruncated": False, "Uploads": self.uploads}

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self._call("put")
        self.body = cast(BinaryIO, kwargs["Body"]).read()
        self.digest = str(cast(dict[str, object], kwargs["Metadata"])["sha256"])
        assert len(self.body) == kwargs["ContentLength"]
        self.versions.append(
            {"Key": kwargs["Key"], "VersionId": "version-one", "Size": len(self.body)}
        )
        if self.lose_response:
            raise TimeoutError("lost after remote commit")
        return {"VersionId": "version-one"}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self._call("get")
        assert kwargs["VersionId"] == "version-one"
        assert self.versions
        return {
            "Body": io.BytesIO(self.body),
            "VersionId": "version-one",
            "ContentLength": len(self.body),
            "Metadata": {"sha256": self.digest},
        }

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        self._call("delete")
        if self.fail_purge:
            raise TimeoutError("purge unavailable")
        assert "VersionId" in kwargs
        for entries in (self.versions, self.markers):
            entries[:] = [
                entry
                for entry in entries
                if (entry["Key"], entry["VersionId"]) != (kwargs["Key"], kwargs["VersionId"])
            ]
        return {"VersionId": kwargs["VersionId"]}


class OpenGate:
    def require_enabled(self) -> None:
        pass


def _entropy(length: int) -> bytes:
    return os.urandom(length)


def fixture(name: str) -> dict[str, object]:
    return decode_contract((_FIXTURES / name).read_bytes())


def write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def setup_root(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "state"
    for name in (
        "",
        "locks",
        "platform",
        "intents",
        "exports",
        "audit",
        "authorization",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
        "tenants",
        f"tenants/{_TENANT}",
        f"tenants/{_TENANT}/archives",
        f"tenants/{_TENANT}/deployments",
    ):
        (root / name).mkdir(mode=0o700)
    with LockManager.initialize(root / "locks", expected_owner=_OWNER):
        pass
    releases = tmp_path / "sites"
    release = releases / _TENANT / "releases" / _DEPLOYMENT
    release.mkdir(parents=True)
    (release / "index.html").write_text("archived bytes", encoding="ascii")
    (release / "index.html").chmod(0o644)
    manifest = fixture("site.json")
    deployment = fixture("deployment-record.json")
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        repository.publication_transaction(),
    ):
        deployment["releaseTreeDigest"] = measure_release_tree(
            release, lock_manager=repository, expected_owner=_OWNER
        ).digest.to_dict()
    write(root, StateRecordPath.platform_namespace(), fixture("platform-namespace.json"))
    write(root, StateRecordPath.tenant_desired(_TENANT), manifest)
    write(root, StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT), deployment)
    observed = fixture("tenant-observed-state.json")
    observed["desiredManifestDigest"] = manifest_digest(manifest).to_dict()
    write(root, StateRecordPath.tenant_observed(_TENANT), observed)
    return root, releases


@pytest.fixture(autouse=True)
def capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    filesystem = FilesystemCapacity(1, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000)
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _self: filesystem,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.export_spool.measure_filesystem_capacity_descriptor",
        lambda _fd: filesystem,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.archive_quarantine.measure_filesystem_capacity_descriptor",
        lambda _fd: filesystem,
    )


@contextmanager
def prepared_source(
    tmp_path: Path, client: MemoryRemote, *, lifecycle: str = "active"
) -> Iterator[tuple[ArchiveJournal, str, ExportSnapshot, ArchiveQuarantine]]:
    root, releases = setup_root(tmp_path)
    if lifecycle == "suspended":
        source_path = StateRecordPath.tenant_desired(_TENANT)
        source = decode_contract(root.joinpath(*source_path.components).read_bytes())
        cast(dict[str, object], source["spec"])["desiredState"] = lifecycle
        write(root, source_path, source)
        observed_path = StateRecordPath.tenant_observed(_TENANT)
        observed = decode_contract(root.joinpath(*observed_path.components).read_bytes())
        observed.update(
            observedState=lifecycle,
            runtimeGenerationId=None,
            desiredManifestDigest=manifest_digest(source).to_dict(),
        )
        write(root, observed_path, observed)
    else:
        assert lifecycle == "active"
    client.expected_intent = root / "intents"
    with (
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
    ):
        issued = AuthorizationIssuer(repository, gate=OpenGate(), entropy=_entropy).issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": "archive",
                    "tenantId": _TENANT,
                    "correlationId": _CORRELATION,
                }
            ),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        path = StateRecordPath.authorization_job(issued.job_id)
        job = repository.read(path)
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(path, job.revision, claimed)
        with repository.transaction(mode=LockMode.SHARED) as transaction:
            manifest = transaction.read(StateRecordPath.tenant_desired(_TENANT)).document
            deployment = transaction.read(
                StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT)
            ).document
            snapshot = capture_export_snapshot(
                spool,
                transaction,
                release_root=releases,
                tenant_id=_TENANT,
                expected_manifest_digest=manifest_digest(manifest),
                expected_deployment_digest=deployment_record_digest(deployment),
                expected_owner=_OWNER,
                archive=True,
            )
        build_portable_bundle(
            snapshot.content,
            snapshot.manifest,
            output_parent=spool.workspace,
            output_name=EXPORT_WORKSPACE_BUNDLE_NAME,
            lock_manager=spool.locks,
            expected_owner=_OWNER,
            read_only_snapshot=True,
        )
        quarantine = ArchiveQuarantine(
            root, bucket=_BUCKET, expected_owner=_OWNER, locks=spool.locks
        )
        journal = ArchiveJournal(
            repository,
            spool,
            ArchiveRemoteStore(client, bucket=_BUCKET),
            expected_owner=_OWNER,
            quarantine=quarantine.record,
            require_quarantine_empty=quarantine.require_empty,
        )
        yield journal, issued.job_id, snapshot, quarantine


def test_construction_syncs_before_remote_calls_and_binds_exact_verified_version(
    tmp_path: Path,
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        assert uploaded.construction.document["phase"] == "uploaded"
        assert uploaded.record["versionId"] == "version-one"
        assert uploaded.record["manifestDigest"] == manifest_digest(snapshot.manifest).to_dict()
        assert client.calls == ["versioning", "list", "multipart", "list", "put", "get"]
        assert quarantine.read() is None
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).document
            == snapshot.source_manifest
        )


def test_local_construction_journal_confirms_only_its_matching_receipt(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (remote_journal, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            remote_journal.repository,
            remote_journal.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        prepared = journal.prepare(job_id, snapshot, now=_NOW)
        revision = prepared.construction.revision
        wrong_revision = StateRevision(revision.contract_kind, revision.byte_count, "a" * 64)
        with pytest.raises(ArchiveJournalError, match="another prepared"):
            journal.confirm(prepared, VerifiedArchiveUpload(wrong_revision, "verified-version"))
        with pytest.raises(ArchiveJournalError, match="reconciled intents"):
            journal.prepare(job_id, snapshot, now=_NOW)
        receipt = VerifiedArchiveUpload(revision, "verified-version")
        uploaded = journal.confirm(prepared, receipt)
        assert uploaded.record["versionId"] == "verified-version"
        assert uploaded.construction.document["phase"] == "uploaded"
        with pytest.raises(StateConflictError):
            journal.confirm(prepared, receipt)
        assert client.calls == []


@pytest.mark.parametrize("version", ["", "null", "x" * 1025])
def test_local_construction_rejects_invalid_version_without_advancing_intent(
    tmp_path: Path, version: str
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (remote_journal, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            remote_journal.repository,
            remote_journal.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        prepared = journal.prepare(job_id, snapshot, now=_NOW)
        with pytest.raises((ContractError, ArchiveJournalError)):
            journal.confirm(
                prepared, VerifiedArchiveUpload(prepared.construction.revision, version)
            )
        current = journal.repository.read(
            StateRecordPath.archive_construction_intent(prepared.construction.document["intentId"])
        )
        assert current.revision == prepared.construction.revision
        assert client.calls == []


def test_local_construction_cannot_advance_a_failed_authorization(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (remote_journal, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            remote_journal.repository,
            remote_journal.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        prepared = journal.prepare(job_id, snapshot, now=_NOW)
        path = StateRecordPath.authorization_job(job_id)
        job = journal.repository.read(path)
        failed = job.document
        failed["phase"] = "failed"
        journal.repository.compare_and_swap(path, job.revision, failed)
        with pytest.raises(ArchiveJournalError, match="no longer claimed"):
            journal.confirm(
                prepared, VerifiedArchiveUpload(prepared.construction.revision, "verified-version")
            )
        assert client.calls == []


@pytest.mark.parametrize(
    "boundary",
    [
        ArchiveJournalBoundary.CONSTRUCTION_SYNC,
        ArchiveJournalBoundary.REMOTE_ADMITTED,
        ArchiveJournalBoundary.REMOTE_PUT,
        ArchiveJournalBoundary.REMOTE_VERIFIED,
        ArchiveJournalBoundary.UPLOADED_SYNC,
    ],
)
def test_interruptions_retain_intent_and_never_repeat_upload(
    tmp_path: Path, boundary: ArchiveJournalBoundary
) -> None:
    class Interrupted(BaseException):
        pass

    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, _quarantine):

        def interrupt(current: ArchiveJournalBoundary) -> None:
            if current == boundary:
                raise Interrupted

        journal.hook = interrupt
        with pytest.raises(Interrupted):
            journal.construct(job_id, snapshot, now=_NOW)
        journal.hook = None
        before = list(client.calls)
        with pytest.raises(ArchiveJournalError, match="reconciled intents"):
            journal.construct(job_id, snapshot, now=_NOW)
        assert client.calls == before
        intent = journal.repository.measure_intent_records().records[0]
        journal.purge_unbound_construction(intent.intent_id)
        assert not client.versions
        assert journal.repository.measure_intent_records().records


def test_lost_response_discovers_versions_and_markers_without_reupload(tmp_path: Path) -> None:
    client = MemoryRemote()
    client.lose_response = True
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        with pytest.raises(TimeoutError):
            journal.construct(job_id, snapshot, now=_NOW)
        assert quarantine.read() is not None
        client.markers = [{"Key": client.versions[0]["Key"], "VersionId": "delete-marker"}]
        intent = journal.repository.measure_intent_records().records[0]
        journal.purge_unbound_construction(intent.intent_id)
        assert not client.versions and not client.markers
        assert client.calls.count("put") == 1
        with pytest.raises(FileNotFoundError):
            journal.finish(intent.intent_id)
        assert journal.repository.measure_intent_records().records
        with pytest.raises(ArchiveRemoteError, match="quarantine"):
            quarantine.require_empty()


def test_failed_purge_keeps_journal_quarantine_and_remote_charge(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        client.fail_purge = True
        with pytest.raises(TimeoutError):
            journal.purge_unbound_construction(str(uploaded.construction.document["intentId"]))
        assert client.versions
        ledger = quarantine.read()
        assert ledger is not None
        assert ledger["discoveryIncomplete"] is True
        assert any(
            entry["version_id"] == "version-one"
            for entry in cast(list[dict[str, object]], ledger["versions"])
        )
        assert journal.repository.measure_intent_records().records


def test_authoritative_record_prevents_any_remote_deletion(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        journal.repository.create_immutable(
            StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT), uploaded.record
        )
        with pytest.raises(ArchiveJournalError, match="remains bound"):
            journal.purge_unbound_construction(str(uploaded.construction.document["intentId"]))
        assert "delete" not in client.calls
        assert client.versions


def test_quarantine_survives_reopen_and_preserves_all_observed_versions(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (_journal, _job_id, _snapshot, quarantine):
        first = RemoteVersion("archives/first", "old", 10, False)
        second = RemoteVersion("archives/first", "marker", 0, True)
        quarantine.record(RemoteInventory((first,), ()))
        quarantine.record(None)
        quarantine.record(RemoteInventory((second,), (("archives/upload", "multipart-id"),)))
        reopened = ArchiveQuarantine(
            quarantine.root, bucket=_BUCKET, expected_owner=_OWNER, locks=quarantine.locks
        )
        document = reopened.read()
        assert document is not None
        assert document["discoveryIncomplete"] is True
        assert len(cast(list[object], document["versions"])) == _OBSERVED_VERSIONS
        assert document["multipartUploads"] == [["archives/upload", "multipart-id"]]
        with pytest.raises(ArchiveRemoteError, match="quarantine"):
            reopened.require_empty()


@pytest.mark.parametrize("key", ["archives/unknown", "outside/archive-prefix"])
def test_quarantine_requires_unknown_keys_to_be_independently_resolved_before_reopening(
    tmp_path: Path, key: str
) -> None:
    client = MemoryRemote()
    client.require_intent = False
    with prepared_source(tmp_path, client) as (journal, _job_id, _snapshot, quarantine):
        client.versions = [{"Key": key, "VersionId": "unknown", "Size": 10}]
        quarantine.record(journal.remote.inventory())
        with pytest.raises(ArchiveRemoteError):
            quarantine.resolve(journal.repository, journal.remote)
        assert quarantine.read() is not None
        # Independent administrative resolution is simulated only in the provider;
        # quarantine resolution itself never grants a DeleteObject operation.
        client.versions.clear()
        assert quarantine.resolve(journal.repository, journal.remote)
        assert quarantine.read() is None
        assert "delete" not in client.calls


def terminal_result(
    journal: ArchiveJournal,
    job_id: str,
    result: dict[str, object],
) -> None:
    with journal.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        audit = transaction.inspect_audit()
        transaction.append_audit(
            {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "AuditEntry",
                "sequence": audit.entry_count,
                "previousEntryDigest": audit.terminal_digest,
                "timestamp": "2026-09-12T04:00:00Z",
                "operatorPrincipal": "operator@example.test",
                "operation": result["operation"],
                "tenantId": _TENANT,
                "correlationId": result["correlationId"],
                "resultDigest": result_digest(result).to_dict(),
                "resultStatus": result["status"],
            }
        )
        transaction.create_immutable(StateRecordPath.authorization_result(job_id), result)
        document = job.document
        document["phase"] = "completed" if result["status"] == "succeeded" else "failed"
        transaction.compare_and_swap(
            StateRecordPath.authorization_job(job_id), job.revision, document
        )


def commit_archived_fixture(
    journal: ArchiveJournal, job_id: str, snapshot: ExportSnapshot, record: dict[str, object]
) -> None:
    with journal.repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        transaction.create_immutable(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT), record)
        path = StateRecordPath.tenant_desired(_TENANT)
        source = transaction.read(path)
        transaction.compare_and_swap(path, source.revision, snapshot.manifest)
        path = StateRecordPath.tenant_observed(_TENANT)
        observed = transaction.read(path)
        candidate = observed.document
        candidate.update(
            desiredManifestDigest=manifest_digest(snapshot.manifest).to_dict(),
            observedState="archived",
            activeDeploymentId=None,
            runtimeGenerationId=None,
        )
        transaction.compare_and_swap(path, observed.revision, candidate)
    terminal_result(
        journal,
        job_id,
        {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": job_id},
            "operation": "archive",
            "status": "succeeded",
            "tenantId": _TENANT,
            "canonicalOrigin": cast(dict[str, object], snapshot.manifest["metadata"])[
                "canonicalOrigin"
            ],
            "correlationId": _CORRELATION,
            "manifest": snapshot.manifest,
            "archiveRecord": record,
        },
    )


def test_successful_construction_recovery_rechecks_bound_bytes_before_removal(
    tmp_path: Path,
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        commit_archived_fixture(journal, job_id, snapshot, uploaded.record)
        before = client.calls.count("get")
        journal.finish(str(uploaded.construction.document["intentId"]))
        assert client.calls.count("get") == before + 1
        assert client.versions
        assert "delete" not in client.calls
        assert not journal.repository.measure_intent_records().records


def test_failed_construction_cleanup_requires_audited_result_and_independent_absence(
    tmp_path: Path,
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        intent_id = str(uploaded.construction.document["intentId"])
        journal.purge_unbound_construction(intent_id)
        terminal_result(
            journal,
            job_id,
            {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "OperationResult",
                "provenance": {"kind": "authorization-job", "jobId": job_id},
                "operation": "archive",
                "status": "failed",
                "tenantId": _TENANT,
                "correlationId": _CORRELATION,
                "errorCode": "state_drift",
                "archiveRecord": None,
            },
        )
        before = client.calls.count("list")
        journal.finish(intent_id)
        assert client.calls.count("list") > before
        assert not journal.repository.measure_intent_records().records
        assert not client.versions


@pytest.mark.parametrize("operation", ["restore", "delete"])
@pytest.mark.parametrize("local_only", [False, True])
def test_retirement_requires_new_job_and_preserves_bound_bytes_on_failed_transition(
    tmp_path: Path, operation: str, local_only: bool
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        commit_archived_fixture(journal, job_id, snapshot, uploaded.record)
        journal.finish(str(uploaded.construction.document["intentId"]))
        with pytest.raises(ArchiveJournalError):
            journal.prepare_retirement(job_id, now=_NOW)
        correlation = "0198d17f-6f4a-7000-8000-000000000010"
        issued = AuthorizationIssuer(journal.repository, gate=OpenGate(), entropy=_entropy).issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": operation,
                    "tenantId": _TENANT,
                    "correlationId": correlation,
                }
            ),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        path = StateRecordPath.authorization_job(issued.job_id)
        job = journal.repository.read(path)
        claimed = job.document
        claimed["phase"] = "claimed"
        journal.repository.compare_and_swap(path, job.revision, claimed)
        before = tuple(client.calls)
        retirement = (
            ArchiveRetirementJournal(journal.repository, journal.spool, bucket=_BUCKET).prepare(
                issued.job_id, now=_NOW
            )
            if local_only
            else journal.prepare_retirement(issued.job_id, now=_NOW)
        )
        assert tuple(client.calls) == before
        assert retirement.document["archiveRecord"] == uploaded.record
        assert retirement.document["provenance"] == {
            "kind": "authorization-job",
            "jobId": issued.job_id,
        }
        terminal_result(
            journal,
            issued.job_id,
            {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "OperationResult",
                "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
                "operation": operation,
                "status": "failed",
                "tenantId": _TENANT,
                "correlationId": correlation,
                "errorCode": "state_drift",
            },
        )
        journal.finish(str(retirement.document["intentId"]))
        assert client.versions
        assert "delete" not in client.calls
        assert not journal.repository.measure_intent_records().records


def test_quarantine_resolution_waits_for_every_intent_before_remote_io(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        journal.construct(job_id, snapshot, now=_NOW)
        quarantine.record(None)
        previous = quarantine.read()
        calls = tuple(client.calls)
        with pytest.raises(ArchiveRemoteError, match="resolve all intents"):
            quarantine.resolve(journal.repository, journal.remote)
        assert tuple(client.calls) == calls
        assert quarantine.read() == previous


def test_quarantine_resolution_verifies_retained_bytes_and_both_inventories(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        commit_archived_fixture(journal, job_id, snapshot, uploaded.record)
        quarantine.record(None)
        journal.finish(str(uploaded.construction.document["intentId"]))
        client.require_intent = False
        client.calls.clear()
        assert quarantine.resolve(journal.repository, journal.remote)
        assert client.calls == [
            "versioning",
            "list",
            "multipart",
            "get",
            "versioning",
            "list",
            "multipart",
        ]
        quarantine.require_empty()
        assert client.versions
        assert not quarantine.resolve(journal.repository, journal.remote)


@pytest.mark.parametrize("drift", ["missing", "unknown", "marker", "multipart", "bytes"])
def test_quarantine_resolution_keeps_admission_closed_on_unresolved_evidence(
    tmp_path: Path, drift: str
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        commit_archived_fixture(journal, job_id, snapshot, uploaded.record)
        journal.finish(str(uploaded.construction.document["intentId"]))
        client.require_intent = False
        quarantine.record(None)
        key = uploaded.record["key"]
        if drift == "missing":
            client.versions.clear()
        elif drift == "unknown":
            client.versions.append({"Key": key, "VersionId": "unexpected", "Size": 10})
        elif drift == "marker":
            client.markers.append({"Key": key, "VersionId": "hidden"})
        elif drift == "multipart":
            client.uploads.append({"Key": key, "UploadId": "unexpected-upload"})
        else:
            client.body = b"x" * len(client.body)
        with pytest.raises(ArchiveRemoteError):
            quarantine.resolve(journal.repository, journal.remote)
        ledger = quarantine.read()
        assert ledger is not None
        assert ledger["discoveryIncomplete"] is True
        with pytest.raises(ArchiveRemoteError, match="quarantine"):
            quarantine.require_empty()
        assert "delete" not in client.calls


def test_quarantine_resolution_rechecks_inventory_after_retained_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, snapshot, quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        commit_archived_fixture(journal, job_id, snapshot, uploaded.record)
        journal.finish(str(uploaded.construction.document["intentId"]))
        client.require_intent = False
        quarantine.record(None)
        original = client.get_object

        def mutate_inventory(**kwargs: object) -> dict[str, object]:
            response = original(**kwargs)
            client.markers.append({"Key": uploaded.record["key"], "VersionId": "late-marker"})
            return response

        monkeypatch.setattr(client, "get_object", mutate_inventory)
        with pytest.raises(ArchiveRemoteError, match="unresolved remote inventory"):
            quarantine.resolve(journal.repository, journal.remote)
        ledger = quarantine.read()
        assert ledger is not None
        assert any(
            value["version_id"] == "late-marker"
            for value in cast(list[dict[str, object]], ledger["versions"])
        )
        assert "delete" not in client.calls


def test_quarantine_resolution_confirms_disappeared_unknown_objects_without_deletion(
    tmp_path: Path,
) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, _job_id, _snapshot, quarantine):
        client.require_intent = False
        quarantine.record(
            RemoteInventory((RemoteVersion("archives/unknown", "old", 1, False),), ())
        )
        quarantine.record(None)
        assert quarantine.resolve(journal.repository, journal.remote)
        quarantine.require_empty()
        assert client.calls == [
            "versioning",
            "list",
            "multipart",
            "versioning",
            "list",
            "multipart",
        ]


def test_quarantine_cannot_reopen_against_a_different_bucket(tmp_path: Path) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, _job_id, _snapshot, quarantine):
        quarantine.record(None)
        previous = quarantine.read()
        replacement = ArchiveRemoteStore(client, bucket="different-archive-bucket")
        with pytest.raises(ArchiveRemoteError, match="another bucket"):
            quarantine.resolve(journal.repository, replacement)
        reopened = ArchiveQuarantine(
            quarantine.root,
            bucket=replacement.bucket,
            expected_owner=_OWNER,
            locks=quarantine.locks,
        )
        with pytest.raises(ArchiveRemoteError, match="metadata is inconsistent"):
            reopened.require_empty()
        assert quarantine.read() == previous
        assert not client.calls
