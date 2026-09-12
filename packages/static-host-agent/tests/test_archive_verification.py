from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.archive_verification import verify_archive_terminal
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_activate import _activate, _prepared
from test_archive_cleanup_service import _serve
from test_archive_journal import (
    _CORRELATION,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
    terminal_result,
)


def test_terminal_verification_reads_the_exact_retained_object_after_journal_removal(
    tmp_path: Path,
) -> None:
    with _prepared(tmp_path, "active") as (journal, store, prepared, runtime):
        _activate(journal, store, prepared, runtime)
        journal.finish(prepared.plan.construction_intent_id)
        remote = journal.remote
        cast(MemoryRemote, remote.client).require_intent = False
        job_id = str(prepared.job.document["jobId"])
        record = prepared.plan.archive_record
        assert verify_archive_terminal(journal, job_id)["archiveRecord"] == record
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(tmp_path / "state", expected_owner=_OWNER) as spool,
    ):
        future = pool.submit(_serve, receiver, tmp_path / "state", remote)
        assert ArchiveCleanupClient(
            spool, connector=lambda: sender, expected_peer_uid=_OWNER
        ).verify_terminal(job_id, record, mode="retained")
        future.result(timeout=5)


@pytest.mark.parametrize(
    "defect", ["missing-object", "corrupt-bytes", "changed-binding", "no-audit"]
)
def test_terminal_verification_rejects_independently_changed_evidence(
    tmp_path: Path, defect: str
) -> None:
    with _prepared(tmp_path, "suspended") as (journal, store, prepared, runtime):
        _activate(journal, store, prepared, runtime)
        journal.finish(prepared.plan.construction_intent_id)
        remote = cast(MemoryRemote, journal.remote.client)
        remote.require_intent = False
        if defect == "missing-object":
            remote.versions.clear()
        elif defect == "corrupt-bytes":
            remote.body = b"x" * len(remote.body)
        elif defect == "changed-binding":
            path = StateRecordPath.tenant_archive(
                _TENANT, prepared.plan.archive_record["deploymentId"]
            )
            stored = journal.repository.read(path)
            changed = stored.document
            changed["versionId"] = "another-version"
            (tmp_path / "state").joinpath(*path.components).write_bytes(
                canonical_json_bytes(changed)
            )
        else:
            for audit_path in (tmp_path / "state" / "audit").glob("*.jsonl"):
                audit_path.unlink()
        with pytest.raises((ArchiveRemoteError, RuntimeError, AssertionError)):
            verify_archive_terminal(journal, str(prepared.job.document["jobId"]))


@pytest.mark.parametrize("unknown", [False, True])
def test_failed_unreturned_version_requires_a_complete_accounted_inventory(
    tmp_path: Path, unknown: bool
) -> None:
    remote = MemoryRemote()
    remote.lose_response = True
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        with pytest.raises(TimeoutError):
            journal.construct(job_id, snapshot, now=_NOW)
        intent = journal.repository.measure_intent_records().records[0]
        journal.purge_unbound_construction(intent.intent_id)
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
        journal.finish(intent.intent_id)
        remote.require_intent = False
        if unknown:
            remote.versions.append({"Key": "unknown-object", "VersionId": "unknown", "Size": 10})
            with pytest.raises(ArchiveRemoteError, match="unaccounted"):
                verify_archive_terminal(journal, job_id)
        else:
            assert verify_archive_terminal(journal, job_id) == {
                "status": "verified",
                "mode": "accounted",
                "archiveRecord": None,
            }


@pytest.mark.parametrize("unknown_remains", [False, True])
def test_terminal_retry_resolves_quarantine_after_the_journal_is_already_removed(
    tmp_path: Path, unknown_remains: bool
) -> None:

    with _prepared(tmp_path, "active") as (journal, store, prepared, runtime):
        _activate(journal, store, prepared, runtime)
        remote = journal.remote
        client = cast(MemoryRemote, remote.client)
        quarantine = ArchiveQuarantine(
            tmp_path / "state",
            bucket=remote.bucket,
            expected_owner=_OWNER,
            locks=journal.spool.locks,
        )
        unknown = dict(client.versions[0], Key="unknown/object", VersionId="unowned-version")
        client.versions.append(unknown)
        quarantine.record(remote.inventory())
        # Model interruption after the authorized journal removal, before the
        # final whole-bucket quarantine proof can finish.
        journal.finish(prepared.plan.construction_intent_id)
        client.require_intent = False
        assert quarantine.read() is not None
        job_id = str(prepared.job.document["jobId"])
        record = prepared.plan.archive_record
        if not unknown_remains:
            # Independent resolution of unowned data; the service never deletes it.
            client.versions.remove(unknown)
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(tmp_path / "state", expected_owner=_OWNER) as spool,
    ):
        future = pool.submit(_serve, receiver, tmp_path / "state", remote)
        cleanup = ArchiveCleanupClient(spool, connector=lambda: sender, expected_peer_uid=_OWNER)
        if unknown_remains:
            with pytest.raises(ArchiveRemoteError):
                cleanup.verify_terminal(job_id, record, mode="retained")
            with pytest.raises(ArchiveRemoteError):
                future.result(timeout=5)
        else:
            assert cleanup.verify_terminal(job_id, record, mode="retained")
            future.result(timeout=5)
        with spool.locks.acquire(LockName.EXPORT):
            remaining = ArchiveQuarantine(
                tmp_path / "state",
                bucket=remote.bucket,
                expected_owner=_OWNER,
                locks=spool.locks,
            ).read()
            assert (remaining is not None) == unknown_remains
        assert "delete" not in client.calls
