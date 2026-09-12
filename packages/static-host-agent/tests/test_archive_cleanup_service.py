from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.archive_cleanup_service import (
    ArchiveCleanupClient,
    serve_archive_cleanup,
)
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, ArchiveRemoteStore
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_RESPONSE_BYTES,
    ArchiveChannel,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_activate import _activate, _prepared
from test_archive_journal import (
    _DEPLOYMENT,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)


def _serve(stream: socket.socket, root: Path, remote: ArchiveRemoteStore) -> None:
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        serve_archive_cleanup(
            stream,
            repository,
            spool,
            remote,
            expected_owner=_OWNER,
            quarantine=ArchiveQuarantine(
                root, bucket=remote.bucket, expected_owner=_OWNER, locks=spool.locks
            ),
        )


@pytest.mark.parametrize("lost_response", [False, True])
def test_cleanup_service_purges_all_versions_and_markers_without_repeating_upload(
    tmp_path: Path, lost_response: bool
) -> None:
    remote = MemoryRemote()
    remote.lose_response = lost_response
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        if lost_response:
            with pytest.raises(TimeoutError):
                journal.construct(job_id, snapshot, now=_NOW)
        else:
            journal.construct(job_id, snapshot, now=_NOW)
        remote.markers = [{"Key": remote.versions[0]["Key"], "VersionId": "marker"}]
        intent = journal.repository.measure_intent_records().records[0]
        sender, receiver = socket.socketpair()
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", journal.remote)
            ArchiveCleanupClient(
                journal.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).purge_construction(job_id, intent.intent_id)
            future.result(timeout=5)
        assert not remote.versions and not remote.markers
        assert remote.calls.count("put") == 1
        assert journal.repository.measure_intent_records().records == (intent,)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_cleanup_service_independently_verifies_committed_archive_before_removing_journal(
    tmp_path: Path, lifecycle: str
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, store, prepared, runtime):
        _activate(journal, store, prepared, runtime)
        sender, receiver = socket.socketpair()
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", journal.remote)
            ArchiveCleanupClient(
                journal.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).finish(str(prepared.job.document["jobId"]), prepared.plan.construction_intent_id)
            future.result(timeout=5)
        assert not journal.repository.measure_intent_records().records
        assert (
            journal.repository.read(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT)).document
            == prepared.plan.archive_record
        )


@pytest.mark.parametrize("defect", ["caller-key", "wrong-job", "premature-finish", "bound-record"])
def test_cleanup_service_rejects_excess_or_incomplete_authority_before_deletion(
    tmp_path: Path, defect: str
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        if defect == "bound-record":
            journal.repository.create_immutable(
                StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT), uploaded.record
            )
        payload: dict[str, object] = {
            "protocol": "lowerduckpond-archive-cleanup-v1",
            "operation": "finish" if defect == "premature-finish" else "purge-construction",
            "jobId": _TENANT if defect == "wrong-job" else job_id,
        }
        if defect == "caller-key":
            payload["key"] = "arbitrary"
        sender, receiver = socket.socketpair()
        lease = journal.spool.locks.duplicate_export_descriptor()
        try:
            with (
                ThreadPoolExecutor() as pool,
                ArchiveChannel(
                    sender,
                    expected_peer_uid=_OWNER,
                    maximum_receive_bytes=MAX_ARCHIVE_RESPONSE_BYTES,
                ) as channel,
            ):
                channel.send(payload, descriptor=lease)
                future = pool.submit(_serve, receiver, tmp_path / "state", journal.remote)
                with pytest.raises((ArchiveRemoteError, FileNotFoundError)):
                    future.result(timeout=5)
        finally:
            os.close(lease)
        assert remote.versions
        assert "delete" not in remote.calls
        assert journal.repository.measure_intent_records().records


def test_cleanup_service_cannot_skip_an_unfinished_local_transaction(tmp_path: Path) -> None:
    with _prepared(tmp_path, "active") as (journal, _store, prepared, _runtime):
        sender, receiver = socket.socketpair()
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", journal.remote)
            with pytest.raises(ArchiveRemoteError):
                ArchiveCleanupClient(
                    journal.spool, connector=lambda: sender, expected_peer_uid=_OWNER
                ).finish(str(prepared.job.document["jobId"]), prepared.plan.construction_intent_id)
            with pytest.raises(ArchiveRemoteError, match="sole journal"):
                future.result(timeout=5)
        assert len(journal.repository.measure_intent_records().records) == 2  # noqa: PLR2004
