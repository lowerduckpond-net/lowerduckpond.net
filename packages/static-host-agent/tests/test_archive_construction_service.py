from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.archive_construction_service import (
    ArchiveConstructionClient,
    serve_archive_construction,
)
from lowerduckpond_static_host_agent.archive_journal import ArchiveConstructionJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, ArchiveRemoteStore
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_RESPONSE_BYTES,
    ArchiveChannel,
    ArchiveTransportError,
)
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockMode, LockName, StateBusyError
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_journal import (
    _BUCKET,
    _NOW,
    _OWNER,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)

_PROTOCOL = "lowerduckpond-archive-construction-v1"


def _serve(stream: socket.socket, root: Path, client: MemoryRemote) -> None:
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        serve_archive_construction(
            stream,
            repository,
            spool,
            ArchiveRemoteStore(client, bucket=_BUCKET),
            quarantine=ArchiveQuarantine(
                root, bucket=_BUCKET, expected_owner=_OWNER, locks=spool.locks
            ),
            expected_owner=_OWNER,
        )


def test_construction_session_binds_one_upload_and_keeps_confirmation_in_worker(
    tmp_path: Path,
) -> None:
    client = MemoryRemote()
    sender, receiver = socket.socketpair()
    with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            original.repository,
            original.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            boundary = ArchiveConstructionClient(
                original.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            )
            with boundary.session(job_id) as session:
                assert session.bucket == _BUCKET
                assert not client.calls
                prepared = journal.prepare(job_id, snapshot, now=_NOW)
                with (original.spool.workspace / "bundle.zip").open("rb") as body:
                    verified = session.upload(prepared, body)
                    with pytest.raises(ArchiveRemoteError, match="consumed"):
                        session.upload(prepared, body)
                future.result(timeout=5)
                path = StateRecordPath.archive_construction_intent(
                    prepared.construction.document["intentId"]
                )
                assert original.repository.read(path).document["phase"] == "prepared"
                assert verified.construction_revision == prepared.construction.revision
                uploaded = journal.confirm(prepared, verified)
                assert uploaded.record["versionId"] == "version-one"
                assert uploaded.record["bucket"] == _BUCKET
                assert uploaded.construction.document["phase"] == "uploaded"
        assert client.calls == ["versioning", "list", "multipart", "list", "put", "get"]


def test_new_session_cannot_upload_an_existing_prepared_intent(tmp_path: Path) -> None:
    client = MemoryRemote()
    sender, receiver = socket.socketpair()
    with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            original.repository,
            original.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        journal.prepare(job_id, snapshot, now=_NOW)
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            with (
                pytest.raises(ArchiveRemoteError),
                ArchiveConstructionClient(
                    original.spool, connector=lambda: sender, expected_peer_uid=_OWNER
                ).session(job_id),
            ):
                pytest.fail("prepared intent admitted a new upload session")
            with pytest.raises(ArchiveRemoteError, match="fresh claimed"):
                future.result(timeout=5)
        assert not client.calls


@pytest.mark.parametrize("defect", ["other-file", "writable", "offset", "size", "hard-link"])
def test_construction_rejects_untrusted_source_descriptor_before_remote_io(
    tmp_path: Path, defect: str
) -> None:
    client = MemoryRemote()
    sender, receiver = socket.socketpair()
    with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            original.repository,
            original.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            with ArchiveConstructionClient(
                original.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).session(job_id) as session:
                prepared = journal.prepare(job_id, snapshot, now=_NOW)
                source = original.spool.workspace / "bundle.zip"
                if defect == "other-file":
                    other = tmp_path / "another-bundle"
                    other.write_bytes(source.read_bytes())
                    other.chmod(0o600)
                    source = other
                if defect == "size":
                    with source.open("ab") as output:
                        output.write(b"extra")
                if defect == "hard-link":
                    (tmp_path / "another-link").hardlink_to(source)
                with source.open("r+b" if defect == "writable" else "rb") as body:
                    if defect == "offset":
                        body.seek(1)
                    with pytest.raises(ArchiveRemoteError):
                        session.upload(prepared, body)
                try:
                    with pytest.raises((ArchiveRemoteError, StatePathError)):
                        future.result(timeout=5)
                finally:
                    if defect == "hard-link":
                        (tmp_path / "another-link").unlink()
        assert not client.calls


@pytest.mark.parametrize("defect", ["candidate", "source", "bucket", "job-phase"])
def test_construction_revalidates_durable_source_after_ready(tmp_path: Path, defect: str) -> None:
    client = MemoryRemote()
    sender, receiver = socket.socketpair()
    with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            original.repository,
            original.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            with ArchiveConstructionClient(
                original.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).session(job_id) as session:
                prepared = journal.prepare(job_id, snapshot, now=_NOW)
                intent = prepared.construction.document
                path = StateRecordPath.archive_construction_intent(intent["intentId"])
                if defect == "job-phase":
                    path = StateRecordPath.authorization_job(job_id)
                    document = original.repository.read(path).document
                    document["phase"] = "failed"
                else:
                    document = intent
                    if defect == "bucket":
                        document["bucket"] = "another-archive-bucket"
                    else:
                        field = (
                            "candidateManifestDigest"
                            if defect == "candidate"
                            else "sourceManifestDigest"
                        )
                        cast(dict[str, object], document[field])["value"] = "a" * 64
                (tmp_path / "state").joinpath(*path.components).write_bytes(
                    canonical_json_bytes(document)
                )
                with (
                    (original.spool.workspace / "bundle.zip").open("rb") as body,
                    pytest.raises(ArchiveRemoteError),
                ):
                    session.upload(prepared, body)
                with pytest.raises(ArchiveRemoteError):
                    future.result(timeout=5)
        assert not client.calls


def test_lost_provider_response_preserves_prepared_intent_and_closes_admission(
    tmp_path: Path,
) -> None:
    client = MemoryRemote()
    client.lose_response = True
    sender, receiver = socket.socketpair()
    with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            original.repository,
            original.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            with ArchiveConstructionClient(
                original.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).session(job_id) as session:
                prepared = journal.prepare(job_id, snapshot, now=_NOW)
                with (
                    (original.spool.workspace / "bundle.zip").open("rb") as body,
                    pytest.raises(ArchiveRemoteError),
                ):
                    session.upload(prepared, body)
                with pytest.raises(TimeoutError, match="lost after"):
                    future.result(timeout=5)
            observed = quarantine.read()
            assert observed is not None and observed["discoveryIncomplete"]
            assert (
                original.repository.read(
                    StateRecordPath.archive_construction_intent(
                        prepared.construction.document["intentId"]
                    )
                ).document["phase"]
                == "prepared"
            )
        assert client.calls.count("put") == 1
        assert len(client.versions) == 1


def test_client_disconnect_retains_export_exclusion_through_upload_and_verification(
    tmp_path: Path,
) -> None:
    started = Event()
    proceed = Event()

    class PausedRemote(MemoryRemote):
        def put_object(self, **kwargs: object) -> dict[str, object]:
            started.set()
            assert proceed.wait(5)
            return super().put_object(**kwargs)

    client = PausedRemote()
    sender, receiver = socket.socketpair()
    with ThreadPoolExecutor() as pool:
        with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            channel = ArchiveChannel(
                sender,
                expected_peer_uid=_OWNER,
                maximum_receive_bytes=MAX_ARCHIVE_RESPONSE_BYTES,
            )
            lease = original.spool.locks.duplicate_export_descriptor()
            channel.send(
                {"protocol": _PROTOCOL, "operation": "begin", "jobId": job_id},
                descriptor=lease,
            )
            os.close(lease)
            with channel.receive() as response:
                assert response.payload["status"] == "ready"
            prepared = ArchiveConstructionJournal(
                original.repository,
                original.spool,
                expected_owner=_OWNER,
                bucket=_BUCKET,
                require_quarantine_empty=quarantine.require_empty,
            ).prepare(job_id, snapshot, now=_NOW)
            with (original.spool.workspace / "bundle.zip").open("rb") as source:
                channel.send(
                    {"operation": "upload", "intentId": prepared.construction.document["intentId"]},
                    descriptor=source.fileno(),
                )
            assert started.wait(5)
            channel.close()
        try:
            with (
                ExportSpool(tmp_path / "state", expected_owner=_OWNER) as contender,
                pytest.raises(StateBusyError),
                contender.locks.acquire(LockName.EXPORT, mode=LockMode.EXCLUSIVE),
            ):
                pytest.fail("a disconnected worker released a running provider operation")
        finally:
            proceed.set()
        with pytest.raises((OSError, ArchiveTransportError)):
            future.result(timeout=5)
    assert client.calls.count("put") == 1
    assert client.calls[-1] == "get"
    with (
        ExportSpool(tmp_path / "state", expected_owner=_OWNER) as contender,
        contender.locks.acquire(LockName.EXPORT, mode=LockMode.EXCLUSIVE),
    ):
        pass


@pytest.mark.parametrize("defect", ["unknown-version", "bad-verified-body"])
def test_construction_closes_admission_for_remote_inventory_or_verification_failure(
    tmp_path: Path, defect: str
) -> None:
    class CorruptRemote(MemoryRemote):
        def get_object(self, **kwargs: object) -> dict[str, object]:
            self.body = b"x" * len(self.body)
            return super().get_object(**kwargs)

    client = CorruptRemote() if defect == "bad-verified-body" else MemoryRemote()
    if defect == "unknown-version":
        client.versions.append(
            {
                "Key": "archives/0191e2c4-8f7a-7c3b-8d1e-5f62047a2100.zip",
                "VersionId": "unknown-version",
                "Size": 1,
            }
        )
    sender, receiver = socket.socketpair()
    with prepared_source(tmp_path, client) as (original, job_id, snapshot, quarantine):
        journal = ArchiveConstructionJournal(
            original.repository,
            original.spool,
            expected_owner=_OWNER,
            bucket=_BUCKET,
            require_quarantine_empty=quarantine.require_empty,
        )
        with ThreadPoolExecutor() as pool:
            future = pool.submit(_serve, receiver, tmp_path / "state", client)
            with ArchiveConstructionClient(
                original.spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).session(job_id) as session:
                prepared = journal.prepare(job_id, snapshot, now=_NOW)
                with (
                    (original.spool.workspace / "bundle.zip").open("rb") as body,
                    pytest.raises(ArchiveRemoteError),
                ):
                    session.upload(prepared, body)
                with pytest.raises(ArchiveRemoteError):
                    future.result(timeout=5)
            observed = quarantine.read()
            assert observed is not None
            versions = cast(list[dict[str, object]], observed["versions"])
            assert len(versions) == 1
            assert versions[0]["version_id"] == (
                "unknown-version" if defect == "unknown-version" else "version-one"
            )
        assert client.calls.count("put") == (0 if defect == "unknown-version" else 1)
