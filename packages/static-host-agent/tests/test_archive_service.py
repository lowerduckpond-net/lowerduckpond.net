from __future__ import annotations

import io
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import BinaryIO, cast

import pytest
from lowerduckpond_static_contracts import ContractError, canonical_json_bytes
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveClient,
    ArchiveRemoteError,
    ArchiveRemoteStore,
)
from lowerduckpond_static_host_agent.archive_service import (
    ArchiveExportClient,
    serve_archive_export,
)
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_RESPONSE_BYTES,
    ArchiveChannel,
    ArchiveTransportError,
)
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.execution import AuthorizationExecutor
from lowerduckpond_static_host_agent.export_handler import ExportLifecycleHandler
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.locks import (
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    StateBusyError,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_export_handler import (
    _NOW,
    _archived_source,
    _filesystem,  # noqa: F401 - shared autouse capacity fixture
    _issue,
    _OpenGate,
)

_OWNER = os.geteuid()
_PROTOCOL = "lowerduckpond-archive-export-v1"


def _claimed(root: Path) -> str:
    with StateRepository(root, expected_owner=_OWNER) as repository:
        job_id = _issue(repository)
        path = StateRecordPath.authorization_job(job_id)
        job = repository.read(path)
        document = job.document
        document["phase"] = "claimed"
        repository.compare_and_swap(path, job.revision, document)
        return job_id


def _remote(
    body: bytes, record: dict[str, object], calls: list[dict[str, object]]
) -> ArchiveRemoteStore:
    def get_object(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "Body": io.BytesIO(body),
            "VersionId": record["versionId"],
            "ContentLength": len(body),
            "Metadata": {"sha256": cast(dict[str, object], record["bundleDigest"])["value"]},
        }

    return ArchiveRemoteStore(
        cast(ArchiveClient, SimpleNamespace(get_object=get_object)), bucket=str(record["bucket"])
    )


def _serve(stream: socket.socket, root: Path, remote: ArchiveRemoteStore) -> None:
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        serve_archive_export(stream, repository, spool, remote, expected_owner=_OWNER)


def _channel(stream: socket.socket) -> ArchiveChannel:
    return ArchiveChannel(
        stream,
        expected_peer_uid=_OWNER,
        maximum_receive_bytes=MAX_ARCHIVE_RESPONSE_BYTES,
        timeout=2.0,
    )


def _request(
    channel: ArchiveChannel, spool: ExportSpool, job_id: str, destination: BinaryIO, **extra: object
) -> None:
    lease = spool.locks.duplicate_export_descriptor()
    try:
        channel.send(
            {"protocol": _PROTOCOL, "operation": "export", "jobId": job_id, **extra},
            descriptor=lease,
        )
        channel.send({"operation": "destination"}, descriptor=destination.fileno())
    finally:
        os.close(lease)


def test_archive_service_derives_exact_version_and_leaves_the_worker_to_parse(
    tmp_path: Path,
) -> None:
    root, _releases, body, record = _archived_source(tmp_path)
    job_id = _claimed(root)
    calls: list[dict[str, object]] = []
    remote = _remote(body, record, calls)
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
    ):
        future = pool.submit(_serve, receiver, root, remote)
        output = spool.workspace / "bundle.zip"
        with output.open("xb", buffering=0) as destination:
            output.chmod(0o600)
            ArchiveExportClient(
                spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ).read_archive(job_id, record, destination)
        future.result(timeout=5)
        assert output.read_bytes() == body
    assert calls == [
        {"Bucket": record["bucket"], "Key": record["key"], "VersionId": record["versionId"]}
    ]


def test_export_lifecycle_downloads_and_publishes_through_the_private_service(
    tmp_path: Path,
) -> None:
    root, releases, body, record = _archived_source(tmp_path)
    calls: list[dict[str, object]] = []
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ArtifactIntake(root, expected_owner=_OWNER) as intake,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        job_id = _issue(repository)
        future = pool.submit(_serve, receiver, root, _remote(body, record, calls))
        handler = ExportLifecycleHandler(
            repository,
            spool,
            _OpenGate(),
            release_root=releases,
            expected_owner=_OWNER,
            archive_source=ArchiveExportClient(
                spool, connector=lambda: sender, expected_peer_uid=_OWNER
            ),
            now=lambda: _NOW,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={"export": handler},
            tenant_runtime_validator=lambda *_args: True,
        )
        outcome = executor.execute(job_id)
        future.result(timeout=5)
        assert outcome.result["status"] == "succeeded"
        assert (root / "exports" / f"{job_id}.zip").read_bytes() == body
        assert executor.execute(job_id).result == outcome.result
        assert len(calls) == 1


@pytest.mark.parametrize(
    "extra",
    [
        {"key": "arbitrary"},
        {"bucket": "arbitrary"},
        {"url": "https://example.test"},
        {"operation": "delete"},
        {"protocol": "unknown"},
    ],
)
def test_archive_service_rejects_worker_selected_authority(
    tmp_path: Path, extra: dict[str, object]
) -> None:
    root, _releases, body, record = _archived_source(tmp_path)
    job_id = _claimed(root)
    calls: list[dict[str, object]] = []
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
        _channel(sender) as channel,
    ):
        with (spool.workspace / "bundle.zip").open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            _request(channel, spool, job_id, output, **extra)
        future = pool.submit(_serve, receiver, root, _remote(body, record, calls))
        with pytest.raises(ArchiveRemoteError, match="export job"):
            future.result(timeout=5)
    assert not calls


@pytest.mark.parametrize("defect", ["issued", "wrong-bucket", "manifest-binding", "source-drift"])
def test_archive_service_rejects_missing_or_changed_durable_authority(
    tmp_path: Path, defect: str
) -> None:
    root, _releases, body, record = _archived_source(tmp_path)
    if defect == "issued":
        with StateRepository(root, expected_owner=_OWNER) as repository:
            job_id = _issue(repository)
    else:
        job_id = _claimed(root)
    if defect == "manifest-binding":
        record["manifestDigest"] = {
            **cast(dict[str, object], record["manifestDigest"]),
            "value": "a" * 64,
        }
        archive = next((root / "tenants").glob("*/archives/*.json"))
        archive.write_bytes(canonical_json_bytes(record))
    if defect == "source-drift":
        record["versionId"] = "another-version"
        archive = next((root / "tenants").glob("*/archives/*.json"))
        archive.write_bytes(canonical_json_bytes(record))
    calls: list[dict[str, object]] = []
    remote = _remote(body, record, calls)
    if defect == "wrong-bucket":
        remote = ArchiveRemoteStore(remote.client, bucket="another-archive-bucket")
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
        _channel(sender) as channel,
    ):
        with (spool.workspace / "bundle.zip").open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            _request(channel, spool, job_id, output)
        future = pool.submit(_serve, receiver, root, remote)
        with pytest.raises((ArchiveRemoteError, ContractError)):
            future.result(timeout=5)
    assert not calls


@pytest.mark.parametrize(
    "defect", ["outside", "nonempty", "offset", "readonly", "append", "mode", "hardlink", "symlink"]
)
def test_archive_service_writes_only_the_empty_private_spool_descriptor(
    tmp_path: Path, defect: str
) -> None:
    root, _releases, body, record = _archived_source(tmp_path)
    job_id = _claimed(root)
    calls: list[dict[str, object]] = []
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
        _channel(sender) as channel,
    ):
        path = spool.workspace / "bundle.zip"
        path.touch(mode=0o600)
        if defect == "outside":
            path = tmp_path / "outside"
            path.touch(mode=0o600)
        elif defect == "nonempty":
            path.write_bytes(b"existing")
        elif defect == "mode":
            path.chmod(0o644)
        elif defect == "hardlink":
            (tmp_path / "extra-link").hardlink_to(path)
        elif defect == "symlink":
            path.unlink()
            (tmp_path / "target").touch(mode=0o600)
            path.symlink_to(tmp_path / "target")
        with path.open(
            "rb" if defect == "readonly" else "ab" if defect == "append" else "r+b"
        ) as output:
            if defect == "offset":
                output.seek(1)
            _request(channel, spool, job_id, output)
            future = pool.submit(_serve, receiver, root, _remote(body, record, calls))
            with pytest.raises((ArchiveRemoteError, StatePathError)):
                future.result(timeout=5)
        # Deliberately invalid test fixtures must not reach ordinary cleanup.
        path.unlink()
    assert not calls


def test_client_refuses_to_lend_a_lease_under_an_inner_state_lock(tmp_path: Path) -> None:
    root, _releases, _body, record = _archived_source(tmp_path)
    job_id = _claimed(root)
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        spool.construction(),
        repository.transaction(mode=LockMode.SHARED),
        io.BytesIO() as output,
        pytest.raises(LockOrderError, match="inner host lock"),
    ):
        ArchiveExportClient(spool, connector=lambda: pytest.fail("must not connect")).read_archive(
            job_id, record, output
        )


def test_disconnected_worker_cannot_release_an_inflight_service_download(tmp_path: Path) -> None:
    root, _releases, body, record = _archived_source(tmp_path)
    job_id = _claimed(root)
    started, proceed = Event(), Event()

    class DelayedBody(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            started.set()
            assert proceed.wait(timeout=5)
            return super().read(size)

    stream_body = DelayedBody(body)
    remote = ArchiveRemoteStore(
        cast(
            ArchiveClient,
            SimpleNamespace(
                get_object=lambda **_kwargs: {
                    "Body": stream_body,
                    "VersionId": record["versionId"],
                    "ContentLength": len(body),
                    "Metadata": {
                        "sha256": cast(dict[str, object], record["bundleDigest"])["value"]
                    },
                }
            ),
        ),
        bucket=str(record["bucket"]),
    )
    sender, receiver = socket.socketpair()
    with (
        ThreadPoolExecutor() as pool,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        LockManager(root / "locks", expected_owner=_OWNER) as contender,
    ):
        future = pool.submit(_serve, receiver, root, remote)
        try:
            with (
                spool.construction(),
                _channel(sender) as channel,
                (spool.workspace / "bundle.zip").open("xb", buffering=0) as output,
            ):
                os.fchmod(output.fileno(), 0o600)
                _request(channel, spool, job_id, output)
                assert started.wait(timeout=5)
            with pytest.raises(StateBusyError), contender.acquire(LockName.EXPORT):
                pytest.fail("remote stream still owns export exclusion")
        finally:
            proceed.set()
        with pytest.raises((OSError, ArchiveTransportError)):
            future.result(timeout=5)
        assert stream_body.closed
        with contender.acquire(LockName.EXPORT):
            pass
