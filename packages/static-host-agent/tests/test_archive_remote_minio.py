"""Exercise the production low-level boundary against disposable versioned S3."""

from __future__ import annotations

import hashlib
import io
import os
import uuid
from collections.abc import Mapping
from typing import Protocol, cast

import pytest
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.session import Session  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent import archive_remote
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveCapacityError,
    ArchiveClient,
    ArchiveRemoteError,
    ArchiveRemoteStore,
    archive_key,
    make_archive_client,
)

pytestmark = pytest.mark.minio


class MinioAdmin(ArchiveClient, Protocol):
    def create_bucket(self, **kwargs: object) -> Mapping[str, object]: ...

    def put_bucket_versioning(self, **kwargs: object) -> Mapping[str, object]: ...

    def delete_bucket(self, **kwargs: object) -> Mapping[str, object]: ...

    def create_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...

    def abort_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...


def _clients(monkeypatch: pytest.MonkeyPatch) -> tuple[ArchiveClient, MinioAdmin]:
    endpoint = os.environ.get("M3_ARCHIVE_MINIO_ENDPOINT")
    access = os.environ.get("M3_ARCHIVE_MINIO_ACCESS_KEY")
    secret = os.environ.get("M3_ARCHIVE_MINIO_SECRET_KEY")
    if not endpoint or not access or not secret:
        pytest.skip("pinned MinIO endpoint is not configured")
    session = Session()
    create = session.create_client
    administrator = create(
        "s3",
        region_name="us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, proxies={}),
    )

    def local_client(service: str, **kwargs: object) -> object:
        assert kwargs["endpoint_url"] == "https://nyc3.digitaloceanspaces.com"
        kwargs["endpoint_url"] = endpoint
        return create(service, **kwargs)

    # Only the transport endpoint changes; production SDK configuration,
    # explicit credentials, request shapes, checksums, and retry policy remain.
    monkeypatch.setattr(session, "create_client", local_client)
    monkeypatch.setattr(archive_remote, "Session", lambda: session)
    client = make_archive_client(region="nyc3", access_key_id=access, secret_access_key=secret)
    return client, cast(MinioAdmin, administrator)


def _lost_commit_responses(
    remote: ArchiveRemoteStore, monkeypatch: pytest.MonkeyPatch, body: bytes, digest: str
) -> None:
    key = archive_key(str(uuid.uuid7()))
    put = remote.client.put_object
    calls = 0

    def committed_put(**arguments: object) -> Mapping[str, object]:
        nonlocal calls
        calls += 1
        put(**arguments)
        raise OSError("lost successful provider upload response")

    with monkeypatch.context() as fault:
        fault.setattr(remote.client, "put_object", committed_put)
        with pytest.raises(OSError, match="lost successful"):
            remote.put_once(key, io.BytesIO(body), size=len(body), sha256=digest)
    assert calls == 1
    discovered = remote.list_versions(exact_key=key)
    assert len(discovered) == 1
    remote.read_verified(key, discovered[0].version_id, size=len(body), sha256=digest)
    with pytest.raises(ArchiveRemoteError):
        remote.inventory().require_reservation(frozenset())

    delete = remote.client.delete_object
    deleted: list[object] = []

    def committed_delete(**arguments: object) -> Mapping[str, object]:
        deleted.append(arguments["VersionId"])
        delete(**arguments)
        raise OSError("lost successful provider deletion response")

    with monkeypatch.context() as fault:
        fault.setattr(remote.client, "delete_object", committed_delete)
        with pytest.raises(OSError, match="lost successful"):
            remote.purge_unbound(key, require_unbound=lambda _key: None)
    # Recovery relists actual provider state after the ambiguous response.
    # It never uploads again and never needs an unversioned delete.
    remote.purge_unbound(key, require_unbound=lambda _key: None)
    remote.require_absent(key)
    assert deleted == [discovered[0].version_id]


def _real_inventory_capacity(remote: ArchiveRemoteStore) -> None:
    body = b"bounded real inventory quota proof"
    digest = hashlib.sha256(body).hexdigest()
    keys = [archive_key(str(uuid.uuid7())) for _ in range(archive_remote.MAX_REMOTE_KEYS)]
    try:
        for key in keys:
            inventory = remote.inventory()
            inventory.require_reservation(frozenset(inventory.versions))
            remote.put_once(key, io.BytesIO(body), size=len(body), sha256=digest)
        inventory = remote.inventory()
        with pytest.raises(ArchiveCapacityError):
            inventory.require_reservation(frozenset(inventory.versions))
    finally:
        for key in keys:
            remote.purge_unbound(key, require_unbound=lambda _key: None)
    assert not remote.inventory().versions


def test_installed_remote_boundary_versions_markers_pagination_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, administrator = _clients(monkeypatch)
    bucket = f"m3-10-archive-ci-{uuid.uuid4().hex}"
    key = archive_key(str(uuid.uuid7()))
    body = b"exact remote bundle bytes\n" * 5000
    digest = hashlib.sha256(body).hexdigest()
    administrator.create_bucket(Bucket=bucket)
    administrator.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )
    remote = ArchiveRemoteStore(client, bucket=bucket)
    upload_id: str | None = None
    try:
        _lost_commit_responses(remote, monkeypatch, body, digest)
        _real_inventory_capacity(remote)
        remote.inventory().require_reservation(frozenset())
        remote.require_absent(key)
        version = remote.put_once(key, io.BytesIO(body), size=len(body), sha256=digest)
        downloaded = io.BytesIO()
        remote.read_verified(key, version, size=len(body), sha256=digest, destination=downloaded)
        assert downloaded.getvalue() == body
        assert len(remote.inventory().versions) == 1
        # Deliberately create a marker using the test administrator, never the
        # managed writer. The bound version must remain readable beneath it.
        marker = administrator.delete_object(Bucket=bucket, Key=key)
        assert marker["DeleteMarker"] is True
        monkeypatch.setattr(archive_remote, "_PAGE_SIZE", 1)
        inventory = remote.inventory()
        assert {entry.version_id for entry in inventory.versions} == {version, marker["VersionId"]}
        assert any(entry.delete_marker for entry in inventory.versions)
        with pytest.raises(ArchiveRemoteError):
            inventory.require_reservation(frozenset())
        remote.read_verified(key, version, size=len(body), sha256=digest)

        def bound(_key: str) -> None:
            raise ArchiveRemoteError("authoritative state still binds this object")

        with pytest.raises(ArchiveRemoteError):
            remote.purge_unbound(key, require_unbound=bound)
        assert remote.list_versions(exact_key=key)
        remote.purge_unbound(key, require_unbound=lambda _key: None)
        remote.require_absent(key)
        assert not remote.inventory().versions
        with pytest.raises(ArchiveRemoteError, match="not permitted"):
            cast(MinioAdmin, client).create_multipart_upload(Bucket=bucket, Key=key)
        assert not remote.inventory().multipart_uploads
        upload_id = str(administrator.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"])
        with pytest.raises(ArchiveRemoteError):
            remote.inventory().require_reservation(frozenset())
    finally:
        if upload_id is not None:
            administrator.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        for entry in remote.list_versions():
            administrator.delete_object(Bucket=bucket, Key=entry.key, VersionId=entry.version_id)
        remote.inventory().require_reservation(frozenset())
        administrator.delete_bucket(Bucket=bucket)
