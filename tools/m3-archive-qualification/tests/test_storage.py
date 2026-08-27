from __future__ import annotations

import io
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, field

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import (
    ArchiveQualificationError,
    assert_storage_empty,
    list_current_objects,
    list_multipart_uploads,
    list_versions,
    purge_qualification_prefix,
    run_acceptance,
)

EXPECTED_PAGINATED_ENTRIES = 2


@dataclass(slots=True)
class StoredVersion:
    version_id: str
    body: bytes
    delete_marker: bool = False


@dataclass(slots=True)
class FakeBackend:
    objects: dict[str, dict[str, list[StoredVersion]]] = field(default_factory=dict)
    uploads: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    next_version: int = 1
    remote_calls: int = 0
    fail_at_call: int | None = None
    omit_next_version_marker: bool = False
    omit_is_truncated: bool = False
    invalid_is_truncated: object | None = None


class FakeS3Client:
    def __init__(
        self,
        backend: FakeBackend,
        allowed_buckets: set[str],
        *,
        write_buckets: set[str] | None = None,
        denial_code: str = "AccessDenied",
        denial_status: int = 403,
    ) -> None:
        self.backend = backend
        self.allowed_buckets = allowed_buckets
        self.write_buckets = write_buckets if write_buckets is not None else allowed_buckets
        self.denial_code = denial_code
        self.denial_status = denial_status
        self.corrupt_reads = False

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, object]:
        self._authorize(kwargs, "GetBucketVersioning")
        return {"Status": "Enabled"}

    def list_objects_v2(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "ListObjectsV2")
        prefix = _string_argument(kwargs, "Prefix")
        contents = []
        for key, versions in sorted(self.backend.objects.setdefault(bucket, {}).items()):
            if key.startswith(prefix) and versions and not versions[0].delete_marker:
                contents.append({"Key": key})
        start = int(str(kwargs.get("ContinuationToken", "0")))
        max_keys = kwargs.get("MaxKeys")
        assert isinstance(max_keys, int)
        page = contents[start : start + max_keys]
        truncated = start + len(page) < len(contents)
        response: dict[str, object] = {"Contents": page, "IsTruncated": truncated}
        self._alter_is_truncated(response)
        if truncated:
            response["NextContinuationToken"] = str(start + len(page))
        return response

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "ListObjectVersions")
        prefix = _string_argument(kwargs, "Prefix")
        flattened = [
            (key, version)
            for key, versions in sorted(self.backend.objects.setdefault(bucket, {}).items())
            if key.startswith(prefix)
            for version in versions
        ]
        key_marker = kwargs.get("KeyMarker")
        version_marker = kwargs.get("VersionIdMarker")
        start = 0
        if key_marker is not None or version_marker is not None:
            marker = (key_marker, version_marker)
            start = next(
                index + 1
                for index, (key, version) in enumerate(flattened)
                if (key, version.version_id) == marker
            )
        max_keys = kwargs.get("MaxKeys")
        assert isinstance(max_keys, int)
        page = flattened[start : start + max_keys]
        truncated = start + len(page) < len(flattened)
        response: dict[str, object] = {
            "Versions": [
                {"Key": key, "VersionId": version.version_id}
                for key, version in page
                if not version.delete_marker
            ],
            "DeleteMarkers": [
                {"Key": key, "VersionId": version.version_id}
                for key, version in page
                if version.delete_marker
            ],
            "IsTruncated": truncated,
        }
        self._alter_is_truncated(response)
        if truncated:
            response["NextKeyMarker"] = page[-1][0]
            if not self.backend.omit_next_version_marker:
                response["NextVersionIdMarker"] = page[-1][1].version_id
        return response

    def list_multipart_uploads(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "ListMultipartUploads")
        prefix = _string_argument(kwargs, "Prefix")
        uploads = [
            (key, upload_id)
            for key, upload_id in self.backend.uploads.setdefault(bucket, [])
            if key.startswith(prefix)
        ]
        key_marker = kwargs.get("KeyMarker")
        upload_marker = kwargs.get("UploadIdMarker")
        start = 0
        if key_marker is not None or upload_marker is not None:
            assert isinstance(key_marker, str)
            assert isinstance(upload_marker, str)
            marker = (key_marker, upload_marker)
            start = uploads.index(marker) + 1
        max_uploads = kwargs.get("MaxUploads")
        assert isinstance(max_uploads, int)
        page = uploads[start : start + max_uploads]
        truncated = start + len(page) < len(uploads)
        response: dict[str, object] = {
            "Uploads": [{"Key": key, "UploadId": upload_id} for key, upload_id in page],
            "IsTruncated": truncated,
        }
        self._alter_is_truncated(response)
        if truncated:
            response["NextKeyMarker"] = page[-1][0]
            response["NextUploadIdMarker"] = page[-1][1]
        return response

    def put_object(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "PutObject", write=True)
        key = _string_argument(kwargs, "Key")
        body = kwargs.get("Body")
        content_length = kwargs.get("ContentLength")
        assert isinstance(body, bytes)
        assert content_length == len(body)
        version_id = self._new_version_id()
        self.backend.objects.setdefault(bucket, {}).setdefault(key, []).insert(
            0, StoredVersion(version_id=version_id, body=body)
        )
        return {"VersionId": version_id}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "GetObject")
        key = _string_argument(kwargs, "Key")
        versions = self.backend.objects.setdefault(bucket, {}).get(key, [])
        requested_version = kwargs.get("VersionId")
        if requested_version is None:
            selected = versions[0] if versions else None
        else:
            selected = next(
                (version for version in versions if version.version_id == requested_version),
                None,
            )
        if selected is None or selected.delete_marker:
            raise _client_error("NoSuchKey", 404, "GetObject")
        body = b"corrupt" if self.corrupt_reads else selected.body
        return {"ContentLength": len(body), "Body": io.BytesIO(body)}

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "DeleteObject", write=True)
        key = _string_argument(kwargs, "Key")
        requested_version = kwargs.get("VersionId")
        versions = self.backend.objects.setdefault(bucket, {}).setdefault(key, [])
        if requested_version is None:
            marker_id = self._new_version_id()
            versions.insert(0, StoredVersion(marker_id, b"", delete_marker=True))
            return {"DeleteMarker": True, "VersionId": marker_id}
        assert isinstance(requested_version, str)
        versions[:] = [item for item in versions if item.version_id != requested_version]
        if not versions:
            del self.backend.objects[bucket][key]
        return {"VersionId": requested_version}

    def abort_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        bucket = self._authorize(kwargs, "AbortMultipartUpload", write=True)
        key = _string_argument(kwargs, "Key")
        upload_id = _string_argument(kwargs, "UploadId")
        uploads = self.backend.uploads.setdefault(bucket, [])
        uploads[:] = [item for item in uploads if item != (key, upload_id)]
        return {}

    def _authorize(
        self, kwargs: Mapping[str, object], operation: str, *, write: bool = False
    ) -> str:
        self.backend.remote_calls += 1
        if self.backend.remote_calls == self.backend.fail_at_call:
            raise _client_error("ServiceUnavailable", 503, operation)
        bucket = _string_argument(kwargs, "Bucket")
        allowed = self.write_buckets if write else self.allowed_buckets
        if bucket not in allowed:
            raise _client_error(self.denial_code, self.denial_status, operation)
        return bucket

    def _new_version_id(self) -> str:
        value = f"version-{self.backend.next_version}"
        self.backend.next_version += 1
        return value

    def _alter_is_truncated(self, response: dict[str, object]) -> None:
        if self.backend.omit_is_truncated:
            del response["IsTruncated"]
        elif self.backend.invalid_is_truncated is not None:
            response["IsTruncated"] = self.backend.invalid_is_truncated


def test_acceptance_proves_isolation_pagination_and_cleanup() -> None:
    backend = FakeBackend()
    backup = FakeS3Client(backend, {"backups"})
    archive = FakeS3Client(backend, {"archives"})

    evidence = run_acceptance(
        backup_client=backup,
        archive_client=archive,
        backup_bucket="backups",
        archive_bucket="archives",
    )

    assert all(asdict(evidence).values())
    assert backend.objects == {"backups": {}, "archives": {}}


def test_acceptance_cleans_both_prefixes_after_read_failure() -> None:
    backend = FakeBackend()
    backup = FakeS3Client(backend, {"backups"})
    archive = FakeS3Client(backend, {"archives"})
    archive.corrupt_reads = True

    with pytest.raises(ArchiveQualificationError, match="exact-version"):
        run_acceptance(
            backup_client=backup,
            archive_client=archive,
            backup_bucket="backups",
            archive_bucket="archives",
        )

    assert backend.objects == {"backups": {}, "archives": {}}


def test_acceptance_cleans_after_every_remote_failure_point() -> None:
    baseline_backend = FakeBackend()
    run_acceptance(
        backup_client=FakeS3Client(baseline_backend, {"backups"}),
        archive_client=FakeS3Client(baseline_backend, {"archives"}),
        backup_bucket="backups",
        archive_bucket="archives",
    )

    for failure_point in range(1, baseline_backend.remote_calls + 1):
        backend = FakeBackend(fail_at_call=failure_point)
        with suppress(ArchiveQualificationError, ClientError):
            run_acceptance(
                backup_client=FakeS3Client(backend, {"backups"}),
                archive_client=FakeS3Client(backend, {"archives"}),
                backup_bucket="backups",
                archive_bucket="archives",
            )
        assert all(not objects for objects in backend.objects.values())
        assert all(not uploads for uploads in backend.uploads.values())


def test_acceptance_rejects_the_wrong_cross_bucket_error() -> None:
    backend = FakeBackend()

    with pytest.raises(ArchiveQualificationError, match="unexpected error class"):
        run_acceptance(
            backup_client=FakeS3Client(
                backend,
                {"backups"},
                denial_code="NoSuchBucket",
                denial_status=404,
            ),
            archive_client=FakeS3Client(backend, {"archives"}),
            backup_bucket="backups",
            archive_bucket="archives",
        )

    assert all(not objects for objects in backend.objects.values())


def test_acceptance_permanently_deletes_an_unexpected_cross_bucket_write() -> None:
    backend = FakeBackend()

    with pytest.raises(ArchiveQualificationError, match="cross-bucket write"):
        run_acceptance(
            backup_client=FakeS3Client(
                backend,
                {"backups"},
                write_buckets={"backups", "archives"},
            ),
            archive_client=FakeS3Client(backend, {"archives"}),
            backup_bucket="backups",
            archive_bucket="archives",
        )

    assert all(not objects for objects in backend.objects.values())


def test_preflight_rejects_current_versions_and_markers() -> None:
    backend = FakeBackend()
    client = FakeS3Client(backend, {"backups"})
    client.put_object(Bucket="backups", Key="archives/probe", Body=b"x", ContentLength=1)

    with pytest.raises(ArchiveQualificationError, match="current objects"):
        assert_storage_empty(client, bucket="backups", prefix="archives/")


def test_preflight_rejects_incomplete_multipart_uploads() -> None:
    backend = FakeBackend(uploads={"backups": [("archives/probe", "upload-1")]})
    client = FakeS3Client(backend, {"backups"})

    with pytest.raises(ArchiveQualificationError, match="multipart uploads"):
        assert_storage_empty(client, bucket="backups", prefix="archives/")


def test_preflight_rejects_delete_marker_without_a_current_object() -> None:
    backend = FakeBackend()
    client = FakeS3Client(backend, {"backups"})
    client.put_object(Bucket="backups", Key="archives/probe", Body=b"x", ContentLength=1)
    client.delete_object(Bucket="backups", Key="archives/probe")

    with pytest.raises(ArchiveQualificationError, match="versions or delete markers"):
        assert_storage_empty(client, bucket="backups", prefix="archives/")


def test_preflight_rejects_a_null_version() -> None:
    backend = FakeBackend(
        objects={
            "backups": {
                "archives/legacy": [
                    StoredVersion("marker", b"", delete_marker=True),
                    StoredVersion("null", b"legacy"),
                ]
            }
        }
    )
    client = FakeS3Client(backend, {"backups"})

    with pytest.raises(ArchiveQualificationError, match="versions or delete markers"):
        assert_storage_empty(client, bucket="backups", prefix="archives/")


def test_qualification_cleanup_removes_versions_markers_and_uploads() -> None:
    backend = FakeBackend()
    client = FakeS3Client(backend, {"archives"})
    prefix = "m3-1-qualification/test-run/"
    key = f"{prefix}probe"
    client.put_object(Bucket="archives", Key=key, Body=b"x", ContentLength=1)
    client.delete_object(Bucket="archives", Key=key)
    backend.uploads["archives"] = [(f"{prefix}multipart", "upload-1")]

    purge_qualification_prefix(client, bucket="archives", prefix=prefix)

    assert_storage_empty(client, bucket="archives", prefix=prefix)


def test_forced_listing_exercises_both_continuation_markers() -> None:
    backend = FakeBackend()
    client = FakeS3Client(backend, {"archives"})
    response = client.put_object(Bucket="archives", Key="probe/object", Body=b"x", ContentLength=1)
    assert isinstance(response["VersionId"], str)
    client.delete_object(Bucket="archives", Key="probe/object")

    listing = list_versions(client, bucket="archives", prefix="probe/", max_keys=1)

    assert listing.pages == EXPECTED_PAGINATED_ENTRIES
    assert len(listing.entries) == EXPECTED_PAGINATED_ENTRIES
    assert len(listing.continuation_pairs) == 1
    assert all(
        key_marker and version_marker for key_marker, version_marker in listing.continuation_pairs
    )


def test_every_accounting_view_follows_pagination() -> None:
    entry_count = 1_001
    backend = FakeBackend(
        objects={
            "archives": {
                f"probe/object-{index:04}": [StoredVersion(f"version-{index}", b"x")]
                for index in range(entry_count)
            }
        },
        uploads={
            "archives": [
                (f"probe/upload-{index:04}", f"upload-{index}") for index in range(entry_count)
            ]
        },
    )
    client = FakeS3Client(backend, {"archives"})

    assert len(list_current_objects(client, bucket="archives", prefix="probe/")) == entry_count
    assert len(list_versions(client, bucket="archives", prefix="probe/").entries) == entry_count
    multipart = list_multipart_uploads(client, bucket="archives", prefix="probe/")
    assert len(multipart.uploads) == entry_count
    assert multipart.pages == EXPECTED_PAGINATED_ENTRIES


def test_version_pagination_rejects_a_missing_continuation_marker() -> None:
    backend = FakeBackend(omit_next_version_marker=True)
    client = FakeS3Client(backend, {"archives"})
    client.put_object(Bucket="archives", Key="probe/object", Body=b"x", ContentLength=1)
    client.delete_object(Bucket="archives", Key="probe/object")

    with pytest.raises(ArchiveQualificationError, match="NextVersionIdMarker"):
        list_versions(client, bucket="archives", prefix="probe/", max_keys=1)


@pytest.mark.parametrize(
    "listing",
    [
        lambda client: list_current_objects(client, bucket="archives", prefix="probe/"),
        lambda client: list_versions(client, bucket="archives", prefix="probe/"),
        lambda client: list_multipart_uploads(client, bucket="archives", prefix="probe/"),
    ],
)
@pytest.mark.parametrize(
    ("omit_is_truncated", "invalid_is_truncated", "message"),
    [
        (True, None, "IsTruncated is missing"),
        (False, 0, "IsTruncated is not boolean"),
    ],
)
def test_every_listing_rejects_an_ambiguous_truncation_flag(
    listing: Callable[[FakeS3Client], object],
    omit_is_truncated: bool,
    invalid_is_truncated: object | None,
    message: str,
) -> None:
    backend = FakeBackend(
        omit_is_truncated=omit_is_truncated,
        invalid_is_truncated=invalid_is_truncated,
    )
    client = FakeS3Client(backend, {"archives"})

    with pytest.raises(ArchiveQualificationError, match=message):
        listing(client)


def _string_argument(arguments: Mapping[str, object], name: str) -> str:
    value = arguments.get(name)
    assert isinstance(value, str)
    return value


def _client_error(code: str, status: int, operation: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )
