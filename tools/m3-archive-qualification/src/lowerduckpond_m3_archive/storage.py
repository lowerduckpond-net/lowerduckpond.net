"""Exact, low-level S3 operations for the M3.1 archive storage gate."""

from __future__ import annotations

import io
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

import botocore.session  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

MAX_LIST_PAGES = 10_000
LIST_PAGE_SIZE = 1_000
QUALIFICATION_BODY = b"lowerduckpond-m3.1-archive-qualification\n"
EXPECTED_PAGINATED_ENTRIES = 2
REQUIRED_S3_OPERATIONS = {
    "AbortMultipartUpload",
    "DeleteObject",
    "GetBucketVersioning",
    "GetObject",
    "ListMultipartUploads",
    "ListObjectsV2",
    "ListObjectVersions",
    "PutObject",
}


class ArchiveQualificationError(RuntimeError):
    """Raised when a storage response violates the M3.1 contract."""


class S3Client(Protocol):
    """The exact low-level client surface used by the qualification."""

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, object]: ...

    def list_objects_v2(self, **kwargs: object) -> dict[str, object]: ...

    def list_object_versions(self, **kwargs: object) -> dict[str, object]: ...

    def list_multipart_uploads(self, **kwargs: object) -> dict[str, object]: ...

    def put_object(self, **kwargs: object) -> dict[str, object]: ...

    def get_object(self, **kwargs: object) -> dict[str, object]: ...

    def delete_object(self, **kwargs: object) -> dict[str, object]: ...

    def abort_multipart_upload(self, **kwargs: object) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class VersionEntry:
    kind: str
    key: str
    version_id: str


@dataclass(frozen=True, slots=True)
class VersionListing:
    entries: tuple[VersionEntry, ...]
    pages: int
    continuation_pairs: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class MultipartUpload:
    key: str
    upload_id: str


@dataclass(frozen=True, slots=True)
class MultipartListing:
    uploads: tuple[MultipartUpload, ...]
    pages: int


@dataclass(frozen=True, slots=True)
class AcceptanceEvidence:
    buckets_versioned: bool
    credential_isolation: bool
    exact_version_read: bool
    delete_marker: bool
    forced_pagination: bool
    empty_archive_baseline: bool
    cleanup_complete: bool


def create_client(
    *, access_key_id: str, secret_access_key: str, region: str, endpoint_url: str
) -> S3Client:
    """Create a path-style SigV4 client without ambient credential discovery."""
    if not access_key_id or not secret_access_key:
        raise ArchiveQualificationError("Spaces credentials are missing")
    session = botocore.session.get_session()
    client = session.create_client(
        "s3",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region,
        endpoint_url=endpoint_url,
        config=Config(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "standard"},
            s3={"addressing_style": "path"},
        ),
    )
    missing_operations = REQUIRED_S3_OPERATIONS - set(client.meta.service_model.operation_names)
    if missing_operations:
        raise ArchiveQualificationError("the locked S3 client lacks required operations")
    return cast(S3Client, client)


def assert_versioning_enabled(client: S3Client, *, bucket: str) -> None:
    response = client.get_bucket_versioning(Bucket=bucket)
    if response.get("Status") != "Enabled":
        raise ArchiveQualificationError("bucket versioning is not enabled")


def list_current_objects(client: S3Client, *, bucket: str, prefix: str) -> tuple[str, ...]:
    keys: list[str] = []
    continuation_token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(MAX_LIST_PAGES):
        request: dict[str, object] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxKeys": LIST_PAGE_SIZE,
        }
        if continuation_token is not None:
            request["ContinuationToken"] = continuation_token
        response = client.list_objects_v2(**request)
        for item in _mapping_list(response, "Contents"):
            key = _required_string(item, "Key")
            _require_prefix(key, prefix)
            keys.append(key)
        if not _is_truncated(response):
            return tuple(keys)
        continuation_token = _required_string(response, "NextContinuationToken")
        if continuation_token in seen_tokens:
            raise ArchiveQualificationError("object listing repeated a continuation token")
        seen_tokens.add(continuation_token)
    raise ArchiveQualificationError("object listing exceeded its page bound")


def list_versions(
    client: S3Client,
    *,
    bucket: str,
    prefix: str,
    max_keys: int = LIST_PAGE_SIZE,
) -> VersionListing:
    entries: list[VersionEntry] = []
    continuations: list[tuple[str, str]] = []
    key_marker: str | None = None
    version_marker: str | None = None
    seen_markers: set[tuple[str, str]] = set()
    for page_index in range(1, MAX_LIST_PAGES + 1):
        request: dict[str, object] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxKeys": max_keys,
        }
        if key_marker is not None and version_marker is not None:
            request["KeyMarker"] = key_marker
            request["VersionIdMarker"] = version_marker
        response = client.list_object_versions(**request)
        for kind, response_key in (("version", "Versions"), ("delete-marker", "DeleteMarkers")):
            for item in _mapping_list(response, response_key):
                key = _required_string(item, "Key")
                _require_prefix(key, prefix)
                entries.append(
                    VersionEntry(
                        kind=kind,
                        key=key,
                        version_id=_required_string(item, "VersionId"),
                    )
                )
        if not _is_truncated(response):
            return VersionListing(tuple(entries), page_index, tuple(continuations))
        key_marker = _required_string(response, "NextKeyMarker")
        version_marker = _required_string(response, "NextVersionIdMarker")
        marker_pair = (key_marker, version_marker)
        if marker_pair in seen_markers:
            raise ArchiveQualificationError("version listing repeated continuation markers")
        seen_markers.add(marker_pair)
        continuations.append(marker_pair)
    raise ArchiveQualificationError("version listing exceeded its page bound")


def list_multipart_uploads(client: S3Client, *, bucket: str, prefix: str) -> MultipartListing:
    uploads: list[MultipartUpload] = []
    key_marker: str | None = None
    upload_marker: str | None = None
    seen_markers: set[tuple[str, str]] = set()
    for page_index in range(1, MAX_LIST_PAGES + 1):
        request: dict[str, object] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxUploads": LIST_PAGE_SIZE,
        }
        if key_marker is not None and upload_marker is not None:
            request["KeyMarker"] = key_marker
            request["UploadIdMarker"] = upload_marker
        response = client.list_multipart_uploads(**request)
        for item in _mapping_list(response, "Uploads"):
            key = _required_string(item, "Key")
            _require_prefix(key, prefix)
            uploads.append(MultipartUpload(key=key, upload_id=_required_string(item, "UploadId")))
        if not _is_truncated(response):
            return MultipartListing(tuple(uploads), page_index)
        key_marker = _required_string(response, "NextKeyMarker")
        upload_marker = _required_string(response, "NextUploadIdMarker")
        marker_pair = (key_marker, upload_marker)
        if marker_pair in seen_markers:
            raise ArchiveQualificationError("multipart listing repeated continuation markers")
        seen_markers.add(marker_pair)
    raise ArchiveQualificationError("multipart listing exceeded its page bound")


def assert_storage_empty(client: S3Client, *, bucket: str, prefix: str = "") -> None:
    """Prove all three relevant S3 accounting views are empty."""
    assert_versioning_enabled(client, bucket=bucket)
    if list_current_objects(client, bucket=bucket, prefix=prefix):
        raise ArchiveQualificationError("current objects exist inside the required empty boundary")
    if list_versions(client, bucket=bucket, prefix=prefix).entries:
        raise ArchiveQualificationError("versions or delete markers exist inside the boundary")
    if list_multipart_uploads(client, bucket=bucket, prefix=prefix).uploads:
        raise ArchiveQualificationError("multipart uploads exist inside the boundary")


def purge_qualification_prefix(client: S3Client, *, bucket: str, prefix: str) -> None:
    """Purge only an explicitly namespaced M3.1 qualification prefix."""
    if not prefix.startswith("m3-1-qualification/") or not prefix.endswith("/"):
        raise ArchiveQualificationError("cleanup prefix is outside the qualification namespace")
    _purge_prefix(client, bucket=bucket, prefix=prefix)
    assert_storage_empty(client, bucket=bucket, prefix=prefix)


def run_acceptance(
    *,
    backup_client: S3Client,
    archive_client: S3Client,
    backup_bucket: str,
    archive_bucket: str,
) -> AcceptanceEvidence:
    """Exercise isolation, exact versions, forced pagination, and complete cleanup."""
    if backup_bucket == archive_bucket:
        raise ArchiveQualificationError("backup and archive buckets must be distinct")
    assert_versioning_enabled(backup_client, bucket=backup_bucket)
    assert_storage_empty(archive_client, bucket=archive_bucket)
    qualification_prefix = f"m3-1-qualification/{uuid.uuid7()}/"
    backup_key = f"{qualification_prefix}backup-owner"
    archive_key = f"{qualification_prefix}archive-owner"
    try:
        backup_version = _put_exact(backup_client, bucket=backup_bucket, key=backup_key)
        archive_version = _put_exact(archive_client, bucket=archive_bucket, key=archive_key)
        _assert_exact_read(
            backup_client, bucket=backup_bucket, key=backup_key, version_id=backup_version
        )
        _assert_exact_read(
            archive_client, bucket=archive_bucket, key=archive_key, version_id=archive_version
        )

        _assert_cross_bucket_denial(
            source=backup_client,
            target_owner=archive_client,
            target_bucket=archive_bucket,
            existing_key=archive_key,
            write_key=f"{qualification_prefix}backup-to-archive",
        )
        _assert_cross_bucket_denial(
            source=archive_client,
            target_owner=backup_client,
            target_bucket=backup_bucket,
            existing_key=backup_key,
            write_key=f"{qualification_prefix}archive-to-backup",
        )

        delete_response = archive_client.delete_object(Bucket=archive_bucket, Key=archive_key)
        if delete_response.get("DeleteMarker") is not True:
            raise ArchiveQualificationError("unversioned delete did not create a delete marker")
        marker_version = _nonnull_version_id(delete_response)
        _expect_error_code(
            lambda: archive_client.get_object(Bucket=archive_bucket, Key=archive_key),
            expected_code="NoSuchKey",
            expected_status=404,
        )
        _assert_exact_read(
            archive_client,
            bucket=archive_bucket,
            key=archive_key,
            version_id=archive_version,
        )

        paginated = list_versions(
            archive_client,
            bucket=archive_bucket,
            prefix=qualification_prefix,
            max_keys=1,
        )
        expected_entries = {
            ("version", archive_key, archive_version),
            ("delete-marker", archive_key, marker_version),
        }
        observed_entries = {
            (entry.kind, entry.key, entry.version_id) for entry in paginated.entries
        }
        if (
            len(paginated.entries) != EXPECTED_PAGINATED_ENTRIES
            or observed_entries != expected_entries
            or paginated.pages != EXPECTED_PAGINATED_ENTRIES
            or len(paginated.continuation_pairs) != 1
        ):
            raise ArchiveQualificationError("forced version pagination did not bind both entries")

        _delete_version(
            archive_client,
            bucket=archive_bucket,
            key=archive_key,
            version_id=archive_version,
        )
        _delete_version(
            archive_client,
            bucket=archive_bucket,
            key=archive_key,
            version_id=marker_version,
        )
        _delete_version(
            backup_client,
            bucket=backup_bucket,
            key=backup_key,
            version_id=backup_version,
        )
        assert_storage_empty(archive_client, bucket=archive_bucket)
        assert_storage_empty(backup_client, bucket=backup_bucket, prefix=qualification_prefix)
        return AcceptanceEvidence(
            buckets_versioned=True,
            credential_isolation=True,
            exact_version_read=True,
            delete_marker=True,
            forced_pagination=True,
            empty_archive_baseline=True,
            cleanup_complete=True,
        )
    finally:
        _cleanup_acceptance_prefixes(
            (
                (archive_client, archive_bucket),
                (backup_client, backup_bucket),
            ),
            prefix=qualification_prefix,
        )


def _cleanup_acceptance_prefixes(targets: tuple[tuple[S3Client, str], ...], *, prefix: str) -> None:
    """Attempt and prove every bucket cleanup even when one target errors."""
    cleanup_errors: list[Exception] = []
    for client, bucket in targets:
        last_error: Exception | None = None
        for _ in range(2):
            try:
                purge_qualification_prefix(client, bucket=bucket, prefix=prefix)
            except Exception as error:
                last_error = error
                continue
            last_error = None
            break
        if last_error is not None:
            cleanup_errors.append(last_error)
    if cleanup_errors:
        raise ArchiveQualificationError(
            "qualification cleanup could not prove every prefix absent"
        ) from cleanup_errors[0]


def _assert_cross_bucket_denial(
    *,
    source: S3Client,
    target_owner: S3Client,
    target_bucket: str,
    existing_key: str,
    write_key: str,
) -> None:
    _expect_error_code(
        lambda: source.list_objects_v2(Bucket=target_bucket, Prefix=write_key, MaxKeys=1),
        expected_code="AccessDenied",
        expected_status=403,
    )
    _expect_error_code(
        lambda: source.get_object(Bucket=target_bucket, Key=existing_key),
        expected_code="AccessDenied",
        expected_status=403,
    )
    try:
        response = source.put_object(
            Bucket=target_bucket,
            Key=write_key,
            Body=QUALIFICATION_BODY,
            ContentLength=len(QUALIFICATION_BODY),
        )
    except ClientError as error:
        _require_client_error(error, expected_code="AccessDenied", expected_status=403)
        return
    unexpected_version = _nonnull_version_id(response)
    _delete_version(
        target_owner,
        bucket=target_bucket,
        key=write_key,
        version_id=unexpected_version,
    )
    assert_storage_empty(target_owner, bucket=target_bucket, prefix=write_key)
    raise ArchiveQualificationError("cross-bucket write unexpectedly succeeded")


def _put_exact(client: S3Client, *, bucket: str, key: str) -> str:
    response = client.put_object(
        Bucket=bucket,
        Key=key,
        Body=QUALIFICATION_BODY,
        ContentLength=len(QUALIFICATION_BODY),
    )
    return _nonnull_version_id(response)


def _assert_exact_read(client: S3Client, *, bucket: str, key: str, version_id: str) -> None:
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    if response.get("ContentLength") != len(QUALIFICATION_BODY):
        raise ArchiveQualificationError("exact-version length does not match")
    body = response.get("Body")
    if not hasattr(body, "read"):
        raise ArchiveQualificationError("exact-version response body is not readable")
    stream = cast(io.BufferedIOBase, body)
    try:
        observed = stream.read(len(QUALIFICATION_BODY) + 1)
    finally:
        stream.close()
    if observed != QUALIFICATION_BODY:
        raise ArchiveQualificationError("exact-version bytes do not match")


def _delete_version(client: S3Client, *, bucket: str, key: str, version_id: str) -> None:
    response = client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    returned_version = response.get("VersionId")
    if returned_version is not None and returned_version != version_id:
        raise ArchiveQualificationError("version delete returned a different version ID")


def _purge_prefix(client: S3Client, *, bucket: str, prefix: str) -> None:
    """Best-effort exact cleanup used on every terminal acceptance path."""
    for _ in range(3):
        uploads = list_multipart_uploads(client, bucket=bucket, prefix=prefix).uploads
        for upload in uploads:
            client.abort_multipart_upload(
                Bucket=bucket,
                Key=upload.key,
                UploadId=upload.upload_id,
            )
        entries = list_versions(client, bucket=bucket, prefix=prefix).entries
        for entry in entries:
            _delete_version(
                client,
                bucket=bucket,
                key=entry.key,
                version_id=entry.version_id,
            )
        if not uploads and not entries:
            return
    if (
        list_multipart_uploads(client, bucket=bucket, prefix=prefix).uploads
        or list_versions(client, bucket=bucket, prefix=prefix).entries
    ):
        raise ArchiveQualificationError("qualification cleanup could not prove absence")


def _expect_error_code(
    operation: Callable[[], object], *, expected_code: str, expected_status: int
) -> None:
    try:
        operation()
    except ClientError as error:
        _require_client_error(error, expected_code=expected_code, expected_status=expected_status)
        return
    raise ArchiveQualificationError("operation unexpectedly succeeded")


def _require_client_error(error: ClientError, *, expected_code: str, expected_status: int) -> None:
    response = error.response
    code = response.get("Error", {}).get("Code")
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    if code != expected_code or status != expected_status:
        raise ArchiveQualificationError(
            "S3 operation returned an unexpected error class"
        ) from error


def _nonnull_version_id(response: Mapping[str, object]) -> str:
    version_id = response.get("VersionId")
    if not isinstance(version_id, str) or not version_id or version_id == "null":
        raise ArchiveQualificationError("S3 operation did not return a non-null version ID")
    return version_id


def _mapping_list(response: Mapping[str, object], key: str) -> tuple[Mapping[str, object], ...]:
    value = response.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ArchiveQualificationError(f"{key} is not a valid response list")
    return tuple(cast(Mapping[str, object], item) for item in value)


def _required_string(response: Mapping[str, object], key: str) -> str:
    value = response.get(key)
    if not isinstance(value, str) or not value:
        raise ArchiveQualificationError(f"{key} is missing from the S3 response")
    return value


def _is_truncated(response: Mapping[str, object]) -> bool:
    if "IsTruncated" not in response:
        raise ArchiveQualificationError("IsTruncated is missing from the S3 response")
    value = response["IsTruncated"]
    if not isinstance(value, bool):
        raise ArchiveQualificationError("IsTruncated is not boolean")
    return value


def _require_prefix(key: str, prefix: str) -> None:
    if not key.startswith(prefix):
        raise ArchiveQualificationError("S3 listing escaped the requested prefix")
