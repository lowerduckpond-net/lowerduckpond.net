from __future__ import annotations

import os
import uuid
from typing import Protocol, cast

import pytest
from lowerduckpond_m3_archive.storage import (
    S3Client,
    assert_storage_empty,
    create_client,
    list_multipart_uploads,
    list_versions,
)

pytestmark = pytest.mark.minio
EXPECTED_VERSION_ENTRIES = 2


class MinioAdminClient(S3Client, Protocol):
    def create_bucket(self, **kwargs: object) -> dict[str, object]: ...

    def put_bucket_versioning(self, **kwargs: object) -> dict[str, object]: ...

    def create_multipart_upload(self, **kwargs: object) -> dict[str, object]: ...

    def upload_part(self, **kwargs: object) -> dict[str, object]: ...

    def delete_bucket(self, **kwargs: object) -> dict[str, object]: ...


def test_pinned_minio_exercises_versions_markers_pagination_and_multipart() -> None:
    endpoint = os.environ.get("M3_ARCHIVE_MINIO_ENDPOINT")
    access_key = os.environ.get("M3_ARCHIVE_MINIO_ACCESS_KEY")
    secret_key = os.environ.get("M3_ARCHIVE_MINIO_SECRET_KEY")
    if not endpoint or not access_key or not secret_key:
        pytest.skip("pinned MinIO endpoint is not configured")
    protocol_client = create_client(
        access_key_id=access_key,
        secret_access_key=secret_key,
        region="us-east-1",
        endpoint_url=endpoint,
    )
    client = cast(MinioAdminClient, protocol_client)
    bucket = f"m3-archive-ci-{uuid.uuid4().hex}"
    prefix = "m3-1-qualification/minio/"
    key = f"{prefix}versioned"
    upload_key = f"{prefix}multipart"
    client.create_bucket(Bucket=bucket)
    client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    try:
        assert_storage_empty(protocol_client, bucket=bucket)
        put_response = client.put_object(Bucket=bucket, Key=key, Body=b"minio", ContentLength=5)
        version_id = put_response["VersionId"]
        delete_response = client.delete_object(Bucket=bucket, Key=key)
        marker_id = delete_response["VersionId"]

        listing = list_versions(protocol_client, bucket=bucket, prefix=prefix, max_keys=1)
        assert listing.pages == EXPECTED_VERSION_ENTRIES
        assert {(item.kind, item.version_id) for item in listing.entries} == {
            ("version", version_id),
            ("delete-marker", marker_id),
        }
        assert len(listing.continuation_pairs) == 1

        upload = client.create_multipart_upload(Bucket=bucket, Key=upload_key)
        upload_id = upload["UploadId"]
        client.upload_part(
            Bucket=bucket,
            Key=upload_key,
            UploadId=upload_id,
            PartNumber=1,
            Body=b"multipart-probe",
            ContentLength=len(b"multipart-probe"),
        )
        # The final open-source MinIO release intentionally supports only an
        # empty or exact-object multipart prefix. Fake-client tests cover the
        # ordinary S3 prefix contract; this still exercises the live XML shape.
        assert list_multipart_uploads(protocol_client, bucket=bucket, prefix="").uploads

        client.abort_multipart_upload(Bucket=bucket, Key=upload_key, UploadId=upload_id)
        client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
        client.delete_object(Bucket=bucket, Key=key, VersionId=marker_id)
        assert_storage_empty(protocol_client, bucket=bucket)
    finally:
        _empty_bucket(protocol_client, client=client, bucket=bucket)
        client.delete_bucket(Bucket=bucket)


def _empty_bucket(protocol_client: S3Client, *, client: MinioAdminClient, bucket: str) -> None:
    for upload in list_multipart_uploads(protocol_client, bucket=bucket, prefix="").uploads:
        client.abort_multipart_upload(Bucket=bucket, Key=upload.key, UploadId=upload.upload_id)
    for entry in list_versions(protocol_client, bucket=bucket, prefix="").entries:
        client.delete_object(Bucket=bucket, Key=entry.key, VersionId=entry.version_id)
