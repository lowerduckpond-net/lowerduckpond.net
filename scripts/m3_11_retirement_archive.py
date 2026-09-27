"""Bounded exact-version storage proofs; never infer deletion authority from counts."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from lowerduckpond_m3_archive.storage import S3Client, assert_versioning_enabled

from scripts.m3_11_backup_fixture import _version
from scripts.m3_11_qualification_evidence import count, digest, fields
from scripts.m3_11_retirement_files import CHUNK, RetirementError, preserve

MAX_VERSIONS = 25
MAX_BUNDLE_BYTES = 120 * 1024 * 1024
MAX_TOTAL_BYTES = 3000 * 1024 * 1024


class Body(Protocol):
    def read(self, size: int) -> bytes: ...
    def close(self) -> None: ...


def records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_VERSIONS:
        raise RetirementError("retirement needs a bounded nonempty archive inventory")
    result = []
    for item in value:
        row = fields(item, {"key", "version", "size", "sha256"})
        _version(row["key"])
        _version(row["version"])
        count(row["size"], minimum=1, maximum=MAX_BUNDLE_BYTES)
        digest(row["sha256"])
        result.append(row)
    if (
        len({row["key"] for row in result}) != len(result)
        or sum(cast(int, row["size"]) for row in result) > MAX_TOTAL_BYTES
        or result != sorted(result, key=lambda row: str(row["key"]))
    ):
        raise RetirementError("retirement archive identities are ambiguous")
    return result


def inventory(client: S3Client, bucket: str) -> list[tuple[str, str]]:
    """One bounded page suffices for this <=25-version exception; truncation rejects."""
    assert_versioning_enabled(client, bucket=bucket)
    current = client.list_objects_v2(Bucket=bucket, MaxKeys=MAX_VERSIONS + 1)
    versions = client.list_object_versions(Bucket=bucket, MaxKeys=MAX_VERSIONS + 1)
    uploads = client.list_multipart_uploads(Bucket=bucket, MaxUploads=1)
    for response in (current, versions, uploads):
        if response.get("IsTruncated") is not False:
            raise RetirementError("retirement inventory is truncated or malformed")
    if versions.get("DeleteMarkers", []) != [] or uploads.get("Uploads", []) != []:
        raise RetirementError("retirement does not authorize markers or multipart uploads")
    objects, entries = current.get("Contents", []), versions.get("Versions", [])
    if not isinstance(objects, list) or not isinstance(entries, list):
        raise RetirementError("retirement inventory is malformed")
    if len(objects) > MAX_VERSIONS or len(entries) > MAX_VERSIONS:
        raise RetirementError("retirement inventory exceeds its bound")
    keys = [_version(item.get("Key")) for item in objects if isinstance(item, dict)]
    rows = [
        (_version(item.get("Key")), _version(item.get("VersionId")))
        for item in entries
        if isinstance(item, dict)
    ]
    if (
        len(keys) != len(objects)
        or len(rows) != len(entries)
        or len(set(keys)) != len(keys)
        or len({key for key, _ in rows}) != len(rows)
        or set(keys) != {key for key, _ in rows}
        or any(item.get("IsLatest") is not True for item in entries)
    ):
        raise RetirementError("retirement inventory contains unknown or ambiguous versions")
    return sorted(rows)


@dataclass
class Archives:
    writer: S3Client
    observer: S3Client
    bucket: str

    def observed(self) -> list[tuple[str, str]]:
        first = inventory(self.writer, self.bucket)
        if first != inventory(self.observer, self.bucket):
            raise RetirementError("independent archive inventories disagree")
        return first

    def preserve(self, row: dict[str, object], path: Path) -> dict[str, object]:
        response = self.observer.get_object(
            Bucket=self.bucket, Key=row["key"], VersionId=row["version"]
        )
        body = cast(Body, response.get("Body"))
        try:
            if (
                response.get("VersionId") != row["version"]
                or type(response.get("ContentLength")) is not int
                or response.get("ContentLength") != row["size"]
            ):
                raise RetirementError("archive read differs from its exact record")

            def chunks() -> Iterator[bytes]:
                while data := body.read(CHUNK):
                    yield data

            return preserve(path, chunks(), cast(int, row["size"]), str(row["sha256"]))
        finally:
            body.close()

    def delete(self, row: dict[str, object]) -> None:
        response = self.writer.delete_object(
            Bucket=self.bucket, Key=row["key"], VersionId=row["version"]
        )
        if response.get("VersionId") not in (None, row["version"]):
            raise RetirementError("archive deletion returned a different identity")
