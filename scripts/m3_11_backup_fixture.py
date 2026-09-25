"""Private ownership of one disposable M3.11 Restic prefix in the backup Space.

Only the secure-workstation producer calls this module. It does not expose a
production snapshot deletion command or accept a caller-selected prefix.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from lowerduckpond_m3_archive.storage import (
    S3Client,
    assert_storage_empty,
    create_client,
    list_versions,
)

from scripts.m3_11_qualification_evidence import (
    BINDING_FIELDS,
    canonical_bytes,
    digest,
    fields,
    uuid7,
)
from scripts.production_qualification_inputs import POLICY, revision

FORMAT = "lowerduckpond-m3-11-backup-fixture-v1"
MAX_VERSION_BYTES = 1024
ASCII_SPACE = 0x20
ASCII_DELETE = 0x7F


class Body(Protocol):
    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class Target:
    run_id: str
    region: str
    backup_bucket: str
    archive_bucket: str

    def __post_init__(self) -> None:
        uuid7(self.run_id)
        if re.fullmatch(r"[a-z]{3}[1-9][0-9]?", self.region) is None:
            raise ValueError("qualification backup region is invalid")
        for bucket in (self.backup_bucket, self.archive_bucket):
            if (
                re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
                or ".." in bucket
                or re.fullmatch(r"[0-9.]+", bucket) is not None
            ):
                raise ValueError("qualification storage bucket is invalid")
        if self.backup_bucket == self.archive_bucket:
            raise ValueError("backup and archive buckets must be distinct")

    @property
    def prefix(self) -> str:
        return f"m3-11-qualification/{self.run_id}/"

    @property
    def owner_key(self) -> str:
        return self.prefix + "owner.json"

    @property
    def repository(self) -> str:
        return (
            f"s3:https://{self.region}.digitaloceanspaces.com/"
            f"{self.backup_bucket}/{self.prefix}restic"
        )

    @property
    def storage_target_sha256(self) -> str:
        # Match ADR 0029's existing storage target format (which excludes LF).
        raw = canonical_bytes(
            {
                "SPACES_REGION": self.region,
                "SPACES_BACKUP_BUCKET": self.backup_bucket,
                "SPACES_ARCHIVE_BUCKET": self.archive_bucket,
            }
        ).removesuffix(b"\n")
        return hashlib.sha256(raw).hexdigest()

    def manifest(self, binding: dict[str, object]) -> dict[str, object]:
        fields(binding, BINDING_FIELDS)
        revision(binding["source_revision"])
        uuid7(binding["storage_run_id"])
        for key in (
            "artifact_sha256",
            "qualification_inputs_sha256",
            "storage_target_sha256",
            "storage_report_sha256",
        ):
            digest(binding[key])
        if (
            binding["input_policy"] != POLICY
            or binding["storage_target_sha256"] != self.storage_target_sha256
        ):
            raise ValueError("qualification backup target differs from captured inputs")
        return {
            "format": FORMAT,
            "run_id": self.run_id,
            "region": self.region,
            "bucket": self.backup_bucket,
            "prefix": self.prefix,
            "repository": self.repository,
            **binding,
        }

    def clients(self, environment: Mapping[str, str]) -> tuple[S3Client, S3Client]:
        """Use separate explicit runtime/operator credentials and the bound endpoint."""
        expected = {
            "SPACES_REGION": self.region,
            "SPACES_BACKUP_BUCKET": self.backup_bucket,
            "SPACES_ARCHIVE_BUCKET": self.archive_bucket,
        }
        if any(environment.get(key) != value for key, value in expected.items()):
            raise ValueError("qualification backup environment changed its target")
        names = (
            ("SPACES_BACKUP_ACCESS_KEY_ID", "SPACES_BACKUP_SECRET_ACCESS_KEY"),
            ("SPACES_ACCESS_KEY_ID", "SPACES_SECRET_ACCESS_KEY"),
        )
        if any(not environment.get(key) for pair in names for key in pair):
            raise ValueError("qualification backup credentials are unavailable")
        if environment[names[0][0]] == environment[names[1][0]]:
            raise ValueError(
                "qualification backup observation requires the independent operator key"
            )
        writer, observer = (
            create_client(
                access_key_id=environment[key],
                secret_access_key=environment[secret],
                region=self.region,
                endpoint_url=f"https://{self.region}.digitaloceanspaces.com",
            )
            for key, secret in names
        )
        return writer, observer

    def begin(self, writer: S3Client, observer: S3Client, binding: dict[str, object]) -> str:
        """Require empty versioned storage through both principals before claiming it.

        Callers persist the returned full marker version before starting Restic.
        A lost response or failed observation retains the prefix for diagnosis;
        it never retries ownership creation or removes remote bytes here.
        """
        if writer is observer:
            raise ValueError("qualification backup requires an independent observer")
        raw = canonical_bytes(self.manifest(binding))
        for client in (writer, observer):
            assert_storage_empty(client, bucket=self.backup_bucket, prefix=self.prefix)
        response = writer.put_object(
            Bucket=self.backup_bucket, Key=self.owner_key, Body=raw, ContentType="application/json"
        )
        version = _version(response.get("VersionId"))
        for client in (writer, observer):
            self.require_owner(client, binding, version=version)
        return version

    def require_owner(self, client: S3Client, binding: dict[str, object], *, version: str) -> None:
        """Prove the original unique owner version and exact context, never latest."""
        version = _version(version)
        raw = canonical_bytes(self.manifest(binding))
        versions = list_versions(client, bucket=self.backup_bucket, prefix=self.owner_key).entries
        if len(versions) != 1 or (
            versions[0].key != self.owner_key
            or versions[0].kind != "version"
            or versions[0].version_id != version
        ):
            raise ValueError("qualification backup ownership is missing or ambiguous")
        response = client.get_object(
            Bucket=self.backup_bucket, Key=self.owner_key, VersionId=version
        )
        body = cast(Body, response.get("Body"))
        try:
            if (
                response.get("VersionId") != version
                or type(response.get("ContentLength")) is not int
                or response["ContentLength"] != len(raw)
                or body.read(len(raw) + 1) != raw
            ):
                raise ValueError("qualification backup ownership changed")
        finally:
            body.close()


def _version(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value == "null"
        or len(value.encode("utf-8")) > MAX_VERSION_BYTES
        or any(ord(char) < ASCII_SPACE or ord(char) == ASCII_DELETE for char in value)
    ):
        raise ValueError("qualification backup owner version is invalid")
    return value
