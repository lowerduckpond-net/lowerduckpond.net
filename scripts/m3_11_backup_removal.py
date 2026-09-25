"""Resume exact cleanup of an owned disposable backup prefix, never production.

The combined controller supplies a fresh proof that its writers are fenced or
retired, after exact installed-test completion. Resuming this cleanup does not
resume or convert a failed qualification into a passing attempt.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import (
    S3Client,
    assert_versioning_enabled,
    list_current_objects,
    list_multipart_uploads,
    list_versions,
)

from scripts.m3_11_backup_fixture import Target, _version
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, digest, fields

FORMAT = "lowerduckpond-m3-11-backup-removal-v1"
MAX_ENTRIES = 1024


def _once(path: Path, value: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        if read_private(path) != value:
            raise ValueError("owned backup removal intent changed")
    else:
        write_private(path, value)


@dataclass
class Removal:
    target: Target
    binding: dict[str, object]
    owner_version: str
    writer: S3Client
    observer: S3Client
    directory: Path
    quiescent: Callable[[], str]

    def _key(self, key: str) -> None:
        _version(key)  # Same bounded opaque UTF-8/control-character rules as full IDs.
        if key != self.target.owner_key and not key.startswith(self.target.prefix + "restic/"):
            raise ValueError("backup removal found a key outside its owned Restic namespace")
        if any(part in {"", ".", ".."} for part in key.split("/")):
            raise ValueError("backup removal found an ambiguous object key")

    def _inventory(self, client: S3Client) -> dict[str, object]:
        target = self.target
        assert_versioning_enabled(client, bucket=target.backup_bucket)
        current = list_current_objects(
            client, bucket=target.backup_bucket, prefix=target.prefix, maximum_entries=MAX_ENTRIES
        )
        versions = list_versions(
            client, bucket=target.backup_bucket, prefix=target.prefix, maximum_entries=MAX_ENTRIES
        ).entries
        uploads = list_multipart_uploads(
            client, bucket=target.backup_bucket, prefix=target.prefix, maximum_entries=MAX_ENTRIES
        ).uploads
        result: dict[str, object] = {
            "current": sorted(current),
            "versions": sorted([item.kind, item.key, item.version_id] for item in versions),
            "uploads": sorted([item.key, item.upload_id] for item in uploads),
        }
        self._validate_inventory(result)
        return result

    def _validate_inventory(self, value: dict[str, object]) -> None:
        fields(value, {"current", "versions", "uploads"})
        if any(not isinstance(items, list) for items in value.values()):
            raise ValueError("backup removal inventory is malformed")
        current = cast("list[object]", value["current"])
        versions = cast("list[object]", value["versions"])
        uploads = cast("list[object]", value["uploads"])
        if sum(map(len, (current, versions, uploads))) > MAX_ENTRIES:
            raise ValueError("backup removal inventory exceeds its bound")
        for key in current:
            if not isinstance(key, str):
                raise ValueError("backup removal current key is invalid")
            self._key(key)
        for rows, length in ((versions, 3), (uploads, 2)):
            for row in rows:
                if (
                    not isinstance(row, list)
                    or len(row) != length
                    or any(not isinstance(item, str) for item in row)
                ):
                    raise ValueError("backup removal exact identity is malformed")
                self._key(row[-2])
                _version(row[-1])
                if length == 2 and row[0] == self.target.owner_key:  # noqa: PLR2004
                    raise ValueError("backup ownership has an unexpected multipart upload")
                if length == 3 and row[0] not in {"version", "delete-marker"}:  # noqa: PLR2004
                    raise ValueError("backup removal version kind is invalid")
        for rows in (current, versions, uploads):
            encoded = [canonical_bytes(row) for row in rows]
            if len(set(encoded)) != len(encoded):
                raise ValueError("backup removal inventory contains duplicate identities")
        version_keys = {row[1] for row in cast("list[list[str]]", versions) if row[0] == "version"}
        if not set(cast("list[str]", current)) <= version_keys:
            raise ValueError("backup removal current objects lack exact version identities")

    def _observed(self) -> dict[str, object]:
        before = self._inventory(self.writer)
        if before != self._inventory(self.observer):
            raise ValueError("independent backup removal inventories disagree")
        return before

    def _owner(self) -> None:
        for client in (self.writer, self.observer):
            self.target.require_owner(client, self.binding, version=self.owner_version)

    def _quiet(self, expected: str | None = None) -> str:
        actual = self.quiescent()
        digest(actual)
        if expected is not None and actual != expected:
            raise ValueError("backup writers changed after removal authorization")
        return actual

    def _intent(self) -> dict[str, object]:
        original = self.target.manifest(self.binding)
        _version(self.owner_version)
        path = self.directory / "intent.json"
        if self.directory.exists() or self.directory.is_symlink():
            intent = fields(
                read_private(path),
                {"format", "ownership", "owner_version", "quiescent_sha256", "inventory"},
            )
            if (
                intent["format"] != FORMAT
                or intent["ownership"] != original
                or intent["owner_version"] != self.owner_version
                or not isinstance(intent["quiescent_sha256"], str)
                or not isinstance(intent["inventory"], dict)
            ):
                raise ValueError("backup removal belongs to different original inputs")
            self._validate_inventory(intent["inventory"])
            self._quiet(intent["quiescent_sha256"])
            return intent
        quiet = self._quiet()
        self._owner()
        inventory = self._observed()
        self._quiet(quiet)
        self.directory.mkdir(mode=0o700)
        intent = {
            "format": FORMAT,
            "ownership": original,
            "owner_version": self.owner_version,
            "quiescent_sha256": quiet,
            "inventory": inventory,
        }
        write_private(path, intent)
        return intent

    def _delete(self, key: str, version: str) -> None:
        response = self.writer.delete_object(
            Bucket=self.target.backup_bucket, Key=key, VersionId=version
        )
        if response.get("VersionId") not in {None, version}:
            raise ValueError("backup removal deleted a different version")

    def _private_directory(self) -> None:
        if not self.directory.is_absolute() or self.directory.resolve() != self.directory:
            raise ValueError("backup removal journal must use its original canonical path")
        for path in (self.directory.parent, self.directory):
            if path == self.directory and not path.exists():
                continue
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004 - private run journal
            ):
                raise ValueError("backup removal journal must remain private and owned")

    def run(self) -> dict[str, object]:
        """No hidden retry: lost responses leave the original resumable intent."""
        self._private_directory()
        if self.writer is self.observer:
            raise ValueError("backup removal requires an independent observer")
        intent = self._intent()
        intent_sha256 = hashlib.sha256(canonical_bytes(intent)).hexdigest()
        authorization: dict[str, object] = {"intent_sha256": intent_sha256}
        owner_started = self.directory / "owner-delete.started.json"
        remaining = self._observed()
        # A lost owner-delete response is recoverable only from the previously
        # durable authorization AND independently observed complete absence.
        empty: dict[str, object] = {"current": [], "versions": [], "uploads": []}
        if not (owner_started.exists() and remaining == empty):
            self._owner()
            original = cast("dict[str, object]", intent["inventory"])
            for key, rows in remaining.items():
                if any(
                    row not in cast("list[object]", original[key])
                    for row in cast("list[object]", rows)
                ):
                    raise ValueError("new backup bytes appeared after removal authorization")
            only_owner = {
                "current": [self.target.owner_key],
                "versions": [["version", self.target.owner_key, self.owner_version]],
                "uploads": [],
            }
            if owner_started.exists() and remaining != only_owner:
                raise ValueError("backup bytes reappeared after owner removal was authorized")
            self._quiet(str(intent["quiescent_sha256"]))
            _once(self.directory / "data-delete.started.json", authorization)
            for key, upload_id in cast("list[list[str]]", remaining["uploads"]):
                self.writer.abort_multipart_upload(
                    Bucket=self.target.backup_bucket, Key=key, UploadId=upload_id
                )
            for _kind, key, version in cast("list[list[str]]", remaining["versions"]):
                if key != self.target.owner_key:
                    self._delete(key, version)
            if self._observed() != only_owner:
                raise ValueError("owned backup data was not completely removed")
            self._owner()
            self._quiet(str(intent["quiescent_sha256"]))
            _once(owner_started, authorization)
            self._delete(self.target.owner_key, self.owner_version)
        if read_private(owner_started) != authorization:
            raise ValueError("backup owner removal lost its original authorization")
        if self._observed() != empty:
            raise ValueError("independent backup absence was not established")
        self._quiet(str(intent["quiescent_sha256"]))
        result: dict[str, object] = {**authorization, "remaining_backup_objects": 0}
        _once(self.directory / "removed.json", result)
        return result
