"""Exact-version prefix cleanup retains authorization across lost responses."""

# ruff: noqa: N803 - these keyword names are the exact S3 SDK request surface

from __future__ import annotations

import io
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest
from lowerduckpond_m3_archive.storage import (
    LIST_PAGE_SIZE,
    ArchiveQualificationError,
    list_current_objects,
    list_multipart_uploads,
    list_versions,
)

from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.production_qualification_inputs import POLICY


@dataclass
class Storage:
    target: Target
    manifest: bytes
    versions: dict[tuple[str, str], str] = field(default_factory=dict)
    uploads: set[tuple[str, str]] = field(default_factory=set)
    operations: list[tuple[str, str, str]] = field(default_factory=list)
    fail_after: str | None = None
    late_write: bool = False

    def objects(self, *, Bucket: str, Prefix: str, MaxKeys: int) -> dict[str, object]:
        assert Bucket == self.target.backup_bucket and MaxKeys == LIST_PAGE_SIZE
        keys = sorted(
            {
                key
                for (key, _), kind in self.versions.items()
                if key.startswith(Prefix) and kind == "version"
            }
        )
        return {"IsTruncated": False, "Contents": [{"Key": key} for key in keys]}

    def version_list(self, *, Bucket: str, Prefix: str, MaxKeys: int) -> dict[str, object]:
        assert Bucket == self.target.backup_bucket and MaxKeys == LIST_PAGE_SIZE
        return {
            "IsTruncated": False,
            **{
                output: [
                    {"Key": key, "VersionId": version}
                    for (key, version), kind in sorted(self.versions.items())
                    if key.startswith(Prefix) and kind == selected
                ]
                for selected, output in (
                    ("version", "Versions"),
                    ("delete-marker", "DeleteMarkers"),
                )
            },
        }

    def upload_list(self, *, Bucket: str, Prefix: str, MaxUploads: int) -> dict[str, object]:
        assert Bucket == self.target.backup_bucket and MaxUploads == LIST_PAGE_SIZE
        return {
            "IsTruncated": False,
            "Uploads": [
                {"Key": key, "UploadId": upload}
                for key, upload in sorted(self.uploads)
                if key.startswith(Prefix)
            ],
        }

    def owner(self, *, Bucket: str, Key: str, VersionId: str) -> dict[str, object]:
        assert Bucket == self.target.backup_bucket and Key == self.target.owner_key
        assert VersionId == "owner-version" and (Key, VersionId) in self.versions
        return {
            "VersionId": VersionId,
            "Body": io.BytesIO(self.manifest),
            "ContentLength": len(self.manifest),
        }

    def deleted(self, kind: str, key: str, identity: str) -> None:
        self.operations.append((kind, key, identity))
        if self.late_write:
            self.versions[(self.target.prefix + "restic/new-writer", "new-version")] = "version"
        if identity == self.fail_after:
            self.fail_after = None
            raise OSError("response lost after provider commit")

    def delete(self, *, Bucket: str, Key: str, VersionId: str) -> dict[str, object]:
        assert Bucket == self.target.backup_bucket
        assert Key.startswith(self.target.prefix)
        del self.versions[Key, VersionId]
        self.deleted("delete", Key, VersionId)
        return {"VersionId": VersionId}

    def abort(self, *, Bucket: str, Key: str, UploadId: str) -> dict[str, object]:
        assert Bucket == self.target.backup_bucket
        self.uploads.remove((Key, UploadId))
        self.deleted("abort", Key, UploadId)
        return {}

    def client(self, *, writable: bool = False) -> Mock:
        result = Mock()
        result.get_bucket_versioning.return_value = {"Status": "Enabled"}
        result.list_objects_v2.side_effect = self.objects
        result.list_object_versions.side_effect = self.version_list
        result.list_multipart_uploads.side_effect = self.upload_list
        result.get_object.side_effect = self.owner
        result.delete_object.side_effect = (
            self.delete if writable else AssertionError("observer wrote")
        )
        result.abort_multipart_upload.side_effect = (
            self.abort if writable else AssertionError("observer wrote")
        )
        return result


@pytest.fixture
def removal(tmp_path: Path) -> tuple[Removal, Storage]:
    target = Target(str(uuid.uuid7()), "ams3", "owned-backups", "owned-archives")
    binding: dict[str, object] = {
        "source_revision": "a" * 40,
        "artifact_sha256": "b" * 64,
        "input_policy": POLICY,
        "qualification_inputs_sha256": "c" * 64,
        "storage_target_sha256": target.storage_target_sha256,
        "storage_run_id": str(uuid.uuid7()),
        "storage_report_sha256": "d" * 64,
    }
    storage = Storage(target, canonical_bytes(target.manifest(binding)))
    storage.versions.update(
        {
            (target.owner_key, "owner-version"): "version",
            (target.prefix + "restic/data/owned", "data-version"): "version",
            (target.prefix + "restic/locks/old", "marker-version"): "delete-marker",
            ("backups/production/untouched", "production-version"): "version",
        }
    )
    storage.uploads.add((target.prefix + "restic/data/unfinished", "upload-id"))
    value = Removal(
        target,
        binding,
        "owner-version",
        storage.client(writable=True),
        storage.client(),
        tmp_path / "removal",
        lambda: "e" * 64,
    )
    return value, storage


def test_only_owned_exact_versions_are_removed_and_owner_is_last(
    removal: tuple[Removal, Storage],
) -> None:
    value, storage = removal
    assert value.run()["remaining_backup_objects"] == 0
    assert storage.versions == {("backups/production/untouched", "production-version"): "version"}
    assert not storage.uploads
    assert storage.operations[-1] == ("delete", value.target.owner_key, "owner-version")
    assert all(key.startswith(value.target.prefix) for _, key, _ in storage.operations)
    assert (value.directory / "intent.json").exists()
    assert (value.directory / "owner-delete.started.json").exists()
    assert (value.directory / "removed.json").exists()


@pytest.mark.parametrize(
    "identity", ["data-version", "marker-version", "upload-id", "owner-version"]
)
def test_lost_response_resumes_original_cleanup_without_redeleting_absent_versions(
    removal: tuple[Removal, Storage], identity: str
) -> None:
    value, storage = removal
    storage.fail_after = identity
    with pytest.raises(OSError, match="response lost"):
        value.run()
    original = (value.directory / "intent.json").read_bytes()
    assert not (value.directory / "removed.json").exists()
    assert value.run()["remaining_backup_objects"] == 0
    assert (value.directory / "intent.json").read_bytes() == original
    assert len(storage.operations) == len(set(storage.operations))
    assert storage.operations[-1][-1] == "owner-version"


@pytest.mark.parametrize(
    "fault", ["owner", "observer", "quiescence", "foreign", "traversal", "unversioned"]
)
def test_uncertain_ownership_or_independent_accounting_prevents_all_deletion(
    removal: tuple[Removal, Storage], fault: str
) -> None:
    value, storage = removal
    if fault == "owner":
        storage.manifest = b"different original owner"
    elif fault == "observer":
        value.observer = storage.client()
        value.observer.list_objects_v2.side_effect = None
        value.observer.list_objects_v2.return_value = {"IsTruncated": False}
    elif fault == "quiescence":
        value.quiescent = Mock(side_effect=ValueError("writer not frozen"))
    elif fault == "foreign":
        storage.versions[(value.target.prefix + "unrelated", "foreign-version")] = "version"
    elif fault == "traversal":
        storage.versions[(value.target.prefix + "restic/../../outside", "foreign-version")] = (
            "version"
        )
    else:
        cast(Mock, value.writer).get_bucket_versioning.return_value = {"Status": "Suspended"}
    with pytest.raises((ValueError, RuntimeError)):
        value.run()
    assert not storage.operations


def test_new_bytes_after_interruption_are_retained_instead_of_added_to_the_plan(
    removal: tuple[Removal, Storage],
) -> None:
    value, storage = removal
    storage.fail_after = "upload-id"
    with pytest.raises(OSError):
        value.run()
    storage.versions[(value.target.prefix + "restic/new", "new-version")] = "version"
    operations = list(storage.operations)
    with pytest.raises(ValueError, match="new backup bytes"):
        value.run()
    assert storage.operations == operations
    assert (value.target.owner_key, "owner-version") in storage.versions


def test_late_writes_keep_the_owner_and_do_not_expand_the_deletion_scope(
    removal: tuple[Removal, Storage],
) -> None:
    value, storage = removal
    storage.late_write = True
    with pytest.raises(ValueError, match="not completely removed"):
        value.run()
    assert (value.target.owner_key, "owner-version") in storage.versions
    assert all(identity != "new-version" for _, _, identity in storage.operations)
    assert not (value.directory / "owner-delete.started.json").exists()


def test_changed_writer_proof_prevents_resumed_deletion(removal: tuple[Removal, Storage]) -> None:
    value, storage = removal
    storage.fail_after = "upload-id"
    with pytest.raises(OSError):
        value.run()
    value.quiescent = lambda: "f" * 64
    operations = list(storage.operations)
    with pytest.raises(ValueError, match="writers changed"):
        value.run()
    assert storage.operations == operations


@pytest.mark.parametrize(
    "function,operation,collection",
    [
        (list_current_objects, "list_objects_v2", "Contents"),
        (list_versions, "list_object_versions", "Versions"),
        (list_multipart_uploads, "list_multipart_uploads", "Uploads"),
    ],
)
def test_entry_limits_stop_listing_before_requesting_another_page(
    function: Callable[..., object], operation: str, collection: str
) -> None:
    client = Mock()
    method = getattr(client, operation)
    method.return_value = {
        "IsTruncated": True,
        collection: [
            {"Key": f"owned/{index}", "VersionId": "v", "UploadId": "u"} for index in range(2)
        ],
    }
    with pytest.raises(ArchiveQualificationError, match="entry bound"):
        function(client, bucket="bucket", prefix="owned/", maximum_entries=1)
    assert method.call_count == 1


@pytest.mark.parametrize("fault", ["duplicate", "null-version", "owner-upload", "unbound-current"])
def test_ambiguous_inventory_fails_before_any_deletion(
    removal: tuple[Removal, Storage], fault: str
) -> None:
    value, storage = removal
    writer = cast(Mock, value.writer)
    if fault == "null-version":
        storage.versions[(value.target.prefix + "restic/null", "null")] = "version"
    elif fault == "owner-upload":
        storage.uploads.add((value.target.owner_key, "unknown-owner-upload"))
    elif fault == "unbound-current":
        writer.list_objects_v2.side_effect = None
        writer.list_objects_v2.return_value = {
            "IsTruncated": False,
            "Contents": [{"Key": value.target.prefix + "restic/unbound"}],
        }
    else:

        def duplicate(**arguments: object) -> dict[str, object]:
            result = storage.version_list(**arguments)  # type: ignore[arg-type]
            if arguments["Prefix"] == value.target.prefix:
                rows = cast(list[dict[str, str]], result["Versions"])
                rows.append(dict(rows[0]))
            return result

        writer.list_object_versions.side_effect = duplicate
    with pytest.raises(ValueError):
        value.run()
    assert not storage.operations


def test_full_paginated_inventory_is_deleted_using_each_original_version(
    removal: tuple[Removal, Storage],
) -> None:
    value, storage = removal

    def pages(**arguments: object) -> dict[str, object]:
        key_marker = arguments.pop("KeyMarker", None)
        version_marker = arguments.pop("VersionIdMarker", None)
        full = storage.version_list(**arguments)  # type: ignore[arg-type]
        rows = cast(list[dict[str, str]], full["Versions"])
        if len(rows) < 2:  # noqa: PLR2004 - a second actual page is required for this fixture
            assert key_marker is None
            return full
        first, rest = rows[0], rows[1:]
        if key_marker is None:
            return {
                "IsTruncated": True,
                "Versions": [first],
                "NextKeyMarker": first["Key"],
                "NextVersionIdMarker": first["VersionId"],
            }
        assert (key_marker, version_marker) == (first["Key"], first["VersionId"])
        return {**full, "Versions": rest}

    cast(Mock, value.writer).list_object_versions.side_effect = pages
    cast(Mock, value.observer).list_object_versions.side_effect = pages
    assert value.run()["remaining_backup_objects"] == 0
    assert {identity for _, _, identity in storage.operations} == {
        "owner-version",
        "data-version",
        "marker-version",
        "upload-id",
    }


@pytest.mark.parametrize("fault", ["owner", "binding", "authorization"])
def test_original_intent_cannot_be_changed_after_a_lost_response(
    removal: tuple[Removal, Storage], fault: str
) -> None:
    value, storage = removal
    storage.fail_after = "owner-version" if fault == "authorization" else "upload-id"
    with pytest.raises(OSError):
        value.run()
    if fault == "owner":
        value.owner_version = "different-owner"
    elif fault == "binding":
        value.binding = {**value.binding, "source_revision": "f" * 40}
    else:
        (value.directory / "owner-delete.started.json").write_bytes(
            canonical_bytes({"intent_sha256": "f" * 64})
        )
    operations = list(storage.operations)
    with pytest.raises(ValueError):
        value.run()
    assert storage.operations == operations
    assert not (value.directory / "removed.json").exists()


@pytest.mark.parametrize("fault", ["public-parent", "public-journal", "symlink"])
def test_removal_authority_requires_a_private_original_journal_directory(
    removal: tuple[Removal, Storage], fault: str
) -> None:
    value, storage = removal
    if fault == "public-parent":
        value.directory.parent.chmod(0o755)
    elif fault == "public-journal":
        value.directory.mkdir(mode=0o755)
    else:
        actual = value.directory.with_name("other")
        actual.mkdir(mode=0o700)
        value.directory.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="journal"):
        value.run()
    assert not storage.operations
