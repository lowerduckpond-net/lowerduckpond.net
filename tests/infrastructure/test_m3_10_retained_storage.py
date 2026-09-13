from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import cast

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.archive_remote import RemoteVersion

from scripts.check_m3_10_provider import (
    GateError,
    PolicyClient,
    check_storage,
    read_archive_authority,
)

from .test_m3_10_production_gate import ARCHIVE_KEY, BOUND_VERSION, ROOT, Storage

ARTIFACT = "c" * 64
SOURCE = "0" * 40
SECOND_KEY = "archives/0198d17f-6f4a-7000-8000-000000000004.zip"


@pytest.fixture
def authority(tmp_path: Path) -> Path:
    record = json.loads(
        (ROOT / "tests/static-publication/fixtures/accepted/archive-record.json").read_text()
    )
    record.update(bucket="archive-fixture", key=ARCHIVE_KEY, versionId="v1", bundleSize=4096)
    path = tmp_path / "authority.json"
    path.write_bytes(
        canonical_json_bytes(
            {
                "format": "lowerduckpond-m3-10-archive-authority-v1",
                "sourceRevision": SOURCE,
                "artifactSha256": ARTIFACT,
                "archives": [record],
            }
        )
    )
    path.chmod(0o600)
    return path


def read_authority(path: Path) -> frozenset[RemoteVersion]:
    return read_archive_authority(
        path, bucket="archive-fixture", artifact=ARTIFACT, source_revision=SOURCE
    )


def populated_storage() -> Storage:
    storage = Storage()
    storage.responses["list_object_versions"] = {
        "IsTruncated": False,
        "Versions": [{"Key": ARCHIVE_KEY, "VersionId": "v1", "Size": 4096}],
    }
    return storage


def check_retained(storage: Storage, expected: frozenset[RemoteVersion] | None = None) -> None:
    check_storage(
        cast(PolicyClient, storage),
        bucket="archive-fixture",
        require_empty=False,
        expected_versions=expected if expected is not None else frozenset({BOUND_VERSION}),
    )


def test_private_authority_binds_the_exact_candidate_and_retained_version(authority: Path) -> None:
    assert read_authority(authority) == frozenset({BOUND_VERSION})
    storage = populated_storage()
    check_retained(storage, read_authority(authority))
    assert storage.acl_requests == [
        {"Bucket": "archive-fixture", "Key": ARCHIVE_KEY, "VersionId": "v1"}
    ]


@pytest.mark.parametrize(
    "drift",
    [
        "source",
        "artifact",
        "format",
        "bucket",
        "duplicate",
        "malformed-record",
        "extra-field",
        "permissions",
        "symlink",
        "hardlink",
        "truncated",
        "oversized",
    ],
)
def test_archive_authority_refuses_untrusted_or_mismatched_snapshots(
    authority: Path, drift: str
) -> None:
    document = json.loads(authority.read_text())
    if drift in {"source", "artifact", "format"}:
        field = {"source": "sourceRevision", "artifact": "artifactSha256", "format": "format"}[
            drift
        ]
        document[field] = "different"
    elif drift == "bucket":
        document["archives"][0]["bucket"] = "foreign-bucket"
    elif drift == "duplicate":
        document["archives"].append(document["archives"][0])
    elif drift == "malformed-record":
        document["archives"][0]["bundleSize"] = 0
    elif drift == "extra-field":
        document["unreviewed"] = True
    else:
        if drift == "permissions":
            authority.chmod(0o644)
        elif drift == "symlink":
            actual = authority.with_suffix(".actual")
            authority.rename(actual)
            authority.symlink_to(actual)
        elif drift == "hardlink":
            authority.with_suffix(".link").hardlink_to(authority)
        elif drift == "truncated":
            authority.write_bytes(b"{")
        else:
            authority.write_bytes(b"x" * (128 * 1024 + 1))
        with pytest.raises((GateError, ValueError)):
            read_authority(authority)
        return
    authority.write_bytes(canonical_json_bytes(document))
    with pytest.raises((GateError, ValueError)):
        read_authority(authority)


@pytest.mark.parametrize(
    "acl",
    [
        {
            "Owner": {"ID": "owner"},
            "Grants": [{"Permission": "READ", "Grantee": {"Type": "Group", "URI": "AllUsers"}}],
        },
        {
            "Owner": {"ID": "foreign"},
            "Grants": [
                {
                    "Permission": "FULL_CONTROL",
                    "Grantee": {"Type": "CanonicalUser", "ID": "foreign"},
                }
            ],
        },
        {
            "Owner": {"ID": "owner"},
            "Grants": [
                {
                    "Permission": "FULL_CONTROL",
                    "Grantee": {"Type": "CanonicalUser", "ID": "foreign"},
                }
            ],
        },
        {"Owner": {"ID": "owner"}, "Grants": []},
        "AccessDenied",
    ],
)
def test_retained_version_requires_its_own_exact_private_acl(acl: object) -> None:
    storage = populated_storage()
    storage.object_acl = acl
    before = copy.deepcopy(storage.responses)
    with pytest.raises((GateError, ClientError)):
        check_retained(storage)
    assert storage.acl_requests == [
        {"Bucket": "archive-fixture", "Key": ARCHIVE_KEY, "VersionId": "v1"}
    ]
    assert storage.responses == before


@pytest.mark.parametrize(
    "drift", ["extra-key", "extra-version", "delete-marker", "missing", "size"]
)
def test_retained_inventory_must_equal_host_authority_without_cleanup(drift: str) -> None:
    storage = populated_storage()
    response = cast(dict[str, object], storage.responses["list_object_versions"])
    versions = cast(list[dict[str, object]], response["Versions"])
    if drift in {"extra-key", "extra-version"}:
        versions.append(
            {
                "Key": SECOND_KEY if drift == "extra-key" else ARCHIVE_KEY,
                "VersionId": "v2",
                "Size": 4096,
            }
        )
    elif drift == "delete-marker":
        response["DeleteMarkers"] = [{"Key": ARCHIVE_KEY, "VersionId": "marker"}]
    elif drift == "missing":
        versions.clear()
    else:
        versions[0]["Size"] = 4097
    before = copy.deepcopy(storage.responses)
    with pytest.raises(GateError, match="inventory"):
        check_retained(storage)
    assert storage.responses == before
    assert not storage.acl_requests


def test_populated_storage_cannot_omit_host_authority() -> None:
    with pytest.raises(GateError, match="host authority"):
        check_storage(
            cast(PolicyClient, populated_storage()), bucket="archive-fixture", require_empty=False
        )


class PaginatedStorage(Storage):
    def list_object_versions(self, **arguments: object) -> dict[str, object]:
        self.calls.append("list_object_versions")
        assert arguments["Prefix"] == ""
        assert arguments["Bucket"] == "archive-fixture"
        if "KeyMarker" not in arguments:
            return {
                "IsTruncated": True,
                "NextKeyMarker": ARCHIVE_KEY,
                "NextVersionIdMarker": "v1",
                "Versions": [{"Key": ARCHIVE_KEY, "VersionId": "v1", "Size": 4096}],
            }
        assert arguments["KeyMarker"] == ARCHIVE_KEY and arguments["VersionIdMarker"] == "v1"
        return {
            "IsTruncated": False,
            "Versions": [{"Key": SECOND_KEY, "VersionId": "v2", "Size": 8192}],
        }


def test_retained_inventory_and_acls_cover_every_version_page() -> None:
    storage = PaginatedStorage()
    check_retained(
        storage, frozenset({BOUND_VERSION, RemoteVersion(SECOND_KEY, "v2", 8192, False)})
    )
    assert storage.calls.count("list_object_versions") == 4  # noqa: PLR2004 - two complete two-page snapshots
    assert storage.acl_requests == [
        {"Bucket": "archive-fixture", "Key": ARCHIVE_KEY, "VersionId": "v1"},
        {"Bucket": "archive-fixture", "Key": SECOND_KEY, "VersionId": "v2"},
    ]


def test_inventory_change_during_object_acl_reads_fails_closed() -> None:
    class ChangingStorage(Storage):
        def get_object_acl(self, **_arguments: object) -> dict[str, object]:
            self.responses["list_object_versions"] = {"IsTruncated": False}
            return cast(dict[str, object], self.object_acl)

    storage = ChangingStorage()
    storage.responses["list_object_versions"] = populated_storage().responses[
        "list_object_versions"
    ]
    with pytest.raises(GateError, match="inventory"):
        check_retained(storage)
