"""Operator-selected cleanup stays inside exact disposable run boundaries."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from unittest.mock import Mock

import pytest
from lowerduckpond_m3_archive.storage import ArchiveQualificationError, S3Client

from scripts import m3_11_backup_discard as cleanup

RUN = "0198d17f-6f4a-7000-8000-000000000001"
OTHER_RUN = "0198d17f-6f4a-7000-8000-000000000002"
PREFIX = f"m3-11-qualification/{RUN}/"
OTHER_PREFIX = f"m3-11-qualification/{OTHER_RUN}/"
BUCKET = "example-backup-space"
FAKE_SECRET = "example-operator-secret"  # noqa: S105 - explicit test credential


@dataclass
class Storage:
    versions: dict[tuple[str, str], str] = field(default_factory=dict)
    uploads: set[tuple[str, str]] = field(default_factory=set)
    operations: list[tuple[str, str, str]] = field(default_factory=list)
    page_size: int = 2
    fail_after: str | None = None
    late_write: bool = False
    late_write_after: str | None = None

    def current(self, **request: object) -> dict[str, object]:
        prefix = str(request["Prefix"])
        latest = {key: kind for (key, _identity), kind in self.versions.items()}
        return {
            "IsTruncated": False,
            "Contents": [
                {"Key": key}
                for key, kind in latest.items()
                if key.startswith(prefix) and kind == "version"
            ],
        }

    def pages(
        self, rows: list[tuple[str, str]], request: dict[str, object], marker: str
    ) -> tuple[list[tuple[str, str]], bool]:
        if "KeyMarker" in request:
            previous = (str(request["KeyMarker"]), str(request[marker]))
            rows = [row for row in rows if row > previous]
        return rows[: self.page_size], len(rows) > self.page_size

    def version_list(self, **request: object) -> dict[str, object]:
        rows = sorted(row for row in self.versions if row[0].startswith(str(request["Prefix"])))
        page, truncated = self.pages(rows, request, "VersionIdMarker")
        response: dict[str, object] = {"IsTruncated": truncated}
        for kind, name in (("version", "Versions"), ("delete-marker", "DeleteMarkers")):
            response[name] = [
                {"Key": key, "VersionId": identity}
                for key, identity in page
                if self.versions[key, identity] == kind
            ]
        if truncated:
            response.update(NextKeyMarker=page[-1][0], NextVersionIdMarker=page[-1][1])
        return response

    def upload_list(self, **request: object) -> dict[str, object]:
        rows = sorted(row for row in self.uploads if row[0].startswith(str(request["Prefix"])))
        page, truncated = self.pages(rows, request, "UploadIdMarker")
        response: dict[str, object] = {
            "IsTruncated": truncated,
            "Uploads": [{"Key": key, "UploadId": identity} for key, identity in page],
        }
        if truncated:
            response.update(NextKeyMarker=page[-1][0], NextUploadIdMarker=page[-1][1])
        return response

    def changed(self, kind: str, key: str, identity: str) -> None:
        self.operations.append((kind, key, identity))
        if self.late_write or self.late_write_after == identity:
            self.versions[PREFIX + "restic/new-writer", "new-version"] = "version"
        if identity == self.fail_after:
            self.fail_after = None
            raise OSError("response lost after provider commit")

    def delete(self, **request: object) -> dict[str, object]:
        assert request["Bucket"] == BUCKET
        key, version = str(request["Key"]), str(request["VersionId"])
        del self.versions[key, version]
        self.changed("delete", key, version)
        return {"VersionId": version}

    def abort(self, **request: object) -> dict[str, object]:
        assert request["Bucket"] == BUCKET
        key, upload = str(request["Key"]), str(request["UploadId"])
        self.uploads.remove((key, upload))
        self.changed("abort", key, upload)
        return {}

    def client(self) -> Mock:
        result = Mock(spec=S3Client)
        result.get_bucket_versioning.return_value = {"Status": "Enabled"}
        result.list_objects_v2.side_effect = self.current
        result.list_object_versions.side_effect = self.version_list
        result.list_multipart_uploads.side_effect = self.upload_list
        result.delete_object.side_effect = self.delete
        result.abort_multipart_upload.side_effect = self.abort
        return result


@pytest.fixture
def storage() -> Storage:
    value = Storage()
    value.versions = {
        (PREFIX + "owner.json", "owner-version"): "version",
        (PREFIX + "restic/data/old", "old-version"): "version",
        (PREFIX + "restic/data/old", "new-version"): "version",
        (PREFIX + "restic/data/old", "deleted-version"): "delete-marker",
        (PREFIX + "restic/data/visible", "null"): "version",
        ("restic/production", "production-version"): "version",
        (OTHER_PREFIX + "restic/data/keep", "other-version"): "version",
        (PREFIX.removesuffix("/") + "-neighbor/data", "neighbor-version"): "version",
    }
    value.uploads = {
        (PREFIX + "restic/data/unfinished", "upload-1"),
        (PREFIX + "restic/data/unfinished", "upload-2"),
        (PREFIX + "restic/data/unfinished", "upload-3"),
        (OTHER_PREFIX + "restic/data/keep", "keep-upload"),
    }
    return value


@pytest.mark.parametrize("target", [RUN, PREFIX, PREFIX.removesuffix("/")])
def test_preview_accepts_ids_and_prefixes_without_mutation(
    storage: Storage, target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    cleanup.run(storage.client(), bucket=BUCKET, targets=[target], apply=False)
    assert not storage.operations
    output = capsys.readouterr().out
    assert (
        f"{BUCKET}/{PREFIX}: 2 current objects, 4 versions, 1 delete markers, 3 unfinished uploads"
        in output
    )
    assert "Preview only" in output


def test_purges_paginated_versions_markers_and_uploads_leaving_neighbors(storage: Storage) -> None:
    cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    assert storage.versions == {
        ("restic/production", "production-version"): "version",
        (OTHER_PREFIX + "restic/data/keep", "other-version"): "version",
        (PREFIX.removesuffix("/") + "-neighbor/data", "neighbor-version"): "version",
    }
    assert storage.uploads == {(OTHER_PREFIX + "restic/data/keep", "keep-upload")}
    assert storage.operations[-1] == ("delete", PREFIX + "owner.json", "owner-version")
    assert len(storage.operations) == 8  # noqa: PLR2004 - five versions plus three uploads
    assert all(key.startswith(PREFIX) for _, key, _ in storage.operations)


def test_multiple_selected_runs_and_duplicates(storage: Storage) -> None:
    cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN, PREFIX, OTHER_RUN], apply=True)
    assert not storage.uploads
    assert len(storage.operations) == len(set(storage.operations)) == 10  # noqa: PLR2004
    assert {key for key, _version in storage.versions} == {
        "restic/production",
        PREFIX.removesuffix("/") + "-neighbor/data",
    }


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "m3-11-qualification/",
        "restic/production/",
        "m3-1-qualification/" + RUN + "/",
        PREFIX + "restic/",
        PREFIX + "../",
        PREFIX + "/",
        RUN + "/",
        "s3://" + BUCKET + "/" + PREFIX,
        RUN.upper(),
        RUN.replace("7000", "4000"),
    ],
)
def test_invalid_or_broad_prefix_rejected_before_any_remote_request(
    storage: Storage, invalid: str
) -> None:
    client = storage.client()
    with pytest.raises(cleanup.DiscardError, match="targets must"):
        cleanup.run(client, bucket=BUCKET, targets=[RUN, invalid], apply=True)
    assert not client.mock_calls


def test_failed_second_inventory_prevents_all_deletion(storage: Storage) -> None:
    client = storage.client()
    client.list_multipart_uploads.side_effect = [
        storage.upload_list(Prefix=PREFIX),
        OSError("unavailable"),
    ]
    with pytest.raises(OSError):
        cleanup.run(client, bucket=BUCKET, targets=[RUN, OTHER_RUN], apply=True)
    assert not storage.operations


def test_nonversioned_bucket_prevents_deletion(storage: Storage) -> None:
    client = storage.client()
    client.get_bucket_versioning.return_value = {"Status": "Suspended"}
    with pytest.raises(ArchiveQualificationError, match="versioning"):
        cleanup.run(client, bucket=BUCKET, targets=[RUN], apply=True)
    assert not storage.operations


@pytest.mark.parametrize(
    "listing", ["list_objects_v2", "list_object_versions", "list_multipart_uploads"]
)
def test_provider_listing_outside_selected_prefix_is_rejected(
    storage: Storage, listing: str
) -> None:
    client = storage.client()
    response = {
        "list_objects_v2": {"IsTruncated": False, "Contents": [{"Key": "restic/production"}]},
        "list_object_versions": {
            "IsTruncated": False,
            "Versions": [{"Key": "restic/production", "VersionId": "version"}],
        },
        "list_multipart_uploads": {
            "IsTruncated": False,
            "Uploads": [{"Key": "restic/production", "UploadId": "upload"}],
        },
    }
    operation = getattr(client, listing)
    operation.side_effect = None
    operation.return_value = response[listing]
    with pytest.raises(ArchiveQualificationError, match="escaped"):
        cleanup.run(client, bucket=BUCKET, targets=[RUN], apply=True)
    assert not storage.operations


def test_changed_inventory_stops_before_first_deletion(storage: Storage) -> None:
    client = storage.client()
    calls = 0

    def version_list(**request: object) -> dict[str, object]:
        nonlocal calls
        if "KeyMarker" not in request:
            calls += 1
        if calls > 1:
            storage.versions[PREFIX + "restic/new-writer", "new-version"] = "version"
        return storage.version_list(**request)

    client.list_object_versions.side_effect = version_list
    with pytest.raises(cleanup.DiscardError, match="changed since inventory"):
        cleanup.run(client, bucket=BUCKET, targets=[RUN], apply=True)
    assert not storage.operations


def test_write_during_deletion_fails_and_retains_owner(storage: Storage) -> None:
    storage.late_write = True
    with pytest.raises(cleanup.DiscardError, match="owner marker was retained"):
        cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    assert (PREFIX + "owner.json", "owner-version") in storage.versions


def test_write_after_owner_deletion_fails_final_absence_check(storage: Storage) -> None:
    storage.late_write_after = "owner-version"
    with pytest.raises(cleanup.DiscardError, match="not empty after deletion"):
        cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    assert (PREFIX + "restic/new-writer", "new-version") in storage.versions


def test_silent_incomplete_provider_deletion_retains_owner(storage: Storage) -> None:
    client = storage.client()
    client.delete_object.side_effect = None
    client.delete_object.return_value = {}
    with pytest.raises(cleanup.DiscardError, match="data remains"):
        cleanup.run(client, bucket=BUCKET, targets=[RUN], apply=True)
    assert (PREFIX + "owner.json", "owner-version") in storage.versions
    assert all(
        call.kwargs["Key"] != PREFIX + "owner.json" for call in client.delete_object.call_args_list
    )


@pytest.mark.parametrize("identity", ["old-version", "upload-1", "owner-version"])
def test_rerun_after_lost_response_finishes_without_local_run_files(
    storage: Storage, identity: str
) -> None:
    storage.fail_after = identity
    with pytest.raises(OSError, match="response lost"):
        cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    cleanup.run(storage.client(), bucket=BUCKET, targets=[PREFIX], apply=True)
    assert not any(key.startswith(PREFIX) for key, _version in storage.versions)
    assert not any(key.startswith(PREFIX) for key, _upload in storage.uploads)
    assert len(storage.operations) == len(set(storage.operations))


def test_existing_markers_without_owner_and_already_empty_prefix_can_be_discarded(
    storage: Storage,
) -> None:
    storage.versions = {(PREFIX + "restic/deleted", "marker"): "delete-marker"}
    storage.uploads.clear()
    cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    assert storage.operations == [("delete", PREFIX + "restic/deleted", "marker")]


def test_inventory_is_not_limited_to_old_1024_entry_gate(storage: Storage) -> None:
    count = 1100
    storage.versions = {
        (PREFIX + "restic/data/large", f"v{index:04}"): "version" for index in range(count)
    }
    storage.uploads.clear()
    storage.page_size = 1000
    cleanup.run(storage.client(), bucket=BUCKET, targets=[RUN], apply=True)
    assert len(storage.operations) == count
    assert not storage.versions


@pytest.fixture
def private_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    values = {
        "SPACES_REGION": "ams3",
        "SPACES_BACKUP_BUCKET": BUCKET,
        "SPACES_ACCESS_KEY_ID": "example-operator-key",
        "SPACES_SECRET_ACCESS_KEY": "example-operator-secret",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    yield


def test_cli_defaults_to_preview_and_uses_explicit_operator_credentials(
    private_environment: None, monkeypatch: pytest.MonkeyPatch, storage: Storage
) -> None:
    factory = Mock(return_value=storage.client())
    monkeypatch.setattr(cleanup, "create_client", factory)
    assert cleanup.main([RUN]) == 0
    assert not storage.operations
    factory.assert_called_once_with(
        access_key_id="example-operator-key",
        secret_access_key=FAKE_SECRET,
        region="ams3",
        endpoint_url="https://ams3.digitaloceanspaces.com",
    )
    assert cleanup.main(["--discard", RUN]) == 0
    assert storage.operations


@pytest.mark.parametrize(
    "arguments",
    [
        ["--bucket", "https://wrong", RUN],
        ["--region", "../", RUN],
        [PREFIX + "restic/"],
        ["--bucket", "127.0.0.1", RUN],
    ],
)
def test_invalid_cli_configuration_never_creates_client(
    private_environment: None, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    factory = Mock()
    monkeypatch.setattr(cleanup, "create_client", factory)
    assert cleanup.main(arguments) == 1
    factory.assert_not_called()


def test_missing_operator_credentials_prevents_client_creation(
    private_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SPACES_SECRET_ACCESS_KEY")
    factory = Mock()
    monkeypatch.setattr(cleanup, "create_client", factory)
    assert cleanup.main([RUN]) == 1
    factory.assert_not_called()


def test_provider_errors_do_not_print_credentials(
    private_environment: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cleanup, "create_client", Mock(side_effect=RuntimeError("example-operator-secret"))
    )
    assert cleanup.main([RUN]) == 1
    output = capsys.readouterr().err
    assert "RuntimeError" in output
    assert "example-operator-secret" not in output
