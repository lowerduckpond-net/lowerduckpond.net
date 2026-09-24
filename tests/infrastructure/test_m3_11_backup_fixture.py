from __future__ import annotations

import io
import uuid
from collections.abc import Iterator
from dataclasses import replace

import pytest
from botocore.stub import Stubber  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import ArchiveQualificationError, S3Client, create_client

from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.production_qualification_inputs import POLICY, storage_target_digest


@pytest.fixture
def target() -> Target:
    return Target(str(uuid.uuid7()), "ams3", "fixture-backups", "fixture-archives")


@pytest.fixture
def binding(target: Target) -> dict[str, object]:
    return {
        "source_revision": "a" * 40,
        "artifact_sha256": "b" * 64,
        "input_policy": POLICY,
        "qualification_inputs_sha256": "c" * 64,
        "storage_target_sha256": target.storage_target_sha256,
    }


@pytest.fixture
def clients() -> Iterator[tuple[S3Client, S3Client, Stubber, Stubber]]:
    writer, observer = (
        create_client(
            access_key_id=key,
            secret_access_key="disposable-fixture-secret",  # noqa: S106 - intercepted SDK fixture
            region="ams3",
            endpoint_url="https://ams3.digitaloceanspaces.com",
        )
        for key in ("fixture-backup-key", "fixture-observer-key")
    )
    with Stubber(writer) as writer_stub, Stubber(observer) as observer_stub:
        yield writer, observer, writer_stub, observer_stub
        writer_stub.assert_no_pending_responses()
        observer_stub.assert_no_pending_responses()


def empty(stub: Stubber, target: Target) -> None:
    stub.add_response(
        "get_bucket_versioning", {"Status": "Enabled"}, {"Bucket": target.backup_bucket}
    )
    stub.add_response(
        "list_objects_v2",
        {"IsTruncated": False},
        {
            "Bucket": target.backup_bucket,
            "Prefix": target.prefix,
            "MaxKeys": 1000,
        },
    )
    stub.add_response(
        "list_object_versions",
        {"IsTruncated": False},
        {
            "Bucket": target.backup_bucket,
            "Prefix": target.prefix,
            "MaxKeys": 1000,
        },
    )
    stub.add_response(
        "list_multipart_uploads",
        {"IsTruncated": False},
        {
            "Bucket": target.backup_bucket,
            "Prefix": target.prefix,
            "MaxUploads": 1000,
        },
    )


def owner(
    stub: Stubber, target: Target, binding: dict[str, object], *, content: bytes | None = None
) -> io.BytesIO:
    raw = canonical_bytes(target.manifest(binding))
    body = io.BytesIO(raw if content is None else content)
    stub.add_response(
        "list_object_versions",
        {
            "IsTruncated": False,
            "Versions": [
                {"Key": target.owner_key, "VersionId": "original-version"},
            ],
        },
        {"Bucket": target.backup_bucket, "Prefix": target.owner_key, "MaxKeys": 1000},
    )
    stub.add_response(
        "get_object",
        {"VersionId": "original-version", "Body": body, "ContentLength": len(raw)},
        {
            "Bucket": target.backup_bucket,
            "Key": target.owner_key,
            "VersionId": "original-version",
        },
    )
    return body


def put(
    stub: Stubber, target: Target, binding: dict[str, object], *, version: str = "original-version"
) -> None:
    stub.add_response(
        "put_object",
        {"VersionId": version},
        {
            "Bucket": target.backup_bucket,
            "Key": target.owner_key,
            "Body": canonical_bytes(target.manifest(binding)),
            "ContentType": "application/json",
        },
    )


def test_prefix_is_derived_and_storage_binding_matches_existing_policy(
    target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        target.repository
        == f"s3:https://ams3.digitaloceanspaces.com/fixture-backups/m3-11-qualification/{target.run_id}/restic"
    )
    assert "backups/lowerduckpond-production-01" not in target.repository
    monkeypatch.setenv("SPACES_REGION", target.region)
    monkeypatch.setenv("SPACES_BACKUP_BUCKET", target.backup_bucket)
    monkeypatch.setenv("SPACES_ARCHIVE_BUCKET", target.archive_bucket)
    assert target.storage_target_sha256 == storage_target_digest()


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "../backups/lowerduckpond-production-01"),
        ("run_id", str(uuid.uuid4())),
        ("region", "ams3/path"),
        ("backup_bucket", "bucket/path"),
        ("backup_bucket", "127.0.0.1"),
        ("backup_bucket", "a..b"),
        ("archive_bucket", "fixture-backups"),
    ],
)
def test_no_caller_selected_or_ambiguous_repository_boundary(
    target: Target, field: str, value: str
) -> None:
    with pytest.raises(ValueError):
        replace(target, **{field: value})


def test_ownership_requires_empty_views_and_exact_version_from_both_clients(
    target: Target, binding: dict[str, object], clients: tuple[S3Client, S3Client, Stubber, Stubber]
) -> None:
    writer, observer, write_stub, observe_stub = clients
    empty(write_stub, target)
    empty(observe_stub, target)
    put(write_stub, target, binding)
    bodies = (owner(write_stub, target, binding), owner(observe_stub, target, binding))
    assert target.begin(writer, observer, binding) == "original-version"
    assert all(body.closed for body in bodies)


def test_independent_observer_disagreement_preserves_created_ownership(
    target: Target, binding: dict[str, object], clients: tuple[S3Client, S3Client, Stubber, Stubber]
) -> None:
    writer, observer, write_stub, observe_stub = clients
    empty(write_stub, target)
    empty(observe_stub, target)
    put(write_stub, target, binding)
    owner(write_stub, target, binding)
    body = owner(observe_stub, target, binding, content=b"foreign context")
    with pytest.raises(ValueError, match="ownership changed"):
        target.begin(writer, observer, binding)
    assert body.closed  # No deletion, overwrite or hidden ownership retry was attempted.


def test_existing_remote_bytes_prevent_ownership_write(
    target: Target, binding: dict[str, object], clients: tuple[S3Client, S3Client, Stubber, Stubber]
) -> None:
    writer, observer, stub, _ = clients
    stub.add_response(
        "get_bucket_versioning", {"Status": "Enabled"}, {"Bucket": target.backup_bucket}
    )
    stub.add_response(
        "list_objects_v2",
        {"IsTruncated": False, "Contents": [{"Key": target.prefix + "restic/config"}]},
        {
            "Bucket": target.backup_bucket,
            "Prefix": target.prefix,
            "MaxKeys": 1000,
        },
    )
    with pytest.raises(ArchiveQualificationError, match="current objects"):
        target.begin(writer, observer, binding)


@pytest.mark.parametrize(
    "fault", ["wrong-version", "delete-marker", "duplicate", "prefix-neighbor"]
)
def test_ambiguous_or_replaced_owner_cannot_authorize_reuse(
    target: Target,
    binding: dict[str, object],
    clients: tuple[S3Client, S3Client, Stubber, Stubber],
    fault: str,
) -> None:
    writer, _, stub, _ = clients
    original = {"Key": target.owner_key, "VersionId": "original-version"}
    response: dict[str, object] = {"IsTruncated": False, "Versions": [original]}
    if fault == "wrong-version":
        response["Versions"] = [{**original, "VersionId": "replacement"}]
    elif fault == "delete-marker":
        response["DeleteMarkers"] = [{**original, "VersionId": "deleted"}]
    elif fault == "duplicate":
        response["Versions"] = [original, {**original, "VersionId": "older"}]
    else:
        response["Versions"] = [{**original, "Key": target.owner_key + "-neighbor"}]
    stub.add_response(
        "list_object_versions",
        response,
        {
            "Bucket": target.backup_bucket,
            "Prefix": target.owner_key,
            "MaxKeys": 1000,
        },
    )
    with pytest.raises(ValueError, match="missing or ambiguous"):
        target.require_owner(writer, binding, version="original-version")


@pytest.mark.parametrize(
    "field",
    [
        "artifact_sha256",
        "qualification_inputs_sha256",
        "input_policy",
        "source_revision",
        "storage_target_sha256",
    ],
)
def test_invalid_captured_binding_never_reaches_the_provider(
    target: Target,
    binding: dict[str, object],
    clients: tuple[S3Client, S3Client, Stubber, Stubber],
    field: str,
) -> None:
    writer, observer, _, _ = clients
    binding[field] = "foreign"
    with pytest.raises(ValueError):
        target.begin(writer, observer, binding)


def test_single_client_cannot_claim_independent_observation(
    target: Target, binding: dict[str, object], clients: tuple[S3Client, S3Client, Stubber, Stubber]
) -> None:
    writer, _, _, _ = clients
    with pytest.raises(ValueError, match="independent observer"):
        target.begin(writer, writer, binding)


@pytest.mark.parametrize("version", ["null", "", "bad\nversion", "x" * 1025])
def test_missing_or_ambiguous_version_never_authorizes_restic(
    target: Target,
    binding: dict[str, object],
    clients: tuple[S3Client, S3Client, Stubber, Stubber],
    version: str,
) -> None:
    writer, observer, write_stub, observe_stub = clients
    empty(write_stub, target)
    empty(observe_stub, target)
    put(write_stub, target, binding, version=version)
    with pytest.raises(ValueError, match="version is invalid"):
        target.begin(writer, observer, binding)


@pytest.fixture
def environment(target: Target) -> dict[str, str]:
    return {
        "SPACES_REGION": target.region,
        "SPACES_BACKUP_BUCKET": target.backup_bucket,
        "SPACES_ARCHIVE_BUCKET": target.archive_bucket,
        "SPACES_BACKUP_ACCESS_KEY_ID": "fixture-runtime-key",
        "SPACES_BACKUP_SECRET_ACCESS_KEY": "fixture-runtime-secret",
        "SPACES_ACCESS_KEY_ID": "fixture-operator-key",
        "SPACES_SECRET_ACCESS_KEY": "fixture-operator-secret",
        "AWS_ACCESS_KEY_ID": "unrelated-ambient-key",
        "AWS_ENDPOINT_URL": "http://untrusted.invalid",
    }


def test_live_clients_use_only_distinct_explicit_keys_and_bound_https_endpoint(
    target: Target,
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    clients: tuple[S3Client, S3Client, Stubber, Stubber],
) -> None:
    writer, observer, _, _ = clients
    observed = []

    def create(**kwargs: str) -> S3Client:
        observed.append(kwargs)
        return writer if len(observed) == 1 else observer

    monkeypatch.setattr("scripts.m3_11_backup_fixture.create_client", create)
    assert target.clients(environment) == (writer, observer)
    assert observed == [
        {
            "access_key_id": "fixture-runtime-key",
            "secret_access_key": "fixture-runtime-secret",
            "region": target.region,
            "endpoint_url": "https://ams3.digitaloceanspaces.com",
        },
        {
            "access_key_id": "fixture-operator-key",
            "secret_access_key": "fixture-operator-secret",
            "region": target.region,
            "endpoint_url": "https://ams3.digitaloceanspaces.com",
        },
    ]


@pytest.mark.parametrize(
    "key,value",
    [
        ("SPACES_REGION", "nyc3"),
        ("SPACES_BACKUP_BUCKET", "foreign-bucket"),
        ("SPACES_ARCHIVE_BUCKET", "foreign-archives"),
        ("SPACES_BACKUP_ACCESS_KEY_ID", ""),
        ("SPACES_BACKUP_SECRET_ACCESS_KEY", ""),
        ("SPACES_ACCESS_KEY_ID", "fixture-runtime-key"),
        ("SPACES_SECRET_ACCESS_KEY", ""),
    ],
)
def test_live_clients_reject_changed_target_missing_or_shared_credentials_before_sdk_creation(
    target: Target,
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
) -> None:
    environment[key] = value

    def forbidden(**kwargs: str) -> S3Client:
        raise AssertionError("invalid credential boundary reached SDK construction")

    monkeypatch.setattr("scripts.m3_11_backup_fixture.create_client", forbidden)
    with pytest.raises(ValueError):
        target.clients(environment)
