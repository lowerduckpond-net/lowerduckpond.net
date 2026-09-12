from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.archive_configuration import (
    ArchiveConfigurationError,
    load_archive_configuration,
)


def _document() -> dict[str, object]:
    return {
        "format": "lowerduckpond-archive-configuration-v1",
        "region": "nyc3",
        "bucket": "example-tenant-archives",
        "accessKeyId": "fixture-archive-access",
        "secretAccessKey": "fixture-archive-secret",
    }


def _file(tmp_path: Path, document: dict[str, object] | None = None) -> Path:
    private = tmp_path / "archive"
    private.mkdir(mode=0o700)
    path = private / "credentials.json"
    path.write_text(json.dumps(_document() if document is None else document), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_archive_configuration_uses_only_explicit_dedicated_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(name, "ambient-fixture")
    configured = load_archive_configuration(_file(tmp_path), expected_owner=os.geteuid())
    assert configured.region == "nyc3"
    assert configured.bucket == "example-tenant-archives"
    assert "fixture-archive-access" not in repr(configured)
    assert "fixture-archive-secret" not in repr(configured)
    remote = configured.remote_store()
    credentials = remote.client._request_signer._credentials  # type: ignore[attr-defined]
    assert credentials.access_key == "fixture-archive-access"
    assert credentials.secret_key == _document()["secretAccessKey"]
    assert credentials.token is None
    assert remote.client.meta.endpoint_url == "https://nyc3.digitaloceanspaces.com"  # type: ignore[attr-defined]


@pytest.mark.parametrize("target", ["directory", "file"])
def test_archive_configuration_rejects_read_access_for_other_accounts(
    tmp_path: Path, target: str
) -> None:
    path = _file(tmp_path)
    if target == "directory":
        path.parent.chmod(0o755)
    else:
        path.chmod(0o640)
    with pytest.raises(ArchiveConfigurationError):
        load_archive_configuration(path, expected_owner=os.geteuid())


def test_archive_configuration_rejects_other_ownership(tmp_path: Path) -> None:
    with pytest.raises(ArchiveConfigurationError):
        load_archive_configuration(_file(tmp_path), expected_owner=os.geteuid() + 1)


@pytest.mark.parametrize("substitution", ["symlink", "hardlink", "directory"])
def test_archive_configuration_rejects_unsafe_file_identity(
    tmp_path: Path, substitution: str
) -> None:
    path = _file(tmp_path)
    if substitution == "hardlink":
        os.link(path, tmp_path / "alias")
    else:
        source = tmp_path / "source"
        path.rename(source)
        if substitution == "symlink":
            path.symlink_to(source)
        else:
            path.mkdir(mode=0o700)
    with pytest.raises(ArchiveConfigurationError):
        load_archive_configuration(path, expected_owner=os.geteuid())


@pytest.mark.parametrize(
    "encoded", [b"{}", b"\xff", b'{"format":"one","format":"two"}', b" " * 4097]
)
def test_archive_configuration_rejects_malformed_or_oversized_data(
    tmp_path: Path, encoded: bytes
) -> None:
    path = _file(tmp_path)
    path.write_bytes(encoded)
    with pytest.raises(ArchiveConfigurationError):
        load_archive_configuration(path, expected_owner=os.geteuid())


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("format", "other-format"),
        ("region", "https://other.invalid"),
        ("region", "us-east-1"),
        ("bucket", "other.example/bucket"),
        ("accessKeyId", ""),
        ("secretAccessKey", "line\nbreak"),
        ("secretAccessKey", " padded "),
        ("secretAccessKey", "x" * 1025),
        ("secretAccessKey", True),
        ("endpoint", "https://other.invalid"),
    ],
)
def test_archive_configuration_rejects_invalid_or_extra_fields(
    tmp_path: Path, field_name: str, value: object
) -> None:
    document = _document()
    document[field_name] = value
    with pytest.raises(ArchiveConfigurationError):
        load_archive_configuration(_file(tmp_path, document), expected_owner=os.geteuid())


def test_missing_private_configuration_does_not_fall_back_to_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, "ambient-fixture")
    private = tmp_path / "archive"
    private.mkdir(mode=0o700)
    with pytest.raises(ArchiveConfigurationError):
        load_archive_configuration(private / "missing.json", expected_owner=os.geteuid())
