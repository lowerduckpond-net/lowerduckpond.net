"""Actual CLI failures retain useful facts without provider-controlled text."""

from __future__ import annotations

import errno
import json
import sys
import time
from http import HTTPStatus
from pathlib import Path
from typing import cast
from urllib.error import URLError

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive import storage as archive_storage
from lowerduckpond_m3_archive.storage import ArchiveQualificationError, S3Client

from scripts import check_m3_10_provider as provider
from scripts import provider_preflight_diagnostics as diagnostics
from scripts import qualification_failure
from scripts.cloudflare_read_diagnostics import MAX_CHAIN

from .test_m3_10_production_gate import Storage

PRIVATE_MODE = 0o600
SENTINEL = "private-credential-in-url-header-body-and-key"


def configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, storage: Storage) -> None:
    monkeypatch.setattr(sys, "argv", ["provider", "--storage-only"])
    for key, value in {
        "SPACES_REGION": "nyc3",
        "SPACES_ARCHIVE_BUCKET": "archive-fixture",
        "SPACES_ACCESS_KEY_ID": "synthetic-operator",
        "SPACES_SECRET_ACCESS_KEY": SENTINEL,
        "LDP_QUALIFICATION_TIMING_EVENTS": str(tmp_path / "timing-events.jsonl"),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(provider, "make_policy_client", lambda _configuration: storage)


@pytest.mark.parametrize(
    ("operation", "response", "reason", "function"),
    [
        (
            "get_bucket_versioning",
            {"Status": "Suspended"},
            "versioning-not-enabled",
            "assert_versioning_enabled",
        ),
        (
            "list_objects_v2",
            {"Contents": [{"Key": SENTINEL}]},
            "current-objects-present",
            "assert_storage_empty",
        ),
        (
            "list_object_versions",
            {"Versions": [{"Key": SENTINEL, "VersionId": SENTINEL}]},
            "versions-or-markers-present",
            "assert_storage_empty",
        ),
        (
            "list_object_versions",
            {"DeleteMarkers": [{"Key": SENTINEL, "VersionId": SENTINEL}]},
            "versions-or-markers-present",
            "assert_storage_empty",
        ),
        (
            "list_multipart_uploads",
            {"Uploads": [{"Key": SENTINEL, "UploadId": SENTINEL}]},
            "multipart-uploads-present",
            "assert_storage_empty",
        ),
        (
            "list_objects_v2",
            {"Contents": SENTINEL},
            "unclassified-storage-contract",
            "_mapping_list",
        ),
    ],
)
def test_required_empty_failure_retains_exact_reason_and_location(  # noqa: PLR0913, PLR0917
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    operation: str,
    response: object,
    reason: str,
    function: str,
) -> None:
    storage = Storage()
    storage.responses[operation] = {
        **cast(dict[str, object], storage.responses[operation]),
        **cast(dict[str, object], response),
    }
    configure(monkeypatch, tmp_path, storage)
    assert provider.main() == 1
    path = tmp_path / "failure-provider-preflight.json"
    raw = path.read_text()
    value = json.loads(raw)
    assert value["authority"] == "diagnostic-only"
    assert value["phase"] == "storage"
    assert value["invocation_attempt"] == 1
    assert value["elapsed_seconds"] >= 0
    node = value["exception_chain"]["nodes"][0]
    assert node["type"] == "ArchiveQualificationError"
    assert node["reason"] == reason
    assert node["source"]["function"] == function
    assert node["source"]["line"] > 0
    assert SENTINEL not in raw + capsys.readouterr().err
    assert path.stat().st_mode & 0o777 == PRIVATE_MODE
    assert all(call.startswith(("get_", "list_")) for call in storage.calls)


def test_provider_metadata_and_wrapped_errno_exclude_response_payloads() -> None:
    error = ClientError(
        {
            "Error": {"Code": "AccessDenied", "Message": SENTINEL},
            "ResponseMetadata": {
                "HTTPStatusCode": 403,
                "RetryAttempts": 0,
                "HTTPHeaders": {"authorization": SENTINEL},
                "RequestId": SENTINEL,
            },
        },
        "ListObjectsV2",
    )
    transport = EndpointConnectionError(
        endpoint_url="https://" + SENTINEL, error=OSError(errno.ENETUNREACH, SENTINEL)
    )
    error.__cause__ = transport
    value = diagnostics.exception_facts(error)
    nodes = cast(list[dict[str, object]], value["nodes"])
    assert nodes[0]["http_status"] == HTTPStatus.FORBIDDEN
    assert nodes[0]["provider_code"] == "AccessDenied"
    assert nodes[0]["operation"] == "ListObjectsV2"
    assert nodes[0]["sdk_retry_count"] == 0
    assert nodes[1]["type"] == "EndpointConnectionError"
    assert nodes[2]["relation"] == "transport"
    assert nodes[2]["errno"] == errno.ENETUNREACH
    assert SENTINEL not in json.dumps(value)


def test_unknown_payloads_cycles_and_chain_length_are_bounded() -> None:
    class UnexpectedError(RuntimeError):
        pass

    UnexpectedError.__name__ = SENTINEL
    error: BaseException = ArchiveQualificationError(SENTINEL)
    error.__cause__ = UnexpectedError(SENTINEL)
    error.__cause__.__cause__ = error
    value = diagnostics.exception_facts(error)
    assert value["repeated"] is True
    assert SENTINEL not in json.dumps(value)
    for _ in range(MAX_CHAIN + 1):
        next_error = RuntimeError(SENTINEL)
        next_error.__cause__ = error
        error = next_error
    value = diagnostics.exception_facts(error)
    assert len(cast(list[object], value["nodes"])) == MAX_CHAIN
    assert value["truncated"] is True
    assert SENTINEL not in json.dumps(value)


def test_url_reasons_and_all_connection_candidates_survive_safe_projection() -> None:
    failures = ExceptionGroup(
        SENTINEL,
        [
            ConnectionRefusedError(errno.ECONNREFUSED, SENTINEL),
            OSError(errno.ENETUNREACH, SENTINEL),
        ],
    )
    value = diagnostics.document(URLError(failures), phase="storage", started=time.monotonic())
    assert diagnostics.verified(value) == value
    nodes = cast(dict[str, list[dict[str, object]]], value["exception_chain"])["nodes"]
    assert nodes[1]["relation"] == "reason"
    assert nodes[1]["type"] == "ExceptionGroup"
    assert [node["errno"] for node in nodes[2:]] == [errno.ECONNREFUSED, errno.ENETUNREACH]
    assert all(node["relation"] == "member" for node in nodes[2:])
    assert SENTINEL not in json.dumps(value)


@pytest.mark.parametrize("elapsed", [True, -1, 10**1000, float("inf"), float("nan")])
def test_safe_helper_boundary_rejects_invalid_numeric_payload(elapsed: object) -> None:
    value = diagnostics.document(ValueError(SENTINEL), phase="storage", started=time.monotonic())
    value["elapsed_seconds"] = elapsed
    with pytest.raises(ValueError, match="invalid provider diagnostic duration"):
        diagnostics.verified(value)


def test_source_alias_retains_location(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    original = Path(str(archive_storage.__file__)).resolve()
    alias = tmp_path / "storage.py"
    alias.symlink_to(original)
    monkeypatch.setattr(archive_storage, "__file__", str(alias))
    client = Storage()
    client.responses["get_bucket_versioning"] = {"Status": "Suspended"}
    with pytest.raises(ArchiveQualificationError) as captured:
        archive_storage.assert_storage_empty(
            cast(S3Client, client), bucket="archive-fixture", prefix=""
        )
    nodes = cast(list[dict[str, object]], diagnostics.exception_facts(captured.value)["nodes"])
    assert cast(dict[str, object], nodes[0]["source"])["function"] == "assert_versioning_enabled"


def test_failed_diagnostic_sink_preserves_cli_failure_and_first_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = Storage()
    storage.responses["get_bucket_versioning"] = {"Status": "Suspended"}
    configure(monkeypatch, tmp_path, storage)
    assert provider.main() == 1
    path = tmp_path / "failure-provider-preflight.json"
    original = path.read_bytes()
    storage.responses["get_bucket_versioning"] = {"Status": "Enabled"}
    storage.responses["list_objects_v2"] = {"Contents": [{"Key": SENTINEL}]}
    assert provider.main() == 1
    assert path.read_bytes() == original

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(SENTINEL)

    monkeypatch.setattr(qualification_failure, "_write", fail)
    assert provider.main() == 1
    monkeypatch.setattr(diagnostics, "document", fail)
    assert provider.main() == 1
    assert SENTINEL not in capsys.readouterr().err
    assert path.read_bytes() == original
