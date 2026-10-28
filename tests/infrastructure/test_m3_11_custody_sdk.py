"""Real SDK event injection, decoded inventory identities and exact request bounds."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit
from xml.sax.saxutils import escape

import pytest
from botocore.awsrequest import AWSResponse  # type: ignore[import-untyped]

from scripts import m3_11_custody_context as native
from scripts.m3_11_retirement_archive import Archives
from scripts.m3_11_retirement_files import RetirementError
from scripts.m3_11_unattended.model import Credential

BUCKET = "test-archives"
KEY = "archives/snow ☃ + 100%/example.zip"
VERSION = "version+%2F==one"
XMLNS = ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'


class Raw:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def stream(self, amt: int | None = None, decode_content: bool = False) -> Iterator[bytes]:
        yield self.body


@pytest.fixture
def owner(monkeypatch: pytest.MonkeyPatch) -> Any:  # noqa: ANN401 - synthetic native state
    value: Any = native.NativeCustody.__new__(native.NativeCustody)
    value.deliveries = {
        "archive": Credential("synthetic-writer", "synthetic-secret", {}),
        "operator": Credential("synthetic-observer", "synthetic-other-secret", {}),
    }
    value.plan = {"archive": {"bucket": BUCKET, "key": KEY, "version": VERSION}}
    value.config = SimpleNamespace(targets=SimpleNamespace(region="nyc3", archive_bucket=BUCKET))
    value.deletes = value.reads = 0
    value.guard = lambda: None
    value.cleanup_current = lambda _seconds: None
    monkeypatch.setattr(native, "require_remaining", lambda _seconds: None)
    return value


def response(operation: str, fault: str | None) -> bytes:
    key = escape(quote(KEY, safe=""))
    truncated = "true" if fault == "truncated" else "false"
    if operation == "versioning":
        body = f"<VersioningConfiguration{XMLNS}><Status>Enabled</Status></VersioningConfiguration>"
    elif operation == "objects":
        body = (
            f"<ListBucketResult{XMLNS}><EncodingType>url</EncodingType>"
            f"<IsTruncated>{truncated}</IsTruncated>"
            f"<Contents><Key>{key}</Key><Size>9</Size></Contents></ListBucketResult>"
        )
    elif operation == "versions":
        extra = (
            "<DeleteMarker><Key>foreign</Key><VersionId>marker</VersionId>"
            "<IsLatest>false</IsLatest></DeleteMarker>"
            if fault == "marker"
            else "<Version><Key>foreign</Key><VersionId>other</VersionId>"
            "<IsLatest>true</IsLatest><Size>9</Size></Version>"
            if fault == "foreign"
            else ""
        )
        body = (
            f"<ListVersionsResult{XMLNS}><EncodingType>url</EncodingType>"
            "<IsTruncated>false</IsTruncated>"
            f"<Version><Key>{key}</Key><VersionId>{escape(VERSION)}</VersionId>"
            f"<IsLatest>true</IsLatest><Size>9</Size></Version>{extra}</ListVersionsResult>"
        )
    else:
        assert operation == "uploads"
        extra = (
            "<Upload><Key>foreign</Key><UploadId>pending</UploadId></Upload>"
            if fault == "upload"
            else ""
        )
        body = (
            f"<ListMultipartUploadsResult{XMLNS}><IsTruncated>false</IsTruncated>"
            f"{extra}</ListMultipartUploadsResult>"
        )
    return body.encode()


@pytest.mark.parametrize("fault", [None, "truncated", "marker", "foreign", "upload"])
def test_real_sdk_injection_and_decoding_preserve_whole_inventory(
    owner: Any,  # noqa: ANN401 - synthetic native state
    monkeypatch: pytest.MonkeyPatch,
    fault: str | None,
) -> None:
    sends: list[tuple[str, str]] = []

    def client(role: str) -> Any:  # noqa: ANN401 - real botocore client
        selected = owner.client(role)

        def send(request: Any) -> AWSResponse:  # noqa: ANN401 - real prepared HTTP request
            url = urlsplit(request.url)
            query = parse_qs(url.query, keep_blank_values=True)
            assert request.method == "GET"
            assert url.scheme == "https" and url.netloc == "nyc3.digitaloceanspaces.com"
            assert url.path == "/" + BUCKET
            if "versioning" in query:
                operation = "versioning"
                assert query == {"versioning": [""]}
            elif "list-type" in query:
                operation = "objects"
                assert query == {"list-type": ["2"], "max-keys": ["26"], "encoding-type": ["url"]}
            elif "versions" in query:
                operation = "versions"
                assert query == {"versions": [""], "max-keys": ["26"], "encoding-type": ["url"]}
            else:
                operation = "uploads"
                assert query == {"uploads": [""], "max-uploads": ["1"]}
            sends.append((role, operation))
            return AWSResponse(request.url, 200, {}, Raw(response(operation, fault)))

        monkeypatch.setattr(selected._endpoint.http_session, "send", send)
        return selected

    archives = Archives(client("archive"), client("operator"), BUCKET)
    if fault is None:
        # The caller omits EncodingType. Exercise Botocore's actual injection
        # and automatic key decoding, while opaque VersionId remains unchanged.
        assert archives.observed() == [(KEY, VERSION)]
        assert sends == [
            (role, operation)
            for role in ("archive", "operator")
            for operation in ("versioning", "objects", "versions", "uploads")
        ]
        assert owner.reads == len(sends)
    else:
        with pytest.raises(RetirementError):
            archives.observed()
    assert owner.deletes == 0


@pytest.mark.parametrize(
    ("method", "parameters"),
    [
        ("list_objects_v2", {"Bucket": "foreign", "MaxKeys": 26}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 27}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 25}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 26, "EncodingType": "plain"}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 26, "Prefix": "archives/"}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 26, "ContinuationToken": "skip"}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 26, "StartAfter": "skip"}),
        ("list_objects_v2", {"Bucket": BUCKET, "MaxKeys": 26, "Delimiter": "/"}),
        ("list_object_versions", {"Bucket": BUCKET, "MaxKeys": 26, "EncodingType": "plain"}),
        ("list_object_versions", {"Bucket": BUCKET, "MaxKeys": 26, "Prefix": "archives/"}),
        ("list_object_versions", {"Bucket": BUCKET, "MaxKeys": 26, "KeyMarker": "skip"}),
        ("list_object_versions", {"Bucket": BUCKET, "MaxKeys": 26, "VersionIdMarker": "skip"}),
        ("list_multipart_uploads", {"Bucket": BUCKET, "MaxUploads": 2}),
        ("list_multipart_uploads", {"Bucket": BUCKET, "MaxUploads": 1, "Prefix": "archives/"}),
        ("list_multipart_uploads", {"Bucket": BUCKET, "MaxUploads": 1, "KeyMarker": "skip"}),
        ("get_bucket_versioning", {"Bucket": BUCKET, "ExpectedBucketOwner": "other"}),
        ("get_object", {"Bucket": BUCKET, "Key": KEY, "VersionId": VERSION}),
        ("delete_object", {"Bucket": BUCKET, "Key": KEY, "VersionId": "foreign"}),
        ("delete_object", {"Bucket": BUCKET, "Key": "foreign", "VersionId": VERSION}),
        ("delete_object", {"Bucket": "foreign", "Key": KEY, "VersionId": VERSION}),
        ("put_object", {"Bucket": BUCKET, "Key": KEY, "Body": b"forbidden"}),
        ("delete_objects", {"Bucket": BUCKET, "Delete": {"Objects": [{"Key": KEY}]}}),
    ],
)
def test_real_sdk_rejects_changed_scope_encoding_and_inventory_bounds_before_http(
    owner: Any,  # noqa: ANN401 - synthetic native state
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    parameters: dict[str, object],
) -> None:
    client = owner.client("archive")

    def forbidden(request: object) -> None:
        pytest.fail("unapproved request reached HTTP transport")

    monkeypatch.setattr(client._endpoint.http_session, "send", forbidden)
    with pytest.raises(RetirementError, match="unapproved"):
        getattr(client, method)(**parameters)
    assert owner.reads == owner.deletes == 0
