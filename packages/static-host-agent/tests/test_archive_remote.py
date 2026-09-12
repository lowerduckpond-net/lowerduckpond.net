from __future__ import annotations

import hashlib
import io
from collections.abc import Iterator, Mapping
from typing import BinaryIO, Protocol, cast

import pytest
from botocore.awsrequest import AWSResponse  # type: ignore[import-untyped]
from botocore.stub import ANY, Stubber  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent.archive_remote import (
    MAX_BUNDLE_BYTES,
    ArchiveCapacityError,
    ArchiveRemoteError,
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
    archive_key,
    make_archive_client,
)

BUCKET = "example-tenant-archives"
KEY = archive_key("0198d17f-6f4a-7000-8000-000000000003")
BODY = b"independently verified bundle bytes"
DIGEST = hashlib.sha256(BODY).hexdigest()


class FakeArchiveClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.pages: list[dict[str, object]] = [{"IsTruncated": False}]
        self.multipart: dict[str, object] = {"IsTruncated": False}
        self.body = io.BytesIO(BODY)
        self.response: dict[str, object] = {
            "Body": self.body,
            "VersionId": "bound-version",
            "ContentLength": len(BODY),
            "Metadata": {"sha256": DIGEST},
        }
        self.put_response: dict[str, object] = {"VersionId": "bound-version"}
        self.put_error: Exception | None = None

    def get_bucket_versioning(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(("versioning", kwargs))
        return {"Status": "Enabled"}

    def list_object_versions(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(("versions", kwargs))
        return self.pages.pop(0)

    def list_multipart_uploads(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(("multipart", kwargs))
        return self.multipart

    def put_object(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(("put", kwargs))
        assert cast(BinaryIO, kwargs["Body"]).read() == BODY
        if self.put_error is not None:
            raise self.put_error
        return self.put_response

    def get_object(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(("get", kwargs))
        return self.response

    def delete_object(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(("delete", kwargs))
        return {"VersionId": kwargs["VersionId"]}


def store(client: FakeArchiveClient) -> ArchiveRemoteStore:
    return ArchiveRemoteStore(client, bucket=BUCKET)


def test_one_known_length_put_then_exact_version_read() -> None:
    client = FakeArchiveClient()
    remote = store(client)
    stream = io.BytesIO(BODY)
    assert remote.put_once(KEY, stream, size=len(BODY), sha256=DIGEST) == "bound-version"
    destination = io.BytesIO()
    remote.read_verified(
        KEY, "bound-version", size=len(BODY), sha256=DIGEST, destination=destination
    )
    assert destination.getvalue() == BODY
    assert client.body.closed
    assert client.calls == [
        (
            "put",
            {
                "Bucket": BUCKET,
                "Key": KEY,
                "Body": stream,
                "ContentLength": len(BODY),
                "ContentType": "application/zip",
                "Metadata": {"sha256": DIGEST},
            },
        ),
        ("get", {"Bucket": BUCKET, "Key": KEY, "VersionId": "bound-version"}),
    ]


@pytest.mark.parametrize("version", [None, "", "null"])
def test_lost_or_unversioned_put_response_never_retries(version: object) -> None:
    client = FakeArchiveClient()
    client.put_response = {"VersionId": version}
    with pytest.raises(ArchiveRemoteError):
        store(client).put_once(KEY, io.BytesIO(BODY), size=len(BODY), sha256=DIGEST)
    assert [name for name, _ in client.calls] == ["put"]


def test_lost_upload_response_is_left_for_durable_reconciliation() -> None:
    client = FakeArchiveClient()
    client.put_error = TimeoutError("response lost after remote commit")
    with pytest.raises(TimeoutError):
        store(client).put_once(KEY, io.BytesIO(BODY), size=len(BODY), sha256=DIGEST)
    assert [name for name, _ in client.calls] == ["put"]


@pytest.mark.parametrize("body", [BODY[:-1], BODY + b"suffix", b"x" * len(BODY)])
def test_upload_is_independently_measured_before_remote_mutation(body: bytes) -> None:
    client = FakeArchiveClient()
    with pytest.raises(ArchiveRemoteError):
        store(client).put_once(KEY, io.BytesIO(body), size=len(BODY), sha256=DIGEST)
    assert not client.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("VersionId", "different"),
        ("VersionId", "null"),
        ("ContentLength", True),
        ("ContentLength", len(BODY) + 1),
        ("Metadata", {}),
        ("DeleteMarker", True),
    ],
)
def test_invalid_read_metadata_always_closes_body(field: str, value: object) -> None:
    client = FakeArchiveClient()
    client.response[field] = value
    with pytest.raises(ArchiveRemoteError):
        store(client).read_verified(KEY, "bound-version", size=len(BODY), sha256=DIGEST)
    assert client.body.closed


@pytest.mark.parametrize("body", [BODY[:-1], BODY + b"suffix", b"x" * len(BODY)])
def test_invalid_read_bytes_always_close_body(body: bytes) -> None:
    client = FakeArchiveClient()
    client.body = io.BytesIO(body)
    client.response["Body"] = client.body
    with pytest.raises(ArchiveRemoteError):
        store(client).read_verified(KEY, "bound-version", size=len(BODY), sha256=DIGEST)
    assert client.body.closed


def test_paginated_listing_accounts_versions_markers_null_and_exact_key_only() -> None:
    client = FakeArchiveClient()
    client.pages = [
        {
            "IsTruncated": True,
            "NextKeyMarker": KEY,
            "NextVersionIdMarker": "one",
            "Versions": [{"Key": KEY, "VersionId": "one", "Size": 10}],
        },
        {
            "IsTruncated": False,
            "Versions": [{"Key": KEY + "extra", "VersionId": "null", "Size": 1}],
            "DeleteMarkers": [{"Key": KEY, "VersionId": "marker"}],
        },
    ]
    assert store(client).list_versions(exact_key=KEY) == (
        RemoteVersion(KEY, "one", 10, False),
        RemoteVersion(KEY, "marker", 0, True),
    )
    assert client.calls[-1][1]["KeyMarker"] == KEY
    assert client.calls[-1][1]["VersionIdMarker"] == "one"


@pytest.mark.parametrize(
    "page",
    [
        {},
        {"IsTruncated": 0},
        {"IsTruncated": True},
        {"IsTruncated": False, "Versions": [{"Key": "outside", "VersionId": "one", "Size": 0}]},
        {"IsTruncated": False, "Versions": [{"Key": KEY, "VersionId": "one", "Size": True}]},
        {"IsTruncated": False, "Versions": [None]},
        {"IsTruncated": False, "Versions": [{}] * 101},
    ],
)
def test_malformed_listing_cannot_prove_absence(page: dict[str, object]) -> None:
    client = FakeArchiveClient()
    client.pages = [page]
    with pytest.raises(ArchiveRemoteError):
        store(client).require_absent(KEY)


def test_repeated_continuation_fails_closed() -> None:
    client = FakeArchiveClient()
    client.pages = [
        {"IsTruncated": True, "NextKeyMarker": KEY, "NextVersionIdMarker": "one"},
    ] * 2
    with pytest.raises(ArchiveRemoteError, match="continuation"):
        store(client).list_versions()


def test_inventory_includes_unknown_keys_outside_the_managed_archive_prefix() -> None:
    client = FakeArchiveClient()
    client.pages = [
        {
            "IsTruncated": False,
            "Versions": [{"Key": "outside/archive-prefix", "VersionId": "unknown", "Size": 10}],
            "DeleteMarkers": [{"Key": "outside/marker", "VersionId": "marker"}],
        }
    ]
    inventory = store(client).inventory()
    assert inventory.versions == (
        RemoteVersion("outside/archive-prefix", "unknown", 10, False),
        RemoteVersion("outside/marker", "marker", 0, True),
    )
    assert client.calls[1][1]["Prefix"] == ""
    with pytest.raises(ArchiveRemoteError, match="reconciliation"):
        inventory.require_reservation(frozenset())


def test_unknown_versions_missing_bound_versions_and_multipart_close_admission() -> None:
    version = RemoteVersion(KEY, "bound", 20, False)
    with pytest.raises(ArchiveRemoteError):
        RemoteInventory((version,), ()).require_reservation(frozenset())
    with pytest.raises(ArchiveRemoteError):
        RemoteInventory((), ()).require_reservation(frozenset({version}))
    with pytest.raises(ArchiveRemoteError):
        RemoteInventory((), ((KEY, "upload"),)).require_reservation(frozenset())


def test_multipart_inventory_preserves_out_of_prefix_identity_for_quarantine() -> None:
    client = FakeArchiveClient()
    client.multipart = {
        "IsTruncated": False,
        "Uploads": [{"Key": "unexpected/outside-prefix", "UploadId": "known-upload"}],
    }
    inventory = store(client).inventory()
    assert inventory.multipart_uploads == (("unexpected/outside-prefix", "known-upload"),)
    assert client.calls[-1][1]["Prefix"] == ""
    with pytest.raises(ArchiveRemoteError):
        inventory.require_reservation(frozenset())


def test_full_reservation_and_all_version_sizes_are_charged() -> None:
    entries = tuple(
        RemoteVersion(f"archives/{number}", str(number), MAX_BUNDLE_BYTES, False)
        for number in range(24)
    )
    RemoteInventory(entries, ()).require_reservation(frozenset(entries))
    for excess in (
        (*entries, RemoteVersion(KEY, "marker", 0, True)),
        (RemoteVersion(KEY, "large", 3000 * 1024 * 1024 - MAX_BUNDLE_BYTES + 1, False),),
    ):
        with pytest.raises(ArchiveCapacityError):
            RemoteInventory(excess, ()).require_reservation(frozenset(excess))


def test_purge_deletes_each_exact_version_and_marker_then_confirms_absence() -> None:
    client = FakeArchiveClient()
    client.pages = [
        {
            "IsTruncated": False,
            "Versions": [{"Key": KEY, "VersionId": "null", "Size": 1}],
            "DeleteMarkers": [{"Key": KEY, "VersionId": "marker"}],
        },
        {"IsTruncated": False},
    ]
    guards: list[str] = []
    store(client).purge_unbound(KEY, require_unbound=guards.append)
    assert [name for name, _ in client.calls] == ["versions", "delete", "delete", "versions"]
    assert [request for name, request in client.calls if name == "delete"] == [
        {"Bucket": BUCKET, "Key": KEY, "VersionId": "null"},
        {"Bucket": BUCKET, "Key": KEY, "VersionId": "marker"},
    ]
    assert guards == [KEY] * 4


def test_bound_key_cannot_be_deleted() -> None:
    client = FakeArchiveClient()

    def bound(key: str) -> None:
        raise ArchiveRemoteError("still bound")

    with pytest.raises(ArchiveRemoteError, match="still bound"):
        store(client).purge_unbound(KEY, require_unbound=bound)
    assert not client.calls


def test_real_sdk_configuration_and_service_model_prohibit_implicit_upload_retries() -> None:
    client = make_archive_client(
        region="nyc3",
        access_key_id="fixture",
        secret_access_key="fixture",  # noqa: S106
    )
    meta = client.meta  # type: ignore[attr-defined]
    assert meta.endpoint_url == "https://nyc3.digitaloceanspaces.com"
    assert meta.config.retries == {"total_max_attempts": 1, "mode": "standard"}
    assert meta.config.proxies == {}
    assert client._endpoint.http_session._verify == "/etc/ssl/certs/ca-certificates.crt"  # type: ignore[attr-defined]
    with Stubber(client) as stub:
        stub.add_response(
            "put_object",
            {"VersionId": "version"},
            {
                "Bucket": BUCKET,
                "Key": KEY,
                "Body": ANY,
                "ContentLength": len(BODY),
                "ContentType": "application/zip",
                "Metadata": {"sha256": DIGEST},
            },
        )
        remote = ArchiveRemoteStore(client, bucket=BUCKET)
        assert remote.put_once(KEY, io.BytesIO(BODY), size=len(BODY), sha256=DIGEST) == "version"
        stub.assert_no_pending_responses()


class _ResponseBody(io.BytesIO):
    def stream(self) -> Iterator[bytes]:
        yield self.read()


class _PreparedRequest(Protocol):
    url: str


@pytest.mark.parametrize(
    ("status", "headers", "body", "error"),
    [
        (
            301,
            {"x-amz-bucket-region": "us-west-2"},
            b"<Error><Code>PermanentRedirect</Code></Error>",
            "automatic retry",
        ),
        (307, {"x-amz-bucket-region": "us-west-2"}, b"", "automatic retry"),
        (
            400,
            {},
            b"<Error><Code>AuthorizationHeaderMalformed</Code><Region>us-west-2</Region></Error>",
            "automatic retry",
        ),
        (301, {}, b"<Error><Code>PermanentRedirect</Code></Error>", "not permitted"),
    ],
)
def test_sdk_redirects_cannot_repeat_upload_or_discover_a_bucket_region(
    status: int, headers: dict[str, str], body: bytes, error: str
) -> None:
    client = make_archive_client(
        region="nyc3",
        access_key_id="fixture",
        secret_access_key="fixture",  # noqa: S106
    )
    attempts: list[str] = []

    def respond(request: object, **_kwargs: object) -> object:
        url = cast(_PreparedRequest, request).url
        attempts.append(url)
        if len(attempts) == 1:
            return AWSResponse(url, status, headers, _ResponseBody(body))
        return AWSResponse(url, 200, {"x-amz-version-id": "extra-version"}, _ResponseBody())

    client.meta.events.register("before-send.s3", respond)  # type: ignore[attr-defined]
    with pytest.raises(ArchiveRemoteError, match=error):
        ArchiveRemoteStore(client, bucket=BUCKET).put_once(
            KEY, io.BytesIO(BODY), size=len(BODY), sha256=DIGEST
        )
    assert attempts == [f"https://nyc3.digitaloceanspaces.com/{BUCKET}/{KEY}"]


@pytest.mark.parametrize(
    ("operation", "parameters"),
    [
        ("head_bucket", {"Bucket": BUCKET}),
        ("create_multipart_upload", {"Bucket": BUCKET, "Key": KEY}),
    ],
)
def test_sdk_implicit_and_multipart_operations_are_blocked_before_transmission(
    operation: str, parameters: dict[str, object]
) -> None:
    client = make_archive_client(
        region="nyc3",
        access_key_id="fixture",
        secret_access_key="fixture",  # noqa: S106
    )
    attempts: list[object] = []

    def respond(request: object, **_kwargs: object) -> object:
        attempts.append(request)
        return AWSResponse(cast(_PreparedRequest, request).url, 200, {}, _ResponseBody())

    client.meta.events.register("before-send.s3", respond)  # type: ignore[attr-defined]
    with pytest.raises(ArchiveRemoteError, match="not permitted"):
        getattr(client, operation)(**parameters)
    assert not attempts


def test_sdk_requests_cannot_escape_the_initial_regional_endpoint() -> None:
    client = make_archive_client(
        region="nyc3",
        access_key_id="fixture",
        secret_access_key="fixture",  # noqa: S106
    )
    attempts: list[object] = []

    def substitute(params: dict[str, object], **_kwargs: object) -> None:
        params["url"] = "https://unexpected.invalid/archive"

    def respond(request: object, **_kwargs: object) -> object:
        attempts.append(request)
        return AWSResponse(cast(_PreparedRequest, request).url, 200, {}, _ResponseBody())

    events = client.meta.events  # type: ignore[attr-defined]
    events.register("before-call.s3.PutObject", substitute)
    events.register("before-send.s3", respond)
    with pytest.raises(ArchiveRemoteError, match="endpoint"):
        client.put_object(Bucket=BUCKET, Key=KEY, Body=BODY, ContentLength=len(BODY))
    assert not attempts


def test_sdk_attempt_budget_is_per_explicit_call() -> None:
    client = make_archive_client(
        region="nyc3",
        access_key_id="fixture",
        secret_access_key="fixture",  # noqa: S106
    )
    attempts: list[str] = []

    def respond(request: object, **_kwargs: object) -> object:
        attempts.append(cast(_PreparedRequest, request).url)
        return AWSResponse(
            cast(_PreparedRequest, request).url,
            200,
            {},
            _ResponseBody(
                b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
            ),
        )

    client.meta.events.register("before-send.s3", respond)  # type: ignore[attr-defined]
    for _ in range(2):
        assert client.get_bucket_versioning(Bucket=BUCKET)["Status"] == "Enabled"
    assert attempts == [f"https://nyc3.digitaloceanspaces.com/{BUCKET}?versioning"] * 2
