from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, cast

import pytest
from botocore.awsrequest import AWSResponse  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.check_m3_10_provider import PolicyClient, check_storage
from scripts.m3_10_policy_client import make_policy_client


class Request(Protocol):
    url: str


class Body:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def stream(self, *_arguments: object, **_kwargs: object) -> Iterator[bytes]:
        yield self.body


@pytest.fixture
def client() -> object:
    return make_policy_client(ArchiveConfiguration("ams3", "archive-fixture", "key", "secret"))


def test_actual_policy_client_transmits_every_required_read(client: object) -> None:
    responses = [
        (
            200,
            b"<AccessControlPolicy><Owner><ID>owner</ID></Owner><AccessControlList>"
            b'<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            b'xsi:type="CanonicalUser"><ID>owner</ID></Grantee>'
            b"<Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>",
        ),
        (404, b"<Error><Code>NoSuchBucketPolicy</Code></Error>"),
        (404, b"<Error><Code>NoSuchLifecycleConfiguration</Code></Error>"),
        (200, b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
        (200, b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"),
        (200, b"<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>"),
        (
            200,
            b"<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>",
        ),
    ]
    urls: list[str] = []
    expected_calls = len(responses)

    def respond(request: object, **_kwargs: object) -> object:
        url = cast(Request, request).url
        urls.append(url)
        status, body = responses.pop(0)
        return AWSResponse(url, status, {}, Body(body))

    client.meta.events.register("before-send.s3", respond)  # type: ignore[attr-defined]
    check_storage(cast(PolicyClient, client), bucket="archive-fixture")
    assert not responses
    assert len(urls) == expected_calls
    assert all(
        url.startswith("https://ams3.digitaloceanspaces.com/archive-fixture?") for url in urls
    )


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        ("put_object", {"Bucket": "archive-fixture", "Key": "x", "Body": b"x"}),
        ("delete_object", {"Bucket": "archive-fixture", "Key": "x", "VersionId": "v1"}),
        ("get_object", {"Bucket": "archive-fixture", "Key": "x"}),
        ("get_bucket_acl", {"Bucket": "another-bucket"}),
    ],
)
def test_policy_client_rejects_other_authority_before_transmission(
    client: object, operation: str, arguments: dict[str, object]
) -> None:
    sent: list[object] = []

    def respond(request: object, **_kwargs: object) -> object:
        sent.append(request)
        raise AssertionError("unapproved request reached the transport")

    client.meta.events.register("before-send.s3", respond)  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match=r"unapproved|escaped"):
        getattr(client, operation)(**arguments)
    assert not sent


def test_policy_client_does_not_follow_regional_redirects(client: object) -> None:
    sent: list[object] = []

    def respond(request: object, **_kwargs: object) -> object:
        sent.append(request)
        return AWSResponse(
            cast(Request, request).url,
            301,
            {"x-amz-bucket-region": "nyc3"},
            Body(b"<Error><Code>PermanentRedirect</Code></Error>"),
        )

    client.meta.events.register("before-send.s3", respond)  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="automatic retry"):
        cast(PolicyClient, client).get_bucket_acl(Bucket="archive-fixture")
    assert len(sent) == 1
