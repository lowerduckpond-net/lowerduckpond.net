"""No automatic retries, one fixed endpoint and exact parameters per request."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast
from urllib.parse import urlsplit

from botocore.config import Config  # type: ignore[import-untyped]
from botocore.session import Session  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.m3_11_retirement_files import RetirementError


class Request(Protocol):
    context: dict[str, object]
    url: str


def make_client(
    configuration: ArchiveConfiguration,
    before: Callable[[dict[str, object], object], None],
    before_wire: Callable[[str], None],
) -> S3Client:
    session = Session()
    session.set_config_variable("config_file", "/dev/null")
    session.set_config_variable("credentials_file", "/dev/null")
    endpoint = f"https://{configuration.region}.digitaloceanspaces.com"
    client = session.create_client(
        "s3",
        aws_access_key_id=configuration.access_key_id,
        aws_secret_access_key=configuration.secret_access_key,
        aws_session_token=None,
        region_name=configuration.region,
        endpoint_url=endpoint,
        verify="/etc/ssl/certs/ca-certificates.crt",
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=30,
            retries={"total_max_attempts": 1, "mode": "standard"},
            proxies={},
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )

    def parameters(params: dict[str, object], model: object, **_kwargs: object) -> None:
        before(params, model)

    def wire(request: object, operation_name: str, **_kwargs: object) -> None:
        prepared = cast(Request, request)
        context = prepared.context
        url = urlsplit(prepared.url)
        if (
            context.get("frozen_retirement_sent") is not None
            or f"{url.scheme}://{url.netloc}" != endpoint
            or url.fragment
            or operation_name
            not in {
                "GetBucketVersioning",
                "ListObjectsV2",
                "ListObjectVersions",
                "ListMultipartUploads",
                "GetObject",
                "DeleteObject",
            }
        ):
            raise RetirementError("frozen retirement rejected retry or changed transport")
        context["frozen_retirement_sent"] = True

    def sending(request: object, event_name: str, **_kwargs: object) -> None:
        # Signing happens after request-created. Check again on the prepared
        # request immediately before the SDK submits it to the HTTP transport.
        url = urlsplit(cast(Request, request).url)
        if f"{url.scheme}://{url.netloc}" != endpoint or url.fragment:
            raise RetirementError("frozen retirement rejected changed final endpoint")
        operation = event_name.removeprefix("before-send.s3.")
        if operation not in {
            "GetBucketVersioning",
            "ListObjectsV2",
            "ListObjectVersions",
            "ListMultipartUploads",
            "GetObject",
            "DeleteObject",
        }:
            raise RetirementError("frozen retirement rejected unknown final operation")
        before_wire(operation)

    client.meta.events.register_first("before-parameter-build.s3", parameters)
    client.meta.events.register_first("request-created.s3", wire)
    client.meta.events.register_last("before-send.s3", sending)
    return cast(S3Client, client)
