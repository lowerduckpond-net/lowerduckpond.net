"""Bounded workstation-only reads of the configured Spaces bucket policy."""

from __future__ import annotations

from typing import Protocol, cast
from urllib.parse import parse_qs, urlsplit

from botocore.config import Config  # type: ignore[import-untyped]
from botocore.session import Session  # type: ignore[import-untyped]
from lowerduckpond_static_contracts import validate_uuid7
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

_READS = frozenset(
    {
        "GetBucketAcl",
        "GetObjectAcl",
        "GetBucketPolicy",
        "GetBucketLifecycleConfiguration",
        "GetBucketVersioning",
        "ListObjectsV2",
        "ListObjectVersions",
        "ListMultipartUploads",
    }
)


class _Request(Protocol):
    context: dict[str, object]
    url: str


def make_policy_client(configuration: ArchiveConfiguration) -> object:
    """Keep operator credentials separate from the runtime's object authority."""
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
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=10,
            read_timeout=30,
            proxies={},
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )

    def guard(request: object, operation_name: str, **_kwargs: object) -> None:
        prepared = cast(_Request, request)
        if operation_name not in _READS:
            raise RuntimeError("policy client attempted an unapproved operation")
        if prepared.context.get("lowerduckpond_policy_attempt") is not None:
            raise RuntimeError("policy client attempted an automatic retry")
        prepared.context["lowerduckpond_policy_attempt"] = True
        target = urlsplit(prepared.url)
        expected_path = f"/{configuration.bucket}"
        if operation_name == "GetObjectAcl":
            prefix = expected_path + "/archives/"
            if not target.path.startswith(prefix) or not target.path.endswith(".zip"):
                raise RuntimeError("policy client escaped managed archive ACL authority")
            validate_uuid7(target.path.removeprefix(prefix).removesuffix(".zip"))
            query = parse_qs(target.query, keep_blank_values=True)
            versions = query.get("versionId", [])
            if (
                set(query) != {"acl", "versionId"}
                or query["acl"] != [""]
                or len(versions) != 1
                or not versions[0]
                or versions[0] == "null"
            ):
                raise RuntimeError("policy client attempted an unapproved mutable object ACL read")
            expected_path = target.path
        if (
            f"{target.scheme}://{target.netloc}" != endpoint
            or target.path != expected_path
            or target.fragment
        ):
            raise RuntimeError("policy client escaped its configured bucket endpoint")

    client.meta.events.register_first("request-created.s3", guard)
    return client
