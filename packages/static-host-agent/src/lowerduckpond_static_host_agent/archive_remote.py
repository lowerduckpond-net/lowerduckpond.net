"""Bounded low-level versioned archive I/O; lifecycle authority belongs to root.

Callers must hold export exclusion and sync construction/retirement authority
before writing/deleting. No method resolves authority from a mutable key view.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import BinaryIO, Final, Protocol, cast
from urllib.parse import urlsplit

from botocore.config import Config  # type: ignore[import-untyped]
from botocore.session import Session  # type: ignore[import-untyped]
from lowerduckpond_static_contracts import validate_uuid7

MAX_BUNDLE_BYTES: Final = 120 * 1024 * 1024
MAX_REMOTE_BYTES: Final = 3000 * 1024 * 1024
MAX_REMOTE_KEYS: Final = 25
MAX_REMOTE_VERSIONS: Final = 25
_PAGE_SIZE: Final = 100
_MAX_PAGES: Final = 100
_CHUNK_SIZE: Final = 1024 * 1024
_MAX_STRING_BYTES: Final = 1024
_ATTEMPT_CONTEXT_KEY: Final = "lowerduckpond_archive_request_created"
_PERMITTED_OPERATIONS: Final = frozenset(
    {
        "GetBucketVersioning",
        "ListObjectVersions",
        "ListMultipartUploads",
        "PutObject",
        "GetObject",
        "DeleteObject",
    }
)


class ArchiveRemoteError(RuntimeError):
    """Remote evidence is missing, ambiguous, inconsistent, or over bounds."""


class ArchiveCapacityError(ArchiveRemoteError):
    """Reconciled remote use cannot admit one worst-case upload reservation."""


class ArchiveClient(Protocol):
    """Only individual, version-aware S3 operations exist at this boundary."""

    def get_bucket_versioning(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_object_versions(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_multipart_uploads(self, **kwargs: object) -> Mapping[str, object]: ...

    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def delete_object(self, **kwargs: object) -> Mapping[str, object]: ...


class _SDKRequest(Protocol):
    context: dict[str, object]
    url: str


@dataclass(frozen=True, slots=True)
class RemoteVersion:
    key: str
    version_id: str
    size: int
    delete_marker: bool


@dataclass(frozen=True, slots=True)
class RemoteInventory:
    versions: tuple[RemoteVersion, ...]
    multipart_uploads: tuple[tuple[str, str], ...]

    def require_reservation(self, known: frozenset[RemoteVersion]) -> None:
        """Admission requires a complete reconciled inventory, not just totals.

        The caller separately refuses outstanding intents and quarantine. Even
        a missing known object is inconsistent and cannot reopen admission.
        """
        if self.multipart_uploads or frozenset(self.versions) != known:
            raise ArchiveRemoteError("remote inventory requires reconciliation")
        if (
            len({entry.key for entry in self.versions}) + 1 > MAX_REMOTE_KEYS
            or len(self.versions) + 1 > MAX_REMOTE_VERSIONS
            or sum(entry.size for entry in self.versions) + MAX_BUNDLE_BYTES > MAX_REMOTE_BYTES
        ):
            raise ArchiveCapacityError("remote archive reservation exceeds capacity")


def archive_key(upload_attempt_id: object) -> str:
    """Construct a unique object key only from a root-generated attempt UUID."""
    return f"archives/{validate_uuid7(upload_attempt_id)}.zip"


def make_archive_client(
    *, region: str, access_key_id: str, secret_access_key: str
) -> ArchiveClient:
    """Use explicit dedicated credentials, regional TLS, and no upload retry.

    A timed-out PutObject must be discovered using its durable unique key. SDK
    retries can create extra versions and cannot substitute for reconciliation.
    """
    if not re.fullmatch(r"[a-z]{3}[1-9][0-9]?", region):
        raise ArchiveRemoteError("archive region is invalid")
    if not access_key_id or not secret_access_key:
        raise ArchiveRemoteError("dedicated archive credentials are required")
    session = Session()
    # Isolate SDK configuration as well as credentials from workstation files.
    session.set_config_variable("config_file", "/dev/null")
    session.set_config_variable("credentials_file", "/dev/null")
    client = session.create_client(
        "s3",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=None,
        region_name=region,
        endpoint_url=f"https://{region}.digitaloceanspaces.com",
        # Use the host-administered trust store mounted read-only in each service.
        # An explicit path prevents ambient SDK CA-bundle configuration from overriding it.
        verify="/etc/ssl/certs/ca-certificates.crt",
        config=Config(
            signature_version="s3v4",
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=10,
            read_timeout=30,
            proxies={},
            s3={"addressing_style": "path", "payload_signing_enabled": True},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )
    endpoint = urlsplit(client.meta.endpoint_url)

    def guard_request(request: object, operation_name: str, **_kwargs: object) -> None:
        """Fence SDK redirects and auxiliary requests before another transmission.

        Botocore's S3 region redirector can retry outside the configured retry
        budget, and can issue HeadBucket to discover a region. Every actual
        attempt creates a request with the original call's shared context.
        """

        prepared = cast(_SDKRequest, request)
        if operation_name not in _PERMITTED_OPERATIONS:
            raise ArchiveRemoteError("archive SDK operation is not permitted")
        if prepared.context.get(_ATTEMPT_CONTEXT_KEY) is not None:
            raise ArchiveRemoteError("archive SDK attempted an automatic retry")
        prepared.context[_ATTEMPT_CONTEXT_KEY] = True
        target = urlsplit(prepared.url)
        if target.scheme != endpoint.scheme or target.netloc != endpoint.netloc or target.fragment:
            raise ArchiveRemoteError("archive SDK request escaped its configured endpoint")

    client.meta.events.register_first("request-created.s3", guard_request)
    return cast(ArchiveClient, client)


class ArchiveRemoteStore:
    """All operations are confined to one configured dedicated archive bucket."""

    def __init__(self, client: ArchiveClient, *, bucket: str) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket):
            raise ArchiveRemoteError("archive bucket is invalid")
        self.client = client
        self.bucket = bucket

    def inventory(self) -> RemoteInventory:
        response = self.client.get_bucket_versioning(Bucket=self.bucket)
        if response.get("Status") != "Enabled":
            raise ArchiveRemoteError("archive bucket versioning is not enabled")
        return RemoteInventory(self.list_versions(), self._list_multipart())

    def list_versions(self, *, exact_key: str | None = None) -> tuple[RemoteVersion, ...]:
        """List all versions/markers, filtering exact-key queries after pagination."""
        # The entire bucket is dedicated. Unknown keys outside archives/ must
        # still retain their capacity charge and close new admission.
        prefix = "" if exact_key is None else _managed_key(exact_key)
        versions: list[RemoteVersion] = []
        seen: set[tuple[str, str]] = set()
        for response in self._pages(prefix=prefix, multipart=False):
            for field, marker in (("Versions", False), ("DeleteMarkers", True)):
                for item in _items(response, field):
                    key = _string(item, "Key")
                    if not key.startswith(prefix):
                        raise ArchiveRemoteError("version listing escaped its prefix")
                    version_id = _string(item, "VersionId")
                    identity = (key, version_id)
                    if identity in seen:
                        raise ArchiveRemoteError("version listing repeated an object identity")
                    seen.add(identity)
                    size = 0 if marker else _size(item, "Size")
                    if exact_key is None or key == exact_key:
                        versions.append(RemoteVersion(key, version_id, size, marker))
        return tuple(versions)

    def require_absent(self, key: str) -> None:
        if self.list_versions(exact_key=key):
            raise ArchiveRemoteError("archive key still contains versions or markers")

    def put_once(self, key: str, stream: BinaryIO, *, size: int, sha256: str) -> str:
        """Send one independently checked, known-length body with no automatic retry.

        The caller has already synced the construction intent and checked exact
        key absence. This operation cannot safely be retried after any exception.
        """
        _managed_key(key)
        _bundle_binding(size, sha256)
        stream.seek(0)
        _copy_verified(stream, None, size=size, sha256=sha256)
        stream.seek(0)
        response = self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=stream,
            ContentLength=size,
            ContentType="application/zip",
            Metadata={"sha256": sha256},
        )
        return _nonnull_version(response)

    def read_verified(
        self,
        key: str,
        version_id: str,
        *,
        size: int,
        sha256: str,
        destination: BinaryIO | None = None,
    ) -> None:
        """Stream the exact bound version; independently measure every byte.

        Destinations are private incomplete spool files until their caller also
        validates the portable bundle, syncs, and publishes them.
        """
        _managed_key(key)
        _nonnull_version({"VersionId": version_id})
        _bundle_binding(size, sha256)
        response = self.client.get_object(Bucket=self.bucket, Key=key, VersionId=version_id)
        body = response.get("Body")
        if not callable(getattr(body, "read", None)) or not callable(getattr(body, "close", None)):
            if callable(getattr(body, "close", None)):
                cast(BinaryIO, body).close()
            raise ArchiveRemoteError("archive response has no bounded readable body")
        stream = cast(BinaryIO, body)
        try:
            if (
                _nonnull_version(response) != version_id
                or _size(response, "ContentLength") != size
                or response.get("DeleteMarker", False) is not False
                or response.get("Metadata") != {"sha256": sha256}
            ):
                raise ArchiveRemoteError("exact archive version metadata does not match")
            _copy_verified(stream, destination, size=size, sha256=sha256)
        finally:
            stream.close()

    def purge_unbound(self, key: str, *, require_unbound: Callable[[str], None]) -> None:
        """Purge a durably journaled key only while no tenant binds any version.

        The caller holds export exclusion throughout. Retain its retirement or
        construction journal on every exception, including confirmation errors.
        """
        _managed_key(key)
        for _ in range(3):
            require_unbound(key)
            versions = self.list_versions(exact_key=key)
            if not versions:
                return
            for entry in versions:
                require_unbound(key)
                response = self.client.delete_object(
                    Bucket=self.bucket, Key=key, VersionId=entry.version_id
                )
                if response.get("VersionId") != entry.version_id:
                    raise ArchiveRemoteError("version deletion response is ambiguous")
        self.require_absent(key)

    def _list_multipart(self) -> tuple[tuple[str, str], ...]:
        uploads: set[tuple[str, str]] = set()
        # The bucket is dedicated. Enumerating its entire multipart namespace
        # also detects out-of-prefix uploads and supports MinIO's exact/empty
        # multipart-prefix behavior in local qualification.
        for response in self._pages(prefix="", multipart=True):
            for item in _items(response, "Uploads"):
                key = _string(item, "Key")
                identity = (key, _string(item, "UploadId"))
                if identity in uploads:
                    raise ArchiveRemoteError("multipart listing repeated an upload")
                uploads.add(identity)
        return tuple(sorted(uploads))

    def _pages(self, *, prefix: str, multipart: bool) -> tuple[Mapping[str, object], ...]:
        pages: list[Mapping[str, object]] = []
        seen: set[tuple[str, str]] = set()
        marker: tuple[str, str] | None = None
        token = "UploadId" if multipart else "VersionId"
        for _ in range(_MAX_PAGES):
            request: dict[str, object] = {
                "Bucket": self.bucket,
                "Prefix": prefix,
                "MaxUploads" if multipart else "MaxKeys": _PAGE_SIZE,
            }
            if marker is not None:
                request["KeyMarker"], request[f"{token}Marker"] = marker
            response = (
                self.client.list_multipart_uploads(**request)
                if multipart
                else self.client.list_object_versions(**request)
            )
            # Validate each page before retaining it or following remote cursors.
            fields = ("Uploads",) if multipart else ("Versions", "DeleteMarkers")
            if sum(len(_items(response, field)) for field in fields) > _PAGE_SIZE:
                raise ArchiveRemoteError("archive listing exceeded its page size")
            pages.append(response)
            truncated = response.get("IsTruncated")
            if type(truncated) is not bool:
                raise ArchiveRemoteError("archive listing omitted its completion flag")
            if not truncated:
                return tuple(pages)
            marker = (_string(response, "NextKeyMarker"), _string(response, f"Next{token}Marker"))
            if not marker[0].startswith(prefix) or marker in seen:
                raise ArchiveRemoteError("archive listing returned an invalid continuation")
            seen.add(marker)
        raise ArchiveRemoteError("archive listing exceeded its page bound")


def _managed_key(key: str) -> str:
    if not key.startswith("archives/") or not key.endswith(".zip"):
        raise ArchiveRemoteError("object key is outside managed archive storage")
    if archive_key(key[len("archives/") : -len(".zip")]) != key:
        raise ArchiveRemoteError("object key is not a canonical archive attempt")
    return key


def _bundle_binding(size: int, sha256: str) -> None:
    if type(size) is not int or not 0 < size <= MAX_BUNDLE_BYTES:
        raise ArchiveRemoteError("archive bundle length is outside its bound")
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ArchiveRemoteError("archive bundle digest is malformed")


def _copy_verified(
    source: BinaryIO, destination: BinaryIO | None, *, size: int, sha256: str
) -> None:
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        requested = min(remaining, _CHUNK_SIZE)
        chunk = source.read(requested)
        if type(chunk) is not bytes or not chunk or len(chunk) > requested:
            raise ArchiveRemoteError("archive body length differs from its binding")
        digest.update(chunk)
        remaining -= len(chunk)
        if destination is not None and destination.write(chunk) != len(chunk):
            raise ArchiveRemoteError("archive destination did not accept the complete chunk")
    if source.read(1) != b"" or digest.hexdigest() != sha256:
        raise ArchiveRemoteError("archive body bytes differ from their binding")


def _items(response: Mapping[str, object], field: str) -> tuple[Mapping[str, object], ...]:
    value = response.get(field, [])
    if type(value) is not list or len(value) > _PAGE_SIZE:
        raise ArchiveRemoteError("archive listing is not a bounded list")
    if any(not isinstance(item, Mapping) for item in value):
        raise ArchiveRemoteError("archive listing contains a malformed entry")
    return tuple(cast(Mapping[str, object], item) for item in value)


def _string(response: Mapping[str, object], field: str) -> str:
    value = response.get(field)
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_STRING_BYTES:
        raise ArchiveRemoteError("archive response contains an invalid string")
    return value


def _nonnull_version(response: Mapping[str, object]) -> str:
    value = _string(response, "VersionId")
    if value == "null":
        raise ArchiveRemoteError("archive response did not bind a versioned object")
    return value


def _size(response: Mapping[str, object], field: str) -> int:
    value = response.get(field)
    if type(value) is not int or value < 0:
        raise ArchiveRemoteError("archive response contains an invalid length")
    return value
