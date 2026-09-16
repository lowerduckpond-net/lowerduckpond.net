"""Fixed archive failure labels without exception text or provider identifiers."""

from __future__ import annotations

import errno
from typing import Final

from botocore import exceptions as sdk_errors  # type: ignore[import-untyped]

from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfigurationError
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.archive_transport import ArchiveTransportError
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.repository import StateRecordError
from lowerduckpond_static_host_agent.state_inventory import StateInventoryError

_MIN_HTTP_STATUS: Final = 100
_MAX_HTTP_STATUS: Final = 599
_OPERATIONS: Final = {
    "GetBucketVersioning": "get_bucket_versioning",
    "ListObjectVersions": "list_object_versions",
    "ListMultipartUploads": "list_multipart_uploads",
    "PutObject": "put_object",
    "GetObject": "get_object",
    "DeleteObject": "delete_object",
}
_PROVIDER_CODES: Final = {
    "AccessDenied": "access_denied",
    "InvalidAccessKeyId": "invalid_access_key",
    "SignatureDoesNotMatch": "signature_mismatch",
    "RequestTimeTooSkewed": "clock_skew",
    "RequestTimeout": "request_timeout",
    "SlowDown": "slow_down",
    "InternalError": "internal_error",
    "ServiceUnavailable": "service_unavailable",
    "BadDigest": "bad_digest",
    "InvalidDigest": "invalid_digest",
    "InvalidRequest": "invalid_request",
    "NoSuchBucket": "no_such_bucket",
    "NoSuchKey": "no_such_key",
    "NoSuchVersion": "no_such_version",
    "NotImplemented": "not_implemented",
}
_ERROR_CATEGORIES: Final[tuple[tuple[type[BaseException], str], ...]] = (
    (sdk_errors.ReadTimeoutError, "provider_read_timeout"),
    (sdk_errors.ConnectTimeoutError, "provider_connect_timeout"),
    (sdk_errors.ConnectionClosedError, "provider_connection_closed"),
    (sdk_errors.SSLError, "provider_tls"),
    (sdk_errors.ConnectionError, "provider_connection"),
    (sdk_errors.ResponseStreamingError, "provider_stream"),
    (sdk_errors.BotoCoreError, "provider_sdk"),
    (ArchiveRemoteError, "archive_validation"),
    (ArchiveTransportError, "archive_transport"),
    (ArchiveConfigurationError, "archive_configuration"),
    (StatePathError, "state_validation"),
    (StateRecordError, "state_validation"),
    (StateInventoryError, "state_validation"),
    (TimeoutError, "local_timeout"),
    (ConnectionError, "local_connection"),
    (PermissionError, "local_permission"),
    (MemoryError, "local_memory"),
    (OSError, "local_io"),
)


def archive_failure_diagnostic(error: Exception) -> str:
    """Emit only literal labels and an integer HTTP status in the valid range.

    Never format an exception, its class name, chained exceptions, URLs,
    request/response headers, or arbitrary provider response values. In
    particular, unknown service codes and operation names become ``other``.
    """

    if isinstance(error, sdk_errors.ClientError):
        response = error.response
        details = response.get("Error") if type(response) is dict else None
        metadata = response.get("ResponseMetadata") if type(response) is dict else None
        code = details.get("Code") if type(details) is dict else None
        status = metadata.get("HTTPStatusCode") if type(metadata) is dict else None
        status_label = (
            str(status)
            if type(status) is int and _MIN_HTTP_STATUS <= status <= _MAX_HTTP_STATUS
            else "other"
        )
        return (
            "category=provider_response "
            f"operation={_label(error.operation_name, _OPERATIONS)} "
            f"code={_label(code, _PROVIDER_CODES)} http_status={status_label}"
        )
    if isinstance(error, OSError) and error.errno in {errno.ENOSPC, errno.EDQUOT}:
        return "category=local_storage_full"
    for error_type, label in _ERROR_CATEGORIES:
        if isinstance(error, error_type):
            return f"category={label}"
    return "category=unexpected"


def _label(value: object, choices: dict[str, str]) -> str:
    return choices.get(value, "other") if type(value) is str else "other"
