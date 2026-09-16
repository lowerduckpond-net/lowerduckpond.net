from __future__ import annotations

import errno

import pytest
from botocore import exceptions as sdk_errors  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent.archive_diagnostics import archive_failure_diagnostic
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.archive_transport import ArchiveTransportError

_PRIVATE = "private endpoint, object identity, or credential\nforged journal entry"


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (sdk_errors.ReadTimeoutError(endpoint_url=_PRIVATE), "provider_read_timeout"),
        (sdk_errors.ConnectTimeoutError(endpoint_url=_PRIVATE), "provider_connect_timeout"),
        (sdk_errors.ConnectionClosedError(endpoint_url=_PRIVATE), "provider_connection_closed"),
        (sdk_errors.SSLError(endpoint_url=_PRIVATE, error=_PRIVATE), "provider_tls"),
        (sdk_errors.EndpointConnectionError(endpoint_url=_PRIVATE), "provider_connection"),
        (sdk_errors.ResponseStreamingError(error=_PRIVATE), "provider_stream"),
        (sdk_errors.HTTPClientError(error=_PRIVATE), "provider_sdk"),
        (ArchiveRemoteError(_PRIVATE), "archive_validation"),
        (ArchiveTransportError(_PRIVATE), "archive_transport"),
        (TimeoutError(_PRIVATE), "local_timeout"),
        (BrokenPipeError(_PRIVATE), "local_connection"),
        (PermissionError(errno.EACCES, _PRIVATE, _PRIVATE), "local_permission"),
        (OSError(errno.ENOSPC, _PRIVATE, _PRIVATE), "local_storage_full"),
        (OSError(errno.EDQUOT, _PRIVATE, _PRIVATE), "local_storage_full"),
        (OSError(errno.EIO, _PRIVATE, _PRIVATE), "local_io"),
        (MemoryError(_PRIVATE), "local_memory"),
        (ValueError(_PRIVATE), "unexpected"),
    ],
)
def test_failure_classification_never_formats_private_details(
    error: Exception, category: str
) -> None:
    assert archive_failure_diagnostic(error) == f"category={category}"


def _provider_error() -> sdk_errors.ClientError:
    return sdk_errors.ClientError(
        {
            "Error": {"Code": "RequestTimeout", "Message": _PRIVATE},
            "ResponseMetadata": {
                "HTTPStatusCode": 400,
                "HTTPHeaders": {"authorization": _PRIVATE},
                "RequestId": _PRIVATE,
                "HostId": _PRIVATE,
            },
            "BucketName": _PRIVATE,
            "Key": _PRIVATE,
        },
        "PutObject",
    )


def test_provider_rejection_reports_only_selected_labels_and_http_status() -> None:
    assert archive_failure_diagnostic(_provider_error()) == (
        "category=provider_response operation=put_object code=request_timeout http_status=400"
    )


@pytest.mark.parametrize("value", [_PRIVATE * 1000, [], {}, None, True, 99, 600])
def test_arbitrary_provider_fields_cannot_escape_or_break_diagnostics(value: object) -> None:
    error = _provider_error()
    error.operation_name = value
    error.response["Error"]["Code"] = value
    error.response["ResponseMetadata"]["HTTPStatusCode"] = value
    assert archive_failure_diagnostic(error) == (
        "category=provider_response operation=other code=other http_status=other"
    )


@pytest.mark.parametrize("value", [None, _PRIVATE, [], True])
def test_malformed_provider_response_sections_are_not_formatted(value: object) -> None:
    error = _provider_error()
    error.response = {"Error": value, "ResponseMetadata": value}
    assert archive_failure_diagnostic(error) == (
        "category=provider_response operation=put_object code=other http_status=other"
    )
    error.response = value
    assert archive_failure_diagnostic(error) == (
        "category=provider_response operation=put_object code=other http_status=other"
    )


def test_unknown_exception_and_its_cause_are_never_rendered() -> None:
    class UnrenderableError(Exception):
        def __str__(self) -> str:
            raise AssertionError("must not format unknown exceptions")

    error = UnrenderableError(_PRIVATE)
    error.__cause__ = _provider_error()
    assert archive_failure_diagnostic(error) == "category=unexpected"
