"""Validate Cloudflare's reserved namespace without recording trace data."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final

BLOCKED_RESERVED_PATHS: Final = (
    "/cdn-cgi",
    "/cdn-cgi/",
    "/CDN-CGI/trace",
    "/cdn-cgi/lowerduckpond-unclaimed",
)
PROVIDER_TRACE_PATH: Final = "/cdn-cgi/trace"
MAXIMUM_PROVIDER_TRACE_BYTES: Final = 4096
TRACE_KEY_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CLOUDFLARE_COLO_PATTERN: Final = re.compile(r"^[A-Z]{3}$")


class ReservedNamespaceError(RuntimeError):
    """Raised when the edge does not preserve the reserved-path contract."""


@dataclass(frozen=True, slots=True)
class NamespaceResponse:
    """The bounded response surface needed by the reserved-path check."""

    status: int
    fields: Mapping[str, str]
    content: bytes


type NamespaceRequest = Callable[[str, str], NamespaceResponse]


def check_reserved_namespace(
    *, hostnames: Sequence[str], request: NamespaceRequest
) -> dict[str, bool]:
    """Prove tenant paths are blocked and Cloudflare's internal route is isolated."""
    if not hostnames or len(set(hostnames)) != len(hostnames):
        raise ReservedNamespaceError("reserved-path hostname set is invalid")

    for hostname in hostnames:
        for path in BLOCKED_RESERVED_PATHS:
            response = request(hostname, path)
            if response.status != HTTPStatus.FORBIDDEN or _origin_reached(response):
                raise ReservedNamespaceError("reserved path escaped the edge block")

        trace = request(hostname, PROVIDER_TRACE_PATH)
        _require_provider_trace(trace)

    # These evidence names are retained for compatibility with the archived v3
    # M3.0 report. The block applies to paths that enter the custom-rules phase;
    # provider-owned internal endpoints are instead proven origin-isolated.
    return {"origin_preempted": True, "provider_namespace_blocked": True}


def _require_provider_trace(response: NamespaceResponse) -> None:
    if response.status != HTTPStatus.OK or _origin_reached(response):
        raise ReservedNamespaceError("provider trace did not remain origin-isolated")
    if response.fields.get("server", "").casefold() != "cloudflare":
        raise ReservedNamespaceError("provider trace server identity is invalid")
    content_type = response.fields.get("content-type", "").partition(";")[0].strip().casefold()
    if content_type != "text/plain":
        raise ReservedNamespaceError("provider trace media type is invalid")
    if not response.content or len(response.content) > MAXIMUM_PROVIDER_TRACE_BYTES:
        raise ReservedNamespaceError("provider trace size is invalid")

    try:
        lines = response.content.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ReservedNamespaceError("provider trace encoding is invalid") from error

    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or TRACE_KEY_PATTERN.fullmatch(key) is None or not value or key in values:
            raise ReservedNamespaceError("provider trace shape is invalid")
        values[key] = value
    if CLOUDFLARE_COLO_PATTERN.fullmatch(values.get("colo", "")) is None:
        raise ReservedNamespaceError("provider trace location is invalid")


def _origin_reached(response: NamespaceResponse) -> bool:
    return response.fields.get("x-m3-origin-reached") == "true"
