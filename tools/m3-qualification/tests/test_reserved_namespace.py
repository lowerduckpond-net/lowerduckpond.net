from __future__ import annotations

import pytest
from lowerduckpond_m3_qualification.reserved_namespace import (
    BLOCKED_RESERVED_PATHS,
    PROVIDER_TRACE_PATH,
    NamespaceResponse,
    ReservedNamespaceError,
    check_reserved_namespace,
)

HOSTNAMES = ("m3-qualification.lowerduckpond.net", "m3-tenant.lowerduckpond.com")


def blocked_response() -> NamespaceResponse:
    return NamespaceResponse(status=403, fields={"server": "cloudflare"}, content=b"blocked")


def trace_response(
    *, fields: dict[str, str] | None = None, content: bytes | None = None
) -> NamespaceResponse:
    return NamespaceResponse(
        status=200,
        fields=fields or {"server": "cloudflare", "content-type": "text/plain"},
        content=content or b"fl=test\ncolo=DFW\n",
    )


def test_reserved_namespace_distinguishes_internal_trace_from_blocked_paths() -> None:
    observed: list[tuple[str, str]] = []

    def request(hostname: str, path: str) -> NamespaceResponse:
        observed.append((hostname, path))
        if path == PROVIDER_TRACE_PATH:
            return trace_response()
        return blocked_response()

    assert check_reserved_namespace(hostnames=HOSTNAMES, request=request) == {
        "origin_preempted": True,
        "provider_namespace_blocked": True,
    }
    assert observed == [
        (hostname, path)
        for hostname in HOSTNAMES
        for path in (*BLOCKED_RESERVED_PATHS, PROVIDER_TRACE_PATH)
    ]


@pytest.mark.parametrize(
    "response",
    (
        NamespaceResponse(status=403, fields={"server": "cloudflare"}, content=b"blocked"),
        trace_response(fields={"server": "origin", "content-type": "text/plain"}),
        trace_response(fields={"server": "cloudflare", "content-type": "text/html"}),
        trace_response(content=b"fl=test\ncolo=not-a-colo\n"),
        trace_response(
            fields={
                "server": "cloudflare",
                "content-type": "text/plain",
                "x-m3-origin-reached": "true",
            }
        ),
    ),
)
def test_reserved_namespace_rejects_an_invalid_internal_trace(
    response: NamespaceResponse,
) -> None:
    def request(hostname: str, path: str) -> NamespaceResponse:
        if path == PROVIDER_TRACE_PATH:
            return response
        return blocked_response()

    with pytest.raises(ReservedNamespaceError):
        check_reserved_namespace(hostnames=HOSTNAMES, request=request)


@pytest.mark.parametrize(
    "replacement",
    (
        NamespaceResponse(status=200, fields={}, content=b"origin"),
        NamespaceResponse(
            status=403,
            fields={"x-m3-origin-reached": "true"},
            content=b"origin",
        ),
    ),
)
def test_reserved_namespace_requires_the_waf_block_before_origin(
    replacement: NamespaceResponse,
) -> None:
    def request(hostname: str, path: str) -> NamespaceResponse:
        if path == BLOCKED_RESERVED_PATHS[0]:
            return replacement
        if path == PROVIDER_TRACE_PATH:
            return trace_response()
        return blocked_response()

    with pytest.raises(ReservedNamespaceError, match="escaped the edge block"):
        check_reserved_namespace(hostnames=HOSTNAMES, request=request)


def test_reserved_namespace_rejects_duplicate_hostnames() -> None:
    def request(hostname: str, path: str) -> NamespaceResponse:
        return blocked_response()

    with pytest.raises(ReservedNamespaceError, match="hostname set"):
        check_reserved_namespace(hostnames=(HOSTNAMES[0], HOSTNAMES[0]), request=request)
