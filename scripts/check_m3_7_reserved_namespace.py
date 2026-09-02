#!/usr/bin/env python3
"""Run the read-only M3.7 production reserved-namespace acceptance check."""

from __future__ import annotations

import http.client
import sys
from collections.abc import Mapping
from typing import Final

from lowerduckpond_m3_qualification.reserved_namespace import (
    BLOCKED_RESERVED_PATHS,
    PROVIDER_TRACE_PATH,
    NamespaceRequest,
    NamespaceResponse,
    ReservedNamespaceError,
    check_reserved_namespace,
)

PRODUCTION_HOSTNAMES: Final = ("lowerduckpond.net", "lowerduckpond.com")
ALLOWED_PATHS: Final = frozenset((*BLOCKED_RESERVED_PATHS, PROVIDER_TRACE_PATH))
HTTP_TIMEOUT_SECONDS: Final = 10
MAXIMUM_RESPONSE_BYTES: Final = 65_536


def _request(hostname: str, path: str) -> NamespaceResponse:
    if hostname not in PRODUCTION_HOSTNAMES or path not in ALLOWED_PATHS:
        raise ReservedNamespaceError("production reserved-path request is not allowlisted")

    connection = http.client.HTTPSConnection(hostname, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Cache-Control": "no-cache",
                "User-Agent": "lowerduckpond-m3-production-acceptance/1",
            },
        )
        response = connection.getresponse()
        content = response.read(MAXIMUM_RESPONSE_BYTES + 1)
        if len(content) > MAXIMUM_RESPONSE_BYTES:
            raise ReservedNamespaceError("production edge response exceeded its bound")
        fields: Mapping[str, str] = {
            key.casefold(): value.strip() for key, value in response.getheaders()
        }
        return NamespaceResponse(status=response.status, fields=fields, content=content)
    except (OSError, http.client.HTTPException) as error:
        raise ReservedNamespaceError("production reserved-path request failed") from error
    finally:
        connection.close()


def run(*, request: NamespaceRequest = _request) -> None:
    """Check the exact production hostnames without exposing provider trace fields."""
    check_reserved_namespace(hostnames=PRODUCTION_HOSTNAMES, request=request)


def main() -> int:
    try:
        run()
    except ReservedNamespaceError as error:
        print(f"M3.7 production reserved-namespace check failed: {error}", file=sys.stderr)
        return 1
    print("M3.7 production reserved namespace passed.")
    print("Tenant paths are blocked; Cloudflare's internal trace never reached Caddy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
