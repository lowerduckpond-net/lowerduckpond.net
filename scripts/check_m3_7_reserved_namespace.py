#!/usr/bin/env python3
"""Run the read-only M3.7 production reserved-namespace acceptance check."""

from __future__ import annotations

import http.client
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.reserved_namespace import (
    BLOCKED_RESERVED_PATHS,
    PROVIDER_TRACE_PATH,
    NamespaceResponse,
    ReservedNamespaceError,
    check_reserved_namespace,
)

PRODUCTION_HOSTNAMES: Final = ("lowerduckpond.net", "lowerduckpond.com")
ALLOWED_PATHS: Final = frozenset((*BLOCKED_RESERVED_PATHS, PROVIDER_TRACE_PATH))
HTTP_TIMEOUT_SECONDS: Final = 10
SSH_TIMEOUT_SECONDS: Final = 30
MAXIMUM_RESPONSE_BYTES: Final = 65_536
MAXIMUM_JOURNAL_BYTES: Final = 65_536
JOURNAL_SETTLE_SECONDS: Final = 1.0
PROBE_MARKER_PATTERN: Final = re.compile(r"^m3-7-reserved-[0-9a-f]{32}$")

type ProductionNamespaceRequest = Callable[[str, str, str], NamespaceResponse]
type OriginProbe = Callable[[str], bool]
type Settler = Callable[[float], None]


def _probe_marker() -> str:
    return f"m3-7-reserved-{secrets.token_hex(16)}"


def _request(hostname: str, path: str, marker: str) -> NamespaceResponse:
    if (
        hostname not in PRODUCTION_HOSTNAMES
        or path not in ALLOWED_PATHS
        or PROBE_MARKER_PATTERN.fullmatch(marker) is None
    ):
        raise ReservedNamespaceError("production reserved-path request is not allowlisted")

    connection = http.client.HTTPSConnection(hostname, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.request(
            "GET",
            f"{path}?ldp_m3_reserved_probe={marker}",
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


def _origin_was_reached(marker: str) -> bool:
    private_key_value = os.environ.get("ANSIBLE_PRIVATE_KEY_FILE", "")
    origin_value = os.environ.get("PRODUCTION_ORIGIN_IPV4", "")
    private_key = Path(private_key_value)
    try:
        origin = ipaddress.ip_address(origin_value)
    except ValueError as error:
        raise ReservedNamespaceError("production origin address is invalid") from error
    if (
        PROBE_MARKER_PATTERN.fullmatch(marker) is None
        or not private_key.is_file()
        or not isinstance(origin, ipaddress.IPv4Address)
        or not origin.is_global
    ):
        raise ReservedNamespaceError("production origin journal inputs are invalid")

    command = (
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "HostKeyAlias=lowerduckpond.net",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-i",
        str(private_key),
        f"ldp-admin@{origin}",
        "sudo",
        "--non-interactive",
        "/usr/bin/journalctl",
        "--unit=caddy.service",
        "--since=-2min",
        "--lines=32",
        "--no-pager",
        "--output=cat",
        f"--grep={marker}",
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable and validated inputs
            command,
            check=False,
            capture_output=True,
            timeout=SSH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReservedNamespaceError("production Caddy journal read failed") from error
    if completed.returncode != 0:
        raise ReservedNamespaceError("production Caddy journal read failed")
    if len(completed.stdout) > MAXIMUM_JOURNAL_BYTES:
        raise ReservedNamespaceError("production Caddy journal result exceeded its bound")
    return bool(completed.stdout.strip())


def run(
    *,
    request: ProductionNamespaceRequest = _request,
    origin_was_reached: OriginProbe = _origin_was_reached,
    marker: str | None = None,
    settle: Settler = time.sleep,
) -> None:
    """Check the exact production hostnames without exposing provider trace fields."""
    probe_marker = marker or _probe_marker()
    if PROBE_MARKER_PATTERN.fullmatch(probe_marker) is None:
        raise ReservedNamespaceError("production reserved-path marker is invalid")
    check_reserved_namespace(
        hostnames=PRODUCTION_HOSTNAMES,
        request=lambda hostname, path: request(hostname, path, probe_marker),
    )
    settle(JOURNAL_SETTLE_SECONDS)
    if origin_was_reached(probe_marker):
        raise ReservedNamespaceError("reserved-path probe reached production Caddy")


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
