#!/usr/bin/env python3
"""Fail when the reviewed Cloudflare proxy network snapshot has drifted."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.request
from collections.abc import Iterable, Sequence
from datetime import date
from http import HTTPStatus
from pathlib import Path
from typing import Final

IPV4_URL: Final = "https://www.cloudflare.com/ips-v4/"
IPV6_URL: Final = "https://www.cloudflare.com/ips-v6/"
DEFAULT_SNAPSHOT: Final = Path(__file__).parents[1] / "platform/cloudflare-networks.json"
TIMEOUT_SECONDS: Final = 15
MAXIMUM_NETWORK_LIST_BYTES: Final = 65_536


class NetworkSnapshotError(RuntimeError):
    """Raised when the reviewed or published network set is unsafe."""


def load_snapshot(path: Path) -> tuple[frozenset[str], frozenset[str]]:
    """Read and validate the committed IPv4 and IPv6 network sets."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
        "reviewed_at",
        "cloudflare_ipv4_cidrs",
        "cloudflare_ipv6_cidrs",
    }:
        raise NetworkSnapshotError("reviewed snapshot shape is not recognized")
    reviewed_at = value["reviewed_at"]
    try:
        reviewed_date = date.fromisoformat(reviewed_at)
    except (TypeError, ValueError) as error:
        raise NetworkSnapshotError("review date is not canonical") from error
    if reviewed_at != reviewed_date.isoformat() or reviewed_date > date.today():
        raise NetworkSnapshotError("review date is not canonical")
    return (
        _validated_networks(value["cloudflare_ipv4_cidrs"], version=4),
        _validated_networks(value["cloudflare_ipv6_cidrs"], version=6),
    )


def fetch_networks(url: str, *, version: int) -> frozenset[str]:
    """Fetch one canonical provider list without following arbitrary input."""
    request = urllib.request.Request(  # noqa: S310 - URL is one of two fixed HTTPS constants.
        url, headers={"User-Agent": "lowerduckpond-ci/1"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        if response.status != HTTPStatus.OK:
            raise NetworkSnapshotError("Cloudflare network endpoint did not return HTTP 200")
        encoded = response.read(MAXIMUM_NETWORK_LIST_BYTES + 1)
        if len(encoded) > MAXIMUM_NETWORK_LIST_BYTES:
            raise NetworkSnapshotError("Cloudflare network list exceeded its bound")
        raw = encoded.decode("ascii")
    return _validated_networks(raw.splitlines(), version=version)


def compare_snapshot(path: Path) -> None:
    """Require exact equality with both independently published lists."""
    reviewed_ipv4, reviewed_ipv6 = load_snapshot(path)
    published_ipv4 = fetch_networks(IPV4_URL, version=4)
    published_ipv6 = fetch_networks(IPV6_URL, version=6)
    if reviewed_ipv4 != published_ipv4 or reviewed_ipv6 != published_ipv6:
        raise NetworkSnapshotError(
            "Cloudflare proxy networks changed; review an additive two-phase firewall update"
        )


def _validated_networks(value: object, *, version: int) -> frozenset[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise NetworkSnapshotError("network list is malformed")
    networks: set[str] = set()
    for raw in value:
        if not isinstance(raw, str) or not raw or raw != raw.strip():
            raise NetworkSnapshotError("network entry is malformed")
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as error:
            raise NetworkSnapshotError("network entry is not canonical") from error
        if network.version != version or network.prefixlen == 0 or str(network) != raw:
            raise NetworkSnapshotError("network entry crossed the reviewed boundary")
        if raw in networks:
            raise NetworkSnapshotError("network list contains a duplicate")
        networks.add(raw)
    if not networks:
        raise NetworkSnapshotError("network list cannot be empty")
    return frozenset(networks)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT, type=Path)
    arguments = parser.parse_args(argv)
    try:
        compare_snapshot(arguments.snapshot)
    except (OSError, UnicodeError, json.JSONDecodeError, NetworkSnapshotError) as error:
        print(f"Cloudflare network snapshot rejected: {error}", file=sys.stderr)
        return 1
    print("Cloudflare network snapshot matches the published proxy ranges.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
