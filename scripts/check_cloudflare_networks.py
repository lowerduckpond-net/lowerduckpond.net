#!/usr/bin/env python3
"""Fail when the reviewed Cloudflare proxy network snapshot has drifted."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from http import HTTPStatus
from pathlib import Path
from typing import Final

IPV4_URL: Final = "https://www.cloudflare.com/ips-v4/"
IPV6_URL: Final = "https://www.cloudflare.com/ips-v6/"
DEFAULT_SNAPSHOT: Final = Path(__file__).parents[1] / "platform/cloudflare-networks.json"
DEFAULT_REPOSITORY: Final = Path(__file__).parents[1]
DEFAULT_REVIEWED_REF: Final = "origin/main"
TIMEOUT_SECONDS: Final = 15
MAXIMUM_NETWORK_LIST_BYTES: Final = 65_536
COMMIT_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
IPV4_VERSION: Final = 4
GIT_EXECUTABLE: Final = "/usr/bin/git"


class NetworkSnapshotError(RuntimeError):
    """Raised when the reviewed or published network set is unsafe."""


@dataclass(frozen=True)
class NetworkSnapshot:
    """Active provider ranges plus temporarily retained retiring ranges."""

    active_ipv4: frozenset[str]
    active_ipv6: frozenset[str]
    retiring_ipv4: frozenset[str]
    retiring_ipv6: frozenset[str]
    retiring_provenance: dict[str, str]


def load_snapshot(path: Path) -> NetworkSnapshot:
    """Read and validate the committed active and retiring network sets."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
        "reviewed_at",
        "cloudflare_ipv4_cidrs",
        "cloudflare_ipv6_cidrs",
        "retiring_ipv4_cidrs",
        "retiring_ipv6_cidrs",
        "retiring_cidr_provenance",
    }:
        raise NetworkSnapshotError("reviewed snapshot shape is not recognized")
    reviewed_at = value["reviewed_at"]
    try:
        reviewed_date = date.fromisoformat(reviewed_at)
    except (TypeError, ValueError) as error:
        raise NetworkSnapshotError("review date is not canonical") from error
    if reviewed_at != reviewed_date.isoformat() or reviewed_date > date.today():
        raise NetworkSnapshotError("review date is not canonical")
    snapshot = NetworkSnapshot(
        active_ipv4=_validated_networks(value["cloudflare_ipv4_cidrs"], version=4),
        active_ipv6=_validated_networks(value["cloudflare_ipv6_cidrs"], version=6),
        retiring_ipv4=_validated_networks(
            value["retiring_ipv4_cidrs"], version=4, allow_empty=True
        ),
        retiring_ipv6=_validated_networks(
            value["retiring_ipv6_cidrs"], version=6, allow_empty=True
        ),
        retiring_provenance=_validated_provenance(value["retiring_cidr_provenance"]),
    )
    _reject_overlapping_networks(snapshot.active_ipv4, snapshot.retiring_ipv4)
    _reject_overlapping_networks(snapshot.active_ipv6, snapshot.retiring_ipv6)
    if set(snapshot.retiring_provenance) != set(snapshot.retiring_ipv4 | snapshot.retiring_ipv6):
        raise NetworkSnapshotError(
            "retiring provenance must cover exactly the retiring network set"
        )
    return snapshot


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


def compare_snapshot(
    path: Path,
    *,
    repository: Path = DEFAULT_REPOSITORY,
    reviewed_ref: str = DEFAULT_REVIEWED_REF,
) -> None:
    """Require exact equality with both independently published lists."""
    reviewed = load_snapshot(path)
    _verify_retiring_provenance(
        reviewed,
        repository=repository,
        reviewed_ref=reviewed_ref,
        snapshot_path=path,
    )
    published_ipv4 = fetch_networks(IPV4_URL, version=4)
    published_ipv6 = fetch_networks(IPV6_URL, version=6)
    if reviewed.active_ipv4 != published_ipv4 or reviewed.active_ipv6 != published_ipv6:
        raise NetworkSnapshotError(
            "Cloudflare proxy networks changed; review an additive two-phase firewall update"
        )


def _validated_networks(
    value: object, *, version: int, allow_empty: bool = False
) -> frozenset[str]:
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
    if not networks and not allow_empty:
        raise NetworkSnapshotError("network list cannot be empty")
    return frozenset(networks)


def _validated_provenance(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise NetworkSnapshotError("retiring provenance is malformed")
    result: dict[str, str] = {}
    for network, commit in value.items():
        if (
            not isinstance(network, str)
            or not isinstance(commit, str)
            or COMMIT_PATTERN.fullmatch(commit) is None
        ):
            raise NetworkSnapshotError("retiring provenance is malformed")
        result[network] = commit
    return result


def _verify_retiring_provenance(
    snapshot: NetworkSnapshot,
    *,
    repository: Path,
    reviewed_ref: str,
    snapshot_path: Path,
) -> None:
    if not snapshot.retiring_provenance:
        return
    try:
        relative_snapshot = snapshot_path.resolve().relative_to(repository.resolve())
    except ValueError as error:
        raise NetworkSnapshotError("snapshot is outside the reviewed repository") from error
    referenced: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for commit in sorted(set(snapshot.retiring_provenance.values())):
        ancestry = subprocess.run(  # noqa: S603 - fixed Git operation over validated IDs.
            [
                GIT_EXECUTABLE,
                "-C",
                str(repository),
                "merge-base",
                "--is-ancestor",
                commit,
                reviewed_ref,
            ],
            check=False,
            capture_output=True,
        )
        if ancestry.returncode != 0:
            raise NetworkSnapshotError(
                "retiring provenance is not reachable from the reviewed main line"
            )
        historical = subprocess.run(  # noqa: S603 - fixed Git operation over validated IDs.
            [
                GIT_EXECUTABLE,
                "-C",
                str(repository),
                "show",
                f"{commit}:{relative_snapshot.as_posix()}",
            ],
            check=False,
            capture_output=True,
        )
        if historical.returncode != 0 or len(historical.stdout) > MAXIMUM_NETWORK_LIST_BYTES:
            raise NetworkSnapshotError("retiring provenance snapshot is unavailable")
        try:
            value = json.loads(historical.stdout.decode("utf-8"))
            active_ipv4 = _validated_networks(value["cloudflare_ipv4_cidrs"], version=4)
            active_ipv6 = _validated_networks(value["cloudflare_ipv6_cidrs"], version=6)
        except (KeyError, UnicodeError, json.JSONDecodeError, NetworkSnapshotError) as error:
            raise NetworkSnapshotError("retiring provenance snapshot is invalid") from error
        referenced[commit] = (active_ipv4, active_ipv6)
    for network, commit in snapshot.retiring_provenance.items():
        version = ipaddress.ip_network(network, strict=True).version
        active = referenced[commit][0 if version == IPV4_VERSION else 1]
        if network not in active:
            raise NetworkSnapshotError(
                "retiring network was not active in its reviewed provenance snapshot"
            )


def _reject_overlapping_networks(*groups: frozenset[str]) -> None:
    networks = [ipaddress.ip_network(raw, strict=True) for group in groups for raw in group]
    for index, network in enumerate(networks):
        if any(network.overlaps(other) for other in networks[index + 1 :]):
            raise NetworkSnapshotError("network entries overlap")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT, type=Path)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY, type=Path)
    parser.add_argument("--reviewed-ref", default=DEFAULT_REVIEWED_REF)
    arguments = parser.parse_args(argv)
    try:
        compare_snapshot(
            arguments.snapshot,
            repository=arguments.repository,
            reviewed_ref=arguments.reviewed_ref,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, NetworkSnapshotError) as error:
        print(f"Cloudflare network snapshot rejected: {error}", file=sys.stderr)
        return 1
    print("Cloudflare network snapshot matches the published proxy ranges.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
