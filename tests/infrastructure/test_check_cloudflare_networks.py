from __future__ import annotations

import json
from pathlib import Path

import pytest
from lowerduckpond_m3_qualification.edge import CLOUDFLARE_NETWORKS

from scripts import check_cloudflare_networks
from scripts.assert_m3_qualification_plan import REVIEWED_CLOUDFLARE_CIDRS
from scripts.check_cloudflare_networks import NetworkSnapshotError, compare_snapshot, load_snapshot

IPV4_NETWORK_COUNT = 15
IPV6_NETWORK_COUNT = 7
IPV4_VERSION = 4


def test_committed_snapshot_contains_only_canonical_provider_networks() -> None:
    ipv4, ipv6 = load_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)

    assert len(ipv4) == IPV4_NETWORK_COUNT
    assert len(ipv6) == IPV6_NETWORK_COUNT
    assert "0.0.0.0/0" not in ipv4
    assert "::/0" not in ipv6
    assert ipv4 | ipv6 == frozenset(CLOUDFLARE_NETWORKS)
    assert ipv4 | ipv6 == REVIEWED_CLOUDFLARE_CIDRS


def test_drift_check_requires_exact_published_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    reviewed = load_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)
    monkeypatch.setattr(
        check_cloudflare_networks,
        "fetch_networks",
        lambda url, *, version: reviewed[0 if version == IPV4_VERSION else 1],
    )

    compare_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)


def test_drift_check_rejects_an_unreviewed_range(monkeypatch: pytest.MonkeyPatch) -> None:
    reviewed = load_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)
    monkeypatch.setattr(
        check_cloudflare_networks,
        "fetch_networks",
        lambda url, *, version: (
            reviewed[0] | {"192.0.2.0/24"} if version == IPV4_VERSION else reviewed[1]
        ),
    )

    with pytest.raises(NetworkSnapshotError, match="changed"):
        compare_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)


def test_snapshot_rejects_duplicate_networks(tmp_path: Path) -> None:
    snapshot = tmp_path / "networks.json"
    snapshot.write_text(
        json.dumps(
            {
                "reviewed_at": "2026-08-25",
                "cloudflare_ipv4_cidrs": ["192.0.2.0/24", "192.0.2.0/24"],
                "cloudflare_ipv6_cidrs": ["2001:db8::/32"],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(NetworkSnapshotError, match="duplicate"):
        load_snapshot(snapshot)
