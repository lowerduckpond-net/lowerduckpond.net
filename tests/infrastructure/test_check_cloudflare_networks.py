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
    snapshot = load_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)

    assert len(snapshot.active_ipv4) == IPV4_NETWORK_COUNT
    assert len(snapshot.active_ipv6) == IPV6_NETWORK_COUNT
    assert "0.0.0.0/0" not in snapshot.active_ipv4
    assert "::/0" not in snapshot.active_ipv6
    assert snapshot.active_ipv4 | snapshot.active_ipv6 == frozenset(CLOUDFLARE_NETWORKS)
    assert not snapshot.retiring_ipv4
    assert not snapshot.retiring_ipv6
    assert snapshot.active_ipv4 | snapshot.active_ipv6 == REVIEWED_CLOUDFLARE_CIDRS


def test_drift_check_requires_exact_published_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    reviewed = load_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)
    monkeypatch.setattr(
        check_cloudflare_networks,
        "fetch_networks",
        lambda url, *, version: (
            reviewed.active_ipv4 if version == IPV4_VERSION else reviewed.active_ipv6
        ),
    )

    compare_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)


def test_drift_check_rejects_an_unreviewed_range(monkeypatch: pytest.MonkeyPatch) -> None:
    reviewed = load_snapshot(check_cloudflare_networks.DEFAULT_SNAPSHOT)
    monkeypatch.setattr(
        check_cloudflare_networks,
        "fetch_networks",
        lambda url, *, version: (
            reviewed.active_ipv4 | {"192.0.2.0/24"}
            if version == IPV4_VERSION
            else reviewed.active_ipv6
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
                "retiring_ipv4_cidrs": [],
                "retiring_ipv6_cidrs": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(NetworkSnapshotError, match="duplicate"):
        load_snapshot(snapshot)


def test_drift_check_accepts_reviewed_retiring_ranges(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    committed = json.loads(check_cloudflare_networks.DEFAULT_SNAPSHOT.read_text(encoding="utf-8"))
    committed["retiring_ipv4_cidrs"] = ["192.0.2.0/24"]
    committed["retiring_ipv6_cidrs"] = ["2001:db8::/32"]
    snapshot_path = tmp_path / "networks.json"
    snapshot_path.write_text(json.dumps(committed), encoding="utf-8")
    reviewed = load_snapshot(snapshot_path)
    monkeypatch.setattr(
        check_cloudflare_networks,
        "fetch_networks",
        lambda url, *, version: (
            reviewed.active_ipv4 if version == IPV4_VERSION else reviewed.active_ipv6
        ),
    )

    compare_snapshot(snapshot_path)


def test_snapshot_rejects_overlap_between_active_and_retiring_ranges(tmp_path: Path) -> None:
    snapshot = tmp_path / "networks.json"
    snapshot.write_text(
        json.dumps(
            {
                "reviewed_at": "2026-08-25",
                "cloudflare_ipv4_cidrs": ["192.0.2.0/24"],
                "cloudflare_ipv6_cidrs": ["2001:db8::/32"],
                "retiring_ipv4_cidrs": ["192.0.2.0/24"],
                "retiring_ipv6_cidrs": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(NetworkSnapshotError, match="overlap"):
        load_snapshot(snapshot)
