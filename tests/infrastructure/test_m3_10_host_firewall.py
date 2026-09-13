from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_cloudflare_networks as networks
from scripts.check_m3_10_host_firewall import check_firewall, main

ROOT = Path(__file__).parents[2]
FIXTURE = Path(__file__).parent / "fixtures/m3-10-host-firewall.json"


def web_networks() -> list[str]:
    published = json.loads((ROOT / "platform/cloudflare-networks.json").read_text())
    return [
        item
        for key in (
            "cloudflare_ipv4_cidrs",
            "cloudflare_ipv6_cidrs",
            "retiring_ipv4_cidrs",
            "retiring_ipv6_cidrs",
        )
        for item in published[key]
    ]


def test_real_installed_firewall_snapshot_matches_reviewed_policy() -> None:
    # Captured from the disposable Ubuntu 26.04 host; its administrative source
    # was replaced with an RFC 5737 documentation address before committing.
    check_firewall(json.loads(FIXTURE.read_text()), admin=["192.0.2.1/32"], web=web_networks())


@pytest.mark.parametrize(
    "mutation",
    ["broad-web", "extra-rule", "input-accept", "extra-chain", "metadata-access", "admin-drift"],
)
def test_active_firewall_drift_closes_the_gate(mutation: str) -> None:
    document = json.loads(FIXTURE.read_text())
    for entry in document["nftables"]:
        if mutation == "broad-web" and entry.get("set", {}).get("name") == "web_ipv4":
            entry["set"]["elem"] = [{"prefix": {"addr": "0.0.0.0", "len": 0}}]  # noqa: S104 - refusal fixture
        if mutation == "admin-drift" and entry.get("set", {}).get("name") == "admin_ipv4":
            entry["set"]["elem"] = ["192.0.2.2"]
        if mutation == "input-accept" and entry.get("chain", {}).get("name") == "input":
            entry["chain"]["policy"] = "accept"
        if mutation == "metadata-access" and entry.get("rule", {}).get("chain") == "output":
            entry["rule"]["expr"] = [{"accept": None}]
    if mutation == "extra-rule":
        document["nftables"].append(
            {
                "rule": {
                    "family": "inet",
                    "table": "lowerduckpond",
                    "chain": "input",
                    "expr": [{"accept": None}],
                }
            }
        )
    if mutation == "extra-chain":
        document["nftables"].append({"chain": {"name": "bypass"}})
    with pytest.raises(ValueError):
        check_firewall(document, admin=["192.0.2.1/32"], web=web_networks())


@pytest.mark.parametrize("family", ["inet", "ip", "ip6", "bridge", "netdev"])
def test_firewall_gate_rejects_tables_outside_the_managed_policy(family: str) -> None:
    document = json.loads(FIXTURE.read_text())
    document["nftables"].append({"table": {"family": family, "name": "unexpected"}})
    with pytest.raises(ValueError):
        check_firewall(document, admin=["192.0.2.1/32"], web=web_networks())


@pytest.mark.parametrize("unexpected", [False, True])
def test_firewall_probe_requests_the_full_remote_ruleset(
    monkeypatch: pytest.MonkeyPatch, unexpected: bool
) -> None:
    document = json.loads(FIXTURE.read_text())
    if unexpected:
        document["nftables"].append({"table": {"family": "ip", "name": "unexpected"}})

    def remote(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert arguments[-1] == "sudo --non-interactive /usr/sbin/nft --json list ruleset"
        return subprocess.CompletedProcess(arguments, 0, stdout=json.dumps(document).encode())

    monkeypatch.setenv("PRODUCTION_ORIGIN_IPV4", "192.0.2.1")
    monkeypatch.setenv("ADMIN_SOURCE_CIDRS_JSON", '["192.0.2.1/32"]')
    monkeypatch.setenv("ANSIBLE_PRIVATE_KEY_FILE", "/private/fixture-key")
    monkeypatch.setattr("scripts.check_m3_10_host_firewall.subprocess.run", remote)
    monkeypatch.setattr(
        "scripts.check_m3_10_host_firewall.compare_snapshot", lambda *_a, **_k: None
    )
    assert main() == int(unexpected)


@pytest.mark.parametrize("version", [4, 6])
@pytest.mark.parametrize("change", ["none", "added", "removed", "unavailable"])
def test_live_firewall_gate_revalidates_published_networks_before_contacting_host(
    monkeypatch: pytest.MonkeyPatch, version: int, change: str
) -> None:
    reviewed = networks.load_snapshot(ROOT / "platform/cloudflare-networks.json")
    calls: list[str] = []

    def fetch(url: str, *, version: int) -> frozenset[str]:
        assert url == (networks.IPV4_URL if version == networks.IPV4_VERSION else networks.IPV6_URL)
        calls.append(str(version))
        values = reviewed.active_ipv4 if version == networks.IPV4_VERSION else reviewed.active_ipv6
        if version != changed_version or change == "none":
            return values
        if change == "unavailable":
            raise OSError("public network endpoint is unavailable")
        if change == "added":
            return values | {
                "192.0.2.0/24" if version == networks.IPV4_VERSION else "2001:db8::/32"
            }
        return values - {sorted(values)[0]}

    def remote(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append("ssh")
        return subprocess.CompletedProcess(arguments, 0, stdout=FIXTURE.read_bytes())

    changed_version = version
    monkeypatch.setenv("PRODUCTION_ORIGIN_IPV4", "192.0.2.1")
    monkeypatch.setenv("ADMIN_SOURCE_CIDRS_JSON", '["192.0.2.1/32"]')
    monkeypatch.setenv("ANSIBLE_PRIVATE_KEY_FILE", "/private/fixture-key")
    monkeypatch.setattr(networks, "fetch_networks", fetch)
    monkeypatch.setattr("scripts.check_m3_10_host_firewall.subprocess.run", remote)
    assert main() == int(change != "none")
    assert calls == (
        ["4", "6", "ssh"]
        if change == "none"
        else ["4"]
        if change == "unavailable" and version == networks.IPV4_VERSION
        else ["4", "6"]
    )
