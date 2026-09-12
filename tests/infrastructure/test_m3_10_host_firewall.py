from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

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
    assert main() == int(unexpected)
