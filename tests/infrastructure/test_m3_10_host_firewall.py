from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_m3_10_host_firewall import check_firewall

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
