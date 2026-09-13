"""Read the active host firewall and compare its complete ruleset with reviewed policy."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from pathlib import Path

from scripts.check_cloudflare_networks import NetworkSnapshotError, compare_snapshot


def match(left: object, right: object, operation: str = "==") -> dict[str, object]:
    return {"match": {"op": operation, "left": left, "right": right}}


def payload(protocol: str, field: str) -> dict[str, object]:
    return {"payload": {"protocol": protocol, "field": field}}


def expected_expressions(set_names: set[str]) -> dict[str, list[list[dict[str, object]]]]:
    state = {"ct": {"key": "state"}}
    accept: dict[str, object] = {"accept": None}
    input_rules: list[list[dict[str, object]]] = [
        [match({"meta": {"key": "iifname"}}, "lo"), accept],
        [match(state, ["established", "related"], "in"), accept],
        [match(state, "invalid", "in"), {"drop": None}],
        [match(payload("ip", "protocol"), "icmp"), accept],
        [match(payload("ip6", "nexthdr"), "ipv6-icmp"), accept],
    ]
    for name in ("admin_ipv4", "admin_ipv6", "web_ipv4", "web_ipv6"):
        if name in set_names:
            input_rules.append(  # noqa: PERF401 - preserve firewall rule order explicitly
                [
                    match(payload("ip" if name.endswith("4") else "ip6", "saddr"), "@" + name),
                    match(
                        payload("tcp", "dport"),
                        22 if name.startswith("admin") else {"set": [80, 443]},
                    ),
                    match(state, "new", "in"),
                    accept,
                ]
            )
    metadata = match(payload("ip", "daddr"), "169.254.169.254")
    reject: dict[str, object] = {"reject": {"type": "icmp", "expr": "port-unreachable"}}
    return {
        "input": input_rules,
        "forward": [[metadata, reject]],
        "output": [[match({"meta": {"key": "skuid"}}, 0, "!="), metadata, reject]],
    }


def network(element: object) -> str:
    if isinstance(element, str):
        return str(ipaddress.ip_network(element, strict=True))
    if isinstance(element, dict) and set(element) == {"prefix"}:
        prefix = element["prefix"]
        if isinstance(prefix, dict) and set(prefix) == {"addr", "len"}:
            return str(ipaddress.ip_network(f"{prefix['addr']}/{prefix['len']}", strict=True))
    raise ValueError("firewall set element is not a plain address or network")


def check_firewall(  # noqa: PLR0912 - every independent firewall object must be validated
    document: object, *, admin: list[str], web: list[str]
) -> None:
    if not isinstance(document, dict) or set(document) != {"nftables"}:
        raise ValueError("firewall response is invalid")
    entries = document["nftables"]
    if not isinstance(entries, list):
        raise ValueError("firewall inventory is invalid")
    expected_sets: dict[str, set[str]] = {}
    for name, addresses in (("admin", admin), ("web", web)):
        for address in addresses:
            cidr = ipaddress.ip_network(address, strict=True)
            expected_sets.setdefault(f"{name}_ipv{cidr.version}", set()).add(str(cidr))
    if not admin or not web:
        raise ValueError("reviewed firewall sources are absent")
    tables = []
    chains = []
    observed_sets: dict[str, set[str]] = {}
    observed_rules: dict[str, list[object]] = {"input": [], "forward": [], "output": []}
    for entry in entries:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError("firewall entry is invalid")
        kind, raw = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        if not isinstance(raw, dict):
            raise ValueError("firewall entry is invalid")
        value = {key: item for key, item in raw.items() if key != "handle"}
        if kind == "table":
            tables.append(value)
        elif kind == "chain":
            chains.append(value)
        elif kind == "set":
            if (
                set(value) != {"family", "table", "name", "type", "flags", "elem"}
                or value["family"] != "inet"
                or value["table"] != "lowerduckpond"
                or value["name"] not in expected_sets
                or value["name"] in observed_sets
                or value["type"] != ("ipv4_addr" if value["name"].endswith("4") else "ipv6_addr")
                or value["flags"] != ["interval"]
                or not isinstance(value["elem"], list)
            ):
                raise ValueError("firewall source set drifted")
            observed_sets[value["name"]] = {network(element) for element in value["elem"]}
        elif kind == "rule":
            if (
                set(value) != {"family", "table", "chain", "expr"}
                or value["family"] != "inet"
                or value["table"] != "lowerduckpond"
                or value["chain"] not in observed_rules
            ):
                raise ValueError("firewall rule inventory drifted")
            observed_rules[value["chain"]].append(value["expr"])
        else:
            raise ValueError("firewall has an unrecognized object")
    expected_chains = [
        {
            "family": "inet",
            "table": "lowerduckpond",
            "name": name,
            "type": "filter",
            "hook": name,
            "prio": 0,
            "policy": "drop" if name == "input" else "accept",
        }
        for name in ("input", "forward", "output")
    ]
    if (
        tables != [{"family": "inet", "name": "lowerduckpond"}]
        or chains != expected_chains
        or observed_sets != expected_sets
        or observed_rules != expected_expressions(set(expected_sets))
    ):
        raise ValueError("active firewall differs from reviewed host policy")


def main() -> int:
    try:
        origin = str(ipaddress.IPv4Address(os.environ["PRODUCTION_ORIGIN_IPV4"]))
        admin = json.loads(os.environ["ADMIN_SOURCE_CIDRS_JSON"])
        if not isinstance(admin, list) or not all(isinstance(item, str) for item in admin):
            raise ValueError("administrative source contract is invalid")
        root = Path(__file__).resolve().parents[1]
        snapshot = root / "platform/cloudflare-networks.json"
        compare_snapshot(snapshot, repository=root)
        published = json.loads(snapshot.read_text())
        web = [
            value
            for name in (
                "cloudflare_ipv4_cidrs",
                "cloudflare_ipv6_cidrs",
                "retiring_ipv4_cidrs",
                "retiring_ipv6_cidrs",
            )
            for value in published[name]
        ]
        outcome = subprocess.run(  # noqa: S603 - validated origin, fixed read-only remote command
            [
                "/usr/bin/ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "HostKeyAlias=lowerduckpond.net",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=15",
                "-i",
                os.environ["ANSIBLE_PRIVATE_KEY_FILE"],
                f"ldp-admin@{origin}",
                "sudo --non-interactive /usr/sbin/nft --json list ruleset",
            ],
            capture_output=True,
            check=True,
            timeout=30,
        )
        check_firewall(json.loads(outcome.stdout), admin=admin, web=web)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        NetworkSnapshotError,
    ):
        print("M3.10 active host firewall proof failed closed.")
        return 1
    print("M3.10 active host firewall matches reviewed administrative and Cloudflare-only policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
