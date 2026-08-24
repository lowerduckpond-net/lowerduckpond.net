#!/usr/bin/env python3
"""Require an exact disposable-resource plan for the M3.0 live gate."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Final

DNS_NAMES: Final = (
    "m3-a.lowerduckpond.com",
    "m3-qualification.lowerduckpond.net",
    "m3-unknown.lowerduckpond.com",
    "t-0198d17f6f4a70008000000000000001.lowerduckpond.com",
)
DNS_TTL: Final = 60
EXPECTED_RESOURCES: Final = {
    "digitalocean_droplet.qualification": "digitalocean_droplet",
    "digitalocean_firewall.qualification": "digitalocean_firewall",
    "digitalocean_project_resources.qualification": "digitalocean_project_resources",
    **{
        f'cloudflare_dns_record.qualification["{name}"]': "cloudflare_dns_record"
        for name in DNS_NAMES
    },
}
NON_MUTATING_ACTIONS: Final = {("no-op",), ("read",)}


class QualificationPlanError(RuntimeError):
    """Raised when a qualification plan crosses its disposable boundary."""


def assert_plan(plan: Mapping[str, Any], *, destroy: bool) -> None:
    """Validate the exact resource set, operation direction, and fixed safe attributes."""
    required_actions = ("delete",) if destroy else ("create",)
    observed: dict[str, Mapping[str, Any]] = {}
    errors: list[str] = []

    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        raise QualificationPlanError("resource_changes must be a list")
    for raw_change in changes:
        if not isinstance(raw_change, dict):
            errors.append("plan contains a malformed resource change")
            continue
        actions = tuple(raw_change.get("change", {}).get("actions", []))
        if actions in NON_MUTATING_ACTIONS:
            continue
        address = str(raw_change.get("address", ""))
        resource_type = str(raw_change.get("type", ""))
        if address in observed:
            errors.append(f"duplicate resource address: {address}")
            continue
        observed[address] = raw_change
        if EXPECTED_RESOURCES.get(address) != resource_type:
            errors.append(f"unexpected qualification resource: {address}")
        if actions != required_actions:
            errors.append(f"{address} must have only {required_actions[0]} action")

    missing = EXPECTED_RESOURCES.keys() - observed.keys()
    errors.extend(f"missing qualification resource: {address}" for address in sorted(missing))
    unexpected = observed.keys() - EXPECTED_RESOURCES.keys()
    errors.extend(f"unexpected qualification resource: {address}" for address in sorted(unexpected))

    if not destroy:
        _check_create_attributes(observed, errors)
    if errors:
        raise QualificationPlanError("\n".join(errors))


def _check_create_attributes(resources: Mapping[str, Mapping[str, Any]], errors: list[str]) -> None:
    droplet = _after(resources.get("digitalocean_droplet.qualification"))
    required_droplet = {
        "backups": False,
        "graceful_shutdown": True,
        "image": "ubuntu-26-04-x64",
        "ipv6": False,
        "monitoring": False,
        "name": "lowerduckpond-m3-qualification",
        "region": "nyc1",
        "resize_disk": False,
        "size": "s-1vcpu-2gb",
    }
    if any(droplet.get(key) != value for key, value in required_droplet.items()):
        errors.append("qualification Droplet attributes crossed the fixed boundary")

    firewall = _after(resources.get("digitalocean_firewall.qualification"))
    if firewall.get("name") != "lowerduckpond-m3-qualification":
        errors.append("qualification firewall name crossed the fixed boundary")

    for name in DNS_NAMES:
        address = f'cloudflare_dns_record.qualification["{name}"]'
        record = _after(resources.get(address))
        if (
            record.get("name") != name
            or record.get("type") != "A"
            or record.get("ttl") != DNS_TTL
            or record.get("proxied") is not False
        ):
            errors.append(f"qualification DNS attributes crossed the fixed boundary: {name}")


def _after(resource: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if resource is None:
        return {}
    change = resource.get("change", {})
    if not isinstance(change, dict):
        return {}
    after = change.get("after", {})
    return after if isinstance(after, dict) else {}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destroy", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        plan = json.load(sys.stdin)
        if not isinstance(plan, dict):
            raise QualificationPlanError("plan root must be an object")
        assert_plan(plan, destroy=arguments.destroy)
    except (json.JSONDecodeError, QualificationPlanError) as error:
        print(f"M3.0 qualification plan rejected: {error}", file=sys.stderr)
        return 1
    print("M3.0 qualification plan matches the exact disposable boundary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
