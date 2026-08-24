#!/usr/bin/env python3
"""Require an exact disposable-resource plan for the M3.0 live gate."""

from __future__ import annotations

import argparse
import ipaddress
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
IPV4_VERSION: Final = 4
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
QUALIFICATION_NAME: Final = "lowerduckpond-m3-qualification"
QUALIFICATION_REGION: Final = "nyc1"
QUALIFICATION_IMAGE: Final = "ubuntu-26-04-x64"
QUALIFICATION_SIZE: Final = "s-1vcpu-2gb"


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

    if not destroy:
        missing = EXPECTED_RESOURCES.keys() - observed.keys()
        errors.extend(f"missing qualification resource: {address}" for address in sorted(missing))
    unexpected = observed.keys() - EXPECTED_RESOURCES.keys()
    errors.extend(f"unexpected qualification resource: {address}" for address in sorted(unexpected))

    _check_resource_attributes(observed, destroy=destroy, errors=errors)
    if errors:
        raise QualificationPlanError("\n".join(errors))


def _check_resource_attributes(
    resources: Mapping[str, Mapping[str, Any]], *, destroy: bool, errors: list[str]
) -> None:
    value_side = _before if destroy else _after
    droplet_resource = resources.get("digitalocean_droplet.qualification")
    droplet = value_side(droplet_resource) if droplet_resource is not None else {}
    required_droplet: dict[str, object] = {
        "image": QUALIFICATION_IMAGE,
        "name": QUALIFICATION_NAME,
        "region": QUALIFICATION_REGION,
        "size": QUALIFICATION_SIZE,
    }
    if not destroy:
        required_droplet |= {
            "backups": False,
            "graceful_shutdown": True,
            "ipv6": False,
            "monitoring": False,
            "resize_disk": False,
        }
    if droplet_resource is not None and any(
        droplet.get(key) != value for key, value in required_droplet.items()
    ):
        errors.append("qualification Droplet attributes crossed the fixed boundary")

    firewall_resource = resources.get("digitalocean_firewall.qualification")
    firewall = value_side(firewall_resource) if firewall_resource is not None else {}
    if firewall_resource is not None and firewall.get("name") != QUALIFICATION_NAME:
        errors.append("qualification firewall name crossed the fixed boundary")

    for name in DNS_NAMES:
        address = f'cloudflare_dns_record.qualification["{name}"]'
        record_resource = resources.get(address)
        if record_resource is None:
            continue
        record = value_side(record_resource)
        if (
            record.get("name") != name
            or record.get("type") != "A"
            or record.get("proxied") is not False
            or (not destroy and record.get("ttl") != DNS_TTL)
        ):
            errors.append(f"qualification DNS attributes crossed the fixed boundary: {name}")

    if destroy:
        _check_destroy_bindings(resources, droplet, firewall, errors)


def _check_destroy_bindings(
    resources: Mapping[str, Mapping[str, Any]],
    droplet: Mapping[str, Any],
    firewall: Mapping[str, Any],
    errors: list[str],
) -> None:
    droplet_present = "digitalocean_droplet.qualification" in resources
    droplet_id = _droplet_id(droplet) if droplet_present else None
    droplet_urn = droplet.get("urn") if droplet_present else None
    droplet_ip = droplet.get("ipv4_address") if droplet_present else None
    if droplet_present and (
        droplet_id is None or droplet_urn != f"do:droplet:{droplet_id}" or not _is_ipv4(droplet_ip)
    ):
        errors.append("qualification Droplet destroy identity is incomplete")

    if "digitalocean_firewall.qualification" in resources:
        attached = firewall.get("droplet_ids")
        if droplet_id is None:
            if attached != []:
                errors.append("orphaned qualification firewall still targets an unproven Droplet")
        elif not _is_single_identifier(attached, droplet_id):
            errors.append("qualification firewall is not bound only to the disposable Droplet")

    project_resource = resources.get("digitalocean_project_resources.qualification")
    if project_resource is not None:
        members = _before(project_resource).get("resources")
        if droplet_urn is None:
            if members != []:
                errors.append("orphaned qualification project assignment has unproven members")
        elif members != [droplet_urn]:
            errors.append("qualification project assignment is not bound only to the Droplet")

    if droplet_ip is not None:
        for name in DNS_NAMES:
            address = f'cloudflare_dns_record.qualification["{name}"]'
            record_resource = resources.get(address)
            if (
                record_resource is not None
                and _before(record_resource).get("content") != droplet_ip
            ):
                errors.append(f"qualification DNS record is not bound to the Droplet: {name}")


def _droplet_id(droplet: Mapping[str, Any]) -> str | None:
    value = droplet.get("id")
    if isinstance(value, int) and value > 0:
        return str(value)
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return value
    return None


def _is_ipv4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value).version == IPV4_VERSION
    except ValueError:
        return False


def _is_single_identifier(value: object, expected: str) -> bool:
    return isinstance(value, list) and len(value) == 1 and str(value[0]) == expected


def _after(resource: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return _change_side(resource, "after")


def _before(resource: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return _change_side(resource, "before")


def _change_side(resource: Mapping[str, Any] | None, side: str) -> Mapping[str, Any]:
    if resource is None:
        return {}
    change = resource.get("change", {})
    if not isinstance(change, dict):
        return {}
    value = change.get(side, {})
    return value if isinstance(value, dict) else {}


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
    print("M3.0 qualification plan stays within the exact disposable boundary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
