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
WORLD_CIDRS: Final = frozenset({"0.0.0.0/0", "::/0"})
INBOUND_ALTERNATE_SOURCES: Final = (
    "source_droplet_ids",
    "source_kubernetes_ids",
    "source_load_balancer_uids",
    "source_tags",
)
OUTBOUND_ALTERNATE_DESTINATIONS: Final = (
    "destination_droplet_ids",
    "destination_kubernetes_ids",
    "destination_load_balancer_uids",
    "destination_tags",
)
EXPECTED_INBOUND_PORTS: Final = frozenset({"22", "80", "443"})
EXPECTED_OUTBOUND_RULES: Final = frozenset(
    {
        ("icmp", "0"),
        ("tcp", "53"),
        ("udp", "53"),
        ("udp", "123"),
        ("tcp", "80"),
        ("tcp", "443"),
    }
)
EXPECTED_CREATE_REFERENCES: Final = {
    "digitalocean_firewall.qualification": {
        "droplet_ids": (
            "digitalocean_droplet.qualification.id",
            "digitalocean_droplet.qualification",
        )
    },
    "digitalocean_project_resources.qualification": {
        "resources": (
            "digitalocean_droplet.qualification.urn",
            "digitalocean_droplet.qualification",
        )
    },
    "cloudflare_dns_record.qualification": {
        "content": (
            "digitalocean_droplet.qualification.ipv4_address",
            "digitalocean_droplet.qualification",
        )
    },
}


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

    _check_resource_attributes(plan, observed, destroy=destroy, errors=errors)
    if errors:
        raise QualificationPlanError("\n".join(errors))


def _check_resource_attributes(
    plan: Mapping[str, Any],
    resources: Mapping[str, Mapping[str, Any]],
    *,
    destroy: bool,
    errors: list[str],
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
    if firewall_resource is not None and not destroy:
        _check_firewall_rules(firewall, errors)

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
    else:
        _check_create_bindings(plan, errors)


def _check_firewall_rules(firewall: Mapping[str, Any], errors: list[str]) -> None:
    if firewall.get("tags") not in (None, [], ()):
        errors.append("qualification firewall must not target Droplets by tag")
    _check_inbound_rules(firewall.get("inbound_rule"), errors)
    _check_outbound_rules(firewall.get("outbound_rule"), errors)


def _check_inbound_rules(value: object, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) != len(EXPECTED_INBOUND_PORTS):
        errors.append("qualification firewall must have exactly three inbound rules")
        return
    observed_ports: list[str] = []
    for rule in value:
        if not isinstance(rule, dict):
            errors.append("qualification firewall contains a malformed inbound rule")
            continue
        protocol = rule.get("protocol")
        port = str(rule.get("port_range", ""))
        sources = _string_set(rule.get("source_addresses"))
        if any(rule.get(field) for field in INBOUND_ALTERNATE_SOURCES):
            errors.append("qualification firewall inbound rules must use only address sources")
        if protocol != "tcp" or port not in EXPECTED_INBOUND_PORTS or sources is None:
            errors.append("qualification firewall contains an unexpected inbound rule")
            continue
        observed_ports.append(port)
        if port == "22" and (not sources or not _are_restricted_networks(sources)):
            errors.append("qualification SSH must use a restricted address allowlist")
        elif port != "22" and sources != WORLD_CIDRS:
            errors.append(f"qualification TCP {port} must use the exact public address set")
    if (
        len(observed_ports) != len(EXPECTED_INBOUND_PORTS)
        or set(observed_ports) != EXPECTED_INBOUND_PORTS
    ):
        errors.append("qualification firewall inbound ports must be exactly 22, 80, and 443")


def _check_outbound_rules(value: object, errors: list[str]) -> None:
    observed_outbound: list[tuple[str, str]] = []
    if not isinstance(value, list) or len(value) != len(EXPECTED_OUTBOUND_RULES):
        errors.append("qualification firewall must have exactly six outbound rules")
        return
    for rule in value:
        if not isinstance(rule, dict):
            errors.append("qualification firewall contains a malformed outbound rule")
            continue
        protocol = str(rule.get("protocol", ""))
        port = str(rule.get("port_range") or "0")
        destinations = _string_set(rule.get("destination_addresses"))
        if any(rule.get(field) for field in OUTBOUND_ALTERNATE_DESTINATIONS):
            errors.append(
                "qualification firewall outbound rules must use only address destinations"
            )
        if destinations != WORLD_CIDRS:
            errors.append("qualification firewall egress must use the exact public address set")
        observed_outbound.append((protocol, port))
    if (
        len(observed_outbound) != len(set(observed_outbound))
        or set(observed_outbound) != EXPECTED_OUTBOUND_RULES
    ):
        errors.append("qualification firewall outbound protocols and ports are not exact")


def _check_create_bindings(plan: Mapping[str, Any], errors: list[str]) -> None:
    configuration = plan.get("configuration")
    root_module = configuration.get("root_module") if isinstance(configuration, dict) else None
    configured = root_module.get("resources", []) if isinstance(root_module, dict) else []
    if not isinstance(configured, list):
        configured = []
    for address, fields in EXPECTED_CREATE_REFERENCES.items():
        resource = next(
            (
                item
                for item in configured
                if isinstance(item, dict) and item.get("address") == address
            ),
            None,
        )
        if resource is None:
            errors.append(f"qualification configuration is missing {address}")
            continue
        expressions = resource.get("expressions", {})
        for field, expected in fields.items():
            expression = expressions.get(field, {}) if isinstance(expressions, dict) else {}
            references = expression.get("references", []) if isinstance(expression, dict) else []
            if not isinstance(references, list) or tuple(references) != expected:
                errors.append(f"{address}.{field} is not bound only to the disposable Droplet")


def _string_set(value: object) -> frozenset[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return frozenset(value)


def _are_restricted_networks(values: frozenset[str]) -> bool:
    try:
        networks = tuple(ipaddress.ip_network(value, strict=False) for value in values)
    except ValueError:
        return False
    ipv4_networks = [network for network in networks if isinstance(network, ipaddress.IPv4Network)]
    ipv6_networks = [network for network in networks if isinstance(network, ipaddress.IPv6Network)]
    return not any(
        network.prefixlen == 0 for network in ipaddress.collapse_addresses(ipv4_networks)
    ) and not any(network.prefixlen == 0 for network in ipaddress.collapse_addresses(ipv6_networks))


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
