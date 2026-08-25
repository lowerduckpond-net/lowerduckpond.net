#!/usr/bin/env python3
"""Require an exact disposable-resource plan for the M3.0 live gate."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Final

ZONE_HOSTNAMES: Final = {
    "lowerduckpond_net": ("m3-qualification.lowerduckpond.net",),
    "lowerduckpond_com": (
        "m3-a.lowerduckpond.com",
        "m3-unknown.lowerduckpond.com",
        "t-0198d17f6f4a70008000000000000001.lowerduckpond.com",
    ),
}
DNS_NAMES: Final = tuple(sorted(name for names in ZONE_HOSTNAMES.values() for name in names))
DNS_TTL: Final = 1
IPV4_VERSION: Final = 4
EXPECTED_RESOURCES: Final = {
    "digitalocean_droplet.qualification": "digitalocean_droplet",
    "digitalocean_firewall.qualification": "digitalocean_firewall",
    "digitalocean_project_resources.qualification": "digitalocean_project_resources",
    **{
        f'cloudflare_dns_record.qualification["{name}"]': "cloudflare_dns_record"
        for name in DNS_NAMES
    },
    **{
        f'cloudflare_authenticated_origin_pulls.qualification["{name}"]': (
            "cloudflare_authenticated_origin_pulls"
        )
        for name in DNS_NAMES
    },
    **{
        f'cloudflare_ruleset.qualification_{policy}["{zone}"]': "cloudflare_ruleset"
        for policy in ("cache_bypass", "cdn_cgi_block", "transform_disable")
        for zone in ZONE_HOSTNAMES
    },
}
AOP_RESOURCES: Final = frozenset(
    f'cloudflare_authenticated_origin_pulls.qualification["{name}"]' for name in DNS_NAMES
)
NON_MUTATING_ACTIONS: Final = {("no-op",), ("read",)}
QUALIFICATION_NAME: Final = "lowerduckpond-m3-qualification"
QUALIFICATION_REGION: Final = "nyc1"
QUALIFICATION_IMAGE: Final = "ubuntu-26-04-x64"
QUALIFICATION_SIZE: Final = "s-1vcpu-2gb"
WORLD_CIDRS: Final = frozenset({"0.0.0.0/0", "::/0"})
REVIEWED_CLOUDFLARE_CIDRS: Final = frozenset(
    {
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    }
)
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


def _assert_transition(  # noqa: PLR0912 - each branch rejects one boundary escape.
    plan: Mapping[str, Any], *, transition: str
) -> None:
    if transition not in {"primary", "replacement"}:
        raise QualificationPlanError("transition must select primary or replacement")
    if _plan_generation(plan) != transition:
        raise QualificationPlanError("saved plan does not select the requested AOP generation")

    errors: list[str] = []
    observed: dict[str, Mapping[str, Any]] = {}
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
        if address in observed:
            errors.append(f"duplicate resource address: {address}")
            continue
        observed[address] = raw_change
        if address not in AOP_RESOURCES:
            errors.append(f"unexpected AOP transition resource: {address}")
        if raw_change.get("type") != "cloudflare_authenticated_origin_pulls":
            errors.append(f"unexpected AOP transition resource type: {address}")
        if actions != ("update",):
            errors.append(f"{address} must have only update action")

    errors.extend(
        f"missing AOP transition resource: {address}"
        for address in sorted(AOP_RESOURCES - observed.keys())
    )
    prior_generation = "replacement" if transition == "primary" else "primary"
    for name in DNS_NAMES:
        address = f'cloudflare_authenticated_origin_pulls.qualification["{name}"]'
        resource = observed.get(address)
        if resource is None:
            continue
        _check_aop_resource(
            plan,
            _before(resource),
            hostname=name,
            generation=prior_generation,
            errors=errors,
        )
        _check_aop_resource(
            plan,
            _after(resource),
            hostname=name,
            generation=transition,
            errors=errors,
        )
        _check_aop_transition_shape(resource, hostname=name, errors=errors)
    if errors:
        raise QualificationPlanError("\n".join(errors))


def _check_aop_transition_shape(
    resource: Mapping[str, Any], *, hostname: str, errors: list[str]
) -> None:
    before = _before(resource)
    after = _after(resource)
    if {key: value for key, value in before.items() if key != "config"} != {
        key: value for key, value in after.items() if key != "config"
    }:
        errors.append(f"qualification AOP transition changed more than config: {hostname}")
        return
    before_config = before.get("config")
    after_config = after.get("config")
    if (
        not isinstance(before_config, list)
        or len(before_config) != 1
        or not isinstance(before_config[0], dict)
        or not isinstance(after_config, list)
        or len(after_config) != 1
        or not isinstance(after_config[0], dict)
    ):
        return
    before_item = {key: value for key, value in before_config[0].items() if key != "cert_id"}
    after_item = {key: value for key, value in after_config[0].items() if key != "cert_id"}
    if before_item != after_item:
        errors.append(f"qualification AOP transition changed more than cert_id: {hostname}")


def _check_aop_resource(
    plan: Mapping[str, Any],
    value: Mapping[str, Any],
    *,
    hostname: str,
    generation: str,
    errors: list[str],
) -> None:
    zone_key = _zone_key_for_hostname(hostname)
    expected_zone = _plan_variable(plan, f"{zone_key}_zone_id")
    expected_certificate = _certificate_id(plan, generation=generation, zone_key=zone_key)
    config = value.get("config")
    if not isinstance(config, list) or len(config) != 1 or not isinstance(config[0], dict):
        errors.append(f"qualification AOP config must contain one item: {hostname}")
        return
    item = config[0]
    if (
        value.get("zone_id") != expected_zone
        or item.get("hostname") != hostname
        or item.get("enabled") is not True
        or item.get("cert_id") != expected_certificate
    ):
        errors.append(f"qualification AOP association crossed its boundary: {hostname}")


def _check_ruleset(
    value: Mapping[str, Any], *, policy: str, zone_key: str, errors: list[str]
) -> None:
    host_expression = _host_expression(zone_key)
    names = {
        "cache_bypass": "Lower Duck Pond M3.0 qualification cache bypass",
        "transform_disable": "Lower Duck Pond M3.0 qualification transform policy",
        "cdn_cgi_block": "Lower Duck Pond M3.0 qualification reserved path",
    }
    phases = {
        "cache_bypass": "http_request_cache_settings",
        "transform_disable": "http_config_settings",
        "cdn_cgi_block": "http_request_firewall_custom",
    }
    actions = {
        "cache_bypass": "set_cache_settings",
        "transform_disable": "set_config",
        "cdn_cgi_block": "block",
    }
    descriptions = {
        "cache_bypass": "Never cache a Milestone 3 qualification response",
        "transform_disable": "Preserve origin representations for qualification",
        "cdn_cgi_block": "Block Cloudflare's reserved path before it reaches Caddy",
    }
    expressions = {
        "cache_bypass": host_expression,
        "transform_disable": host_expression,
        "cdn_cgi_block": (
            f'({host_expression}) and (lower(http.request.uri.path) eq "/cdn-cgi" '
            'or starts_with(lower(http.request.uri.path), "/cdn-cgi/"))'
        ),
    }
    rules = value.get("rules")
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        errors.append(f"qualification {policy} ruleset must contain one rule for {zone_key}")
        return
    rule = rules[0]
    if (
        value.get("kind") != "zone"
        or value.get("phase") != phases[policy]
        or value.get("name") != names[policy]
        or value.get("description")
        != "Disposable qualification hostnames only; remove during complete teardown"
        or rule.get("action") != actions[policy]
        or rule.get("expression") != expressions[policy]
        or rule.get("description") != descriptions[policy]
        or rule.get("enabled") is not True
        or rule.get("ref") != f"lowerduckpond_m3_qualification_{policy}"
    ):
        errors.append(f"qualification {policy} ruleset crossed its boundary: {zone_key}")

    expected_parameters: dict[str, object]
    if policy == "cache_bypass":
        expected_parameters = {"cache": False}
    elif policy == "transform_disable":
        expected_parameters = {
            "automatic_https_rewrites": False,
            "disable_rum": True,
            "disable_zaraz": True,
            "email_obfuscation": False,
            "fonts": False,
            "rocket_loader": False,
        }
    else:
        expected_parameters = {}
    parameters = rule.get("action_parameters")
    if expected_parameters:
        if not isinstance(parameters, dict) or any(
            parameters.get(key) != expected for key, expected in expected_parameters.items()
        ):
            errors.append(f"qualification {policy} action parameters are incomplete: {zone_key}")
        elif any(
            value is not None and key not in expected_parameters
            for key, value in parameters.items()
        ):
            errors.append(f"qualification {policy} action parameters are overbroad: {zone_key}")
    elif isinstance(parameters, dict) and any(value is not None for value in parameters.values()):
        errors.append(f"qualification {policy} block rule must not configure another action")


def _host_expression(zone_key: str) -> str:
    quoted = " ".join(f'"{hostname}"' for hostname in ZONE_HOSTNAMES[zone_key])
    return f"http.host in {{{quoted}}}"


def _zone_key_for_hostname(hostname: str) -> str:
    return "lowerduckpond_net" if hostname.endswith(".lowerduckpond.net") else "lowerduckpond_com"


def _plan_generation(plan: Mapping[str, Any]) -> str:
    value = _plan_variable(plan, "origin_pull_generation")
    if value not in {"primary", "replacement"}:
        raise QualificationPlanError("plan has no recognized AOP generation")
    return value


def _certificate_id(plan: Mapping[str, Any], *, generation: str, zone_key: str) -> str:
    values = _plan_variable(plan, "origin_pull_certificate_ids")
    if not isinstance(values, dict):
        raise QualificationPlanError("plan has no AOP certificate ID map")
    generation_values = values.get(generation)
    certificate_id = (
        generation_values.get(zone_key) if isinstance(generation_values, dict) else None
    )
    if (
        not isinstance(certificate_id, str)
        or re.fullmatch(
            r"(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})",
            certificate_id,
        )
        is None
    ):
        raise QualificationPlanError("plan has a malformed AOP certificate ID")
    return certificate_id


def _plan_variable(plan: Mapping[str, Any], name: str) -> object:
    variables = plan.get("variables")
    item = variables.get(name) if isinstance(variables, dict) else None
    if not isinstance(item, dict) or "value" not in item:
        raise QualificationPlanError(f"plan is missing required variable: {name}")
    return item["value"]


def assert_plan(plan: Mapping[str, Any], *, destroy: bool, transition: str | None = None) -> None:
    """Validate the exact resource set, operation direction, and fixed safe attributes."""
    if transition is not None:
        if destroy:
            raise QualificationPlanError("destroy and transition modes are mutually exclusive")
        _assert_transition(plan, transition=transition)
        return
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


def _check_resource_attributes(  # noqa: PLR0912
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
            or record.get("proxied") is not True
            or (not destroy and record.get("ttl") != DNS_TTL)
        ):
            errors.append(f"qualification DNS attributes crossed the fixed boundary: {name}")

    for name in DNS_NAMES:
        address = f'cloudflare_authenticated_origin_pulls.qualification["{name}"]'
        resource = resources.get(address)
        if resource is not None:
            _check_aop_resource(
                plan,
                value_side(resource),
                hostname=name,
                generation=_plan_generation(plan),
                errors=errors,
            )

    for policy in ("cache_bypass", "cdn_cgi_block", "transform_disable"):
        for zone_key in ZONE_HOSTNAMES:
            address = f'cloudflare_ruleset.qualification_{policy}["{zone_key}"]'
            resource = resources.get(address)
            if resource is not None:
                _check_ruleset(
                    value_side(resource), policy=policy, zone_key=zone_key, errors=errors
                )

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
        elif port != "22" and sources != REVIEWED_CLOUDFLARE_CIDRS:
            errors.append(f"qualification TCP {port} must use reviewed Cloudflare networks")
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
    parser.add_argument("--transition", choices=("primary", "replacement"))
    arguments = parser.parse_args(argv)
    try:
        plan = json.load(sys.stdin)
        if not isinstance(plan, dict):
            raise QualificationPlanError("plan root must be an object")
        assert_plan(plan, destroy=arguments.destroy, transition=arguments.transition)
    except (json.JSONDecodeError, QualificationPlanError) as error:
        print(f"M3.0 qualification plan rejected: {error}", file=sys.stderr)
        return 1
    if arguments.transition:
        print(
            "M3.0 AOP transition plan changes only the four disposable "
            f"hostname associations to {arguments.transition}."
        )
    else:
        print("M3.0 qualification plan stays within the exact disposable boundary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
