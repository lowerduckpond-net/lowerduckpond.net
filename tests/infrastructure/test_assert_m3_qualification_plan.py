from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.assert_m3_qualification_plan import (
    AOP_COMPUTED_ATTRIBUTES,
    AOP_RESOURCES,
    AOP_TRANSITION_UNKNOWN_ATTRIBUTES,
    DNS_NAMES,
    EXPECTED_RESOURCES,
    REVIEWED_CLOUDFLARE_CIDRS,
    ZONE_HOSTNAMES,
    QualificationPlanError,
    assert_plan,
)

PRIMARY_IDS = {
    "lowerduckpond_net": "11111111-1111-4111-8111-111111111111",
    "lowerduckpond_com": "22222222-2222-4222-8222-222222222222",
}
REPLACEMENT_IDS = {
    "lowerduckpond_net": "33333333-3333-4333-8333-333333333333",
    "lowerduckpond_com": "44444444-4444-4444-8444-444444444444",
}
ZONE_IDS = {
    "lowerduckpond_net": "a" * 32,
    "lowerduckpond_com": "b" * 32,
}


def _zone_key(hostname: str) -> str:
    return "lowerduckpond_net" if hostname.endswith(".lowerduckpond.net") else "lowerduckpond_com"


def _host_expression(zone_key: str) -> str:
    names = " ".join(f'"{hostname}"' for hostname in ZONE_HOSTNAMES[zone_key])
    return f"http.host in {{{names}}}"


def _ruleset_attributes(policy: str, zone_key: str) -> dict[str, Any]:
    names = {
        "cache_bypass": "Lower Duck Pond M3.0 qualification cache bypass",
        "cdn_cgi_block": "Lower Duck Pond M3.0 qualification reserved path",
        "transform_disable": "Lower Duck Pond M3.0 qualification transform policy",
    }
    phases = {
        "cache_bypass": "http_request_cache_settings",
        "cdn_cgi_block": "http_request_firewall_custom",
        "transform_disable": "http_config_settings",
    }
    actions = {
        "cache_bypass": "set_cache_settings",
        "cdn_cgi_block": "block",
        "transform_disable": "set_config",
    }
    descriptions = {
        "cache_bypass": "Never cache a Milestone 3 qualification response",
        "cdn_cgi_block": "Block Cloudflare's reserved path before it reaches Caddy",
        "transform_disable": "Preserve origin representations for qualification",
    }
    expression = _host_expression(zone_key)
    if policy == "cdn_cgi_block":
        expression = (
            f'({expression}) and (lower(http.request.uri.path) eq "/cdn-cgi" '
            'or starts_with(lower(http.request.uri.path), "/cdn-cgi/"))'
        )
    parameters: dict[str, Any] = {}
    if policy == "cache_bypass":
        parameters = {"cache": False}
    elif policy == "transform_disable":
        parameters = {
            "automatic_https_rewrites": False,
            "disable_rum": True,
            "disable_zaraz": True,
            "email_obfuscation": False,
            "fonts": False,
            "rocket_loader": False,
        }
    return {
        "description": "Disposable qualification hostnames only; remove during complete teardown",
        "kind": "zone",
        "name": names[policy],
        "phase": phases[policy],
        "rules": [
            {
                "action": actions[policy],
                "action_parameters": parameters,
                "description": descriptions[policy],
                "enabled": True,
                "expression": expression,
                "ref": f"lowerduckpond_m3_qualification_{policy}",
            }
        ],
        "zone_id": ZONE_IDS[zone_key],
    }


def _variables(generation: str = "primary") -> dict[str, Any]:
    return {
        "lowerduckpond_net_zone_id": {"value": ZONE_IDS["lowerduckpond_net"]},
        "lowerduckpond_com_zone_id": {"value": ZONE_IDS["lowerduckpond_com"]},
        "origin_pull_generation": {"value": generation},
        "origin_pull_certificate_ids": {
            "value": {"primary": PRIMARY_IDS, "replacement": REPLACEMENT_IDS}
        },
    }


def _valid_plan(*, destroy: bool = False) -> dict[str, Any]:
    actions = ["delete"] if destroy else ["create"]
    droplet_id = 42
    droplet_urn = f"do:droplet:{droplet_id}"
    droplet_ip = "203.0.113.42"
    resources: list[dict[str, Any]] = []
    for address, resource_type in EXPECTED_RESOURCES.items():
        attributes: dict[str, Any] = {}
        if address == "digitalocean_droplet.qualification":
            attributes = {
                "backups": False,
                "graceful_shutdown": True,
                "id": droplet_id,
                "image": "ubuntu-26-04-x64",
                "ipv6": False,
                "ipv4_address": droplet_ip,
                "monitoring": False,
                "name": "lowerduckpond-m3-qualification",
                "region": "nyc1",
                "resize_disk": False,
                "size": "s-1vcpu-2gb",
                "urn": droplet_urn,
            }
        elif address == "digitalocean_firewall.qualification":
            attributes = {
                "droplet_ids": [droplet_id],
                "inbound_rule": [
                    {
                        "protocol": "tcp",
                        "port_range": "22",
                        "source_addresses": ["192.0.2.10/32"],
                    },
                    {
                        "protocol": "tcp",
                        "port_range": "80",
                        "source_addresses": sorted(REVIEWED_CLOUDFLARE_CIDRS),
                    },
                    {
                        "protocol": "tcp",
                        "port_range": "443",
                        "source_addresses": sorted(REVIEWED_CLOUDFLARE_CIDRS),
                    },
                ],
                "name": "lowerduckpond-m3-qualification",
                "outbound_rule": [
                    {
                        "protocol": protocol,
                        "port_range": port,
                        "destination_addresses": ["0.0.0.0/0", "::/0"],
                    }
                    for protocol, port in (
                        ("icmp", "0"),
                        ("tcp", "53"),
                        ("udp", "53"),
                        ("udp", "123"),
                        ("tcp", "80"),
                        ("tcp", "443"),
                    )
                ],
                "tags": [],
            }
        elif address == "digitalocean_project_resources.qualification":
            attributes = {"resources": [droplet_urn]}
        elif resource_type == "cloudflare_dns_record":
            name = next(name for name in DNS_NAMES if f'["{name}"]' in address)
            attributes = {
                "content": droplet_ip,
                "name": name,
                "proxied": True,
                "ttl": 1,
                "type": "A",
            }
        elif resource_type == "cloudflare_authenticated_origin_pulls":
            name = next(name for name in DNS_NAMES if f'["{name}"]' in address)
            zone_key = _zone_key(name)
            attributes = {
                "zone_id": ZONE_IDS[zone_key],
                "config": [
                    {
                        "cert_id": PRIMARY_IDS[zone_key],
                        "enabled": True,
                        "hostname": name,
                    }
                ],
            }
        elif resource_type == "cloudflare_ruleset":
            policy = next(
                policy
                for policy in ("cache_bypass", "cdn_cgi_block", "transform_disable")
                if f"qualification_{policy}" in address
            )
            zone_key = next(zone for zone in ZONE_HOSTNAMES if f'["{zone}"]' in address)
            attributes = _ruleset_attributes(policy, zone_key)
        resources.append(
            {
                "address": address,
                "type": resource_type,
                "change": {
                    "actions": actions,
                    "after": None if destroy else attributes,
                    "before": attributes if destroy else None,
                },
            }
        )
    return {
        "variables": _variables(),
        "resource_changes": resources,
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "digitalocean_firewall.qualification",
                        "expressions": {
                            "droplet_ids": {
                                "references": [
                                    "digitalocean_droplet.qualification.id",
                                    "digitalocean_droplet.qualification",
                                ]
                            }
                        },
                    },
                    {
                        "address": "digitalocean_project_resources.qualification",
                        "expressions": {
                            "resources": {
                                "references": [
                                    "digitalocean_droplet.qualification.urn",
                                    "digitalocean_droplet.qualification",
                                ]
                            }
                        },
                    },
                    {
                        "address": "cloudflare_dns_record.qualification",
                        "expressions": {
                            "content": {
                                "references": [
                                    "digitalocean_droplet.qualification.ipv4_address",
                                    "digitalocean_droplet.qualification",
                                ]
                            }
                        },
                    },
                ]
            }
        },
    }


def _valid_transition(target: str) -> dict[str, Any]:
    source = "replacement" if target == "primary" else "primary"
    identifiers = {"primary": PRIMARY_IDS, "replacement": REPLACEMENT_IDS}
    resources: list[dict[str, Any]] = []
    for address in sorted(AOP_RESOURCES):
        name = next(name for name in DNS_NAMES if f'["{name}"]' in address)
        zone_key = _zone_key(name)

        def attributes(
            generation: str,
            *,
            computed_unknown: bool = False,
            bound_zone_key: str = zone_key,
            bound_name: str = name,
        ) -> dict[str, Any]:
            computed: dict[str, Any] = {
                "cert_id": identifiers[generation][bound_zone_key],
                "cert_status": "active",
                "cert_updated_at": "2026-08-25T00:00:00Z",
                "cert_uploaded_on": "2026-08-25T00:00:00Z",
                "certificate": "public-certificate",
                "created_at": "2026-08-25T00:00:00Z",
                "enabled": True,
                "expires_on": "2026-09-24T00:00:00Z",
                "hostname": bound_name,
                "id": bound_name,
                "issuer": "Lower Duck Pond qualification CA",
                "private_key": None,
                "serial_number": "01",
                "signature": "SHA256-RSA",
                "status": "active",
                "updated_at": "2026-08-25T00:00:00Z",
            }
            assert set(computed) == AOP_COMPUTED_ATTRIBUTES
            if computed_unknown:
                computed.update(dict.fromkeys(AOP_TRANSITION_UNKNOWN_ATTRIBUTES))
            return {
                "zone_id": ZONE_IDS[bound_zone_key],
                "config": [
                    {
                        "cert_id": identifiers[generation][bound_zone_key],
                        "enabled": True,
                        "hostname": bound_name,
                    }
                ],
                **computed,
            }

        resources.append(
            {
                "address": address,
                "type": "cloudflare_authenticated_origin_pulls",
                "change": {
                    "actions": ["update"],
                    "before": attributes(source),
                    "after": attributes(target, computed_unknown=True),
                    "after_unknown": {
                        **dict.fromkeys(AOP_TRANSITION_UNKNOWN_ATTRIBUTES, True),
                        "config": [{}],
                    },
                },
            }
        )
    return {"variables": _variables(target), "resource_changes": resources}


def test_create_plan_accepts_only_exact_disposable_boundary() -> None:
    assert_plan(_valid_plan(), destroy=False)


def test_destroy_plan_accepts_only_exact_disposable_boundary() -> None:
    assert_plan(_valid_plan(destroy=True), destroy=True)


def test_aop_transition_accepts_only_four_association_updates() -> None:
    assert_plan(_valid_transition("replacement"), destroy=False, transition="replacement")
    assert_plan(_valid_transition("primary"), destroy=False, transition="primary")


def test_aop_transition_rejects_an_unrelated_mutation() -> None:
    plan = _valid_transition("replacement")
    plan["resource_changes"].append(
        {
            "address": 'cloudflare_dns_record.qualification["m3-a.lowerduckpond.com"]',
            "type": "cloudflare_dns_record",
            "change": {"actions": ["update"], "before": {}, "after": {}},
        }
    )

    with pytest.raises(QualificationPlanError, match="unexpected AOP transition"):
        assert_plan(plan, destroy=False, transition="replacement")


def test_aop_transition_rejects_an_extra_field_change() -> None:
    plan = _valid_transition("replacement")
    plan["resource_changes"][0]["change"]["after"]["deployment_status"] = "pending"

    with pytest.raises(QualificationPlanError, match="attribute shape drifted"):
        assert_plan(plan, destroy=False, transition="replacement")


def test_aop_transition_rejects_a_known_computed_change() -> None:
    plan = _valid_transition("replacement")
    resource = plan["resource_changes"][0]
    resource["change"]["after"]["status"] = "active"

    with pytest.raises(QualificationPlanError, match="did not become unknown"):
        assert_plan(plan, destroy=False, transition="replacement")


def test_aop_transition_rejects_an_unknown_configured_attribute() -> None:
    plan = _valid_transition("replacement")
    resource = plan["resource_changes"][0]
    resource["change"]["after_unknown"]["zone_id"] = True

    with pytest.raises(QualificationPlanError, match="computed unknown set drifted"):
        assert_plan(plan, destroy=False, transition="replacement")


def test_aop_transition_rejects_private_key_material() -> None:
    plan = _valid_transition("replacement")
    resource = plan["resource_changes"][0]
    resource["change"]["before"]["private_key"] = "must-not-enter-state"

    with pytest.raises(QualificationPlanError, match="exposed private key material"):
        assert_plan(plan, destroy=False, transition="replacement")


def test_destroy_plan_accepts_a_partial_apply_subset() -> None:
    plan = _valid_plan(destroy=True)
    plan["resource_changes"] = plan["resource_changes"][:2]

    assert_plan(plan, destroy=True)


def test_destroy_plan_accepts_an_empty_orphaned_assignment() -> None:
    plan = _valid_plan(destroy=True)
    assignment = next(
        item
        for item in plan["resource_changes"]
        if item["address"] == "digitalocean_project_resources.qualification"
    )
    assignment["change"]["before"]["resources"] = []
    plan["resource_changes"] = [assignment]

    assert_plan(plan, destroy=True)


@pytest.mark.parametrize(
    ("mutation", "destroy"),
    [
        ("extra", False),
        ("missing", False),
        ("replace", False),
        ("wrong_dns", False),
        ("create_during_destroy", True),
        ("destroy_apex", True),
        ("destroy_production_droplet", True),
        ("destroy_firewall_binding", True),
        ("destroy_project_binding", True),
        ("destroy_dns_binding", True),
    ],
)
def test_plan_rejects_boundary_changes(mutation: str, destroy: bool) -> None:
    plan = deepcopy(_valid_plan(destroy=destroy))
    changes = plan["resource_changes"]
    if mutation == "extra":
        changes.append(
            {
                "address": "digitalocean_reserved_ip.qualification",
                "type": "digitalocean_reserved_ip",
                "change": {"actions": ["create"], "after": {}},
            }
        )
    elif mutation == "missing":
        changes.pop()
    elif mutation == "replace":
        changes[0]["change"]["actions"] = ["delete", "create"]
    elif mutation == "wrong_dns":
        dns = next(item for item in changes if item["type"] == "cloudflare_dns_record")
        dns["change"]["after"]["proxied"] = False
    elif mutation == "create_during_destroy":
        changes[0]["change"]["actions"] = ["create"]
    elif mutation == "destroy_apex":
        dns = next(item for item in changes if item["type"] == "cloudflare_dns_record")
        dns["change"]["before"]["name"] = "lowerduckpond.com"
    elif mutation == "destroy_production_droplet":
        changes[0]["change"]["before"]["name"] = "lowerduckpond-production-01"
    elif mutation == "destroy_firewall_binding":
        firewall = next(item for item in changes if item["type"] == "digitalocean_firewall")
        firewall["change"]["before"]["droplet_ids"] = [999]
    elif mutation == "destroy_project_binding":
        assignment = next(
            item for item in changes if item["type"] == "digitalocean_project_resources"
        )
        assignment["change"]["before"]["resources"] = ["do:droplet:999"]
    else:
        dns = next(item for item in changes if item["type"] == "cloudflare_dns_record")
        dns["change"]["before"]["content"] = "203.0.113.99"

    with pytest.raises(QualificationPlanError):
        assert_plan(plan, destroy=destroy)


def test_destroy_rejects_an_orphaned_firewall_with_unproven_targets() -> None:
    plan = _valid_plan(destroy=True)
    firewall = next(
        item
        for item in plan["resource_changes"]
        if item["address"] == "digitalocean_firewall.qualification"
    )
    plan["resource_changes"] = [firewall]

    with pytest.raises(QualificationPlanError):
        assert_plan(plan, destroy=True)


@pytest.mark.parametrize(
    ("address", "field"),
    [
        ("digitalocean_firewall.qualification", "droplet_ids"),
        ("digitalocean_project_resources.qualification", "resources"),
        ("cloudflare_dns_record.qualification", "content"),
    ],
)
def test_create_rejects_non_disposable_configuration_bindings(address: str, field: str) -> None:
    plan = _valid_plan()
    resource = next(
        item
        for item in plan["configuration"]["root_module"]["resources"]
        if item["address"] == address
    )
    resource["expressions"][field]["references"] = ["digitalocean_droplet.production.id"]

    with pytest.raises(QualificationPlanError, match="not bound only"):
        assert_plan(plan, destroy=False)


@pytest.mark.parametrize(
    "mutation",
    [
        "world_ssh",
        "split_world_ssh",
        "extra_inbound",
        "missing_egress",
        "tag_target",
        "alternate_ssh_source",
        "world_web",
    ],
)
def test_create_rejects_non_exact_firewall_rules(mutation: str) -> None:
    plan = _valid_plan()
    firewall = next(
        item
        for item in plan["resource_changes"]
        if item["address"] == "digitalocean_firewall.qualification"
    )["change"]["after"]
    if mutation == "world_ssh":
        firewall["inbound_rule"][0]["source_addresses"] = ["0.0.0.0/0"]
    elif mutation == "split_world_ssh":
        firewall["inbound_rule"][0]["source_addresses"] = ["0.0.0.0/1", "128.0.0.0/1"]
    elif mutation == "extra_inbound":
        firewall["inbound_rule"].append(
            {
                "protocol": "tcp",
                "port_range": "5432",
                "source_addresses": ["0.0.0.0/0", "::/0"],
            }
        )
    elif mutation == "missing_egress":
        firewall["outbound_rule"].pop()
    elif mutation == "tag_target":
        firewall["tags"] = ["production"]
    elif mutation == "alternate_ssh_source":
        firewall["inbound_rule"][0]["source_tags"] = ["production"]
    else:
        firewall["inbound_rule"][1]["source_addresses"] = ["0.0.0.0/0", "::/0"]

    with pytest.raises(QualificationPlanError):
        assert_plan(plan, destroy=False)


@pytest.mark.parametrize(
    "resource_type", ["cloudflare_authenticated_origin_pulls", "cloudflare_ruleset"]
)
def test_create_rejects_overbroad_edge_policy(resource_type: str) -> None:
    plan = _valid_plan()
    resource = next(item for item in plan["resource_changes"] if item["type"] == resource_type)
    if resource_type == "cloudflare_authenticated_origin_pulls":
        resource["change"]["after"]["config"][0]["hostname"] = "lowerduckpond.com"
    else:
        resource["change"]["after"]["rules"][0]["expression"] = "true"

    with pytest.raises(QualificationPlanError):
        assert_plan(plan, destroy=False)
