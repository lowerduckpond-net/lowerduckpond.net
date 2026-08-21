from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.assert_opentofu_plan import PlanPolicyError, assert_plan


def _resource(
    resource_type: str,
    name: str,
    after: dict[str, Any],
    *,
    address: str | None = None,
) -> dict[str, Any]:
    return {
        "address": address or f"module.test.{resource_type}.{name}",
        "type": resource_type,
        "change": {"actions": ["create"], "after": after},
    }


def _valid_plan() -> dict[str, Any]:
    return {
        "resource_changes": [
            _resource(
                "digitalocean_droplet",
                "host",
                {
                    "resize_disk": False,
                    "monitoring": True,
                    "backups": False,
                    "size": "s-1vcpu-2gb",
                    "tags": [
                        "environment:production",
                        "managed-by:opentofu",
                        "project:lowerduckpond",
                    ],
                },
            ),
            _resource(
                "digitalocean_firewall",
                "host",
                {
                    "droplet_ids": [42],
                    "inbound_rule": [
                        {
                            "protocol": "tcp",
                            "port_range": "22",
                            "source_addresses": ["192.0.2.10/32"],
                        },
                        {
                            "protocol": "tcp",
                            "port_range": "80",
                            "source_addresses": ["0.0.0.0/0", "::/0"],
                        },
                        {
                            "protocol": "tcp",
                            "port_range": "443",
                            "source_addresses": ["0.0.0.0/0", "::/0"],
                        },
                    ],
                    "outbound_rule": [
                        {
                            "protocol": "tcp",
                            "port_range": "443",
                            "destination_addresses": ["0.0.0.0/0", "::/0"],
                        }
                    ],
                },
            ),
            _resource(
                "digitalocean_spaces_bucket",
                "backups",
                {
                    "acl": "private",
                    "force_destroy": False,
                    "versioning": [{"enabled": True}],
                    "lifecycle_rule": [
                        {"prefix": "backups/"},
                        {"prefix": "archives/"},
                    ],
                },
            ),
            _resource(
                "digitalocean_spaces_key",
                "runtime",
                {"grant": [{"bucket": "example-backups", "permission": "readwrite"}]},
            ),
            _resource("digitalocean_reserved_ip", "host", {}),
            _resource(
                "digitalocean_reserved_ip_assignment",
                "host",
                {"droplet_id": 42, "id": "203.0.113.10-42", "ip_address": "203.0.113.10"},
            ),
            _resource(
                "digitalocean_project_resources",
                "production",
                {
                    "id": "project-id",
                    "project": "project-id",
                    "resources": [
                        "do:floatingip:203.0.113.10",
                        "do:space:example-backups",
                    ],
                },
                address="digitalocean_project_resources.production",
            ),
            _resource(
                "digitalocean_project_resources",
                "host",
                {
                    "id": "project-id",
                    "project": "project-id",
                    "resources": ["do:droplet:42"],
                },
                address="digitalocean_project_resources.host",
            ),
            _resource(
                "cloudflare_dns_record",
                "apex",
                {"name": "lowerduckpond.net", "type": "A", "proxied": False},
            ),
            _resource(
                "cloudflare_dns_record",
                "wildcard",
                {"name": "*.lowerduckpond.net", "type": "A", "proxied": False},
            ),
        ],
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "digitalocean_project_resources.production",
                        "expressions": {
                            "project": {"references": ["var.digitalocean_project_id"]},
                            "resources": {
                                "references": [
                                    "module.host.reserved_ip_urn",
                                    "module.host",
                                    "module.storage.bucket_urn",
                                    "module.storage",
                                ]
                            },
                        },
                    },
                    {
                        "address": "digitalocean_project_resources.host",
                        "expressions": {
                            "project": {"references": ["var.digitalocean_project_id"]},
                            "resources": {
                                "references": [
                                    "module.host.droplet_urn",
                                    "module.host",
                                ]
                            },
                        },
                    },
                ],
                "module_calls": {
                    "host": {
                        "module": {
                            "resources": [
                                {
                                    "address": "digitalocean_firewall.host",
                                    "expressions": {
                                        "droplet_ids": {
                                            "references": [
                                                "digitalocean_droplet.host.id",
                                                "digitalocean_droplet.host",
                                            ]
                                        }
                                    },
                                },
                                {
                                    "address": "digitalocean_reserved_ip_assignment.host",
                                    "expressions": {
                                        "droplet_id": {
                                            "references": [
                                                "digitalocean_droplet.host.id",
                                                "digitalocean_droplet.host",
                                            ]
                                        },
                                        "ip_address": {
                                            "references": [
                                                "digitalocean_reserved_ip.host.ip_address",
                                                "digitalocean_reserved_ip.host",
                                            ]
                                        },
                                    },
                                },
                            ]
                        }
                    }
                },
            }
        },
    }


def _valid_rebuild_drill_plan() -> dict[str, Any]:
    plan = deepcopy(_valid_plan())
    addresses = {
        "digitalocean_droplet": "module.host.digitalocean_droplet.host",
        "digitalocean_firewall": "module.host.digitalocean_firewall.host",
        "digitalocean_reserved_ip_assignment": (
            "module.host.digitalocean_reserved_ip_assignment.host"
        ),
        "digitalocean_project_resources": "digitalocean_project_resources.host",
    }
    drill_actions = {
        "digitalocean_droplet": ["create", "delete"],
        "digitalocean_firewall": ["update"],
        "digitalocean_reserved_ip_assignment": ["delete", "create"],
        "digitalocean_project_resources": ["update"],
    }
    for resource in plan["resource_changes"]:
        resource["change"]["before"] = deepcopy(resource["change"]["after"])
        resource["change"]["after_unknown"] = {}
        resource["change"]["actions"] = ["no-op"]
        resource_type = resource["type"]
        is_drill_resource = resource_type in addresses and (
            resource_type != "digitalocean_project_resources"
            or resource.get("address") == addresses[resource_type]
        )
        if is_drill_resource:
            resource["address"] = addresses[resource_type]
            resource["change"]["actions"] = drill_actions[resource_type]

    droplet = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.host.digitalocean_droplet.host"
    )
    droplet["action_reason"] = "replace_by_request"
    droplet["change"]["before"].update({"id": "42", "urn": "do:droplet:42"})
    droplet["change"]["after_unknown"] = {"id": True, "urn": True}

    firewall = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.host.digitalocean_firewall.host"
    )
    del firewall["change"]["after"]["droplet_ids"]
    firewall["change"]["after_unknown"] = {"droplet_ids": True}

    assignment = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.host.digitalocean_reserved_ip_assignment.host"
    )
    del assignment["change"]["after"]["droplet_id"]
    del assignment["change"]["after"]["id"]
    assignment["change"]["after_unknown"] = {"droplet_id": True, "id": True}

    project = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "digitalocean_project_resources.host"
    )
    del project["change"]["after"]["resources"]
    project["change"]["after_unknown"] = {"resources": True}
    return plan


def test_accepts_expected_foundation() -> None:
    assert_plan(_valid_plan())


def test_rejects_world_accessible_ssh() -> None:
    plan = _valid_plan()
    firewall = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_firewall"
    )
    firewall["change"]["after"]["inbound_rule"][0]["source_addresses"] = ["0.0.0.0/0"]

    with pytest.raises(PlanPolicyError, match="SSH must use"):
        assert_plan(plan)


def test_rejects_durable_storage_deletion() -> None:
    plan = deepcopy(_valid_plan())
    bucket = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_spaces_bucket"
    )
    bucket["change"]["actions"] = ["delete"]

    with pytest.raises(PlanPolicyError, match="must not delete durable infrastructure"):
        assert_plan(plan)


def test_rejects_bucket_policy_with_scoped_key() -> None:
    plan = _valid_plan()
    plan["resource_changes"].append(
        _resource("digitalocean_spaces_bucket_policy", "incompatible", {})
    )

    with pytest.raises(PlanPolicyError, match="incompatible with bucket-scoped"):
        assert_plan(plan)


def test_rejects_permanent_disk_resize() -> None:
    plan = _valid_plan()
    droplet = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_droplet"
    )
    droplet["change"]["after"]["resize_disk"] = True

    with pytest.raises(PlanPolicyError, match="resize_disk must be false"):
        assert_plan(plan)


def test_allows_explicit_droplet_replacement_drill() -> None:
    assert_plan(_valid_rebuild_drill_plan(), allow_droplet_replacement=True)


def test_rejects_unrelated_rebuild_drill_change() -> None:
    plan = _valid_rebuild_drill_plan()
    bucket = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_spaces_bucket"
    )
    bucket["change"]["actions"] = ["update"]

    with pytest.raises(PlanPolicyError, match="unrelated rebuild-drill actions"):
        assert_plan(plan, allow_droplet_replacement=True)


def test_rejects_destroy_before_create_droplet_drill() -> None:
    plan = _valid_rebuild_drill_plan()
    droplet = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_droplet"
    )
    droplet["change"]["actions"] = ["delete", "create"]

    with pytest.raises(PlanPolicyError, match="rebuild-drill actions must be"):
        assert_plan(plan, allow_droplet_replacement=True)


def test_rejects_missing_rebuild_drill_attachment_change() -> None:
    plan = _valid_rebuild_drill_plan()
    firewall = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_firewall"
    )
    firewall["change"]["actions"] = ["no-op"]

    with pytest.raises(PlanPolicyError, match="must change during the rebuild drill"):
        assert_plan(plan, allow_droplet_replacement=True)


def test_rejects_firewall_rule_change_hidden_inside_expected_update() -> None:
    plan = _valid_rebuild_drill_plan()
    firewall = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_firewall"
    )
    firewall["change"]["after"]["outbound_rule"] = []

    with pytest.raises(PlanPolicyError, match="unrelated rebuild-drill field changes"):
        assert_plan(plan, allow_droplet_replacement=True)


def test_rejects_durable_project_membership_change_during_drill() -> None:
    plan = _valid_rebuild_drill_plan()
    durable = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    durable["change"]["actions"] = ["update"]
    durable["change"]["after"]["resources"] = ["do:floatingip:203.0.113.10"]

    with pytest.raises(PlanPolicyError, match="unrelated rebuild-drill actions"):
        assert_plan(plan, allow_droplet_replacement=True)


def test_rejects_missing_durable_project_configuration_reference() -> None:
    plan = _valid_rebuild_drill_plan()
    durable_configuration = next(
        resource
        for resource in plan["configuration"]["root_module"]["resources"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    durable_configuration["expressions"]["resources"]["references"] = [
        "module.host.reserved_ip_urn",
        "module.host",
    ]

    with pytest.raises(PlanPolicyError, match="must retain its exact infrastructure references"):
        assert_plan(plan, allow_droplet_replacement=True)


def test_rejects_incidental_droplet_replacement_during_drill() -> None:
    plan = _valid_rebuild_drill_plan()
    droplet = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_droplet"
    )
    droplet["action_reason"] = "replace_because_cannot_update"

    with pytest.raises(PlanPolicyError, match="explicit -replace request"):
        assert_plan(plan, allow_droplet_replacement=True)
