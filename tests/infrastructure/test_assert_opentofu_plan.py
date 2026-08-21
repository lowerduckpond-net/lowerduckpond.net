from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.assert_opentofu_plan import PlanPolicyError, assert_plan


def _resource(resource_type: str, name: str, after: dict[str, Any]) -> dict[str, Any]:
    return {
        "address": f"module.test.{resource_type}.{name}",
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
                    ]
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
            _resource("digitalocean_project_resources", "production", {}),
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
        ]
    }


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
    plan = _valid_plan()
    droplet = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "digitalocean_droplet"
    )
    droplet["change"]["actions"] = ["create", "delete"]

    assert_plan(plan, allow_droplet_replacement=True)
