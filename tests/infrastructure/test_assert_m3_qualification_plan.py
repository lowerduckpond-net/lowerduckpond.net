from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.assert_m3_qualification_plan import (
    DNS_NAMES,
    EXPECTED_RESOURCES,
    QualificationPlanError,
    assert_plan,
)


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
                "name": "lowerduckpond-m3-qualification",
            }
        elif address == "digitalocean_project_resources.qualification":
            attributes = {"resources": [droplet_urn]}
        elif resource_type == "cloudflare_dns_record":
            name = next(name for name in DNS_NAMES if f'["{name}"]' in address)
            attributes = {
                "content": droplet_ip,
                "name": name,
                "proxied": False,
                "ttl": 60,
                "type": "A",
            }
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
    return {"resource_changes": resources}


def test_create_plan_accepts_only_exact_disposable_boundary() -> None:
    assert_plan(_valid_plan(), destroy=False)


def test_destroy_plan_accepts_only_exact_disposable_boundary() -> None:
    assert_plan(_valid_plan(destroy=True), destroy=True)


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
        dns["change"]["after"]["proxied"] = True
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
