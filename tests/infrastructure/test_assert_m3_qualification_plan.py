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
    resources: list[dict[str, Any]] = []
    for address, resource_type in EXPECTED_RESOURCES.items():
        after: dict[str, Any] | None = {}
        if address == "digitalocean_droplet.qualification":
            after = {
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
        elif address == "digitalocean_firewall.qualification":
            after = {"name": "lowerduckpond-m3-qualification"}
        elif resource_type == "cloudflare_dns_record":
            name = next(name for name in DNS_NAMES if f'["{name}"]' in address)
            after = {"name": name, "type": "A", "ttl": 60, "proxied": False}
        if destroy:
            after = None
        resources.append(
            {
                "address": address,
                "type": resource_type,
                "change": {"actions": actions, "after": after},
            }
        )
    return {"resource_changes": resources}


def test_create_plan_accepts_only_exact_disposable_boundary() -> None:
    assert_plan(_valid_plan(), destroy=False)


def test_destroy_plan_accepts_only_exact_disposable_boundary() -> None:
    assert_plan(_valid_plan(destroy=True), destroy=True)


@pytest.mark.parametrize(
    ("mutation", "destroy"),
    [
        ("extra", False),
        ("missing", False),
        ("replace", False),
        ("wrong_dns", False),
        ("create_during_destroy", True),
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
    else:
        changes[0]["change"]["actions"] = ["create"]

    with pytest.raises(QualificationPlanError):
        assert_plan(plan, destroy=destroy)
