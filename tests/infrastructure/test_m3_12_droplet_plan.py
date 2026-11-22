"""Synthetic offline plan-scope vectors with no provider or state access."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from scripts.m3_12_contracts import Document, ValidationError
from scripts.m3_12_droplet_plan import (
    CONFIGURATION_FIELDS,
    EGRESS,
    FIREWALL,
    HOST,
    HOST_FIELDS,
    MEMBERSHIP,
    PROVIDER,
    ApprovedHostPlan,
    verify_initial_host_plan,
)

CLOUD_INIT = "#cloud-config\nssh_pwauth: false\n"


@pytest.fixture
def reviewed_plan() -> tuple[Document, ApprovedHostPlan]:
    scope = ApprovedHostPlan(
        run_id="00000000-0000-7000-8000-000000000001",
        role="restore",
        project_id="00000000-0000-4000-8000-000000000002",
        ssh_key_fingerprint="00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        admin_cidrs=("192.0.2.14/32",),
        cloud_init_sha256=sha256(CLOUD_INIT.encode()).hexdigest(),
    )
    config = []
    for address, fields in CONFIGURATION_FIELDS.items():
        kind, name = address.split(".")
        config.append(
            {
                "address": address,
                "type": kind,
                "name": name,
                "mode": "managed",
                "provider_config_key": "digitalocean",
                "expressions": {field: {} for field in fields},
            }
        )
    config[1]["expressions"]["droplet_ids"] = {"references": [f"{HOST}.id", HOST]}
    config[2]["expressions"]["resources"] = {"references": [f"{HOST}.urn", HOST]}
    changes = []
    for resource, after in zip(
        config,
        (
            {
                **HOST_FIELDS,
                "name": scope.name,
                "user_data": CLOUD_INIT,
                "ssh_keys": [scope.ssh_key_fingerprint],
                "id": "101",
            },
            {
                "name": scope.name,
                "droplet_ids": [101],
                "inbound_rule": [
                    {"protocol": "tcp", "port_range": "22", "source_addresses": ["192.0.2.14/32"]}
                ],
                "outbound_rule": [
                    {
                        "protocol": protocol,
                        "port_range": port,
                        "destination_addresses": ["0.0.0.0/0", "::/0"],
                    }
                    for protocol, port in sorted(EGRESS)
                ],
            },
            {"project": scope.project_id, "resources": ["do:droplet:101"]},
        ),
        strict=True,
    ):
        changes.append(
            {
                **{key: resource[key] for key in ("address", "mode", "name", "type")},
                "provider_name": PROVIDER,
                "change": {"actions": ["create"], "before": None, "after": after},
            }
        )
    return {
        "errored": False,
        "variables": {
            "qualification_run_id": {"value": scope.run_id},
            "fixture_role": {"value": scope.role},
        },
        "configuration": {"root_module": {"resources": config}},
        "resource_changes": changes,
    }, scope


def test_droplet_plan_accepts_only_the_reviewed_host_and_its_exact_attachments(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> None:
    plan, scope = reviewed_plan
    verify_initial_host_plan(plan, scope)
    host, firewall, membership = [resource["change"] for resource in plan["resource_changes"]]
    host["after"].pop("id")
    host["after_unknown"] = {"id": True}
    firewall["after"]["droplet_ids"] = [None]
    firewall["after_unknown"] = {"droplet_ids": [True]}
    membership["after"].pop("resources")
    membership["after_unknown"] = {"resources": True}
    verify_initial_host_plan(plan, scope)

    firewall["after"]["droplet_ids"] = [999, None]
    with pytest.raises(ValidationError, match="droplet-plan-attachment-changed"):
        verify_initial_host_plan(plan, scope)


@pytest.mark.parametrize(
    ("address", "field", "value", "category"),
    [
        (HOST, "user_data", "# altered bootstrap\n", "droplet-plan-host-changed"),
        (HOST, "public_networking", False, "droplet-plan-host-changed"),
        (HOST, "volume_ids", ["unowned"], "droplet-plan-host-changed"),
        (FIREWALL, "droplet_ids", [999], "droplet-plan-attachment-changed"),
        (FIREWALL, "tags", ["production"], "droplet-plan-firewall-target-changed"),
        (FIREWALL, "inbound_rule", [], "droplet-plan-ingress-changed"),
        (
            FIREWALL,
            "inbound_rule",
            [{"protocol": "tcp", "port_range": "443", "source_addresses": ["192.0.2.14/32"]}],
            "droplet-plan-ingress-changed",
        ),
        (MEMBERSHIP, "project", "production", "droplet-plan-project-changed"),
        (MEMBERSHIP, "resources", ["do:droplet:999"], "droplet-plan-attachment-changed"),
    ],
)
def test_droplet_plan_refuses_foreign_host_scope(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
    address: str,
    field: str,
    value: object,
    category: str,
) -> None:
    plan, scope = reviewed_plan
    target = next(item for item in plan["resource_changes"] if item["address"] == address)
    target["change"]["after"][field] = value
    with pytest.raises(ValidationError, match=category):
        verify_initial_host_plan(plan, scope)


def test_droplet_plan_rejects_existing_changes_imports_and_unreviewed_graph(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> None:
    original, scope = reviewed_plan

    plan = deepcopy(original)
    plan["prior_state"] = {"values": {"root_module": {"resources": [{"address": HOST}]}}}
    with pytest.raises(ValidationError, match="droplet-plan-state-is-not-empty"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["resource_changes"][0]["change"]["importing"] = {"id": "101"}
    with pytest.raises(ValidationError, match="droplet-plan-is-not-creation"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["resource_changes"].append({"address": "digitalocean_reserved_ip.example"})
    with pytest.raises(ValidationError, match="droplet-plan-resource-set-changed"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["configuration"]["root_module"]["resources"][1]["expressions"]["droplet_ids"] = {
        "constant_value": [101]
    }
    with pytest.raises(ValidationError, match="invalid-droplet-plan"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["resource_changes"][1]["change"]["after_unknown"] = {
        "inbound_rule": [{"source_addresses": [True]}]
    }
    with pytest.raises(ValidationError, match="droplet-plan-unsafe-unknown"):
        verify_initial_host_plan(plan, scope)
