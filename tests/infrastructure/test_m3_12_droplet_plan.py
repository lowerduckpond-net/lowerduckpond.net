"""Synthetic offline plan-scope vectors with no provider or state access."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256

import pytest

from scripts.m3_12_contracts import Document, ValidationError, encode
from scripts.m3_12_droplet_cleanup import (
    InitialRetirement,
    capture_initial_retirement,
    reconcile_initial_retirement,
    verify_initial_destroy_plan,
)
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
from scripts.m3_12_droplet_provider import ReviewedReadback, bind_initial_allocation

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


@pytest.fixture
def readback(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> tuple[Document, Document, Document]:
    plan, scope = reviewed_plan
    resources = [
        {
            **{key: row[key] for key in ("address", "mode", "name", "type", "provider_name")},
            "values": deepcopy(row["change"]["after"]),
        }
        for row in plan["resource_changes"]
    ]
    host, firewall, membership = [row["values"] for row in resources]
    host.update(ipv4_address="11.1.2.11", urn="do:droplet:101")
    firewall["id"] = "00000000-0000-4000-8000-000000000003"
    state = {
        "format_version": "1.0",
        "values": {
            "root_module": {"resources": resources},
            "outputs": {
                "allocation": {
                    "sensitive": False,
                    "value": {
                        "run_id": scope.run_id,
                        "role": scope.role,
                        "project_id": scope.project_id,
                        "droplet_id": "101",
                        "urn": host["urn"],
                        "ipv4": host["ipv4_address"],
                        "firewall": firewall["id"],
                    },
                },
            },
        },
    }
    observed = {
        "droplet": {
            "id": 101,
            "name": scope.name,
            "ipv4": host["ipv4_address"],
            "status": "active",
            **{key: host[key] for key in ("region", "image", "size", "ipv6", "backups")},
        },
        "firewalls": [{**deepcopy(firewall), "settled": True}],
        "projectMembership": deepcopy(membership),
    }
    exclusions = {
        "format": "lowerduckpond-m3-12-droplet-production-exclusions-v1",
        "dropletIds": [999],
        "addresses": ["11.1.2.20"],
        "identityDigests": ["1" * 64],
    }
    return state, observed, exclusions


def test_initial_provider_readback_joins_only_the_exact_reviewed_role(
    reviewed_plan: tuple[Document, ApprovedHostPlan], readback: tuple[Document, Document, Document]
) -> None:
    plan, scope = reviewed_plan
    state, observed, exclusions = readback
    plan_raw = encode(plan)
    state_raw = encode(state)
    review = ReviewedReadback(
        scope,
        sha256(plan_raw).hexdigest(),
        sha256(state_raw).hexdigest(),
        f"qualification/m3-12/{scope.run_id}/{scope.role}.tfstate",
    )
    result = bind_initial_allocation(review, plan_raw, state_raw, observed, encode(exclusions))
    assert result.run_id == scope.run_id
    assert result.role == scope.role
    assert result.identity.ipv4 == "11.1.2.11"
    assert result.state_sha256 == review.state_json_sha256
    with pytest.raises(ValidationError, match="droplet-readback-review-changed"):
        bind_initial_allocation(
            replace(review, state_key=review.state_key.replace("restore", "source")),
            plan_raw,
            state_raw,
            observed,
            encode(exclusions),
        )
    foreign = deepcopy(state)
    foreign["values"]["root_module"]["resources"].append(
        {"address": "digitalocean_reserved_ip.foreign"}
    )
    foreign_raw = encode(foreign)
    with pytest.raises(ValidationError, match="droplet-plan-resource-set-changed"):
        bind_initial_allocation(
            replace(review, state_json_sha256=sha256(foreign_raw).hexdigest()),
            plan_raw,
            foreign_raw,
            observed,
            encode(exclusions),
        )
    observed["firewalls"][0]["settled"] = False
    with pytest.raises(ValidationError, match="droplet-readback-provider-firewall-changed"):
        bind_initial_allocation(review, plan_raw, state_raw, observed, encode(exclusions))
    observed["firewalls"][0]["settled"] = True
    observed["projectMembership"]["resources"] = []
    with pytest.raises(ValidationError, match="droplet-readback-provider-identity-changed"):
        bind_initial_allocation(review, plan_raw, state_raw, observed, encode(exclusions))
    observed["projectMembership"]["resources"] = ["do:droplet:101"]
    exclusions["dropletIds"] = [101]
    with pytest.raises(ValidationError, match="production-crossover"):
        bind_initial_allocation(review, plan_raw, state_raw, observed, encode(exclusions))


@pytest.fixture
def retirement(
    reviewed_plan: tuple[Document, ApprovedHostPlan], readback: tuple[Document, Document, Document]
) -> tuple[InitialRetirement, Document, Document]:
    plan, scope = reviewed_plan
    state, provider, exclusions = readback
    raw_plan, raw_state = encode(plan), encode(state)
    original = capture_initial_retirement(
        ReviewedReadback(
            scope,
            sha256(raw_plan).hexdigest(),
            sha256(raw_state).hexdigest(),
            f"qualification/m3-12/{scope.run_id}/{scope.role}.tfstate",
        ),
        raw_plan,
        raw_state,
        provider,
        encode(exclusions),
    )
    resources = state["values"]["root_module"]["resources"]
    plan = {
        "errored": False,
        "prior_state": state,
        "planned_values": {"root_module": {}},
        "resource_changes": [
            {
                **{key: row[key] for key in ("address", "mode", "name", "type", "provider_name")},
                "change": {"actions": ["delete"], "before": deepcopy(row["values"]), "after": None},
            }
            for row in resources
        ],
    }
    return original, plan, state


def test_retirement_review_validates_only_original_deletions(
    retirement: tuple[InitialRetirement, Document, Document],
) -> None:
    original, destroy, _ = retirement

    def verify(plan: Document, *, key: str = original.state_key) -> None:
        raw = encode(plan)
        verify_initial_destroy_plan(
            original, raw, reviewed_sha256=sha256(raw).hexdigest(), state_key=key
        )

    verify(destroy)
    with pytest.raises(ValidationError, match="droplet-cleanup-plan-changed"):
        verify(destroy, key=original.state_key.replace("restore.tfstate", "source.tfstate"))
    replaced = deepcopy(destroy)
    replaced["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
    with pytest.raises(ValidationError, match="droplet-cleanup-resource-changed"):
        verify(replaced)
    foreign = deepcopy(destroy)
    foreign["resource_changes"][0]["change"]["before"]["id"] = "999"
    with pytest.raises(ValidationError, match="droplet-cleanup-resource-changed"):
        verify(foreign)
    extra = deepcopy(destroy)
    extra["resource_changes"].append({"address": "digitalocean_reserved_ip.foreign"})
    with pytest.raises(ValidationError, match="droplet-plan-resource-set-changed"):
        verify(extra)


def test_interrupted_retirement_requires_exact_independent_absence(
    retirement: tuple[InitialRetirement, Document, Document],
) -> None:
    original, _, occupied = retirement
    clean = encode({"format_version": "1.0", "terraform_version": "1.12.6"})
    nonempty = encode({**occupied, "terraform_version": "1.12.6"})
    identity = original.allocation.identity
    observed = {
        "stateKey": original.state_key,
        "allocationSha256": original.allocation.allocation_sha256,
        "projectIdSha256": identity.project_id_sha256,
        "dropletId": identity.droplet_id,
        "firewallId": original.firewall_id,
        "projectUrn": original.urn,
        "stateSha256": sha256(clean).hexdigest(),
        "droplet": "absent",
        "firewall": "absent",
        "projectMembership": "absent",
    }
    complete = reconcile_initial_retirement(original, clean, observed)
    assert complete["outcome"] == "absent"
    assert complete == reconcile_initial_retirement(original, clean, observed)
    assert (
        reconcile_initial_retirement(original, clean, {**observed, "firewall": "unverified"})[
            "outcome"
        ]
        == "unresolved"
    )
    assert (
        reconcile_initial_retirement(
            original, nonempty, {**observed, "stateSha256": sha256(nonempty).hexdigest()}
        )["outcome"]
        == "unresolved"
    )
    with pytest.raises(ValidationError, match="droplet-cleanup-readback-scope-changed"):
        reconcile_initial_retirement(original, clean, {**observed, "projectUrn": "do:droplet:999"})
    with pytest.raises(ValidationError, match="droplet-cleanup-readback-scope-changed"):
        reconcile_initial_retirement(original, nonempty, observed)
