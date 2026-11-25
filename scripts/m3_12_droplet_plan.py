"""Verify a backend-disabled or reviewed initial plan for one M3.12 host role."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha1, sha256
from ipaddress import ip_network
from typing import Any

from scripts.m3_12_contracts import Document, ValidationError, require

PROVIDER = "registry.opentofu.org/digitalocean/digitalocean"
PINNED_PROVIDER = {
    "name": "digitalocean",
    "full_name": PROVIDER,
    "version_constraint": "2.106.0",
}
CLOUD_INIT_OUTPUT = "cloud_init_sha256"
PLAN_OUTPUTS = frozenset({"allocation", CLOUD_INIT_OUTPUT})
HOST = "digitalocean_droplet.fixture"
FIREWALL = "digitalocean_firewall.fixture"
MEMBERSHIP = "digitalocean_project_resources.fixture"
HOST_FIELDS = {
    "image": "ubuntu-26-04-x64",
    "region": "nyc1",
    "size": "s-2vcpu-4gb-amd",
    "backups": False,
    "ipv6": False,
    "public_networking": True,
    "monitoring": False,
    "resize_disk": False,
    "graceful_shutdown": True,
}
CONFIGURATION_FIELDS = {
    HOST: {*HOST_FIELDS, "name", "ssh_keys", "user_data"},
    FIREWALL: {"name", "droplet_ids", "inbound_rule", "outbound_rule"},
    MEMBERSHIP: {"project", "resources"},
}
EGRESS = {("tcp", "53"), ("udp", "53"), ("udp", "123"), ("tcp", "80"), ("tcp", "443")}
SOURCE_FIXTURE_EGRESS_OPTION = "source_fixture_egress_isolated"
METADATA_DESTINATION = frozenset({"169.254.169.254/32"})


@dataclass(frozen=True)
class ApprovedHostPlan:
    """Values from trusted approval, independent of the plan being inspected."""

    run_id: str
    role: str
    project_id: str
    ssh_key_fingerprint: str
    admin_cidrs: tuple[str, ...]
    cloud_init_sha256: str
    source_fixture_egress_isolated: bool = False

    @property
    def name(self) -> str:
        return f"ldp-m312-{self.run_id.replace('-', '')}-{self.role}"


def _address_set(value: object, *, admin: bool) -> frozenset[str]:
    require(isinstance(value, (list, tuple)) and bool(value), "droplet-plan-addresses-invalid")
    if not isinstance(value, (list, tuple)):
        raise ValidationError("droplet-plan-addresses-invalid")
    try:
        require(all(type(item) is str for item in value), "droplet-plan-addresses-invalid")
        parsed = [ip_network(item, strict=True) for item in value]
    except ValueError as error:
        raise ValidationError("droplet-plan-addresses-invalid") from error
    require(
        len(set(parsed)) == len(value) and (not admin or all(net.prefixlen > 0 for net in parsed)),
        "droplet-plan-addresses-invalid",
    )
    return frozenset(str(net) for net in parsed)


def _resource_index(items: list[Document]) -> dict[str, Document]:
    resources = {item["address"]: item for item in items}
    require(
        len(resources) == len(items) and resources.keys() == CONFIGURATION_FIELDS.keys(),
        "droplet-plan-resource-set-changed",
    )
    for address, resource in resources.items():
        kind, name = address.split(".")
        require(
            resource["mode"] == "managed"
            and resource["type"] == kind
            and resource["name"] == name
            and "previous_address" not in resource,
            "droplet-plan-resource-identity-changed",
        )
    return resources


def _change(resource: Document) -> Document:
    require(resource["provider_name"] == PROVIDER, "droplet-plan-provider-changed")
    change = resource["change"]
    if not isinstance(change, dict):
        raise ValidationError("invalid-droplet-plan")
    require(
        change["actions"] == ["create"]
        and change["before"] is None
        and not change.get("importing")
        and not change.get("replace_paths"),
        "droplet-plan-is-not-creation",
    )
    return change


def _references(config: Mapping[str, Document], address: str, name: str, target: str) -> None:
    require(
        set(config[address]["expressions"][name]["references"]) == {HOST, f"{HOST}.{target}"},
        "droplet-plan-attachment-changed",
    )


def _has_unknown(value: object) -> bool:
    if isinstance(value, list):
        return any(_has_unknown(item) for item in value)
    if isinstance(value, dict):
        return any(_has_unknown(item) for item in value.values())
    return value is True


def _require_known(change: Document, fields: set[str]) -> None:
    unknown = change.get("after_unknown", {})
    require(
        not any(_has_unknown(unknown.get(field)) for field in fields),
        "droplet-plan-unsafe-unknown",
    )


def _attachment(change: Document, field: str, expected: list[int | str] | None) -> None:
    planned = change["after"].get(field)
    unknown = change.get("after_unknown", {}).get(field)
    if expected is None:
        require(
            planned in (None, [], [None]) and unknown in (True, [True]),
            "droplet-plan-attachment-changed",
        )
    else:
        require(
            planned == expected and unknown in (None, False, [False]),
            "droplet-plan-attachment-changed",
        )


def _droplet_id(after: Document) -> int | None:
    value = after.get("id")
    if value is None:
        return None
    require(
        type(value) in {str, int} and re.fullmatch(r"[1-9][0-9]*", str(value)) is not None,
        "droplet-plan-id-invalid",
    )
    return int(value)


def _firewall(after: Document, scope: ApprovedHostPlan) -> None:
    require(
        after["name"] == scope.name and not after.get("tags"),
        "droplet-plan-firewall-target-changed",
    )
    rules = after["inbound_rule"]
    require(len(rules) == 1, "droplet-plan-ingress-changed")
    rule = rules[0]
    require(
        rule["protocol"] == "tcp"
        and rule["port_range"] == "22"
        and rule.get("action", "allow") == "allow"
        and not any(
            rule.get(key)
            for key in (
                "source_droplet_ids",
                "source_kubernetes_ids",
                "source_load_balancer_uids",
                "source_tags",
            )
        )
        and _address_set(rule["source_addresses"], admin=True)
        == _address_set(scope.admin_cidrs, admin=True),
        "droplet-plan-ingress-changed",
    )
    outgoing = after["outbound_rule"]
    protocol_ports = {("tcp", "80")} if scope.source_fixture_egress_isolated else EGRESS
    destinations = (
        METADATA_DESTINATION if scope.source_fixture_egress_isolated else {"0.0.0.0/0", "::/0"}
    )
    require(
        len(outgoing) == len(protocol_ports)
        and {(item["protocol"], item["port_range"]) for item in outgoing} == protocol_ports
        and all(
            item.get("action", None if scope.source_fixture_egress_isolated else "allow") == "allow"
            and not any(
                item.get(key)
                for key in (
                    "destination_droplet_ids",
                    "destination_kubernetes_ids",
                    "destination_load_balancer_uids",
                    "destination_tags",
                )
            )
            and _address_set(item["destination_addresses"], admin=False) == destinations
            for item in outgoing
        ),
        "droplet-plan-egress-changed",
    )


def verify_initial_host_plan(
    plan: Mapping[str, Any], scope: ApprovedHostPlan, *, cloud_init: bytes
) -> None:
    """Allow only creation on an empty independently selected role state."""
    require(
        scope.role in {"source", "restore", "fresh"}
        and type(scope.source_fixture_egress_isolated) is bool
        and (not scope.source_fixture_egress_isolated or scope.role == "source")
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            scope.run_id,
        )
        is not None,
        "droplet-plan-scope-invalid",
    )
    try:
        _verify_cloud_init(plan, scope.cloud_init_sha256, cloud_init)
        _verify_initial_host_plan(plan, scope, cloud_init)
    except AttributeError, IndexError, KeyError, TypeError:
        raise ValidationError("invalid-droplet-plan") from None


def _verify_cloud_init(plan: Mapping[str, Any], approved: str, rendered: bytes) -> None:
    require(sha256(rendered).hexdigest() == approved, "droplet-plan-cloud-init-render-changed")
    changes = plan.get("output_changes", {})
    planned = plan.get("planned_values", {}).get("outputs", {})
    require(
        changes.keys() == planned.keys() == PLAN_OUTPUTS
        and changes[CLOUD_INIT_OUTPUT]
        == {
            "actions": ["create"],
            "before": None,
            "after": approved,
            "after_unknown": False,
            "before_sensitive": False,
            "after_sensitive": False,
        }
        and planned[CLOUD_INIT_OUTPUT]
        == {
            "value": approved,
            "type": "string",
            "sensitive": False,
        },
        "droplet-plan-cloud-init-digest-unverified",
    )
    provider = plan["configuration"].get("provider_config", {}).get("digitalocean")
    require(provider == PINNED_PROVIDER, "droplet-plan-provider-changed")


def _verify_initial_host_plan(
    plan: Mapping[str, Any], scope: ApprovedHostPlan, cloud_init: bytes
) -> None:
    prior = (plan.get("prior_state") or {}).get("values", {}).get("root_module", {})
    require(
        plan["errored"] is False
        and plan.get("complete", True) is True
        and not plan.get("resource_drift")
        and not plan.get("deferred_changes")
        and not prior.get("resources")
        and not prior.get("child_modules"),
        "droplet-plan-state-is-not-empty",
    )
    require(
        plan["variables"]["qualification_run_id"]["value"] == scope.run_id
        and plan["variables"]["fixture_role"]["value"] == scope.role
        and plan["variables"].get(SOURCE_FIXTURE_EGRESS_OPTION, {"value": False})["value"]
        is scope.source_fixture_egress_isolated,
        "droplet-plan-scope-changed",
    )
    root = plan["configuration"]["root_module"]
    require(not root.get("module_calls"), "droplet-plan-modules-changed")
    config = _resource_index(root["resources"])
    for address, fields in CONFIGURATION_FIELDS.items():
        # OpenTofu omits dynamic nested blocks from the configuration
        # representation. The expanded, known rules are checked below.
        expected_fields = (
            fields - {"outbound_rule"}
            if address == FIREWALL and SOURCE_FIXTURE_EGRESS_OPTION in plan["variables"]
            else fields
        )
        resource = config[address]
        require(
            resource["provider_config_key"] == "digitalocean"
            and resource["expressions"].keys() == expected_fields
            and not resource.get("depends_on")
            and "count_expression" not in resource
            and "for_each_expression" not in resource,
            "droplet-plan-configuration-changed",
        )
    _references(config, FIREWALL, "droplet_ids", "id")
    _references(config, MEMBERSHIP, "resources", "urn")
    changes = _resource_index(plan["resource_changes"])
    host = _change(changes[HOST])
    _require_known(host, CONFIGURATION_FIELDS[HOST] | {"tags"})
    droplet = host["after"]
    # The exact configuration above omits volume_ids. The pinned provider
    # does not request attachments and leaves the field computed until readback.
    if host.get("after_unknown", {}).get("volume_ids") is not True or "volume_ids" in droplet:
        _require_known(host, {"volume_ids"})
    # The provider hashes user_data for its state representation. Approval is
    # established separately by the rendered bytes and the saved SHA-256 output.
    require(
        droplet["user_data"] == sha1(cloud_init, usedforsecurity=False).hexdigest(),
        "droplet-plan-provider-cloud-init-changed",
    )
    require(
        droplet["name"] == scope.name
        and droplet["ssh_keys"] == [scope.ssh_key_fingerprint]
        and all(
            type(droplet[key]) is type(value) and droplet[key] == value
            for key, value in HOST_FIELDS.items()
        )
        and not droplet.get("tags")
        and ("volume_ids" not in droplet or droplet["volume_ids"] == []),
        "droplet-plan-host-changed",
    )
    firewall = _change(changes[FIREWALL])
    _require_known(firewall, {"inbound_rule", "outbound_rule", "name", "tags"})
    _firewall(firewall["after"], scope)
    membership = _change(changes[MEMBERSHIP])
    _require_known(membership, {"project"})
    require(membership["after"]["project"] == scope.project_id, "droplet-plan-project-changed")
    identity = _droplet_id(droplet)
    require(
        (host.get("after_unknown", {}).get("id") is True) == (identity is None),
        "droplet-plan-id-invalid",
    )
    _attachment(firewall, "droplet_ids", None if identity is None else [identity])
    _attachment(membership, "resources", None if identity is None else [f"do:droplet:{identity}"])
