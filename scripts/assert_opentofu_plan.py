#!/usr/bin/env python3
"""Enforce the production infrastructure safety contract over an OpenTofu JSON plan."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Final

EXPECTED_TAGS = {
    "environment:production",
    "managed-by:opentofu",
    "project:lowerduckpond",
}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
CLOUDFLARE_NETWORKS = json.loads(
    (Path(__file__).parents[1] / "platform/cloudflare-networks.json").read_text(encoding="utf-8")
)
CLOUDFLARE_PROXY_CIDRS = {
    *CLOUDFLARE_NETWORKS["cloudflare_ipv4_cidrs"],
    *CLOUDFLARE_NETWORKS["cloudflare_ipv6_cidrs"],
    *CLOUDFLARE_NETWORKS["retiring_ipv4_cidrs"],
    *CLOUDFLARE_NETWORKS["retiring_ipv6_cidrs"],
}
DURABLE_TYPES = {"digitalocean_reserved_ip", "digitalocean_spaces_bucket"}
MIN_MODULE_ADDRESS_PARTS = 3
BACKUP_MULTIPART_ABORT_DAYS = 7
BACKUP_NONCURRENT_RETENTION_DAYS = 30
DIRECT_DNS_TTL = 300
ARCHIVE_MIGRATION_DURABLE_RESOURCE_COUNT = 3
REBUILD_DRILL_ACTIONS = {
    "module.host.digitalocean_droplet.host": ("create", "delete"),
    "module.host.digitalocean_reserved_ip_assignment.host": ("delete", "create"),
    "module.host.digitalocean_firewall.host": ("update",),
    "digitalocean_project_resources.host": ("update",),
}
REBUILD_DRILL_ALLOWED_FIELD_CHANGES = {
    "module.host.digitalocean_droplet.host": {
        "created_at",
        "disk",
        "id",
        "ipv4_address",
        "ipv4_address_private",
        "ipv6_address",
        "locked",
        "memory",
        "price_hourly",
        "price_monthly",
        "private_networking",
        "public_networking",
        "status",
        "urn",
        "vcpus",
        "volume_ids",
    },
    "module.host.digitalocean_reserved_ip_assignment.host": {"droplet_id", "id"},
    "module.host.digitalocean_firewall.host": {
        "created_at",
        "droplet_ids",
        "id",
        "pending_changes",
        "status",
    },
    "digitalocean_project_resources.host": {"id", "resources"},
}
REBUILD_DRILL_REQUIRED_FIELD_CHANGES = {
    "module.host.digitalocean_droplet.host": {"id", "urn"},
    "module.host.digitalocean_reserved_ip_assignment.host": {"droplet_id", "id"},
    "module.host.digitalocean_firewall.host": {"droplet_ids"},
    "digitalocean_project_resources.host": {"resources"},
}
ARCHIVE_STORAGE_MIGRATION_ACTIONS = {
    "module.storage.digitalocean_spaces_bucket.backups": ("update",),
    "module.tenant_archives.digitalocean_spaces_bucket.archives": ("create",),
    "module.tenant_archives.digitalocean_spaces_key.runtime": ("create",),
    "digitalocean_project_resources.production": ("update",),
}
ARCHIVE_STORAGE_MIGRATION_ALLOWED_FIELD_CHANGES = {
    "module.storage.digitalocean_spaces_bucket.backups": {"lifecycle_rule"},
    "digitalocean_project_resources.production": {"resources"},
}
EXPECTED_CONFIGURATION_REFERENCES: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "module.host.digitalocean_reserved_ip_assignment.host": {
        "droplet_id": (
            "digitalocean_droplet.host.id",
            "digitalocean_droplet.host",
        ),
        "ip_address": (
            "digitalocean_reserved_ip.host.ip_address",
            "digitalocean_reserved_ip.host",
        ),
    },
    "module.host.digitalocean_firewall.host": {
        "droplet_ids": (
            "digitalocean_droplet.host.id",
            "digitalocean_droplet.host",
        ),
    },
    "digitalocean_project_resources.host": {
        "project": ("var.digitalocean_project_id",),
        "resources": ("module.host.droplet_urn", "module.host"),
    },
    "digitalocean_project_resources.production": {
        "project": ("var.digitalocean_project_id",),
        "resources": (
            "module.host.reserved_ip_urn",
            "module.host",
            "module.storage.bucket_urn",
            "module.storage",
            "module.tenant_archives.bucket_urn",
            "module.tenant_archives",
        ),
    },
}
EXPECTED_CONFIGURATION_DEPENDS_ON: Final[dict[str, tuple[str, ...]]] = {
    "digitalocean_project_resources.host": ("digitalocean_project_resources.production",),
    "digitalocean_project_resources.production": ("module.tenant_archives",),
}
EXPECTED_PROJECT_RESOURCE_ADDRESSES = {
    "digitalocean_project_resources.host",
    "digitalocean_project_resources.production",
}
EXPECTED_DURABLE_PROJECT_MEMBERS = {
    "module.host.digitalocean_reserved_ip.host": "urn",
    "module.storage.digitalocean_spaces_bucket.backups": "urn",
    "module.tenant_archives.digitalocean_spaces_bucket.archives": "urn",
}
EXPECTED_SPACES_BUCKET_ADDRESSES = {
    "module.storage.digitalocean_spaces_bucket.backups",
    "module.tenant_archives.digitalocean_spaces_bucket.archives",
}
EXPECTED_SPACES_KEY_ADDRESSES = {
    "module.storage.digitalocean_spaces_key.runtime",
    "module.tenant_archives.digitalocean_spaces_key.runtime",
}
NON_MUTATING_ACTIONS = {("no-op",), ("read",)}
PUBLIC_EDGE_RESOURCE_TYPES = {
    "cloudflare_authenticated_origin_pulls",
    "cloudflare_authenticated_origin_pulls_settings",
    "cloudflare_dns_record",
    "cloudflare_ruleset",
    "cloudflare_zone_setting",
}
EXPECTED_DIRECT_DNS_NAMES = {
    "lowerduckpond.net",
    "*.lowerduckpond.net",
}
EXPECTED_PROXIED_DNS_NAMES = EXPECTED_DIRECT_DNS_NAMES | {
    "lowerduckpond.com",
    "*.lowerduckpond.com",
}
EXPECTED_EDGE_ZONE_IDS = {
    "lowerduckpond_net",
    "lowerduckpond_com",
}
EXPECTED_EDGE_RULESET_PHASES = {
    "http_config_settings",
    "http_request_cache_settings",
    "http_request_firewall_custom",
}
EXPECTED_EDGE_RULESET_PHASES_BY_ZONE = dict.fromkeys(
    EXPECTED_EDGE_ZONE_IDS, EXPECTED_EDGE_RULESET_PHASES
)
EXPECTED_DIRECT_DNS_ADDRESSES = {
    'module.edge["lowerduckpond_net"].cloudflare_dns_record.apex[0]',
    'module.edge["lowerduckpond_net"].cloudflare_dns_record.wildcard[0]',
}
EXPECTED_PROXIED_DNS_ADDRESSES = EXPECTED_DIRECT_DNS_ADDRESSES | {
    'module.edge["lowerduckpond_com"].cloudflare_dns_record.apex[0]',
    'module.edge["lowerduckpond_com"].cloudflare_dns_record.wildcard[0]',
}
EXPECTED_EDGE_AOP_ADDRESSES = {
    f'module.edge["{zone}"].cloudflare_authenticated_origin_pulls_settings.zone[0]'
    for zone in EXPECTED_EDGE_ZONE_IDS
}
EXPECTED_EDGE_ZONE_SETTING_ADDRESSES = {
    f'module.edge["{zone}"].cloudflare_zone_setting.{setting}[0]'
    for zone in EXPECTED_EDGE_ZONE_IDS
    for setting in ("always_online", "always_use_https", "ssl")
}
EXPECTED_EDGE_RULESET_ADDRESSES = {
    f'module.edge["{zone}"].cloudflare_ruleset.{ruleset}[0]'
    for zone in EXPECTED_EDGE_ZONE_IDS
    for ruleset in ("cache_bypass", "cdn_cgi_block", "transform_disable")
}
EXPECTED_EDGE_RESOURCE_ADDRESSES = (
    EXPECTED_PROXIED_DNS_ADDRESSES
    | EXPECTED_EDGE_AOP_ADDRESSES
    | EXPECTED_EDGE_ZONE_SETTING_ADDRESSES
    | EXPECTED_EDGE_RULESET_ADDRESSES
)
EXPECTED_DNS_COMMENT = "Managed by OpenTofu for Lower Duck Pond Hosting"


class PlanPolicyError(RuntimeError):
    """Raised when a plan violates one or more infrastructure policies."""


def _changes_by_type(plan: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in plan.get("resource_changes", [])
        if resource.get("type") == resource_type
    ]


def _change_by_address(plan: dict[str, Any], address: str) -> dict[str, Any] | None:
    return next(
        (
            resource
            for resource in plan.get("resource_changes", [])
            if resource.get("address") == address
        ),
        None,
    )


def _after(resource: dict[str, Any]) -> dict[str, Any]:
    value = resource.get("change", {}).get("after")
    return value if isinstance(value, dict) else {}


def _before(resource: dict[str, Any]) -> dict[str, Any]:
    value = resource.get("change", {}).get("before")
    return value if isinstance(value, dict) else {}


def _contains_unknown(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_contains_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unknown(item) for item in value)
    return False


def _changed_top_level_fields(resource: dict[str, Any]) -> set[str] | None:
    change = resource.get("change", {})
    before = change.get("before")
    after = change.get("after")
    after_unknown = change.get("after_unknown", {})
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    if not isinstance(after_unknown, dict):
        after_unknown = {}

    fields = before.keys() | after.keys() | after_unknown.keys()
    return {
        field
        for field in fields
        if before.get(field) != after.get(field) or _contains_unknown(after_unknown.get(field))
    }


def _configuration_resource(plan: dict[str, Any], address: str) -> dict[str, Any] | None:
    module = plan.get("configuration", {}).get("root_module")
    if not isinstance(module, dict):
        return None

    address_parts = address.split(".")
    while address_parts[:1] == ["module"] and len(address_parts) >= MIN_MODULE_ADDRESS_PARTS:
        module_name = address_parts[1]
        module_call = module.get("module_calls", {}).get(module_name, {})
        module = module_call.get("module")
        if not isinstance(module, dict):
            return None
        address_parts = address_parts[2:]

    relative_address = ".".join(address_parts)
    return next(
        (
            resource
            for resource in module.get("resources", [])
            if resource.get("address") == relative_address
        ),
        None,
    )


def _check_configuration_references(plan: dict[str, Any], address: str, errors: list[str]) -> None:
    resource = _configuration_resource(plan, address)
    if resource is None:
        errors.append(f"{address} is missing from the plan configuration")
        return

    expressions = resource.get("expressions", {})
    for field, expected_references in EXPECTED_CONFIGURATION_REFERENCES[address].items():
        expression = expressions.get(field, {})
        observed_references = tuple(expression.get("references", []))
        if observed_references != expected_references:
            errors.append(
                f"{address}.{field} must retain its exact infrastructure references; "
                f"found {list(observed_references)}"
            )
    expected_dependencies = EXPECTED_CONFIGURATION_DEPENDS_ON.get(address, ())
    observed_dependencies = tuple(resource.get("depends_on", []))
    if observed_dependencies != expected_dependencies:
        errors.append(
            f"{address} must retain its exact creation dependencies; "
            f"found {list(observed_dependencies)}"
        )


def _require_one(
    plan: dict[str, Any], resource_type: str, errors: list[str]
) -> dict[str, Any] | None:
    resources = _changes_by_type(plan, resource_type)
    if len(resources) != 1:
        errors.append(f"expected exactly one {resource_type}, found {len(resources)}")
        return None
    return resources[0]


def _check_destructive_actions(
    plan: dict[str, Any], errors: list[str], *, allow_droplet_replacement: bool
) -> None:
    for resource in plan.get("resource_changes", []):
        actions = set(resource.get("change", {}).get("actions", []))
        resource_type = resource.get("type")
        if resource_type in DURABLE_TYPES and "delete" in actions:
            errors.append(f"{resource.get('address')} must not delete durable infrastructure")
        if (
            resource_type == "digitalocean_droplet"
            and "delete" in actions
            and not allow_droplet_replacement
        ):
            errors.append(
                f"{resource.get('address')} replaces the Droplet; "
                "review it through a dedicated drill"
            )


def _check_rebuild_drill_actions(plan: dict[str, Any], errors: list[str]) -> None:
    observed_changes: set[str] = set()
    for resource in plan.get("resource_changes", []):
        address = str(resource.get("address", ""))
        actions = tuple(resource.get("change", {}).get("actions", []))
        if actions in NON_MUTATING_ACTIONS:
            continue

        expected_actions = REBUILD_DRILL_ACTIONS.get(address)
        if expected_actions is None:
            errors.append(f"{address} has unrelated rebuild-drill actions: {list(actions)}")
            continue

        observed_changes.add(address)
        if actions != expected_actions:
            errors.append(
                f"{address} rebuild-drill actions must be "
                f"{list(expected_actions)}, found {list(actions)}"
            )

        changed_fields = _changed_top_level_fields(resource)
        if changed_fields is None:
            errors.append(f"{address} must have comparable before and after values")
            continue
        unexpected_fields = changed_fields - REBUILD_DRILL_ALLOWED_FIELD_CHANGES[address]
        if unexpected_fields:
            errors.append(
                f"{address} has unrelated rebuild-drill field changes: {sorted(unexpected_fields)}"
            )
        missing_fields = REBUILD_DRILL_REQUIRED_FIELD_CHANGES[address] - changed_fields
        if missing_fields:
            errors.append(
                f"{address} is missing required rebuild-drill field changes: "
                f"{sorted(missing_fields)}"
            )

        if (
            address == "module.host.digitalocean_droplet.host"
            and resource.get("action_reason") != "replace_by_request"
        ):
            errors.append("Droplet rebuild must be an explicit -replace request")

    missing_changes = REBUILD_DRILL_ACTIONS.keys() - observed_changes
    errors.extend(
        f"{address} must change during the rebuild drill" for address in sorted(missing_changes)
    )

    for address in (
        "module.host.digitalocean_firewall.host",
        "module.host.digitalocean_reserved_ip_assignment.host",
    ):
        _check_configuration_references(plan, address, errors)


def _planned_attribute(resource: dict[str, Any], field: str) -> tuple[object, bool]:
    value = _after(resource).get(field)
    unknown = _contains_unknown(resource.get("change", {}).get("after_unknown", {}).get(field))
    return value, unknown


def _plan_variable(plan: dict[str, Any], name: str) -> object:
    variable = plan.get("variables", {}).get(name, {})
    return variable.get("value") if isinstance(variable, dict) else None


def _edge_zone_key(address: str) -> str | None:
    return next(
        (key for key in EXPECTED_EDGE_ZONE_IDS if f'["{key}"]' in address),
        None,
    )


def _expected_edge_zone_id(plan: dict[str, Any], address: str) -> object:
    zone_key = _edge_zone_key(address)
    if zone_key == "lowerduckpond_net":
        return _plan_variable(plan, "cloudflare_zone_id")
    if zone_key == "lowerduckpond_com":
        return _plan_variable(plan, "cloudflare_tenant_zone_id")
    return None


def _expected_durable_member(
    resource: dict[str, Any], *, address: str, field: str
) -> tuple[object, bool]:
    if address != "module.tenant_archives.digitalocean_spaces_bucket.archives":
        return _planned_attribute(resource, field)
    archive_name, unknown = _planned_attribute(resource, "name")
    value = f"do:space:{archive_name}" if isinstance(archive_name, str) else None
    return value, unknown


def _check_project_resources(
    plan: dict[str, Any], errors: list[str], *, allow_archive_storage_migration: bool
) -> None:
    resources = _changes_by_type(plan, "digitalocean_project_resources")
    observed_addresses = {str(resource.get("address", "")) for resource in resources}
    if (
        len(resources) != len(EXPECTED_PROJECT_RESOURCE_ADDRESSES)
        or observed_addresses != EXPECTED_PROJECT_RESOURCE_ADDRESSES
    ):
        errors.append(
            "project assignments must separate replaceable host and durable resources; "
            f"found {sorted(observed_addresses)}"
        )
        return

    resources_by_address = {str(resource.get("address", "")): resource for resource in resources}
    durable = resources_by_address["digitalocean_project_resources.production"]
    durable_members, durable_members_unknown = _planned_attribute(durable, "resources")
    durable_actions = tuple(durable.get("change", {}).get("actions", []))
    expected_durable_members: list[object] = []
    durable_sources_unknown = False
    for address, field in EXPECTED_DURABLE_PROJECT_MEMBERS.items():
        source = _change_by_address(plan, address)
        if source is None:
            errors.append(f"{address} is missing from the plan")
            continue
        value, unknown = _expected_durable_member(source, address=address, field=field)
        durable_sources_unknown |= unknown
        expected_durable_members.append(value)

    if durable_members_unknown:
        migration_unknown_is_expected = (
            allow_archive_storage_migration
            and durable_actions == ("update",)
            and durable_sources_unknown
        )
        initial_creation_unknown_is_expected = (
            durable_actions == ("create",) and durable_sources_unknown
        )
        if not migration_unknown_is_expected and not initial_creation_unknown_is_expected:
            errors.append(
                "durable project membership is unexpectedly unknown outside initial creation "
                "or the archive-storage migration"
            )
    elif (
        durable_sources_unknown
        or not isinstance(durable_members, list)
        or len(durable_members) != len(expected_durable_members)
        or not all(isinstance(member, str) for member in durable_members)
        or not all(isinstance(member, str) for member in expected_durable_members)
        or set(durable_members) != set(expected_durable_members)
    ):
        errors.append(
            "durable project assignment must exactly match the planned reserved IP and "
            "Spaces bucket URNs"
        )

    host = resources_by_address["digitalocean_project_resources.host"]
    host_members, host_members_unknown = _planned_attribute(host, "resources")
    host_actions = tuple(host.get("change", {}).get("actions", []))
    droplet = _change_by_address(plan, "module.host.digitalocean_droplet.host")
    if droplet is None:
        errors.append("module.host.digitalocean_droplet.host is missing from the plan")
    else:
        droplet_urn, droplet_urn_unknown = _planned_attribute(droplet, "urn")
        if host_members_unknown:
            if host_actions not in {("create",), ("update",)} or not droplet_urn_unknown:
                errors.append("host project membership is unexpectedly unknown")
        elif (
            droplet_urn_unknown
            or not isinstance(host_members, list)
            or host_members != [droplet_urn]
        ):
            errors.append("host project assignment must exactly match the planned Droplet URN")

    for address in sorted(EXPECTED_PROJECT_RESOURCE_ADDRESSES):
        _check_configuration_references(plan, address, errors)


def _check_droplet(plan: dict[str, Any], errors: list[str]) -> None:
    resource = _require_one(plan, "digitalocean_droplet", errors)
    if resource is None:
        return
    after = _after(resource)
    if after.get("resize_disk") is not False:
        errors.append("Droplet resize_disk must be false so CPU/RAM scaling remains reversible")
    if after.get("monitoring") is not True:
        errors.append("Droplet monitoring must be enabled")
    if after.get("backups") is not False:
        errors.append("Droplet backups must remain secondary to application-aware Spaces backups")
    if not str(after.get("size", "")).startswith("s-"):
        errors.append("Droplet must use a Basic shared-CPU size slug")
    tags = set(after.get("tags") or [])
    if not EXPECTED_TAGS.issubset(tags):
        errors.append(f"Droplet is missing required tags: {sorted(EXPECTED_TAGS - tags)}")


def _check_firewall(
    plan: dict[str, Any],
    errors: list[str],
    *,
    allow_historical_restricted: bool = False,
) -> str | None:
    resource = _require_one(plan, "digitalocean_firewall", errors)
    if resource is None:
        return None
    rules = _after(resource).get("inbound_rule") or []
    seen_ports: set[str] = set()
    rule_counts = {"22": 0, "80": 0, "443": 0}
    web_sources_by_port: dict[str, set[str]] = {}
    for rule in rules:
        protocol = rule.get("protocol")
        port = str(rule.get("port_range", ""))
        sources = set(rule.get("source_addresses") or [])
        if protocol != "tcp" or port not in {"22", "80", "443"}:
            errors.append(f"unexpected public inbound firewall rule: {protocol}/{port}")
            continue
        seen_ports.add(port)
        rule_counts[port] += 1
        if port == "22" and (not sources or sources & WORLD_CIDRS):
            errors.append("SSH must use a non-empty explicit source allowlist")
        if port in {"80", "443"}:
            web_sources_by_port[port] = sources
    structure_valid = True
    if seen_ports != {"22", "80", "443"}:
        errors.append(f"firewall inbound ports must be exactly 22, 80, and 443; found {seen_ports}")
        structure_valid = False
    if any(count != 1 for count in rule_counts.values()):
        errors.append("firewall must contain exactly one inbound rule for each reviewed port")
        structure_valid = False
    if web_sources_by_port.get("80") != web_sources_by_port.get("443"):
        errors.append("TCP 80 and 443 must share one exact source policy")
        structure_valid = False
    if not structure_valid:
        return None
    web_sources = web_sources_by_port.get("80", set())
    if web_sources == WORLD_CIDRS:
        return "open"
    if web_sources == CLOUDFLARE_PROXY_CIDRS:
        return "restricted"
    if allow_historical_restricted and (
        web_sources < CLOUDFLARE_PROXY_CIDRS or web_sources > CLOUDFLARE_PROXY_CIDRS
    ):
        return "restricted"
    errors.append("web ingress must be exactly world-open or the reviewed Cloudflare CIDRs")
    return None


def _check_spaces_buckets(plan: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    buckets = _changes_by_type(plan, "digitalocean_spaces_bucket")
    buckets_by_address = {str(resource.get("address", "")): resource for resource in buckets}
    if set(buckets_by_address) != EXPECTED_SPACES_BUCKET_ADDRESSES:
        errors.append(
            "Spaces buckets must be exactly the isolated backup and tenant-archive resources; "
            f"found {sorted(buckets_by_address)}"
        )
    for address, bucket in buckets_by_address.items():
        after = _after(bucket)
        if after.get("acl") != "private":
            errors.append(f"{address} ACL must be private")
        if after.get("force_destroy") is not False:
            errors.append(f"{address} force_destroy must be false")
        versioning = after.get("versioning") or []
        if not versioning or versioning[0].get("enabled") is not True:
            errors.append(f"{address} versioning must be enabled")

    backup = buckets_by_address.get("module.storage.digitalocean_spaces_bucket.backups")
    if backup is not None:
        rules = _after(backup).get("lifecycle_rule") or []
        if len(rules) != 1 or rules[0].get("id") != "backups-retention":
            errors.append("backup bucket must retain only the backups-retention lifecycle rule")
        elif (
            rules[0].get("prefix") != "backups/"
            or rules[0].get("enabled") is not True
            or rules[0].get("abort_incomplete_multipart_upload_days") != BACKUP_MULTIPART_ABORT_DAYS
            or bool(rules[0].get("expiration"))
            or rules[0].get("noncurrent_version_expiration")
            != [{"days": BACKUP_NONCURRENT_RETENTION_DAYS}]
        ):
            errors.append("backup bucket lifecycle rule does not match the Restic safety contract")

    archives = buckets_by_address.get("module.tenant_archives.digitalocean_spaces_bucket.archives")
    if archives is not None and (_after(archives).get("lifecycle_rule") or []):
        errors.append("tenant archive bucket must not have lifecycle rules")
    return buckets_by_address


def _check_spaces_keys(
    plan: dict[str, Any],
    errors: list[str],
    *,
    buckets_by_address: dict[str, dict[str, Any]],
) -> None:
    keys = _changes_by_type(plan, "digitalocean_spaces_key")
    keys_by_address = {str(resource.get("address", "")): resource for resource in keys}
    if set(keys_by_address) != EXPECTED_SPACES_KEY_ADDRESSES:
        errors.append(
            "Spaces keys must be exactly the isolated backup and tenant-archive credentials; "
            f"found {sorted(keys_by_address)}"
        )
    bucket_address_by_key = {
        "module.storage.digitalocean_spaces_key.runtime": (
            "module.storage.digitalocean_spaces_bucket.backups"
        ),
        "module.tenant_archives.digitalocean_spaces_key.runtime": (
            "module.tenant_archives.digitalocean_spaces_bucket.archives"
        ),
    }
    for address, key in keys_by_address.items():
        grants = _after(key).get("grant") or []
        if len(grants) != 1:
            errors.append(f"{address} must have exactly one bucket grant")
            continue
        expected_bucket = buckets_by_address.get(bucket_address_by_key.get(address, ""))
        expected_name = _after(expected_bucket).get("name") if expected_bucket else None
        if (
            grants[0].get("permission") != "readwrite"
            or not isinstance(expected_name, str)
            or grants[0].get("bucket") != expected_name
        ):
            errors.append(f"{address} must have readwrite access only to its own bucket")

    backup = buckets_by_address.get("module.storage.digitalocean_spaces_bucket.backups")
    archives = buckets_by_address.get("module.tenant_archives.digitalocean_spaces_bucket.archives")
    if backup is not None and archives is not None:
        backup_name = _after(backup).get("name")
        archive_name = _after(archives).get("name")
        if not isinstance(backup_name, str) or backup_name == archive_name:
            errors.append("backup and tenant archive bucket names must be distinct")


def _check_spaces(plan: dict[str, Any], errors: list[str]) -> None:
    if _changes_by_type(plan, "digitalocean_spaces_bucket_policy"):
        errors.append("Spaces bucket policies are incompatible with bucket-scoped access keys")
    buckets_by_address = _check_spaces_buckets(plan, errors)
    _check_spaces_keys(plan, errors, buckets_by_address=buckets_by_address)


def _check_archive_storage_migration(plan: dict[str, Any], errors: list[str]) -> None:
    observed_changes: set[str] = set()
    resources_by_address = {
        str(resource.get("address", "")): resource for resource in plan.get("resource_changes", [])
    }
    for address, resource in resources_by_address.items():
        actions = tuple(resource.get("change", {}).get("actions", []))
        if actions in NON_MUTATING_ACTIONS:
            continue
        expected_actions = ARCHIVE_STORAGE_MIGRATION_ACTIONS.get(address)
        if expected_actions is None:
            errors.append(f"{address} has unrelated archive-storage migration actions")
            continue
        observed_changes.add(address)
        if actions != expected_actions:
            errors.append(
                f"{address} archive-storage migration actions must be "
                f"{list(expected_actions)}, found {list(actions)}"
            )

        allowed_fields = ARCHIVE_STORAGE_MIGRATION_ALLOWED_FIELD_CHANGES.get(address)
        if allowed_fields is not None:
            changed_fields = _changed_top_level_fields(resource)
            if changed_fields is None:
                errors.append(f"{address} must have comparable before and after values")
            elif changed_fields != allowed_fields:
                errors.append(
                    f"{address} archive-storage migration fields must be "
                    f"{sorted(allowed_fields)}, found {sorted(changed_fields)}"
                )

    missing_changes = ARCHIVE_STORAGE_MIGRATION_ACTIONS.keys() - observed_changes
    errors.extend(
        f"{address} must change during the archive-storage migration"
        for address in sorted(missing_changes)
    )

    _check_archive_storage_migration_invariants(resources_by_address, errors)


def _check_archive_storage_migration_invariants(
    resources_by_address: dict[str, dict[str, Any]], errors: list[str]
) -> None:
    backup = resources_by_address.get("module.storage.digitalocean_spaces_bucket.backups")
    if backup is not None:
        before_rules = _before(backup).get("lifecycle_rule") or []
        after_rules = _after(backup).get("lifecycle_rule") or []
        before_by_id = {rule.get("id"): rule for rule in before_rules}
        after_by_id = {rule.get("id"): rule for rule in after_rules}
        if set(before_by_id) != {"archives-retention", "backups-retention"}:
            errors.append(
                "backup bucket must begin migration with exactly the legacy archive and "
                "backup lifecycle rules"
            )
        if set(after_by_id) != {"backups-retention"}:
            errors.append("backup bucket migration must remove only archives-retention")
        elif before_by_id.get("backups-retention") != after_by_id["backups-retention"]:
            errors.append("backup bucket migration must not alter backups-retention")

    project = resources_by_address.get("digitalocean_project_resources.production")
    reserved_ip = resources_by_address.get("module.host.digitalocean_reserved_ip.host")
    archives = resources_by_address.get(
        "module.tenant_archives.digitalocean_spaces_bucket.archives"
    )
    if (
        backup is not None
        and project is not None
        and reserved_ip is not None
        and archives is not None
    ):
        expected_existing_members = {
            _before(reserved_ip).get("urn"),
            _before(backup).get("urn"),
        }
        archive_name = _after(archives).get("name")
        expected_archive_member = (
            f"do:space:{archive_name}" if isinstance(archive_name, str) else None
        )
        expected_after_members = expected_existing_members | {expected_archive_member}
        before_members = _before(project).get("resources")
        after_members = _after(project).get("resources")
        if (
            None in expected_existing_members
            or not isinstance(before_members, list)
            or set(before_members) != expected_existing_members
        ):
            errors.append(
                "durable project assignment must begin migration with exactly the reserved IP "
                "and backup bucket"
            )
        if (
            None in expected_after_members
            or not isinstance(after_members, list)
            or len(after_members) != ARCHIVE_MIGRATION_DURABLE_RESOURCE_COUNT
            or set(after_members) != expected_after_members
        ):
            errors.append(
                "durable project assignment migration must retain the reserved IP and backup "
                "bucket while adding only the exact archive bucket URN"
            )


def _reject_unapproved_archive_storage_migration(plan: dict[str, Any], errors: list[str]) -> None:
    backup = _change_by_address(plan, "module.storage.digitalocean_spaces_bucket.backups")
    archives = _change_by_address(
        plan, "module.tenant_archives.digitalocean_spaces_bucket.archives"
    )
    if backup is None or archives is None:
        return
    backup_actions = tuple(backup.get("change", {}).get("actions", []))
    archive_actions = tuple(archives.get("change", {}).get("actions", []))
    if backup_actions == ("update",) and archive_actions == ("create",):
        errors.append("archive-storage migration requires --allow-archive-storage-migration")


def _check_dns(plan: dict[str, Any], errors: list[str]) -> str | None:
    records = [
        resource for resource in _changes_by_type(plan, "cloudflare_dns_record") if _after(resource)
    ]
    names: set[object] = set()
    addresses = {str(resource.get("address", "")) for resource in records}
    proxy_values: set[object] = set()
    reserved_ip = _change_by_address(plan, "module.host.digitalocean_reserved_ip.host")
    expected_content, expected_content_unknown = (
        _planned_attribute(reserved_ip, "ip_address") if reserved_ip is not None else (None, False)
    )
    for resource in records:
        after = _after(resource)
        address = str(resource.get("address", ""))
        names.add(after.get("name"))
        proxy_values.add(after.get("proxied"))
        if after.get("type") != "A":
            errors.append(f"{address} must be an A record")
        if after.get("comment") != EXPECTED_DNS_COMMENT:
            errors.append(f"{address} must retain the reviewed management comment")
        if after.get("zone_id") != _expected_edge_zone_id(plan, address):
            errors.append(f"{address} must remain in its reviewed Cloudflare zone")
        content, content_unknown = _planned_attribute(resource, "content")
        if content_unknown != expected_content_unknown or (
            not content_unknown and content != expected_content
        ):
            errors.append(f"{address} must target the production reserved IP")
    if (
        names == EXPECTED_DIRECT_DNS_NAMES
        and addresses == EXPECTED_DIRECT_DNS_ADDRESSES
        and proxy_values == {False}
        and all(_after(resource).get("ttl") == DIRECT_DNS_TTL for resource in records)
    ):
        return "direct"
    if (
        names == EXPECTED_PROXIED_DNS_NAMES
        and addresses == EXPECTED_PROXIED_DNS_ADDRESSES
        and proxy_values == {True}
        and all(_after(resource).get("ttl") == 1 for resource in records)
    ):
        return "proxied"
    errors.append(
        "DNS must be exactly the unproxied .net apex/wildcard or both proxied apex/wildcards"
    )
    return None


def _check_public_edge_rule(
    *,
    address: str,
    zone_key: str,
    after: dict[str, Any],
    errors: list[str],
) -> None:
    rules = after.get("rules") or []
    if len(rules) != 1 or rules[0].get("enabled") is not True:
        errors.append(f"{address} must contain exactly one enabled rule")
        return
    domain = "lowerduckpond.net" if zone_key == "lowerduckpond_net" else "lowerduckpond.com"
    zone_expression = f'(http.host eq "{domain}" or ends_with(http.host, ".{domain}"))'
    rule = rules[0]
    phase = after.get("phase")
    invalid = False
    if phase == "http_request_cache_settings":
        expected_parameters = {"cache": False}
        invalid = (
            rule.get("action") != "set_cache_settings"
            or rule.get("expression") != zone_expression
            or not _action_parameters_match(rule.get("action_parameters"), expected_parameters)
        )
    elif phase == "http_config_settings":
        expected_parameters = {
            "automatic_https_rewrites": False,
            "disable_rum": True,
            "disable_zaraz": True,
            "email_obfuscation": False,
            "fonts": False,
            "rocket_loader": False,
        }
        invalid = (
            rule.get("action") != "set_config"
            or rule.get("expression") != zone_expression
            or not _action_parameters_match(rule.get("action_parameters"), expected_parameters)
        )
    elif phase == "http_request_firewall_custom":
        invalid = rule.get("action") != "block" or rule.get("expression") != (
            f'{zone_expression} and (lower(http.request.uri.path) eq "/cdn-cgi" '
            'or starts_with(lower(http.request.uri.path), "/cdn-cgi/"))'
        )
    if invalid:
        errors.append(f"{address} does not match its reviewed {phase} rule")


def _action_parameters_match(parameters: object, expected: dict[str, object]) -> bool:
    """Accept provider-shaped nulls without permitting another configured action."""
    return (
        isinstance(parameters, dict)
        and all(parameters.get(key) == value for key, value in expected.items())
        and not any(value is not None and key not in expected for key, value in parameters.items())
    )


def _check_public_edge_resources(
    plan: dict[str, Any], errors: list[str], *, dns_mode: str | None
) -> None:
    edge_resources = [
        resource
        for resource in plan.get("resource_changes", [])
        if resource.get("type") in PUBLIC_EDGE_RESOURCE_TYPES
    ]
    unexpected_addresses = {str(resource.get("address", "")) for resource in edge_resources} - set(
        EXPECTED_EDGE_RESOURCE_ADDRESSES
    )
    if unexpected_addresses:
        errors.append(
            "public edge may manage only the exact reviewed resource addresses; "
            f"found {sorted(unexpected_addresses)}"
        )

    active_associations = [
        resource
        for resource in _changes_by_type(plan, "cloudflare_authenticated_origin_pulls")
        if _after(resource)
    ]
    active_settings = [
        resource
        for resource in _changes_by_type(plan, "cloudflare_authenticated_origin_pulls_settings")
        if _after(resource)
    ]
    active_zone_settings = [
        resource
        for resource in _changes_by_type(plan, "cloudflare_zone_setting")
        if _after(resource)
    ]
    active_rulesets = [
        resource for resource in _changes_by_type(plan, "cloudflare_ruleset") if _after(resource)
    ]
    if dns_mode == "direct":
        if active_associations or active_settings or active_zone_settings or active_rulesets:
            errors.append("direct phase must not retain active Cloudflare edge policy resources")
        return
    if dns_mode != "proxied":
        return

    if {
        str(resource.get("address", "")) for resource in active_settings
    } != EXPECTED_EDGE_AOP_ADDRESSES or any(
        _after(resource).get("enabled") is not True
        or _after(resource).get("zone_id")
        != _expected_edge_zone_id(plan, str(resource.get("address", "")))
        for resource in active_settings
    ):
        errors.append("proxied edge must enable zone-level origin pulls in exactly two zones")

    if active_associations:
        errors.append("production edge must not create hostname-level origin-pull associations")

    zone_setting_addresses = {str(resource.get("address", "")) for resource in active_zone_settings}
    zone_settings_valid = all(
        (
            (
                address.endswith(".cloudflare_zone_setting.ssl[0]")
                and _after(resource).get("setting_id") == "ssl"
                and _after(resource).get("value") == "strict"
            )
            or (
                address.endswith(".cloudflare_zone_setting.always_online[0]")
                and _after(resource).get("setting_id") == "always_online"
                and _after(resource).get("value") == "off"
            )
            or (
                address.endswith(".cloudflare_zone_setting.always_use_https[0]")
                and _after(resource).get("setting_id") == "always_use_https"
                and _after(resource).get("value") == "off"
            )
        )
        and _after(resource).get("zone_id") == _expected_edge_zone_id(plan, address)
        for resource in active_zone_settings
        if (address := str(resource.get("address", "")))
    )
    if zone_setting_addresses != EXPECTED_EDGE_ZONE_SETTING_ADDRESSES or not zone_settings_valid:
        errors.append(
            "each proxied zone must use Full (strict) with Always Online and "
            "Always Use HTTPS disabled"
        )

    observed_rulesets: dict[str, set[str]] = {}
    for resource in active_rulesets:
        address = str(resource.get("address", ""))
        zone_key = _edge_zone_key(address)
        if zone_key is None:
            errors.append(f"{address} is outside the two reviewed edge zones")
            continue
        after = _after(resource)
        observed_rulesets.setdefault(zone_key, set()).add(str(after.get("phase", "")))
        if after.get("kind") != "zone":
            errors.append(f"{address} must be a zone ruleset")
        if after.get("zone_id") != _expected_edge_zone_id(plan, address):
            errors.append(f"{address} must remain in its reviewed Cloudflare zone")
        _check_public_edge_rule(
            address=address,
            zone_key=zone_key,
            after=after,
            errors=errors,
        )
    if {
        str(resource.get("address", "")) for resource in active_rulesets
    } != EXPECTED_EDGE_RULESET_ADDRESSES or (
        observed_rulesets != EXPECTED_EDGE_RULESET_PHASES_BY_ZONE
    ):
        errors.append("each proxied zone must own the three reviewed edge ruleset phases")


def _edge_changes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for resource in plan.get("resource_changes", []):
        actions = tuple(resource.get("change", {}).get("actions", []))
        if actions in NON_MUTATING_ACTIONS:
            continue
        if resource.get("type") in PUBLIC_EDGE_RESOURCE_TYPES:
            changes.append(resource)
            continue
        if resource.get("address") == "module.host.digitalocean_firewall.host":
            changed_fields = _changed_top_level_fields(resource)
            if changed_fields == {"inbound_rule"}:
                changes.append(resource)
    return changes


def _project_before(plan: dict[str, Any]) -> dict[str, Any]:
    projected = deepcopy(plan)
    for resource in projected.get("resource_changes", []):
        change = resource.get("change", {})
        change["after"] = change.get("before")
        change["after_unknown"] = change.get("before_unknown", {})
    return projected


def _edge_phase(
    plan: dict[str, Any],
    errors: list[str],
    *,
    allow_historical_restricted: bool = False,
) -> str | None:
    firewall_mode = _check_firewall(
        plan,
        errors,
        allow_historical_restricted=allow_historical_restricted,
    )
    dns_mode = _check_dns(plan, errors)
    _check_public_edge_resources(plan, errors, dns_mode=dns_mode)
    return "enforced" if dns_mode == "proxied" and firewall_mode == "restricted" else dns_mode


def _check_public_edge_transition(
    plan: dict[str, Any],
    errors: list[str],
    *,
    requested_transition: str | None,
    desired_phase: str | None,
) -> None:
    edge_changes = _edge_changes(plan)
    droplet = _change_by_address(plan, "module.host.digitalocean_droplet.host")
    initial_foundation = droplet is not None and tuple(
        droplet.get("change", {}).get("actions", [])
    ) == ("create",)
    if requested_transition == "enforced":
        before_errors: list[str] = []
        before_phase = (
            None
            if initial_foundation
            else _edge_phase(
                _project_before(plan),
                before_errors,
                allow_historical_restricted=True,
            )
        )
        if before_errors or before_phase not in {"proxied", "enforced"}:
            errors.append(
                "enforced ingress requires a fully proxied or already enforced starting state"
            )
    if initial_foundation:
        return
    if not edge_changes:
        if requested_transition is not None:
            errors.append(
                "public-edge transition was requested but the plan contains no edge change"
            )
        return
    if requested_transition is None:
        errors.append("public-edge changes require --public-edge-transition")
        return
    if desired_phase != requested_transition:
        errors.append(
            f"public-edge transition requested {requested_transition}, but the plan selects "
            f"{desired_phase or 'an invalid phase'}"
        )
    if requested_transition == "direct" and any(
        resource.get("address") == "module.host.digitalocean_firewall.host"
        for resource in edge_changes
    ):
        errors.append("enforced ingress must return to the proxied phase before a direct rollback")

    unrelated = [
        str(resource.get("address", ""))
        for resource in plan.get("resource_changes", [])
        if tuple(resource.get("change", {}).get("actions", [])) not in NON_MUTATING_ACTIONS
        and resource not in edge_changes
    ]
    if unrelated:
        errors.append(
            "public-edge transitions must be isolated from other infrastructure changes; "
            f"found {sorted(unrelated)}"
        )


def assert_plan(
    plan: dict[str, Any],
    *,
    allow_droplet_replacement: bool = False,
    allow_archive_storage_migration: bool = False,
    public_edge_transition: str | None = None,
) -> None:
    """Raise PlanPolicyError when a production plan violates policy."""
    errors: list[str] = []
    special_modes = sum(
        (
            allow_droplet_replacement,
            allow_archive_storage_migration,
            public_edge_transition is not None,
        )
    )
    if special_modes > 1:
        errors.append("Droplet, archive-storage, and public-edge changes require separate plans")
    _check_destructive_actions(plan, errors, allow_droplet_replacement=allow_droplet_replacement)
    if allow_droplet_replacement:
        _check_rebuild_drill_actions(plan, errors)
    if allow_archive_storage_migration:
        _check_archive_storage_migration(plan, errors)
    else:
        _reject_unapproved_archive_storage_migration(plan, errors)
    _check_droplet(plan, errors)
    _check_spaces(plan, errors)
    desired_phase = _edge_phase(plan, errors)
    _check_public_edge_transition(
        plan,
        errors,
        requested_transition=public_edge_transition,
        desired_phase=desired_phase,
    )
    _check_project_resources(
        plan, errors, allow_archive_storage_migration=allow_archive_storage_migration
    )
    _require_one(plan, "digitalocean_reserved_ip", errors)
    _require_one(plan, "digitalocean_reserved_ip_assignment", errors)
    if errors:
        detail = "\n".join(f"- {error}" for error in errors)
        raise PlanPolicyError(f"OpenTofu plan violates infrastructure policy:\n{detail}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan_json", type=Path, help="path produced by `tofu show -json`")
    parser.add_argument(
        "--allow-droplet-replacement",
        action="store_true",
        help="allow only the explicit Droplet rebuild and its required attachment changes",
    )
    parser.add_argument(
        "--public-edge-transition",
        choices=("direct", "proxied", "enforced"),
        help="allow only one explicit fail-safe public-edge phase transition",
    )
    parser.add_argument(
        "--allow-archive-storage-migration",
        action="store_true",
        help="allow only the one-time isolated archive storage migration",
    )
    return parser.parse_args()


def main() -> int:
    """Validate the requested JSON plan and return a shell-compatible status."""
    args = _parse_args()
    try:
        plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
        assert_plan(
            plan,
            allow_droplet_replacement=args.allow_droplet_replacement,
            allow_archive_storage_migration=args.allow_archive_storage_migration,
            public_edge_transition=args.public_edge_transition,
        )
    except (OSError, json.JSONDecodeError, PlanPolicyError) as error:
        print(error)
        return 1
    print("OpenTofu plan satisfies the production infrastructure policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
