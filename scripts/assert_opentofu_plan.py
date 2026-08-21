#!/usr/bin/env python3
"""Enforce the Milestone 1 safety contract over an OpenTofu JSON plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

EXPECTED_TAGS = {
    "environment:production",
    "managed-by:opentofu",
    "project:lowerduckpond",
}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
DURABLE_TYPES = {"digitalocean_reserved_ip", "digitalocean_spaces_bucket"}
EXPECTED_DNS_RECORD_COUNT = 2
REBUILD_DRILL_ACTIONS = {
    "module.host.digitalocean_droplet.host": ("create", "delete"),
    "module.host.digitalocean_reserved_ip_assignment.host": ("delete", "create"),
    "module.host.digitalocean_firewall.host": ("update",),
    "digitalocean_project_resources.production": ("update",),
}
NON_MUTATING_ACTIONS = {("no-op",), ("read",)}


class PlanPolicyError(RuntimeError):
    """Raised when a plan violates one or more infrastructure policies."""


def _changes_by_type(plan: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in plan.get("resource_changes", [])
        if resource.get("type") == resource_type
    ]


def _after(resource: dict[str, Any]) -> dict[str, Any]:
    value = resource.get("change", {}).get("after")
    return value if isinstance(value, dict) else {}


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

    missing_changes = REBUILD_DRILL_ACTIONS.keys() - observed_changes
    errors.extend(
        f"{address} must change during the rebuild drill" for address in sorted(missing_changes)
    )


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


def _check_firewall(plan: dict[str, Any], errors: list[str]) -> None:
    resource = _require_one(plan, "digitalocean_firewall", errors)
    if resource is None:
        return
    rules = _after(resource).get("inbound_rule") or []
    seen_ports: set[str] = set()
    for rule in rules:
        protocol = rule.get("protocol")
        port = str(rule.get("port_range", ""))
        sources = set(rule.get("source_addresses") or [])
        if protocol != "tcp" or port not in {"22", "80", "443"}:
            errors.append(f"unexpected public inbound firewall rule: {protocol}/{port}")
            continue
        seen_ports.add(port)
        if port == "22" and (not sources or sources & WORLD_CIDRS):
            errors.append("SSH must use a non-empty explicit source allowlist")
        if port in {"80", "443"} and not WORLD_CIDRS.issubset(sources):
            errors.append(f"TCP {port} must be reachable over IPv4 and IPv6")
    if seen_ports != {"22", "80", "443"}:
        errors.append(f"firewall inbound ports must be exactly 22, 80, and 443; found {seen_ports}")


def _check_spaces(plan: dict[str, Any], errors: list[str]) -> None:
    if _changes_by_type(plan, "digitalocean_spaces_bucket_policy"):
        errors.append("Spaces bucket policies are incompatible with bucket-scoped access keys")

    bucket = _require_one(plan, "digitalocean_spaces_bucket", errors)
    if bucket is not None:
        after = _after(bucket)
        if after.get("acl") != "private":
            errors.append("Spaces bucket ACL must be private")
        if after.get("force_destroy") is not False:
            errors.append("Spaces bucket force_destroy must be false")
        versioning = after.get("versioning") or []
        if not versioning or versioning[0].get("enabled") is not True:
            errors.append("Spaces bucket versioning must be enabled")
        prefixes = {rule.get("prefix") for rule in after.get("lifecycle_rule") or []}
        if not {"backups/", "archives/"}.issubset(prefixes):
            errors.append("Spaces lifecycle rules must cover backups/ and archives/")

    key = _require_one(plan, "digitalocean_spaces_key", errors)
    if key is not None:
        grants = _after(key).get("grant") or []
        if len(grants) != 1:
            errors.append("runtime Spaces key must have exactly one bucket grant")
        elif grants[0].get("permission") != "readwrite" or not grants[0].get("bucket"):
            errors.append("runtime Spaces key must have bucket-scoped readwrite access")


def _check_dns(plan: dict[str, Any], errors: list[str]) -> None:
    records = _changes_by_type(plan, "cloudflare_dns_record")
    if len(records) != EXPECTED_DNS_RECORD_COUNT:
        errors.append(f"expected apex and wildcard DNS records, found {len(records)}")
        return
    names = set()
    for resource in records:
        after = _after(resource)
        names.add(after.get("name"))
        if after.get("type") != "A" or after.get("proxied") is not False:
            errors.append(f"{resource.get('address')} must be an unproxied A record")
    if "lowerduckpond.net" not in names or "*.lowerduckpond.net" not in names:
        errors.append("DNS records must include lowerduckpond.net and *.lowerduckpond.net")


def assert_plan(plan: dict[str, Any], *, allow_droplet_replacement: bool = False) -> None:
    """Raise PlanPolicyError when a production plan violates policy."""
    errors: list[str] = []
    _check_destructive_actions(plan, errors, allow_droplet_replacement=allow_droplet_replacement)
    if allow_droplet_replacement:
        _check_rebuild_drill_actions(plan, errors)
    _check_droplet(plan, errors)
    _check_firewall(plan, errors)
    _check_spaces(plan, errors)
    _check_dns(plan, errors)
    _require_one(plan, "digitalocean_reserved_ip", errors)
    _require_one(plan, "digitalocean_reserved_ip_assignment", errors)
    _require_one(plan, "digitalocean_project_resources", errors)
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
    return parser.parse_args()


def main() -> int:
    """Validate the requested JSON plan and return a shell-compatible status."""
    args = _parse_args()
    try:
        plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
        assert_plan(plan, allow_droplet_replacement=args.allow_droplet_replacement)
    except (OSError, json.JSONDecodeError, PlanPolicyError) as error:
        print(error)
        return 1
    print("OpenTofu plan satisfies the Milestone 1 infrastructure policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
