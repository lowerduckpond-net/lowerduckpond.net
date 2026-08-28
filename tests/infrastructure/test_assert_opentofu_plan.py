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
                    "urn": "do:droplet:42",
                    "tags": [
                        "environment:production",
                        "managed-by:opentofu",
                        "project:lowerduckpond",
                    ],
                },
                address="module.host.digitalocean_droplet.host",
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
                    "name": "example-backups",
                    "urn": "do:space:example-backups",
                    "versioning": [{"enabled": True}],
                    "lifecycle_rule": [
                        {
                            "id": "backups-retention",
                            "prefix": "backups/",
                            "enabled": True,
                            "abort_incomplete_multipart_upload_days": 7,
                            "expiration": [],
                            "noncurrent_version_expiration": [{"days": 30}],
                        },
                    ],
                },
                address="module.storage.digitalocean_spaces_bucket.backups",
            ),
            _resource(
                "digitalocean_spaces_key",
                "runtime",
                {"grant": [{"bucket": "example-backups", "permission": "readwrite"}]},
                address="module.storage.digitalocean_spaces_key.runtime",
            ),
            _resource(
                "digitalocean_spaces_bucket",
                "archives",
                {
                    "acl": "private",
                    "force_destroy": False,
                    "name": "example-tenant-archives",
                    "urn": "do:space:example-tenant-archives",
                    "versioning": [{"enabled": True}],
                    "lifecycle_rule": [],
                },
                address="module.tenant_archives.digitalocean_spaces_bucket.archives",
            ),
            _resource(
                "digitalocean_spaces_key",
                "runtime",
                {"grant": [{"bucket": "example-tenant-archives", "permission": "readwrite"}]},
                address="module.tenant_archives.digitalocean_spaces_key.runtime",
            ),
            _resource(
                "digitalocean_reserved_ip",
                "host",
                {"urn": "do:reservedip:203.0.113.10"},
                address="module.host.digitalocean_reserved_ip.host",
            ),
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
                        "do:reservedip:203.0.113.10",
                        "do:space:example-backups",
                        "do:space:example-tenant-archives",
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
                        "depends_on": ["module.tenant_archives"],
                        "expressions": {
                            "project": {"references": ["var.digitalocean_project_id"]},
                            "resources": {
                                "references": [
                                    "module.host.reserved_ip_urn",
                                    "module.host",
                                    "module.storage.bucket_urn",
                                    "module.storage",
                                    "module.tenant_archives.bucket_urn",
                                    "module.tenant_archives",
                                ]
                            },
                        },
                    },
                    {
                        "address": "digitalocean_project_resources.host",
                        "depends_on": ["digitalocean_project_resources.production"],
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


def _valid_archive_storage_migration_plan() -> dict[str, Any]:
    plan = deepcopy(_valid_plan())
    for resource in plan["resource_changes"]:
        resource["change"]["before"] = deepcopy(resource["change"]["after"])
        resource["change"]["after_unknown"] = {}
        resource["change"]["actions"] = ["no-op"]

    backup = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.storage.digitalocean_spaces_bucket.backups"
    )
    backup_rule = deepcopy(backup["change"]["after"]["lifecycle_rule"][0])
    archive_rule = {
        "id": "archives-retention",
        "prefix": "archives/",
        "enabled": True,
        "abort_incomplete_multipart_upload_days": 7,
        "expiration": [{"days": 180}],
        "noncurrent_version_expiration": [{"days": 30}],
    }
    backup["change"]["before"]["lifecycle_rule"] = [archive_rule, backup_rule]
    backup["change"]["actions"] = ["update"]

    for address in (
        "module.tenant_archives.digitalocean_spaces_bucket.archives",
        "module.tenant_archives.digitalocean_spaces_key.runtime",
    ):
        resource = next(item for item in plan["resource_changes"] if item["address"] == address)
        resource["change"]["before"] = None
        resource["change"]["actions"] = ["create"]

    archive_bucket = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.tenant_archives.digitalocean_spaces_bucket.archives"
    )
    archive_bucket["change"]["after"]["urn"] = None
    archive_bucket["change"]["after_unknown"] = {"urn": True}

    project = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    project["change"]["before"]["resources"] = [
        "do:reservedip:203.0.113.10",
        "do:space:example-backups",
    ]
    project["change"]["after"]["resources"][-1] = "do:space:example-tenant-archives"
    project["change"]["after_unknown"] = {}
    project["change"]["actions"] = ["update"]
    return plan


def test_accepts_expected_foundation() -> None:
    assert_plan(_valid_plan())


def test_allows_exact_archive_storage_migration() -> None:
    assert_plan(_valid_archive_storage_migration_plan(), allow_archive_storage_migration=True)


@pytest.mark.parametrize(
    ("after_members", "after_unknown"),
    [
        (None, True),
        (None, [False, False, True]),
        (["do:reservedip:203.0.113.10", "do:space:example-backups"], True),
    ],
)
def test_rejects_wholly_unknown_or_inconsistent_project_membership_shapes(
    after_members: object, after_unknown: object
) -> None:
    plan = _valid_archive_storage_migration_plan()
    project = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    project["change"]["after"]["resources"] = after_members
    project["change"]["after_unknown"]["resources"] = after_unknown

    with pytest.raises(PlanPolicyError, match="adding only the exact archive bucket URN"):
        assert_plan(plan, allow_archive_storage_migration=True)


def test_rejects_an_incorrect_synthesized_archive_project_member() -> None:
    plan = _valid_archive_storage_migration_plan()
    project = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    project["change"]["after"]["resources"][-1] = "do:space:wrong-archive"

    with pytest.raises(PlanPolicyError, match="adding only the exact archive bucket URN"):
        assert_plan(plan, allow_archive_storage_migration=True)


def test_rejects_archive_storage_migration_without_explicit_mode() -> None:
    with pytest.raises(PlanPolicyError, match="requires --allow-archive-storage-migration"):
        assert_plan(_valid_archive_storage_migration_plan())


def test_rejects_archive_storage_migration_with_unrelated_change() -> None:
    plan = _valid_archive_storage_migration_plan()
    dns = next(
        resource
        for resource in plan["resource_changes"]
        if resource["type"] == "cloudflare_dns_record"
    )
    dns["change"]["actions"] = ["update"]
    dns["change"]["before"]["proxied"] = True

    with pytest.raises(PlanPolicyError, match="unrelated archive-storage migration actions"):
        assert_plan(plan, allow_archive_storage_migration=True)


def test_rejects_archive_storage_migration_that_changes_backup_retention() -> None:
    plan = _valid_archive_storage_migration_plan()
    backup = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.storage.digitalocean_spaces_bucket.backups"
    )
    backup["change"]["after"]["lifecycle_rule"][0]["abort_incomplete_multipart_upload_days"] = 8

    with pytest.raises(PlanPolicyError, match="must not alter backups-retention"):
        assert_plan(plan, allow_archive_storage_migration=True)


def test_rejects_archive_bucket_lifecycle_rule() -> None:
    plan = _valid_plan()
    archives = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.tenant_archives.digitalocean_spaces_bucket.archives"
    )
    archives["change"]["after"]["lifecycle_rule"] = [
        {
            "id": "unsafe-expiration",
            "prefix": "archives/",
            "enabled": True,
            "expiration": [{"days": 3650}],
        }
    ]

    with pytest.raises(PlanPolicyError, match="must not have lifecycle rules"):
        assert_plan(plan)


def test_rejects_archive_key_grant_to_backup_bucket() -> None:
    plan = _valid_plan()
    archive_key = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "module.tenant_archives.digitalocean_spaces_key.runtime"
    )
    archive_key["change"]["after"]["grant"][0]["bucket"] = "example-backups"

    with pytest.raises(PlanPolicyError, match="readwrite access only to its own bucket"):
        assert_plan(plan)


def test_rejects_durable_project_membership_that_does_not_match_resources() -> None:
    plan = _valid_plan()
    durable = next(
        resource
        for resource in plan["resource_changes"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    durable["change"]["after"]["resources"][0] = "do:reservedip:203.0.113.99"

    with pytest.raises(PlanPolicyError, match="must exactly match the planned reserved IP"):
        assert_plan(plan)


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
    durable["change"]["after"]["resources"] = ["do:reservedip:203.0.113.10"]

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


def test_rejects_missing_archive_project_creation_dependency() -> None:
    plan = _valid_archive_storage_migration_plan()
    durable_configuration = next(
        resource
        for resource in plan["configuration"]["root_module"]["resources"]
        if resource["address"] == "digitalocean_project_resources.production"
    )
    durable_configuration["depends_on"] = []

    with pytest.raises(PlanPolicyError, match="must retain its exact creation dependencies"):
        assert_plan(plan, allow_archive_storage_migration=True)


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
