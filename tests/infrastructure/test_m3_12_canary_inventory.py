"""Test reconciliation of three independent canary inventory views."""

from copy import deepcopy

import pytest

from scripts import m3_12_canary_inventory as scope
from scripts.m3_12_contracts import CANARY_DROPLET, Document, ValidationError, digest

from .test_m3_12_contracts import fixture_time, proof

PROJECT = "2d1c1a69-d3dd-4eca-bb3f-cea6a9d7f158"
PUBLIC = "192.0.2.3"
RESERVED = "192.0.2.4"


@pytest.mark.parametrize(
    ("fault", "error"),
    [
        ("none", None),
        ("racing", "provider-changed"),
        ("stale", "provider-changed"),
        ("incomplete", "provider-incomplete"),
        ("membership", "provider-scope"),
        ("state-ip", "state-scope"),
        ("firewall", "firewall-scope"),
        ("bucket", "storage-scope"),
        ("pin", "guest-scope"),
        ("metadata", "guest-scope"),
    ],
)
def test_canary_inventory_agrees_across_readers(fault: str, error: str | None) -> None:
    backup = {"name": "fixture-backups", "region": "nyc3"}
    archive = {"name": "fixture-archives", "region": "nyc3"}
    provider: Document = {
        "observedAt": fixture_time(1),
        "reads": dict.fromkeys(scope.PROVIDER_READS, "verified-http-200"),
        "project": {"id": PROJECT, "environment": "Production"},
        "droplet": {"id": CANARY_DROPLET, "status": "active", "ipv4": [PUBLIC, RESERVED]},
        "reservedAddress": {"address": RESERVED, "attachedDropletId": CANARY_DROPLET},
        "attachedFirewalls": [
            {"id": "fixture-firewall", "settled": True, "attachedIds": [CANARY_DROPLET]}
        ],
        "membership": {
            "droplets": [f"do:droplet:{CANARY_DROPLET}"],
            "allSettled": True,
            "configuredBackupMember": fault != "membership",
            "configuredArchiveMember": True,
        },
    }
    if fault == "incomplete":
        provider["reads"]["account"] = "read-failed"
    after = deepcopy(provider)
    after["observedAt"] = fixture_time(1 if fault == "stale" else 3)
    if fault == "racing":
        after["membership"]["allSettled"] = False
    guest = {
        "metadata": {
            "dropletId": CANARY_DROPLET,
            "ipv4": "192.0.2.99" if fault == "metadata" else PUBLIC,
        },
        "hostIdentity": {"hostKeySha256": proof("other" if fault == "pin" else "pin")},
    }
    state = {
        "edgeRolloutPhase": "enforced",
        "bindings": {
            **{key: {"project": PROJECT} for key in scope.PROJECT_BINDINGS},
            scope.DROPLET: {"id": str(CANARY_DROPLET)},
            scope.RESERVED: {"ip_address": PUBLIC if fault == "state-ip" else RESERVED},
            scope.ASSIGNMENT: {"droplet_id": str(CANARY_DROPLET), "ip_address": RESERVED},
            scope.FIREWALL: {"id": "other" if fault == "firewall" else "fixture-firewall"},
            scope.BACKUP: archive if fault == "bucket" else backup,
            scope.ARCHIVE: archive,
        },
    }

    def check() -> dict[str, object]:
        return scope.observe_scope(
            provider,
            guest,
            state,
            after,
            guest_observed_at=fixture_time(2),
            ssh_pin_sha256=proof("pin"),
            backup_binding=backup,
            archive_binding=archive,
        )

    if error:
        with pytest.raises(ValidationError, match="canary-inventory-" + error):
            check()
        return
    result = check()
    assert result["stateSha256"] == digest(state)
    assert result["hostIdentity"] == guest["hostIdentity"]
    assert result["addressSetSha256"] == digest([PUBLIC, RESERVED])
