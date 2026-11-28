"""Cross-check independent production observations before canary enrollment.

This is not a credential reader, target writer, or live-preflight receipt
producer. Collection, candidate review, and action admission remain separate.
"""

from __future__ import annotations

from hashlib import sha256
from typing import TYPE_CHECKING

from scripts.m3_12_contracts import CANARY_DROPLET, CANARY_PROJECT_SHA, digest, instant, require

if TYPE_CHECKING:
    from scripts.m3_12_contracts import Document

DROPLET = "module.host.digitalocean_droplet.host"
FIREWALL = "module.host.digitalocean_firewall.host"
RESERVED = "module.host.digitalocean_reserved_ip.host"
ASSIGNMENT = "module.host.digitalocean_reserved_ip_assignment.host"
BACKUP = "module.storage.digitalocean_spaces_bucket.backups"
ARCHIVE = "module.tenant_archives.digitalocean_spaces_bucket.archives"
PROVIDER_READS = frozenset(
    {"account", "project", "membership", "host", "address", "attachedFirewall"}
)
PROJECT_BINDINGS = (
    "digitalocean_project_resources.host",
    "digitalocean_project_resources.production",
)


def observe_scope(  # noqa: PLR0913 - independently supplied scope observations
    provider_before: Document,
    guest: Document,
    state: Document,
    provider_after: Document,
    *,
    guest_observed_at: str,
    ssh_pin_sha256: str,
    backup_binding: Document,
    archive_binding: Document,
) -> Document:
    """Bind provider, decrypted state, and strictly pinned guest observations.

    Inputs must come from the actual independent readers for this invocation.
    Nothing here asserts firewall policy, restore, or launch readiness.
    """
    before = {key: value for key, value in provider_before.items() if key != "observedAt"}
    after = {key: value for key, value in provider_after.items() if key != "observedAt"}
    require(
        before == after
        and instant(provider_before["observedAt"])
        < instant(guest_observed_at)
        < instant(provider_after["observedAt"]),
        "canary-inventory-provider-changed",
    )
    require(
        after["reads"] == dict.fromkeys(PROVIDER_READS, "verified-http-200"),
        "canary-inventory-provider-incomplete",
    )
    project, droplet = after["project"], after["droplet"]
    reserved, membership = after["reservedAddress"], after["membership"]
    project_id = project["id"]
    bindings = state["bindings"]
    require(
        sha256(project_id.encode("ascii")).hexdigest() == CANARY_PROJECT_SHA
        and project["environment"] == "Production"
        and droplet["id"] == CANARY_DROPLET
        and droplet["status"] == "active"
        and membership["droplets"] == [f"do:droplet:{CANARY_DROPLET}"]
        and membership["allSettled"] is True
        and membership["configuredBackupMember"] is True
        and membership["configuredArchiveMember"] is True,
        "canary-inventory-provider-scope",
    )
    address = reserved["address"]
    require(
        all(bindings[key] == {"project": project_id} for key in PROJECT_BINDINGS)
        and bindings[DROPLET] == {"id": str(CANARY_DROPLET)}
        and reserved["attachedDropletId"] == CANARY_DROPLET
        and bindings[RESERVED] == {"ip_address": address}
        and bindings[ASSIGNMENT] == {"droplet_id": str(CANARY_DROPLET), "ip_address": address}
        and state["edgeRolloutPhase"] == "enforced",
        "canary-inventory-state-scope",
    )
    firewalls = after["attachedFirewalls"]
    require(
        len(firewalls) == 1
        and firewalls[0]["settled"] is True
        and firewalls[0]["attachedIds"] == [CANARY_DROPLET]
        and bindings[FIREWALL] == {"id": firewalls[0]["id"]},
        "canary-inventory-firewall-scope",
    )
    require(
        bindings[BACKUP] == backup_binding
        and bindings[ARCHIVE] == archive_binding
        and bindings[BACKUP] != bindings[ARCHIVE],
        "canary-inventory-storage-scope",
    )
    require(
        guest["metadata"]["dropletId"] == CANARY_DROPLET
        and guest["metadata"]["ipv4"] in droplet["ipv4"]
        and guest["hostIdentity"]["hostKeySha256"] == ssh_pin_sha256,
        "canary-inventory-guest-scope",
    )
    return {
        "format": "lowerduckpond-m3-12-canary-inventory-observation-v1",
        "providerIdentitySha256": digest(after),
        "metadataIdentitySha256": digest(guest["metadata"]),
        "stateSha256": digest(state),
        "addressSetSha256": digest(sorted({address, *droplet["ipv4"]})),
        "hostIdentity": guest["hostIdentity"],
    }
