"""Read and verify terminal lease facts without cleanup or child credentials.

Closed facts are immutable historical proof, not an active-credential freshness
window. A failed qualification remains failed/unresolved. Neither missing secret
files nor a compact independent ``closed`` row establishes terminal cleanup.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.inventory import ConnectInventoryReader, _collect
from scripts.m3_11_unattended.model import ROLES, LeaseManifest, LifecycleError, instant, stamp
from scripts.m3_11_unattended.state import LeaseState

FORMAT = "lowerduckpond-m3-11-terminal-facts-v1"


def terminal_facts(
    records: object,
    manifest: LeaseManifest,
    *,
    issuer: object,
    created: dict[str, object],
) -> list[dict[str, object]]:
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise LifecycleError("terminal lease inventory is unavailable")
    # Validate the whole authenticated inventory, including foreign leases and
    # duplicate/conflicting immutable facts, before selecting this lease.
    collected = _collect(cast(list[dict[str, object]], records))
    selected = [row for row in collected if row["lease_id"] == manifest.lease_id]
    if any(row["manifest_sha256"] != manifest.sha256 for row in selected):
        raise LifecycleError("terminal lease manifest binding differs")
    facts = {str(row["slot"]): row["payload"] for row in selected}
    stopped = fields(issuer, {"writer_sha256", "stopped_at", "retained_roles"})
    if (
        facts.get("manifest") != manifest.document()
        or facts.get("issuer-stopped") != stopped
        or stopped["retained_roles"] != sorted(ROLES)
        or set(created) != ROLES
        or instant(stopped["stopped_at"]) < instant(manifest.created_at)
        or instant(stopped["stopped_at"]) > datetime.now(UTC)
    ):
        raise LifecycleError("terminal lease lacks its original complete issuer proof")
    results = []
    for intent in manifest.intents:
        original = fields(created[intent.role], {"intent_sha256", "credential_id"})
        if (
            original["intent_sha256"] != intent.sha256
            or "not-submitted:" + intent.role in facts
            or any(
                facts.get(kind + ":" + intent.role) != original
                for kind in ("created", "removed", "denied")
            )
        ):
            raise LifecycleError("terminal lease lacks exact creation/removal/denial identities")
        results.append(
            {
                "intent_sha256": intent.sha256,
                "status": "verified",
                "negative_authentication": "denied",
            }
        )
    closed = fields(facts.get("closed"), {"results"})
    rows = closed["results"]
    if not isinstance(rows, list) or sorted(rows, key=digest) != sorted(results, key=digest):
        raise LifecycleError("terminal lease closure lacks all seven authenticated denials")
    return selected


def retained(lease: LeaseState, records: object) -> dict[str, object]:
    """Read only durable non-secret original metadata; never open credentials."""
    manifest = lease.manifest()
    if not isinstance(records, list):
        raise LifecycleError("terminal lease inventory is unavailable")
    candidates = [
        row["payload"]
        for row in _collect(records)
        if row["lease_id"] == manifest.lease_id and row["slot"] == "issuer-stopped"
    ]
    if len(candidates) != 1:
        raise LifecycleError("terminal lease original issuer proof is unavailable")
    issuer = lease.issuer_stop(published=candidates[0])
    created: dict[str, object] = {intent.role: lease.created(intent) for intent in manifest.intents}
    selected = terminal_facts(records, manifest, issuer=issuer, created=created)
    return {
        "manifest": manifest.document(),
        "issuer": issuer,
        "created": created,
        "facts": selected,
    }


def snapshot(config: LeaseConfiguration, lease: LeaseState) -> dict[str, object]:
    """Concrete authenticated GET-only capture, called under runtime-use lock.

    Reader construction authenticates exact native/signed grants and forbidden
    vault denial. It has no publication spool, provider factories, or cleanup
    lifecycle. Preserve the complete returned inventory, not just its projection.
    """
    manifest = lease.manifest()
    if (
        config.targets != manifest.targets
        or config.approved_policy_sha256 != manifest.policy.sha256
    ):
        raise LifecycleError("terminal reader escaped the retained lease scope")
    bootstrap = config.generations[config.active_generation]["cleanup"]
    started = stamp(datetime.now(UTC))
    client = bootstrap.reader()
    inventory = ConnectInventoryReader(client, config.journal_vault).records()
    return {
        "format": FORMAT,
        "started_at": started,
        "observed_at": stamp(datetime.now(UTC)),
        "generation": bootstrap.generation.document(),
        "reader_policy_sha256": digest(bootstrap.reader_settings),
        "journal_vault_sha256": digest(config.journal_vault),
        "authentication": "native-and-signed-policy-and-forbidden-vaults-verified",
        "inventory": inventory,
        "original": retained(lease, inventory),
    }


def consistent(before: object, after: object, lease: LeaseState) -> dict[str, object]:
    """Validate two authenticated captures surrounding independent artifact read.

    Transport provenance is separately bound by the collector and the exact
    approved file digests. This validator alone does not authenticate arbitrary
    JSON and must never be exposed as an approval/authority shortcut.
    """
    names = {
        "format",
        "started_at",
        "observed_at",
        "generation",
        "reader_policy_sha256",
        "journal_vault_sha256",
        "authentication",
        "inventory",
        "original",
    }
    first, last = fields(before, names), fields(after, names)
    for value in (first, last):
        if (
            value["format"] != FORMAT
            or value["authentication"] != "native-and-signed-policy-and-forbidden-vaults-verified"
            or not instant(value["started_at"])
            <= instant(value["observed_at"])
            <= datetime.now(UTC)
            or value["original"] != retained(lease, value["inventory"])
        ):
            raise LifecycleError("terminal lease capture binding differs")
    invariant = names - {"started_at", "observed_at", "inventory"}
    if any(first[key] != last[key] for key in invariant) or instant(first["observed_at"]) > instant(
        last["started_at"]
    ):
        raise LifecycleError("terminal lease facts changed across independent verification")
    return cast(dict[str, object], first["original"])
