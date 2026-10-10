"""Explicit monthly authority rotation and positive per-child cleanup handover."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.inventory import Inventory
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle
from scripts.m3_11_unattended.model import LeaseManifest, LifecycleError, digest, stamp
from scripts.m3_11_unattended.state import LeaseState

FORMAT = "lowerduckpond-m3-11-generation-handover-v1"


def handover(
    previous: LeaseConfiguration,
    replacement: LeaseConfiguration,
    inventory: Inventory,
    *,
    root: Path,
) -> dict[str, object]:
    now = datetime.now(UTC)
    replacement.require_issuance(now=now)
    if (
        previous.targets != replacement.targets
        or previous.journal_vault != replacement.journal_vault
        or previous.independent_server_id != replacement.independent_server_id
        or previous.migration_sha256 != replacement.migration_sha256
        or previous.active_generation == replacement.active_generation
    ):
        raise LifecycleError("authority rotation changed the logical authority or import")
    if not previous.generations.keys() <= replacement.generations.keys():
        raise LifecycleError("staged rotation must retain original cleanup access")
    for key, roles in previous.generations.items():
        if replacement.generations[key]["cleanup"] != roles["cleanup"]:
            raise LifecycleError("staged rotation changed original cleanup access")
    old = previous.generations[previous.active_generation]["cleanup"]
    new = replacement.generations[replacement.active_generation]["cleanup"]
    new.generation.require_same_principal(old.generation)
    if new.generation.introduced_at <= old.generation.introduced_at:
        raise LifecycleError("replacement generation is not newer than the original")
    clients = new.providers(targets=replacement.targets, now=now)
    records = inventory.records()
    results = []
    for row in records:
        if row["slot"] != "manifest":
            continue
        manifest = LeaseManifest.parse(row["payload"])
        if any(
            item["lease_id"] == manifest.lease_id and item["slot"] == "closed" for item in records
        ):
            continue
        lifecycle = LeaseLifecycle(
            manifest, inventory, LeaseState(root / manifest.lease_id), providers={}
        )
        observed = lifecycle.records()
        generations = {
            lifecycle.cleanup_generation(intent, observed).generation_id
            for intent in manifest.intents
        }
        if len(generations) != 1:
            # A partial prior handover is retried with its original client map.
            generations.discard(replacement.active_generation)
        if len(generations) > 1:
            raise LifecycleError(
                "handover has multiple original generations requiring reconciliation"
            )
        generation = next(iter(generations), replacement.active_generation)
        try:
            original = previous.generations[generation]["cleanup"]
            lifecycle.handover(
                new.generation, clients, original.providers(targets=previous.targets, now=now)
            )
            status = "transferred"
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            status = "retained-original"
        current = lifecycle.records()
        needed = {
            lifecycle.cleanup_generation(intent, current).generation_id
            for intent in manifest.intents
        }
        if not needed <= replacement.generations.keys():
            raise LifecycleError("replacement removed the only cleanup access for an obligation")
        results.append({"lease_id": manifest.lease_id, "status": status})
    return {
        "format": FORMAT,
        "previous_sha256": digest(previous.document()),
        "replacement_sha256": digest(replacement.document()),
        "observed_at": stamp(now),
        "results": results,
    }
