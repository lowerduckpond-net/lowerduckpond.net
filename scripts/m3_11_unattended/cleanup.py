"""Independent repeated revocation; this entry point cannot retire any run data."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import audit_policy_recovery, historical_absence
from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.config import LeaseConfiguration, UnavailableProvider
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.inventory import ConnectInventory, Inventory, fact
from scripts.m3_11_unattended.journal import ConnectObligations, event
from scripts.m3_11_unattended.legacy_terminal import restored as legacy_restored
from scripts.m3_11_unattended.legacy_terminal import terminal
from scripts.m3_11_unattended.lifecycle import (
    LeaseLifecycle,
    Lifecycle,
    Provider,
    intents,
)
from scripts.m3_11_unattended.model import (
    Credential,
    LeaseManifest,
    LifecycleError,
    ProviderKind,
    identity,
    instant,
    stamp,
    strings,
)
from scripts.m3_11_unattended.state import CleanupLockBusyError, LeaseState, cleanup_lock
from scripts.production_qualification_inputs import revision

HEARTBEAT_MAX_AGE = timedelta(minutes=90)
POLL_SECONDS = 60
REMOTE_SECONDS = 3600
RETRY_SECONDS = 300


def sweep(  # noqa: PLR0913 - independent restoration never suppresses child obligations
    lifecycle: Lifecycle,
    *,
    actor: str,
    helper: str,
    secrets: dict[str, Credential] | None = None,
    authority_verified: bool = True,
    recovery_verified: bool = True,
    arm_policy_restore: Callable[[datetime], None] | None = None,
    force_policy_restore: bool = False,
    before_receipt: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    if actor not in {"controller", "watchdog", "github"}:
        raise LifecycleError("unknown cleanup actor")
    # Restoration is separate from child revocation: failure must not prevent
    # any ordinary credential from being deleted and independently verified.
    try:
        policy_status = audit_policy_recovery.reconcile(
            lifecycle.journal,
            lifecycle.providers.get("cloudflare-account"),
            now=datetime.now(UTC),
            arm_restore=arm_policy_restore,
            force_restore=force_policy_restore,
        )
    except RuntimeError, OSError, ValueError, TypeError, KeyError:
        policy_status = "restoration-unresolved"
    if policy_status == "policy-metadata-verified" and (
        not authority_verified or (actor == "github" and arm_policy_restore is None)
    ):
        # Fallback deletion can proceed with a still-active short-lived token;
        # it must not authorize a future permission grant beyond its authority.
        policy_status = "restoration-unresolved"
    policy_observed_at = datetime.now(UTC)
    try:
        audit_policy_recovery.observation(
            lifecycle.journal,
            status=policy_status,
            actor=actor,
            helper=helper,
            now=policy_observed_at,
        )
    except RuntimeError, OSError, ValueError, TypeError, KeyError:
        policy_status = "restoration-unresolved"
    observed = lifecycle.sweep(secrets)
    by_digest = {value.intent_sha256: value for value in observed}
    now = datetime.now(UTC)
    overdue = sum(
        instant(intent.deadline) < now
        and not historical_absence.admits(intent.sha256, by_digest[intent.sha256].status)
        for intent in intents(lifecycle.journal)
    )
    healthy = True
    for provider in lifecycle.providers.values():
        try:
            provider.inventory()
        except RuntimeError, OSError, ValueError:
            healthy = False
    status = (
        "ready"
        if authority_verified
        and recovery_verified
        and policy_status in {"no-obligation", "original-policy-verified"}
        and healthy
        and all(
            value.status == "not-due"
            or historical_absence.admits(value.intent_sha256, value.status)
            for value in observed
        )
        else "unresolved"
    )
    receipt: dict[str, object] = {
        "actor": actor,
        "helper_revision": revision(helper),
        "observed_at": stamp(now),
        "status": status,
        "overdue": overdue,
        "results": [dataclasses.asdict(value) for value in observed],
    }
    if before_receipt is not None:
        # Provider, restoration, authority and independent checkpoint checks are
        # complete. Publishing their informational heartbeat can be slow; let
        # the witness service admission first, never mid-sweep. A new reservation
        # still performs its full fresh capacity, authority and clearance checks.
        before_receipt(receipt)
    prior = [
        record["payload"]
        for record in lifecycle.journal.records()
        if record["kind"] == "heartbeat"
        and isinstance(record["payload"], dict)
        and record["payload"].get("actor") == actor
    ]
    newest = max(prior, key=lambda value: str(value.get("observed_at"))) if prior else None
    # GitHub records every execution; the watchdog records at least hourly.
    # Controller retries keep local status timestamps and journal only changes.
    if (
        actor == "github"
        or newest is None
        or (
            actor == "watchdog"
            and now - instant(newest["observed_at"]) >= timedelta(seconds=REMOTE_SECONDS)
        )
        or any(
            newest.get(key) != receipt[key]
            for key in ("helper_revision", "status", "overdue", "results")
        )
    ):
        lifecycle.journal.append(event("heartbeat", str(uuid.uuid7()), receipt))
    return receipt


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--actor", choices=("watchdog",), required=True)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--runs", type=Path, required=True)
    return parser.parse_args()


def retained_legacy(  # noqa: PLR0912 - independent retained-file and rejection-proof checks
    journal: ConnectObligations,
) -> tuple[dict[str, Credential], bool]:
    """Use only hash-bound original local facts and secrets; absence remains unavailable."""
    from scripts.m3_11_unattended.legacy_actors import (  # noqa: PLC0415
        credential_intents,
        manual_credentials,
        manual_original,
    )
    from scripts.m3_11_unattended.worker import (  # noqa: PLC0415
        restore_created,
        retained_credentials,
    )

    if journal.mapping is None:
        raise LifecycleError("legacy mapping is unavailable")
    retained = strings(journal.mapping["retained_files"])
    runs: set[Path] = set()
    available: dict[str, Credential] = {}
    complete = True
    missing_secrets: set[str] = set()
    for filename, expected in retained.items():
        path = Path(filename)
        if path.parent.name not in {
            "credential-created",
            "credential-aborted",
            "credential-cleanup",
        }:
            continue
        if not path.exists() and not path.is_symlink():
            if path.parent.name == "credential-cleanup":
                missing_secrets.add(path.stem)
            continue  # Independent host loss cannot claim a negative probe passed.
        if hashlib.sha256(read_private_bytes(path)).hexdigest() != expected:
            complete = False
            continue
        runs.add(path.parent.parent)
    for directory in runs:
        try:
            # No unreviewed sibling can be imported by the original bounded readers.
            for kind in ("credential-created", "credential-aborted", "credential-cleanup"):
                for path in (directory / kind).glob("*.json"):
                    if (
                        str(path) not in retained
                        or hashlib.sha256(read_private_bytes(path)).hexdigest()
                        != retained[str(path)]
                    ):
                        raise LifecycleError("local legacy fact is outside the reviewed inventory")
            restore_created(Lifecycle(journal, {}), directory, run_id=identity(directory.name))
            for key, value in retained_credentials(directory).items():
                if key in available and available[key] != value:
                    raise LifecycleError("retained legacy secret identities conflict")
                available[key] = value
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            complete = False
    if missing_secrets:
        records = journal.records()
        owned = {intent.sha256: intent for intent in intents(journal)}
        for key in missing_secrets:
            proof = (
                terminal(owned[key], records, credential_expected=True) if key in owned else None
            )
            if proof is None or proof.negative_authentication != "denied":
                complete = False
    for filename in manual_credentials(journal.mapping):
        try:
            path = Path(filename)
            records = journal.records()
            intent = credential_intents(journal.mapping, records)[filename]
            if path.exists() or path.is_symlink():
                manual_original(path.parent, records, retained)
                raw = fields(read_private(path), {"identifier", "secret"})
                available[intent.sha256] = Credential(
                    str(raw["identifier"]), str(raw["secret"]), {}
                )
            else:
                proof = terminal(intent, records, credential_expected=True)
                if proof is None or proof.negative_authentication != "denied":
                    complete = False
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            complete = False
    return available, complete


def sweep_legacy(  # noqa: PLR0912, PLR0915 - retain independent legacy obligations
    config: LeaseConfiguration,
    client: Connect,
    *,
    root: Path,
    secrets: dict[str, Credential] | None = None,
) -> dict[str, object]:
    """Reconcile the reviewed legacy mapping without re-enabling its issuer."""
    from scripts.m3_11_unattended.cleanup_expiry import (  # noqa: PLC0415
        imported_update,
        readback_proof,
        reconcile_imported,
        terminal_update,
    )

    journal = ConnectObligations(
        client,
        config.journal_vault,
        spool=root / "legacy-pending",
        expected=config.migration_sha256,
    )
    records = journal.records()
    available, local_complete = retained_legacy(journal)
    for key, value in (secrets or {}).items():
        if key in available and available[key] != value:
            raise LifecycleError("legacy cleanup secret conflicts with the approved retained value")
        available[key] = value
    mapping = journal.mapping
    if mapping is None:
        raise LifecycleError("legacy import is unavailable")
    obligations = mapping["obligations"]
    if not isinstance(obligations, dict):
        raise LifecycleError("legacy obligation mapping is unavailable")
    from scripts.m3_11_unattended.legacy_actors import credential_intents  # noqa: PLC0415

    expected_secrets = {item.sha256 for item in credential_intents(mapping, records).values()}
    fenced_after = max(
        (instant(row["stopped_at"]) for row in cast(list[dict[str, object]], mapping["issuers"])),
        default=None,
    )
    now = datetime.now(UTC)
    providers: dict[str, dict[ProviderKind, Provider]] = {}

    def clients_for(generation: str) -> dict[ProviderKind, Provider]:
        if generation not in providers:
            bootstrap = config.generations.get(generation, {}).get("cleanup")
            providers[generation] = (
                bootstrap.providers(
                    targets=config.targets, now=now, reader=client, tolerate_unavailable=True
                )
                if bootstrap is not None
                else {}
            )
        return providers[generation]

    records = journal.records()  # Include restored local facts before deciding closure.
    outcomes = []
    for intent in intents(journal):
        if intent.targets != config.targets:
            raise LifecycleError("legacy obligation target differs")
        row = fields(
            obligations[intent.sha256],
            {"generation_id", "provider_id", "original_status"}
            | (
                {"cleanup_authority_sha256"}
                if mapping["format"] == "lowerduckpond-m3-11-legacy-import-v2"
                else set()
            ),
        )
        generation = row["generation_id"]
        retained = (
            config.generations.get(str(generation), {}).get("cleanup")
            if generation is not None
            else None
        )
        if retained is not None and (
            retained.generation.fingerprints[intent.provider] != intent.cleanup_authority_sha256
        ):
            raise LifecycleError("retained legacy generation differs from original authority")
        completed = terminal(
            intent,
            records,
            available.get(intent.sha256),
            credential_expected=intent.sha256 in expected_secrets,
        )
        if completed is not None:
            outcomes.append(dataclasses.asdict(completed))
            continue
        clients = clients_for(str(generation)) if generation is not None else {}
        selected = clients.get(intent.provider, UnavailableProvider(intent.provider))
        if selected.authority_sha256 != intent.cleanup_authority_sha256:
            outcomes.append(
                {
                    "intent_sha256": intent.sha256,
                    "status": "unresolved",
                    "negative_authentication": "unavailable",
                }
            )
            continue
        lifecycle = Lifecycle(journal, clients)
        # Migration preserves the original failed attempt and requests only its
        # outstanding credential cleanup; imported status never proves removal.
        lifecycle.request_revocation(intent.run_id)
        result = lifecycle.reconcile(intent, available.get(intent.sha256))
        if intent.sha256 in expected_secrets and result.negative_authentication != "denied":
            result = dataclasses.replace(result, status="unresolved")
        outcomes.append(dataclasses.asdict(result))
    restorations = []
    for record in audit_policy_recovery.plans(records):
        if legacy_restored(records, fenced_after=fenced_after, now=now):
            restorations.append("original-policy-verified")
            continue
        bound = next(
            (
                item
                for item in intents(journal)
                if item.run_id == record["run_id"] and item.role == "audit"
            ),
            None,
        )
        if bound is None:
            restorations.append("unresolved")
            continue
        generation = cast(dict[str, object], obligations[bound.sha256])["generation_id"]
        if generation is None:
            restorations.append("unresolved")
            continue
        try:
            restored = audit_policy_recovery.reconcile(
                journal,
                clients_for(str(generation)).get("cloudflare-account"),
                now=now,
                force_restore=True,
            )
            if restored == "original-policy-verified":
                audit_policy_recovery.observation(
                    journal,
                    status=restored,
                    actor="legacy-cleanup",
                    helper=config.helper_revision,
                    now=datetime.now(UTC),
                )
                restored = (
                    "original-policy-verified"
                    if legacy_restored(journal.records(), fenced_after=fenced_after)
                    else "unresolved"
                )
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            restored = "unresolved"
        restorations.append(restored)
    restoration = (
        "no-obligation"
        if not restorations
        else "original-policy-verified"
        if all(item == "original-policy-verified" for item in restorations)
        else "unresolved"
    )
    expiry = "verified"
    updates = mapping["expiry_updates"]
    if not isinstance(updates, list):
        raise LifecycleError("legacy expiry obligation mapping is unavailable")
    for raw in updates:
        row = imported_update(raw)
        if terminal_update(row, targets=config.targets, records=records):
            continue
        if row["generation_id"] is None:
            expiry = "unresolved"
            continue
        clients = clients_for(str(row["generation_id"]))
        cloudflare = {
            str(key): value for key, value in clients.items() if isinstance(value, Cloudflare)
        }
        try:
            reconcile_imported(
                row["plan"],
                targets=config.targets,
                expected=str(row["plan_sha256"]),
                providers=cloudflare,
            )
            journal.persist(event("heartbeat", str(row["generation_id"]), readback_proof(row)))
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            expiry = "unresolved"
    ready = (
        local_complete
        and restoration in {"no-obligation", "original-policy-verified"}
        and expiry == "verified"
        and all(historical_absence.admits(row["intent_sha256"], row["status"]) for row in outcomes)
    )
    return {
        "migration_sha256": config.migration_sha256,
        "status": "ready" if ready else "unresolved",
        "results": outcomes,
        "audit_restoration": restoration,
        "expiry_updates": expiry,
        "accepted_historical_uncertainty": [
            row["intent_sha256"] for row in outcomes if row["status"] == historical_absence.STATUS
        ],
    }


def sweep_leases(  # noqa: PLR0912, PLR0913, PLR0915 - independent cleanup and confirmation gates
    config: LeaseConfiguration,
    inventory: Inventory,
    *,
    root: Path,
    actor: str,
    confirmation: dict[str, object] | None = None,
    connect_client: Connect | None = None,
) -> dict[str, object]:
    """The same compact obligations serve terminal, watchdog and independent cleanup."""
    now = datetime.now(UTC)
    try:
        legacy_client = (
            connect_client or config.generations[config.active_generation]["cleanup"].reader()
        )
        legacy = sweep_legacy(config, legacy_client, root=root.parent)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        legacy = {"migration_sha256": config.migration_sha256, "status": "unresolved"}
    readable = True
    try:
        records = inventory.records()
    except RuntimeError, OSError, ValueError:
        records, readable = [], False
    manifests = {
        row["lease_id"]: LeaseManifest.parse(row["payload"])
        for row in records
        if row["slot"] == "manifest"
    }
    if any(row["lease_id"] not in manifests for row in records):
        readable = False
    closed_ids = {row["lease_id"] for row in records if row["slot"] == "closed"}
    if root.exists():
        for path in root.glob("*/manifest.json"):
            local = LeaseManifest.parse(read_private(path))
            if local.lease_id in manifests and manifests[local.lease_id] != local:
                raise LifecycleError("local lease manifest differs from the external inventory")
            manifests[local.lease_id] = local
    results = []
    for manifest in manifests.values():
        if manifest.targets != config.targets:
            raise LifecycleError("cleanup manifest differs from approved targets")
        own = {str(row["slot"]): row for row in records if row["lease_id"] == manifest.lease_id}
        if "closed" in own:
            results.append(
                {
                    "lease_id": manifest.lease_id,
                    "manifest_sha256": manifest.sha256,
                    "status": "closed",
                    "overdue": False,
                }
            )
            continue
        state = LeaseState(root / manifest.lease_id)
        active = config.generations[config.active_generation]["cleanup"].generation
        active.require_same_principal(manifest.cleanup)
        original = config.generations.get(manifest.cleanup.generation_id, {}).get("cleanup")
        if original is not None and original.generation != manifest.cleanup:
            raise LifecycleError("cleanup generation metadata differs from the manifest")
        # A fully transferred generation need not retain its old access. Any
        # unknown or untransferred role still selects that missing generation
        # during reconciliation and remains unresolved.
        # Keep the original and every handover generation available: an older
        # deployed actor may still need a verified fallback in that chain.
        # Reconciliation validates the chain before using any provider.
        required = {manifest.cleanup.generation_id} | {
            slot.rsplit(":", 1)[-1] for slot in own if slot.startswith("handover:")
        }
        generations = {
            key: roles["cleanup"].providers(
                targets=config.targets, now=now, tolerate_unavailable=True, reader=connect_client
            )
            for key, roles in config.generations.items()
            if key in required
        }
        providers = generations.get(manifest.cleanup.generation_id, {})
        lifecycle = LeaseLifecycle(manifest, inventory, state, providers={})
        closing = any(slot.startswith("close-") for slot in own) or now >= manifest.policy.deadline(
            instant(manifest.created_at)
        )
        if (
            confirmation is not None
            and readable
            and len(manifests.keys() - closed_ids) == 1
            and "confirmed" not in own
            and not closing
            and legacy["status"] == "ready"
        ):
            if (
                actor != "github"
                or confirmation.get("independent_server_id") != config.independent_server_id
                or manifest.helper_revision != config.helper_revision
                or manifest.policy.sha256 != config.approved_policy_sha256
                or original is None
            ):
                raise LifecycleError(
                    "independent lease confirmation differs from approved configuration"
                )
            manifest.cleanup.require_coverage(
                policy=manifest.policy,
                deadline=manifest.policy.deadline(instant(manifest.created_at)),
            )
            if now >= instant(manifest.policy.issuance_before):
                raise LifecycleError("lease issuance cutoff passed before independent confirmation")
            if instant(confirmation["cleanup_access_expires_at"]) < (
                manifest.policy.deadline(instant(manifest.created_at))
                + timedelta(seconds=manifest.policy.cleanup_reserve_seconds)
            ):
                raise LifecycleError("independent cleanup access expires before the reserve")
            for kind, provider in providers.items():
                if provider.authority_sha256 != manifest.cleanup.fingerprints[kind]:
                    raise LifecycleError("independent cleanup authority is unavailable")
                provider.inventory()
            inventory.publish(fact(manifest, "confirmed", confirmation))
        outcomes = lifecycle.reconcile(providers, generations=generations)
        verified = all(outcome.status == "verified" for outcome in outcomes)
        if verified:
            inventory.publish(
                fact(
                    manifest,
                    "closed",
                    {"results": [dataclasses.asdict(result) for result in outcomes]},
                )
            )
            for path in state.directory.glob("credential-*.json"):
                path.unlink()
        results.append(
            {
                "lease_id": manifest.lease_id,
                "manifest_sha256": manifest.sha256,
                "status": "closed"
                if verified
                else "active"
                if not closing and all(outcome.status == "not-due" for outcome in outcomes)
                else "unresolved",
                "overdue": now >= manifest.policy.deadline(instant(manifest.created_at))
                and not verified,
                "results": [dataclasses.asdict(result) for result in outcomes],
            }
        )
    return {
        "format": "lowerduckpond-m3-11-lease-cleanup-v1",
        "helper_revision": config.helper_revision,
        "actor": actor,
        "observed_at": stamp(now),
        "leases": results,
        "legacy": legacy,
        "status": "unresolved"
        if not readable
        or legacy["status"] != "ready"
        or any(row["status"] == "unresolved" for row in results)
        else "ready",
    }


def main() -> int:
    from scripts.m3_11_unattended.docker import Docker  # noqa: PLC0415
    from scripts.m3_11_unattended.watchdog import (  # noqa: PLC0415
        due_processes,
        finish_leases,
        prepare_lease_cleanup,
    )

    args = parse_arguments()
    config = LeaseConfiguration.load(args.config)
    if config.mode != "cleanup-only":
        raise LifecycleError("watchdog requires its cleanup-only bundle")
    root = args.runs.parent
    bootstrap = config.generations[config.active_generation]["cleanup"]
    retry = RETRY_SECONDS
    next_remote = next_retry = 0.0
    last_due: set[tuple[Path, bool]] = set()
    docker = Docker()
    while True:
        try:
            due = {
                (path, (path / "cancel.json").exists()) for path in due_processes(args.runs, docker)
            }
            now = time.monotonic()
            newly_due = bool(due - last_due)
            if args.watch and now < next_remote and not newly_due and (not due or now < next_retry):
                time.sleep(POLL_SECONDS)
                continue
            if newly_due:
                retry = RETRY_SECONDS
            last_due = due
            next_remote, next_retry = now + REMOTE_SECONDS, now + retry
            inventory = ConnectInventory(
                bootstrap.reader(),
                config.journal_vault,
                spool=root / "inventory-pending" / args.actor,
            )
            # Publication and writer recovery precede the provider-cleanup lock.
            try:
                published = prepare_lease_cleanup(args.runs, docker, inventory)
            except RuntimeError, OSError, ValueError, KeyError, TypeError:
                published = False
            with cleanup_lock(args.runs, blocking=False):
                receipt = sweep_leases(config, inventory, root=root / "leases", actor=args.actor)
                if not published:
                    receipt["status"] = "unresolved"
                else:
                    finish_leases(args.runs, receipt)
            print(json.dumps(receipt, sort_keys=True), flush=True)
            status = 0 if receipt["status"] == "ready" else 1
        except CleanupLockBusyError:
            status = 1
            next_remote = next_retry = time.monotonic() + POLL_SECONDS
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            print(
                "Credential cleanup unresolved; obligations retained.", file=sys.stderr, flush=True
            )
            status = 1
        if not args.watch:
            return status
        # Keep the established minute/hour cadence; no timer-policy changes.
        time.sleep(POLL_SECONDS)
        retry = (
            REMOTE_SECONDS if status == 0 else min(max(RETRY_SECONDS, retry * 2), REMOTE_SECONDS)
        )


if __name__ == "__main__":
    raise SystemExit(main())
