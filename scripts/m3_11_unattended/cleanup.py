"""Independent repeated revocation; this entry point cannot retire any run data."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import sys
import time
import uuid
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare
from scripts.m3_11_unattended.config import (
    DO_READ_SCOPES,
    Bootstrap,
    UnavailableProvider,
    _cloudflare_authority,
    cleanup_configuration,
)
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.connect_journal import ConnectJournal, IndependentJournal
from scripts.m3_11_unattended.github_checkpoint import MINIMUM_START_CAPACITY
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.journal import Journal, OpJournal, event
from scripts.m3_11_unattended.lifecycle import Lifecycle, Provider, intents, pending_authentication
from scripts.m3_11_unattended.model import (
    Credential,
    LifecycleError,
    ProviderKind,
    Targets,
    instant,
    stamp,
)
from scripts.m3_11_unattended.spaces import Spaces
from scripts.m3_11_unattended.state import cleanup_lock
from scripts.production_qualification_inputs import git, revision

HEARTBEAT_MAX_AGE = timedelta(minutes=90)
POLL_SECONDS = 60
REMOTE_SECONDS = 3600
RETRY_SECONDS = 300


def connect_cleanup(
    bootstrap: Bootstrap, targets: Targets, vault: str, *, journal_directory: Path | None = None
) -> Lifecycle:
    op = bootstrap.reader()
    providers: dict[ProviderKind, Provider] = {}
    for kind, reference in (
        ("spaces", "digitalocean"),
        ("cloudflare-account", "cloudflare_account"),
        ("cloudflare-user", "cloudflare_user"),
    ):
        selected: ProviderKind = kind  # type: ignore[assignment] # fixed provider table
        try:
            secret = op.read(bootstrap.values[reference])
            if selected == "spaces":
                metadata = fields(
                    json.loads(op.read(bootstrap.values["digitalocean_metadata"])),
                    {
                        "format",
                        "token_sha256",
                        "expires_at",
                        "scopes",
                        "verified_at",
                        "verified_by",
                    },
                )
                if (
                    metadata["format"] != "lowerduckpond-digitalocean-bootstrap-v1"
                    or metadata["token_sha256"] != hashlib.sha256(secret.encode()).hexdigest()
                    or metadata["scopes"] != sorted(DO_READ_SCOPES | {"spaces_key:delete"})
                    or metadata["verified_by"] != "operator-provider-console"
                ):
                    raise LifecycleError("cleanup DigitalOcean identity is unverified")
                providers[selected] = Spaces(Api("https://api.digitalocean.com", secret))
            else:
                client = Cloudflare(
                    Api(ORIGIN, secret),
                    account=targets.account_id if selected == "cloudflare-account" else None,
                )
                _cloudflare_authority(client, target=targets, now=datetime.now(UTC))
                providers[selected] = client
        except RuntimeError, OSError, ValueError, TypeError, KeyError:
            providers[selected] = UnavailableProvider(selected)
    return Lifecycle(bootstrap.journal(vault, directory=journal_directory), providers)


def sweep(
    lifecycle: Lifecycle,
    *,
    actor: str,
    helper: str,
    secrets: dict[str, Credential] | None = None,
) -> dict[str, object]:
    if actor not in {"controller", "watchdog", "github"}:
        raise LifecycleError("unknown cleanup actor")
    observed = lifecycle.sweep(secrets)
    by_digest = {value.intent_sha256: value for value in observed}
    now = datetime.now(UTC)
    overdue = sum(
        instant(intent.deadline) < now and by_digest[intent.sha256].status != "verified"
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
        if healthy and all(value.status in {"verified", "not-due"} for value in observed)
        else "unresolved"
    )
    if isinstance(lifecycle.journal, IndependentJournal) and not lifecycle.journal.cache_complete:
        status = "unresolved"
    receipt: dict[str, object] = {
        "actor": actor,
        "helper_revision": revision(helper),
        "observed_at": stamp(now),
        "status": status,
        "overdue": overdue,
        "results": [dataclasses.asdict(value) for value in observed],
    }
    if isinstance(lifecycle.journal, IndependentJournal):
        receipt["connect"] = lifecycle.journal.readiness()
        if not lifecycle.journal.cache_complete:
            receipt["status"] = "unresolved"
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


def require_independent_ready(journal: Journal, *, helper: str, now: datetime) -> None:
    records = [
        record
        for record in journal.records()
        if record["kind"] == "heartbeat"
        and isinstance(record["payload"], dict)
        and record["payload"].get("actor") == "github"
    ]
    if not records:
        raise LifecycleError("independent GitHub cleanup has not demonstrated readiness")
    newest = max(records, key=lambda record: instant(record["recorded_at"]))
    selected_fields = {"actor", "helper_revision", "observed_at", "status", "overdue", "results"}
    if isinstance(journal, ConnectJournal):
        selected_fields.add("connect")
    value = fields(
        newest["payload"],
        selected_fields,
    )
    if (
        value["helper_revision"] != helper
        or value["status"] != "ready"
        or value["overdue"] != 0
        or not now - HEARTBEAT_MAX_AGE
        <= instant(value["observed_at"])
        <= now + timedelta(minutes=5)
    ):
        raise LifecycleError("independent cleanup is stale, overdue or bound to another helper")
    if isinstance(journal, ConnectJournal):
        proof = fields(
            value["connect"], {"epoch", "remaining_capacity", "cache_complete", "checkpoint"}
        )
        pointer = fields(proof["checkpoint"], {"identity", "sha256"})
        if type(pointer["identity"]) is not int or not isinstance(pointer["sha256"], str):
            raise LifecycleError("independent cleanup checkpoint is invalid")
        checkpoint = Stored(pointer["identity"], pointer["sha256"])
        if (
            journal.witness.helper != helper
            or proof["epoch"] != journal.witness.epoch
            or proof["cache_complete"] is not True
            or type(proof["remaining_capacity"]) is not int
            or proof["remaining_capacity"] < MINIMUM_START_CAPACITY
            or checkpoint.identity < journal.witness.genesis.identity
            or (
                checkpoint.identity == journal.witness.genesis.identity
                and checkpoint != journal.witness.genesis
            )
            or not journal.confirmed(newest)
            or not journal.ledger.authored(newest, journal.witness.author)
        ):
            raise LifecycleError("independent Connect readiness or cleanup capacity is unverified")


def status_document(journal: Journal, *, helper: str, now: datetime) -> dict[str, object]:
    """Observe external obligations without deleting, provisioning, or exporting IDs."""
    records = journal.records()
    pending = 0
    overdue = 0
    for intent in intents(journal):
        results = [
            record
            for record in records
            if record["kind"] in {"resolved", "cleanup"}
            and isinstance(record["payload"], dict)
            and record["payload"].get("intent_sha256") == intent.sha256
            and (
                record["kind"] != "resolved"
                or not isinstance(journal, ConnectJournal)
                or journal.confirmed(record)
            )
        ]
        unresolved = not any(record["kind"] == "resolved" for record in results) or bool(
            pending_authentication(results)
        )
        pending += unresolved
        overdue += unresolved and instant(intent.deadline) < now
    heartbeats = [
        record
        for record in records
        if record["kind"] == "heartbeat"
        and isinstance(record["payload"], dict)
        and record["payload"].get("actor") == "github"
    ]
    independent: dict[str, object] = {"status": "missing", "observed_at": None}
    if heartbeats:
        latest = max(heartbeats, key=lambda record: instant(record["recorded_at"]))
        selected_fields = {
            "actor",
            "helper_revision",
            "observed_at",
            "status",
            "overdue",
            "results",
        }
        if isinstance(journal, ConnectJournal):
            selected_fields.add("connect")
        value = fields(
            latest["payload"],
            selected_fields,
        )
        observed = instant(value["observed_at"])
        fresh = now - HEARTBEAT_MAX_AGE <= observed <= now + timedelta(minutes=5)
        if isinstance(journal, ConnectJournal):
            try:
                require_independent_ready(journal, helper=helper, now=now)
            except LifecycleError, ValueError:
                fresh = False
        independent = {
            "observed_at": stamp(observed),
            "status": "ready"
            if fresh
            and value["helper_revision"] == revision(helper)
            and value["status"] == "ready"
            and value["overdue"] == 0
            else "stale-or-unresolved",
        }
    return {
        "observed_at": stamp(now),
        "outstanding": pending,
        "overdue": overdue,
        "github": independent,
        "new_start": "blocked"
        if pending or independent["status"] != "ready"
        else "eligible-for-preflight",
    }


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--actor", choices=("github", "watchdog"), required=True)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--runs", type=Path)
    parser.add_argument("--journal-cache", type=Path)
    parser.add_argument("--journal-cache-output", type=Path)
    return parser


def parse_arguments() -> argparse.Namespace:
    parser = argument_parser()
    args = parser.parse_args()
    if args.journal_cache_output is not None and args.journal_cache is None:
        parser.error("journal cache output requires an input cache path")
    if args.actor == "github" and (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "lowerduckpond-net/lowerduckpond.net"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
    ):
        parser.exit(1, "Independent cleanup requires its protected main-branch workflow.\n")
    return args


def main() -> int:  # noqa: PLR0912, PLR0915 - remote cadence and explicit backend boundaries
    args = parse_arguments()
    repository = Path(__file__).resolve().parents[2]
    helper = revision(git(repository, "rev-parse", "HEAD").decode().strip())
    status = 1
    journal: Journal | None = None
    next_remote = next_retry = 0.0
    retry_seconds = RETRY_SECONDS
    last_due: set[Path] = set()
    while True:
        try:
            now = time.monotonic()
            due: set[Path] = set()
            if args.runs is not None:
                if args.actor != "watchdog":
                    raise LifecycleError("only the persistent watchdog reads local runtime spools")
                from scripts.m3_11_unattended.docker import Docker  # noqa: PLC0415 - watchdog only
                from scripts.m3_11_unattended.watchdog import (  # noqa: PLC0415 - watchdog only
                    due_processes,
                    finish_reconciled,
                    reconcile_processes,
                )

                due = set(due_processes(args.runs, Docker()))
            newly_due = bool(due - last_due)
            if args.watch and now < next_remote and not newly_due and (not due or now < next_retry):
                time.sleep(POLL_SECONDS)
                continue
            # Local process checks remain every minute. Remote reconciliation is
            # hourly, or immediate on an unresolved local terminal path, with a
            # five-minute first retry and backoff to hourly after failure. Avoid
            # consuming the daily quota rereading idle bootstrap every minute.
            retry_seconds = RETRY_SECONDS if newly_due else retry_seconds
            next_remote, next_retry = now + REMOTE_SECONDS, now + retry_seconds
            last_due = due
            with cleanup_lock(args.runs) if args.runs is not None else nullcontext():
                targets, vault, bootstrap = cleanup_configuration(args.config)
                if bootstrap.connect_settings is not None and args.actor == "github":
                    raise LifecycleError(
                        "GitHub Connect cleanup requires its independent checkpoint action"
                    )
                journal_directory = (
                    (args.runs.parent if args.runs is not None else args.config.parent)
                    / "connect-journal"
                    / "cleanup"
                )
                lifecycle = connect_cleanup(
                    bootstrap, targets, vault, journal_directory=journal_directory
                )
                if journal is None:
                    if isinstance(lifecycle.journal, OpJournal) and args.journal_cache is not None:
                        lifecycle.journal.use_cache(
                            args.journal_cache, output=args.journal_cache_output
                        )
                    journal = lifecycle.journal
                else:
                    # Refresh after acquiring the shared lock: a preceding
                    # controller may have resolved obligations and removed keys.
                    if isinstance(journal, OpJournal):
                        journal.refresh()
                    lifecycle.journal = journal
                available = None
                if args.runs is not None:
                    available = reconcile_processes(lifecycle, args.runs, Docker(), directories=due)
                receipt = sweep(lifecycle, actor=args.actor, helper=helper, secrets=available)
                if args.runs is not None:
                    finish_reconciled(lifecycle, due, receipt)
            print(json.dumps(receipt, sort_keys=True), flush=True)
            status = 0 if receipt["status"] == "ready" else 1
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            print(
                "Credential cleanup unresolved; retained obligations need another reconciliation.",
                file=sys.stderr,
                flush=True,
            )
            status = 1
        retry_seconds = RETRY_SECONDS if status == 0 else min(2 * retry_seconds, REMOTE_SECONDS)
        if not args.watch:
            return status
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
