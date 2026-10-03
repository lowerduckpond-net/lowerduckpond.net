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
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.journal import OpJournal, event
from scripts.m3_11_unattended.lifecycle import Lifecycle, Provider, intents
from scripts.m3_11_unattended.model import (
    Credential,
    LifecycleError,
    ProviderKind,
    Targets,
    instant,
    stamp,
)
from scripts.m3_11_unattended.spaces import Spaces
from scripts.production_qualification_inputs import git, revision

HEARTBEAT_MAX_AGE = timedelta(minutes=45)
POLL_SECONDS = 60


def connect_cleanup(bootstrap: Bootstrap, targets: Targets, vault: str) -> Lifecycle:
    op = bootstrap.op()
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
    return Lifecycle(OpJournal(op, vault), providers)


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
    receipt: dict[str, object] = {
        "actor": actor,
        "helper_revision": revision(helper),
        "observed_at": stamp(now),
        "status": status,
        "overdue": overdue,
        "results": [dataclasses.asdict(value) for value in observed],
    }
    prior = [
        record["payload"]
        for record in lifecycle.journal.records()
        if record["kind"] == "heartbeat"
        and isinstance(record["payload"], dict)
        and record["payload"].get("actor") == actor
    ]
    newest = max(prior, key=lambda value: str(value.get("observed_at"))) if prior else None
    # Avoid an unbounded one-item-per-minute trail when nothing changes. GitHub
    # always records its independent run, including delayed/stale execution.
    if (
        actor == "github"
        or newest is None
        or now - instant(newest["observed_at"]) >= timedelta(minutes=15)
        or any(
            newest.get(key) != receipt[key]
            for key in ("helper_revision", "status", "overdue", "results")
        )
    ):
        lifecycle.journal.append(event("heartbeat", str(uuid.uuid7()), receipt))
    return receipt


def require_independent_ready(journal: OpJournal, *, helper: str, now: datetime) -> None:
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
    value = fields(
        newest["payload"],
        {"actor", "helper_revision", "observed_at", "status", "overdue", "results"},
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--actor", choices=("github", "watchdog"), required=True)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--runs", type=Path)
    args = parser.parse_args()
    if args.actor == "github" and (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "lowerduckpond-net/lowerduckpond.net"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
    ):
        parser.exit(1, "Independent cleanup requires its protected main-branch workflow.\n")
    repository = Path(__file__).resolve().parents[2]
    helper = revision(git(repository, "rev-parse", "HEAD").decode().strip())
    status = 1
    journal: OpJournal | None = None
    while True:
        try:
            targets, vault, bootstrap = cleanup_configuration(args.config)
            lifecycle = connect_cleanup(bootstrap, targets, vault)
            if journal is None:
                if not isinstance(lifecycle.journal, OpJournal):
                    raise LifecycleError("independent cleanup requires the external journal")
                journal = lifecycle.journal
            else:
                journal.refresh()
                lifecycle.journal = journal
            available = None
            if args.runs is not None:
                if args.actor != "watchdog":
                    raise LifecycleError("only the persistent watchdog reads local runtime spools")
                from scripts.m3_11_unattended.docker import Docker  # noqa: PLC0415 - watchdog only
                from scripts.m3_11_unattended.watchdog import (  # noqa: PLC0415 - watchdog only
                    reconcile_processes,
                )

                available = reconcile_processes(lifecycle, args.runs, Docker())
            receipt = sweep(lifecycle, actor=args.actor, helper=helper, secrets=available)
            print(json.dumps(receipt, sort_keys=True), flush=True)
            status = 0 if receipt["status"] == "ready" else 1
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            print(
                "Credential cleanup unresolved; retained obligations need another reconciliation.",
                file=sys.stderr,
                flush=True,
            )
            status = 1
        if not args.watch:
            return status
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
