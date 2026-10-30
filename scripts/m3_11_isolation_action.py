"""Protected, separate GitHub validation/confirmation and three-role cleanup."""

from __future__ import annotations

import json
import os
import signal
import sys
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_isolation_access import account_provider, independent
from scripts.m3_11_isolation_journal import Journal, github
from scripts.m3_11_isolation_lease import Lease
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_action import bootstrap, session
from scripts.m3_11_unattended.http import read_only_requests
from scripts.m3_11_unattended.model import digest, instant, stamp
from scripts.m3_11_unattended.state import replace_private
from scripts.production_qualification_inputs import current_candidate, revision

FORMAT = "lowerduckpond-isolated-public-ca-independent-v1"
REPOSITORY = "lowerduckpond-net/lowerduckpond.net"
WORKFLOW = "m3-11-public-ca-cleanup.yml"
MAX_INPUT = 256 * 1024
OPERATIONS = frozenset({"validate", "confirm", "reconcile", "cleanup"})


def control(journal: Journal, kind: str) -> dict[str, object]:
    rows = [row["payload"] for row in journal.all_records() if row["kind"] == kind]
    if not rows or not isinstance(rows[0], dict) or any(row != rows[0] for row in rows):
        raise ValueError("isolated control fact is unavailable or conflicting")
    return rows[0]


def require_quiesced(journal: Journal) -> None:
    # Journal validates exact five owned stopped actors, images and restart=no.
    control(journal, "quiesced")


def execute(raw: object, *, directory: Path, actor: dict[str, object]) -> dict[str, object]:  # noqa: PLR0912, PLR0915 - explicit protected operation branches
    selected = fields(raw, {"bootstrap", "manifest", "operation"})
    operation = selected["operation"]
    if operation not in OPERATIONS:
        raise ValueError("isolated independent operation is unsupported")
    manifest = Manifest.parse(selected["manifest"])
    original = fields(selected["bootstrap"], {"format", "configuration", "server_credentials"})
    old = LeaseConfiguration.parse(original["configuration"])
    # Validate the existing private bundle at ITS original helper, then bind its
    # complete public projection. Neither its policy nor its bytes are replaced.
    config, credentials = bootstrap(original, helper=old.helper_revision)
    manifest.require_independent_configuration(config)
    with session(config, credentials, directory=directory) as (client, access, authentication):
        if access.server_id != manifest.independent_server_id or authentication != {
            **manifest.independent_access,
            "authenticated": True,
            "forbidden_vaults_denied": 2,
        }:
            raise ValueError("isolated independent Connect identity differs")
        metadata = github(
            {
                **actor,
                "helper_revision": manifest.plan.source_revision,
                "independent_server_id": access.server_id,
                "authentication_sha256": digest(authentication),
                "observed_at": stamp(datetime.now(UTC)),
            },
            manifest,
        )
        active = independent(config, manifest)
        journal = Journal(client, manifest, spool=directory / "pending")
        now = datetime.now(UTC)
        if operation == "validate":
            with read_only_requests():
                account_provider(active, config.targets, manifest, client=client, now=now)
                journal.all_records()
            result: dict[str, object] = {
                "status": "ready",
                "provider_activity_verified": True,
                "create_verified": False,
                "journal_mutations": False,
            }
        elif operation == "confirm":
            if control(journal, "manifest") != manifest.document() or journal.records():
                raise ValueError("isolated manifest is absent or creation has already entered")
            prepared = control(journal, "prepared")
            if instant(prepared["captured_at"]) > instant(manifest.intents[0].requested_at):
                raise ValueError("isolated manifest predates its genuine preparation")
            provider = account_provider(active, config.targets, manifest, client=client, now=now)
            if set(provider.inventory()) != set(manifest.intents[0].baseline_ids):
                raise ValueError("isolated pre-CREATE independent inventory differs")
            if (
                not instant(manifest.intents[0].requested_at)
                <= now
                < instant(manifest.intents[0].create_before)
            ):
                raise ValueError("isolated independent confirmation is outside admission")
            journal.put("confirmed", metadata)
            result = {
                "status": "ready",
                "confirmation": "exact-three-role-manifest",
                "create_verified": False,
                "journal_mutations": True,
            }
        else:
            provider = account_provider(active, config.targets, manifest, client=client, now=now)
            due = now >= instant(manifest.intents[0].expires_at)
            try:
                all_records = journal.all_records()
            except Exception:
                if not due:
                    raise
                all_records = []
            quiesced = any(row["kind"] == "quiesced" for row in all_records)
            if operation == "cleanup" and not (quiesced or due):
                journal.put("stop-requested", metadata)
                result = {
                    "status": "pending",
                    "reason": "awaiting-owned-consumer-stop",
                    "credential_creation": False,
                }
            elif not (quiesced or due):
                # Coverage is explicitly typed by event. It is never substituted
                # for the stock seven-role scheduled retirement/launch gates.
                journal.put("covered", metadata)
                result = {"status": "ready", "lease_state": "active", "credential_creation": False}
            else:
                lease = Lease(None, manifest.intents, journal)

                def authorized() -> None:
                    if datetime.now(UTC) < instant(manifest.intents[0].expires_at):
                        require_quiesced(journal)

                outcomes = lease.revoke_remote(
                    provider,
                    require_issuer_stopped=authorized,
                    allow_not_submitted=quiesced,
                )
                result = {
                    "status": "pending",
                    "reason": "awaiting-host-denials-or-quiescence",
                    "outcomes": outcomes,
                }
                try:
                    closed = [
                        row["payload"] for row in journal.records() if row["kind"] == "closed"
                    ]
                    if closed:
                        closure = digest(closed[0])
                        lease.independent_readback(
                            provider,
                            expected=closure,
                            require_issuer_stopped=lambda: require_quiesced(journal),
                        )
                        control(journal, "dns-clean")
                        journal.put(
                            "readback",
                            {
                                "github": metadata,
                                "closure_sha256": closure,
                                "status": "provider-absence-and-host-denials-verified",
                            },
                        )
                        result = {
                            "status": "ready",
                            "lease_state": "closed",
                            "closure_sha256": closure,
                            "outcomes": outcomes,
                        }
                except ValueError, RuntimeError, OSError:
                    pass  # Preserve successful revocations; unavailable proof stays pending.
        result = {
            "format": FORMAT,
            "manifest_sha256": manifest.sha256,
            "plan_sha256": manifest.plan.sha256,
            "operation": operation,
            "github": metadata,
            "observed_at": stamp(datetime.now(UTC)),
            "credential_creation": False,
            **result,
        }
        replace_private(directory / "result-before-teardown.json", result)
    # Only the unchanged native context manager's successful teardown gets here.
    return {**result, "temporary_runtime_closed": True}


def main() -> int:
    os.umask(0o077)
    root = Path(os.environ["RUNNER_TEMP"]) / "m3-11-public-ca"
    root.mkdir(mode=0o700)
    try:
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main"
        ):
            raise ValueError("isolated cleanup requires its protected main workflow")
        helper = revision(os.environ["M3_11_HELPER_REVISION"])
        current_candidate(Path(__file__).resolve().parents[1], helper)

        def interrupted(_signum: int, _frame: object) -> None:
            raise RuntimeError("isolated cleanup interrupted")

        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupted)
        body = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(body) > MAX_INPUT:
            raise ValueError("isolated independent input exceeds its bound")
        raw = json.loads(body)
        if Manifest.parse(raw["manifest"]).plan.source_revision != helper:
            raise ValueError("isolated manifest differs from its exact executing helper")
        actor: dict[str, object] = {
            "run_id": int(os.environ["GITHUB_RUN_ID"]),
            "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "event": os.environ["GITHUB_EVENT_NAME"],
        }
        receipt = execute(raw, directory=root, actor=actor)
    except Exception:
        receipt = {"format": FORMAT, "status": "unresolved", "credential_creation": False}
    replace_private(root / "receipt.json", receipt)
    return 0 if receipt.get("status") == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
