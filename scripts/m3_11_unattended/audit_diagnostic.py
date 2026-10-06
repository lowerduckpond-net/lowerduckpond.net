"""Once-only approved audit lookup; restart restores policy without replaying access."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import audit_lookup, connect_action
from scripts.m3_11_unattended import audit_policy_recovery as policy
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare
from scripts.m3_11_unattended.config import Configuration, _cloudflare_authority
from scripts.m3_11_unattended.connect_control import BACKEND, SETTING, GitHub
from scripts.m3_11_unattended.connect_journal import ConnectJournal
from scripts.m3_11_unattended.http import MAX_BYTES, Api
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import Intent, LifecycleError, digest, instant, stamp
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import current_candidate, revision

FORMAT = "lowerduckpond-m3-11-audit-access-proposal-v1"
SINCE = "2026-10-06T07:44:00Z"
BEFORE = "2026-10-06T07:53:00Z"
ROOT = Path(__file__).resolve().parents[2]


def proposal(value: object) -> dict[str, object]:
    selected = fields(
        value, {"format", "candidate", "helper_revision", "intent", "since", "before"}
    )
    policy.candidate(selected["candidate"])
    intent = Intent.parse(selected["intent"])
    if (
        selected["format"] != FORMAT
        or intent.sha256 != policy.INTENT_SHA256
        or intent.run_id != policy.RUN_ID
        or selected["since"] != SINCE
        or selected["before"] != BEFORE
    ):
        raise LifecycleError("audit proposal differs from the original uncertain intent")
    revision(selected["helper_revision"])
    return selected


def journal(config: Configuration, directory: Path) -> ConnectJournal:
    selected = config.provision.journal(config.journal_vault, directory=directory / "journal")
    if not isinstance(selected, ConnectJournal):
        raise LifecycleError("audit recovery requires independent Connect persistence")
    return selected


def verified_proof(selected: ConnectJournal, record: dict[str, object]) -> bool:
    now = datetime.now(UTC)
    expected = policy.plan(record)
    observed = selected.records()
    if policy.plans(observed) != [record]:
        return False
    candidates = [
        row
        for row in observed
        if row["kind"] == "heartbeat"
        and isinstance(row["payload"], dict)
        and row["payload"].get("format") == policy.PROOF_FORMAT
        and row["payload"].get("plan_sha256") == digest(record)
        and row["payload"].get("cleanup_actor") == "github"
        and selected.ledger.authored(row, selected.witness.author)
    ]
    if not candidates:
        return False
    latest = max(candidates, key=lambda row: instant(row["recorded_at"]))
    value = latest["payload"]
    return (
        isinstance(value, dict)
        and value.get("helper_revision") == expected["helper_revision"]
        and value.get("status") == "policy-metadata-verified"
        and now - timedelta(seconds=120) <= instant(value.get("observed_at")) <= now
        and selected.confirmed(latest, observed=observed)
        and selected.confirmed(record, observed=observed)
    )


def stage(
    config: Configuration, approved: dict[str, object], directory: Path
) -> tuple[ConnectJournal, dict[str, object]]:
    github = GitHub()
    github.protection()
    github.merged(str(approved["helper_revision"]))
    variables = github.variables()
    selected = connect_action.selection(
        json.loads(variables[SETTING]), helper=str(approved["helper_revision"])
    )
    if variables.get(BACKEND) != "connect" or selected["stage"] != "active":
        raise LifecycleError("audit recovery needs active protected cleanup")
    ledger = journal(config, directory)
    receipt = selected["receipt"]
    if not isinstance(receipt, dict):
        raise LifecycleError("audit recovery has no existing cleanup epoch")
    native = connect_action.witness(receipt, active_helper=str(approved["helper_revision"]))
    if native.binding() != ledger.witness.binding() or native.author != ledger.witness.author:
        raise LifecycleError("audit recovery cannot replace the existing cleanup epoch")
    observed = ledger.records()
    originals = [
        row for row in observed if row["kind"] == "intent" and row["payload"] == approved["intent"]
    ]
    if len(originals) != 1:
        raise LifecycleError("audit recovery has no exact original intent in the journal")
    path = directory / "restoration-plan.json"
    if path.exists():
        record = read_private(path)
        value = policy.plan(record)
        if (
            value["helper_revision"] != approved["helper_revision"]
            or value["candidate"] != approved["candidate"]
        ):
            raise LifecycleError("audit recovery cannot rebind its original plan")
    else:
        if policy.plans(observed):
            raise LifecycleError("an audit recovery plan already exists; use restore")
        record = event("heartbeat", str(uuid.uuid7()), {})
        start = instant(record["recorded_at"])
        record["payload"] = {
            "format": policy.FORMAT,
            "candidate": approved["candidate"],
            "helper_revision": approved["helper_revision"],
            "intent_sha256": policy.INTENT_SHA256,
            "grant_before": stamp(start + policy.GRANT_WINDOW),
            "restore_after": stamp(start + policy.RESTORE_WINDOW),
        }
        policy.plan(record)
        write_private(path, record)
    ledger.append(record)
    github.dispatch(directory / "independent-dispatch", operation="reconcile", selection=selected)
    deadline = instant(policy.plan(record)["grant_before"])
    while datetime.now(UTC) < deadline:
        if verified_proof(ledger, record):
            return ledger, record
        time.sleep(5)
    raise LifecycleError("independent audit restoration readiness was not demonstrated")


def cleanup_client(
    config: Configuration, ledger: ConnectJournal, approved: dict[str, object]
) -> Cloudflare:
    token = config.cleanup.reader().read(config.cleanup.values["cloudflare_account"])
    provider = Cloudflare(Api(ORIGIN, token), account=config.targets.account_id)
    _cloudflare_authority(provider, target=config.targets, now=datetime.now(UTC))
    return policy.restoration_authority(ledger, provider, policy.candidate(approved["candidate"]))


def collect(config: Configuration, approved: dict[str, object], directory: Path) -> None:
    record = read_private(directory / "restoration-plan.json")
    selected = policy.plan(record)
    if (
        selected["candidate"] != approved["candidate"]
        or selected["helper_revision"] != approved["helper_revision"]
        or not instant(record["recorded_at"])
        <= datetime.now(UTC)
        < instant(selected["restore_after"])
    ):
        raise LifecycleError("audit collection escaped the approved access window")
    write_private(directory / "collection-submitted.json", {"plan_sha256": digest(record)})
    reader = config.provision.reader()
    token = reader.read(config.provision.values["cloudflare_account"])
    api = Api(ORIGIN, token)
    bound = policy.candidate(approved["candidate"])
    if api.credential_sha256 != bound["credential_sha256"] or policy.inspect(
        api, bound
    ) != policy.body(bound["candidate_after"]):
        raise LifecycleError("audit reader differs from the approved expanded bootstrap")
    parent = Cloudflare(
        Api(ORIGIN, reader.read(config.provision.values["cloudflare_user"])), account=None
    )
    _cloudflare_authority(parent, target=config.targets, now=datetime.now(UTC))
    verified = parent._get("/user/tokens/verify")
    if not isinstance(verified, dict) or not isinstance(verified.get("id"), str):
        raise LifecycleError("original user-token parent identity is unavailable")
    if datetime.now(UTC) >= instant(selected["restore_after"]):
        raise LifecycleError("audit access window elapsed before log retrieval")
    records = audit_lookup.collect(
        api,
        account=config.targets.account_id,
        since=SINCE,
        before=BEFORE,
        retain=lambda page, value: write_private(
            directory / f"audit-page-{page}.json", value, maximum=MAX_BYTES
        ),
    )
    write_private(
        directory / "audit-analysis.json",
        audit_lookup.analyze(records, Intent.parse(approved["intent"]), parent_id=verified["id"]),
    )


def collection_deadline(signum: int, frame: object) -> None:
    raise LifecycleError("audit collection deadline elapsed")


def execute(config_path: Path, approved: dict[str, object], directory: Path) -> None:
    private_directory(config_path.parent)
    global_claim = config_path.parent / ("audit-grant-" + policy.CANDIDATE_SHA256 + ".json")
    if (directory / "grant-submitted.json").exists() or global_claim.exists():
        raise LifecycleError("audit access cannot be replayed; use restore")
    config = Configuration.load(config_path)
    ledger, record = stage(config, approved, directory)
    # Retained before any provider mutation. A lost response/restart never grants again.
    # One controller configuration also serializes distinct output directories.
    write_private(global_claim, {"plan_sha256": digest(record), "directory": str(directory)})
    write_private(directory / "grant-submitted.json", {"plan_sha256": digest(record)})
    restored = False
    try:
        token = config.provision.reader().read(config.provision.values["cloudflare_account"])
        if not verified_proof(ledger, record):
            raise LifecycleError("independent audit policy observation changed before grant")
        policy.grant(Api(ORIGIN, token), record)
        child = subprocess.run(  # noqa: S603 - secrets remain in private config/pipes, no output export
            [
                sys.executable,
                "-m",
                "scripts.m3_11_unattended.audit_diagnostic",
                "collect",
                "--config",
                str(config_path),
                "--directory",
                str(directory),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=ROOT,
            timeout=audit_lookup.SECONDS,
            check=False,
            env={
                key: value
                for key, value in os.environ.items()
                if key in {"PATH", "HOME", "SSL_CERT_FILE"}
            },
        )
        if child.returncode:
            raise LifecycleError("bounded audit collection failed; evidence remains private")
    finally:
        try:
            provider = cleanup_client(config, ledger, approved)
            restored = (
                policy.restore(provider.api, policy.candidate(approved["candidate"]))
                == "original-policy-verified"
            )
        finally:
            write_private(
                directory / "controller-restoration.json",
                {
                    "plan_sha256": digest(record),
                    "observed_at": stamp(datetime.now(UTC)),
                    "status": "original-policy-verified" if restored else "restoration-unresolved",
                },
            )


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "execute", "restore", "collect"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--intent", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--approved-sha256")
    args = parser.parse_args()
    directory = args.directory
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(directory)
    if args.operation == "prepare":
        current_candidate(ROOT, args.revision)
        value = proposal(
            {
                "format": FORMAT,
                "candidate": read_private(args.candidate),
                "helper_revision": args.revision,
                "intent": read_private(args.intent),
                "since": SINCE,
                "before": BEFORE,
            }
        )
        write_private(directory / "proposal.json", value)
        print(json.dumps({"proposal_sha256": digest(value), "provider_mutations": 0}))
        return
    approved = proposal(read_private(directory / "proposal.json"))
    current_candidate(ROOT, str(approved["helper_revision"]))
    if args.operation == "execute":
        if args.approved_sha256 != digest(approved):
            raise LifecycleError("audit access requires approval of this exact proposal")
        execute(args.config, approved, directory)
    elif args.operation == "restore":
        config = Configuration.load(args.config)
        ledger = journal(config, directory)
        record = read_private(directory / "restoration-plan.json")
        policy.plan(record)
        ledger.append(record)
        provider = cleanup_client(config, ledger, approved)
        print(policy.restore(provider.api, policy.candidate(approved["candidate"])))
    else:
        signal.signal(signal.SIGALRM, collection_deadline)
        signal.alarm(audit_lookup.SECONDS)
        record = read_private(directory / "restoration-plan.json")
        if read_private(directory / "grant-submitted.json") != {"plan_sha256": digest(record)}:
            raise LifecycleError("audit collector has no original grant attempt")
        remaining = (
            instant(policy.plan(record)["restore_after"]) - datetime.now(UTC)
        ).total_seconds()
        if remaining <= 0:
            raise LifecycleError("audit collector's original access window elapsed")
        signal.setitimer(signal.ITIMER_REAL, min(audit_lookup.SECONDS, remaining))
        collect(Configuration.load(args.config), approved, directory)
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(
            "Audit diagnostic incomplete; retain evidence and check policy restoration separately."
        ) from None
