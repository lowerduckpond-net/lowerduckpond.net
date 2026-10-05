"""Protected GitHub execution: independent Connect provenance, persistence and deletion.

Bootstrap arrives on stdin from the JavaScript action. This process has cleanup
authority only; neither provisioning authority nor production inputs are present.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import signal
import sys
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import cleanup, connect_genesis
from scripts.m3_11_unattended.config import BOOTSTRAP_FIELDS, Connections, provider_connections
from scripts.m3_11_unattended.connect_admission import Admission
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import READ, READ_WRITE, Access, authenticate, inspect
from scripts.m3_11_unattended.connect_checkpoint import FORMAT as CHECKPOINT_FORMAT
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint, Stored
from scripts.m3_11_unattended.connect_configuration import PROVIDER_REFERENCES, _references
from scripts.m3_11_unattended.connect_diagnostics import failure
from scripts.m3_11_unattended.connect_host import independent_server
from scripts.m3_11_unattended.connect_journal import IndependentJournal, Witness
from scripts.m3_11_unattended.connect_ledger import ConnectLedger
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.github_checkpoint import REPOSITORY, WORKFLOW, GitHubArtifacts
from scripts.m3_11_unattended.journal import Journal, event, validate
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import (
    LIFETIME,
    LifecycleError,
    Targets,
    digest,
    identity,
    instant,
    stamp,
    strings,
)
from scripts.m3_11_unattended.state import replace_private
from scripts.production_qualification_inputs import current_candidate, revision

FORMAT = "lowerduckpond-m3-11-connect-independent-v1"
READY_FORMAT = "lowerduckpond-m3-11-connect-witness-ready-v1"
RECEIPT_FORMAT = "lowerduckpond-m3-11-connect-action-receipt-v1"
WITNESS_SECONDS = 12 * 60
POLL_SECONDS = 5
SWEEP_SECONDS = 60
SYNC_SECONDS = 120
MAX_INPUT = 128 * 1024
GENESIS_RECEIPT_FIELDS = {
    "format",
    "request_sha256",
    "epoch",
    "helper_revision",
    "registry_revision",
    "initial",
    "genesis",
    "independent_server",
    "independent_author",
    "shared_author",
    "authority_sha256",
    "authority_expires_at",
    "observed_at",
    "forged_author_ignored",
    "shared_forged_author_ignored",
    "provider_children_created",
}


def selection(value: object, *, helper: str) -> dict[str, object]:
    selected = fields(value, {"format", "stage", "active_helper", "request", "receipt"})
    if selected["format"] != FORMAT or selected["stage"] not in {"discovery", "genesis", "active"}:
        raise LifecycleError("independent Connect selection is invalid")
    approved = (
        connect_genesis.discovery_request(selected["request"])
        if selected["stage"] == "discovery"
        else connect_genesis.request(selected["request"])
    )
    if selected["active_helper"] != revision(helper) or (
        selected["stage"] != "active" and approved["helper_revision"] != helper
    ):
        raise LifecycleError("independent Connect helper differs from its installed revision")
    if selected["stage"] != "active":
        if selected["receipt"] is not None:
            raise LifecycleError("Connect initialization cannot replace an active epoch")
        return selected
    receipt = fields(selected["receipt"], GENESIS_RECEIPT_FIELDS)
    probe = validate(approved["independent_probe"])
    initial = {**strings(approved["initial"]), str(probe["event_id"]): digest(probe)}
    if (
        receipt["format"] != connect_genesis.RECEIPT_FORMAT
        or receipt["request_sha256"] != digest(approved)
        or any(
            receipt[key] != approved[key]
            for key in ("epoch", "helper_revision", "registry_revision", "shared_author")
        )
        or receipt["initial"] != initial
        or receipt["independent_server"] == approved["shared_server"]
        or receipt["independent_author"] == approved["shared_author"]
        or receipt["independent_author"]
        != cast(
            dict[str, object], cast(dict[str, object], approved["shared_forgery_probe"])["payload"]
        )["claimed_author"]
        or receipt["forged_author_ignored"] is not True
        or receipt["shared_forged_author_ignored"] is not True
        or receipt["provider_children_created"] is not False
        or re.fullmatch(r"[0-9a-f]{64}", str(receipt["authority_sha256"])) is None
    ):
        raise LifecycleError("independent Connect genesis receipt differs from its approval")
    instant(receipt["observed_at"])
    instant(receipt["authority_expires_at"])
    witness(receipt)
    return selected


def witness(receipt: dict[str, object], *, active_helper: str | None = None) -> Witness:
    pointer = fields(receipt["genesis"], {"identity", "sha256"})
    if type(pointer["identity"]) is not int or not isinstance(pointer["sha256"], str):
        raise LifecycleError("independent Connect genesis pointer is invalid")
    return Witness(
        str(receipt["epoch"]),
        str(receipt["helper_revision"]),
        str(receipt["independent_server"]),
        str(receipt["independent_author"]),
        Stored(pointer["identity"], pointer["sha256"]),
        active_helper=active_helper,
    )


def bootstrap(
    value: object, approved: dict[str, object]
) -> tuple[dict[str, object], Access, Targets, dict[str, str]]:
    selected = fields(
        value,
        {
            "format",
            "targets",
            "journal_vault",
            "cleanup",
            "token",
            "server_credentials",
            "provider_metadata",
        },
    )
    vaults = strings(approved["vaults"])
    targets = Targets.parse(selected["targets"])
    legacy = fields(selected["cleanup"], BOOTSTRAP_FIELDS - {"service_account_token"})
    references = _references(
        {key: legacy[key] for key in PROVIDER_REFERENCES},
        expected=PROVIDER_REFERENCES,
        vault=vaults["cleanup"],
    )
    if (
        selected["format"] != "lowerduckpond-m3-11-connect-bootstrap-v1"
        or selected["journal_vault"] != vaults["journal"]
        or digest(dataclasses.asdict(targets)) != approved["targets_sha256"]
        or not isinstance(selected["token"], dict)
        or not isinstance(selected["provider_metadata"], dict)
        or not isinstance(selected["server_credentials"], dict)
    ):
        raise LifecycleError("independent Connect bootstrap roles or targets differ")
    access = inspect(
        selected["token"],
        selected["provider_metadata"],
        expected={vaults["cleanup"]: READ, vaults["journal"]: READ_WRITE},
        now=datetime.now(UTC),
    )
    if access.server_id == approved["shared_server"]:
        raise LifecycleError("independent Connect needs a distinct server")
    return selected, access, targets, references


class ProbeJournal:
    """Read-only inventory for provider-policy checks before genesis exists."""

    def __init__(self, ledger: ConnectLedger) -> None:
        self.ledger = ledger

    def records(self) -> list[dict[str, object]]:
        return self.ledger.records()

    def append(self, record: dict[str, object]) -> None:
        raise LifecycleError("genesis provider checking cannot create an obligation")

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        raise LifecycleError("genesis provider checking cannot create an obligation")


def restore(
    ledger: ConnectLedger, store: GitHubArtifacts, selected: dict[str, object], access: Access
) -> IndependentJournal:
    receipt = fields(selected["receipt"], GENESIS_RECEIPT_FIELDS)
    independent = witness(receipt, active_helper=revision(selected["active_helper"]))
    if access.server_id != independent.server:
        raise LifecycleError("independent Connect server differs from the installed genesis")
    initial = strings(receipt["initial"])
    store.latest()  # Bind registry history before reading the pinned genesis.
    genesis = fields(
        store.read(independent.genesis), {"format", "epoch", "sequence", "previous", "records"}
    )
    if (
        genesis["format"] != CHECKPOINT_FORMAT
        or genesis["epoch"] != independent.epoch
        or genesis["sequence"] != 1
        or genesis["previous"] is not None
        or not isinstance(genesis["records"], list)
        or len(genesis["records"]) != len(initial)
        or {str(validate(row)["event_id"]): digest(row) for row in genesis["records"]} != initial
    ):
        raise LifecycleError("installed genesis does not recover its exact complete inventory")
    checkpoint = Checkpoint(
        store, epoch=independent.epoch, genesis=independent.genesis, initial=initial
    )
    return IndependentJournal(ledger, checkpoint, independent, capacity=store.remaining_capacity)


def reconcile(  # noqa: PLR0913 - request, execution identity and cleanup fallback are explicit
    journal: IndependentJournal,
    connections: Callable[[], Connections],
    *,
    targets: Targets,
    request_sha256: str,
    run_id: int,
    attempt: int,
    fallback: Callable[[], Lifecycle],
    dispatch_id: str = "",
) -> dict[str, object]:
    """One bounded witness execution; hourly independent sweeps continue afterward."""
    until = time.monotonic() + (WITNESS_SECONDS if request_sha256 else 0)
    next_sweep = 0.0
    receipt: dict[str, object] = {}
    announced = False
    connected: Connections | None = None
    while True:
        now = datetime.now(UTC)
        if time.monotonic() >= next_sweep:
            try:
                connected = connections()
                connected.authority.require(now + LIFETIME)
            except RuntimeError, OSError, ValueError, KeyError, TypeError:
                connected = None
            lifecycle = (
                Lifecycle(journal, connected.providers) if connected is not None else fallback()
            )
            receipt = cleanup.sweep(
                lifecycle,
                actor="github",
                helper=journal.witness.current_helper,
                authority_verified=connected is not None,
            )
            next_sweep = time.monotonic() + SWEEP_SECONDS
        admission = Admission(journal, targets=targets, now=datetime.now(UTC))
        if request_sha256 and connected is not None:
            # Existing reservations retain their original deadline. Only a new
            # reservation invokes the full reconciliation gate before creation.
            admission.reserve(
                request_sha256,
                connected.authority,
                require_clear=Lifecycle(journal, connected.providers).require_clear,
            )
            if not announced and receipt.get("status") == "ready":
                journal.append(
                    event(
                        "heartbeat",
                        str(uuid.uuid7()),
                        {
                            "format": READY_FORMAT,
                            "request_sha256": request_sha256,
                            "dispatch_id": dispatch_id,
                            "active_helper": journal.witness.current_helper,
                            "witness": journal.witness.binding(),
                            "observed_at": stamp(datetime.now(UTC)),
                            "github_run_id": run_id,
                            "github_run_attempt": attempt,
                        },
                    )
                )
                announced = True
        # Recreate both the records snapshot and clock after network/provider I/O.
        admission = Admission(journal, targets=targets, now=datetime.now(UTC))

        def allow(
            record: dict[str, object],
            decision: Admission = admission,
            ready: bool = connected is not None,
        ) -> bool:
            return decision.allow(record, now=datetime.now(UTC)) and (
                ready or record["kind"] not in {"run", "intent"}
            )

        journal.acknowledge(
            run_id=run_id,
            attempt=attempt,
            allow=allow,
        )
        if time.monotonic() >= until:
            return receipt
        time.sleep(min(POLL_SECONDS, max(0, until - time.monotonic())))


def synchronize(ready: Callable[[], bool]) -> bool:
    """A cold replica may expose its vaults before the referenced items arrive."""
    until = time.monotonic() + SYNC_SECONDS
    while True:
        try:
            if ready():
                return True
        except LifecycleError, OSError, ValueError:
            pass
        remaining = until - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(POLL_SECONDS, remaining))


def execute(  # noqa: PLR0915 - staged cleanup keeps private authority in this bounded process
    payload: object,
    *,
    directory: Path,
    helper: str,
    progress: Callable[[str], None] = lambda _phase: None,
) -> dict[str, object]:
    progress("validate-installed-selection")
    value = fields(payload, {"bootstrap", "selection", "operation", "run_sha256", "dispatch_id"})
    selected = selection(value["selection"], helper=helper)
    operation = value["operation"]
    dispatch_id = identity(value["dispatch_id"]) if value["dispatch_id"] != "" else ""
    expected = str(value["run_sha256"])
    if (
        operation not in {"discovery", "genesis", "reconcile", "witness"}
        or (operation != "reconcile" and not dispatch_id)
        or selected["stage"] != ("active" if operation in {"reconcile", "witness"} else operation)
        or (
            re.fullmatch(r"[0-9a-f]{64}", expected) is None
            if operation == "witness"
            else expected != ""
        )
    ):
        raise LifecycleError("Connect dispatch does not match its explicit installed stage")
    approved = cast(dict[str, object], selected["request"])
    progress("validate-cleanup-bootstrap")
    private, access, targets, references = bootstrap(value["bootstrap"], approved)
    vaults = strings(approved["vaults"])
    progress("start-independent-connect")
    with independent_server(
        Docker(), cast(dict[str, object], private["server_credentials"])
    ) as url:
        progress("authenticate-independent-connect")
        client = Connect(url, access.token, local_cleanup=True)
        until = time.monotonic() + SYNC_SECONDS
        while True:
            try:
                authenticate(client, access, forbidden=set(vaults.values()) - access.grants.keys())
                break
            except LifecycleError:
                if time.monotonic() >= until:
                    raise
                time.sleep(POLL_SECONDS)
        minimum = strings(
            cast(dict[str, object], selected["receipt"])["initial"]
            if selected["stage"] == "active"
            else approved["initial"]
        )
        ledger = ConnectLedger(
            client,
            vaults["journal"],
            spool=directory / "journal",
            anchor=str(approved["anchor"]),
            anchor_sha256=str(approved["anchor_sha256"]),
            minimum=minimum,
        )
        store = GitHubArtifacts(
            epoch=str(approved["epoch"]),
            registry_revision=str(approved["registry_revision"]),
            token=access.token,
            directory=directory / "checkpoints",
        )
        journal: Journal = ProbeJournal(ledger)

        def connections() -> Connections:
            return provider_connections(
                client,
                references,
                journal=journal,
                expires_at=access.expires_at,
                targets=targets,
                vault=vaults["journal"],
                now=datetime.now(UTC),
            )

        if operation == "discovery":
            progress("verify-cleanup-policy-and-provenance")
            if not synchronize(lambda: bool(ledger.records())):
                raise LifecycleError("Connect discovery inventory is not synchronized")
            connections().authority.require(datetime.now(UTC) + LIFETIME)
            proof = connect_genesis.discover(
                ledger,
                approved,
                helper=helper,
                server=access.server_id,
                now=datetime.now(UTC),
            )
        elif operation == "genesis":
            progress("verify-provenance-and-persist-genesis")
            if not synchronize(lambda: bool(ledger.records())):
                raise LifecycleError("Connect genesis inventory is not synchronized")
            proof = connect_genesis.initialize(
                ledger,
                store,
                approved,
                helper=helper,
                server=access.server_id,
                authority=connections().authority,
                now=datetime.now(UTC),
            )
        else:
            progress("recover-independent-checkpoint")
            independent = restore(ledger, store, selected, access)
            journal = independent

            def complete() -> bool:
                independent.records()
                return independent.cache_complete

            # On timeout still attempt cleanup from the authoritative checkpoint;
            # incomplete replica state can never produce readiness or new ACKs.
            synchronize(complete)
            progress("reconcile-and-witness")
            proof = reconcile(
                independent,
                connections,
                targets=targets,
                request_sha256=expected,
                dispatch_id=dispatch_id,
                run_id=int(os.environ["GITHUB_RUN_ID"]),
                attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
                fallback=lambda: Lifecycle(
                    independent, cleanup.cleanup_providers(client, references, targets)
                ),
            )
        progress("remove-ephemeral-connect")
        return {
            "format": RECEIPT_FORMAT,
            "operation": operation,
            "dispatch_id": dispatch_id,
            "helper_revision": helper,
            "selection_sha256": digest(selected),
            "observed_at": stamp(datetime.now(UTC)),
            "status": "ready" if operation in {"discovery", "genesis"} else proof["status"],
            "proof": proof,
        }


def main() -> int:
    os.umask(0o077)
    directory = Path(os.environ["RUNNER_TEMP"]) / "m3-11-connect"
    directory.mkdir(mode=0o700)
    output = directory / "receipt.json"
    receipt: dict[str, object] = {"format": RECEIPT_FORMAT, "status": "unresolved"}
    phase = "validate-protected-execution"

    def progress(value: str) -> None:
        nonlocal phase
        phase = value
        replace_private(output, {"format": RECEIPT_FORMAT, "status": "unresolved", "phase": phase})

    try:
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main"
        ):
            raise LifecycleError("independent Connect requires the protected main workflow")
        root = Path(__file__).resolve().parents[2]
        helper = revision(os.environ["M3_11_HELPER_REVISION"])
        current_candidate(root, helper)

        def interrupted(_signum: int, _frame: object) -> None:
            raise LifecycleError("independent Connect action was interrupted")

        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, interrupted)
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise LifecycleError("independent Connect input exceeds its bound")
        receipt = execute(json.loads(raw), directory=directory, helper=helper, progress=progress)
    except Exception as error:
        receipt = {"format": RECEIPT_FORMAT, "status": "unresolved", "phase": phase}
        # No exception text, arguments, locals, arbitrary names or provider output.
        with suppress(Exception):
            receipt["failure"] = failure(error)
    replace_private(output, receipt)
    return 0 if receipt["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
