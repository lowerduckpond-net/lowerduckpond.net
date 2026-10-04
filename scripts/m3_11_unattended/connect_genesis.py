"""Explicit one-time Connect provenance and recoverable genesis installation."""

from __future__ import annotations

import re
from datetime import datetime

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.connect_auth import identity as account_identity
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint, Store
from scripts.m3_11_unattended.connect_journal import acknowledgement
from scripts.m3_11_unattended.connect_ledger import ConnectLedger
from scripts.m3_11_unattended.journal import validate
from scripts.m3_11_unattended.model import (
    LIFETIME,
    Authority,
    LifecycleError,
    digest,
    identity,
    stamp,
    strings,
)
from scripts.production_qualification_inputs import revision

REQUEST_FORMAT = "lowerduckpond-m3-11-connect-genesis-request-v1"
RECEIPT_FORMAT = "lowerduckpond-m3-11-connect-genesis-receipt-v1"
PROBE_FORMAT = "lowerduckpond-m3-11-connect-provenance-v1"
REQUEST_FIELDS = {
    "format",
    "epoch",
    "helper_revision",
    "registry_revision",
    "vaults",
    "anchor",
    "anchor_sha256",
    "initial",
    "shared_server",
    "shared_author",
    "shared_probe",
    "shared_forgery_probe",
    "independent_probe",
    "targets_sha256",
}


def request(value: object) -> dict[str, object]:  # noqa: PLR0912 - explicit immutable probe bindings
    selected = fields(value, REQUEST_FIELDS)
    if selected["format"] != REQUEST_FORMAT:
        raise LifecycleError("Connect genesis request format is invalid")
    epoch = identity(selected["epoch"])
    revision(selected["helper_revision"])
    revision(selected["registry_revision"])
    for key in ("anchor", "shared_server", "shared_author"):
        account_identity(selected[key])
    vaults = strings(fields(selected["vaults"], {"provision", "cleanup", "production", "journal"}))
    if len(set(vaults.values())) != len(vaults):
        raise LifecycleError("Connect genesis vault roles overlap")
    for vault in vaults.values():
        if re.fullmatch(r"[a-z0-9]{26}", vault) is None:
            raise LifecycleError("Connect genesis vault identity is invalid")
    initial = strings(selected["initial"])
    if not initial:
        raise LifecycleError("Connect genesis has no approved initial inventory")
    for key, expected in initial.items():
        identity(key)
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise LifecycleError("Connect genesis inventory digest is invalid")
    for key in ("anchor_sha256", "targets_sha256"):
        value = selected[key]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise LifecycleError("Connect genesis digest is invalid")
    for role in ("shared", "independent"):
        probe = validate(selected[role + "_probe"])
        if (
            probe["kind"] != "run"
            or probe["run_id"] != epoch
            or probe["payload"] != {"format": PROBE_FORMAT, "epoch": epoch, "actor": role}
            or (role == "shared" and initial.get(str(probe["event_id"])) != digest(probe))
            or (role == "independent" and str(probe["event_id"]) in initial)
        ):
            raise LifecycleError("Connect genesis provenance probe is misbound")
    forged = validate(selected["shared_forgery_probe"])
    claimed = fields(forged["payload"], {"format", "epoch", "actor", "claimed_author"})
    account_identity(claimed["claimed_author"])
    if (
        forged["kind"] != "run"
        or forged["run_id"] != epoch
        or claimed["format"] != PROBE_FORMAT
        or claimed["epoch"] != epoch
        or claimed["actor"] != "shared-forgery"
        or claimed["claimed_author"] == selected["shared_author"]
        or initial.get(str(forged["event_id"])) != digest(forged)
    ):
        raise LifecycleError("Connect shared forgery probe is misbound")
    return selected


def discover_author(ledger: ConnectLedger, probe: dict[str, object], *, shared_author: str) -> str:
    """Before genesis, learn the independent author for the shared-side forgery probe."""
    validate(probe)
    payload = fields(probe["payload"], {"format", "epoch", "actor"})
    if probe["kind"] != "run" or payload != {
        "format": PROBE_FORMAT,
        "epoch": identity(probe["run_id"]),
        "actor": "independent",
    }:
        raise LifecycleError("Connect independent discovery probe is invalid")
    ledger.stage(probe, claimed_author=account_identity(shared_author))
    ledger.records()
    authors = ledger.authors(probe)
    if len(authors) != 1 or shared_author in authors:
        raise LifecycleError("Connect cannot prove distinct immutable native authors")
    return authors.pop()


def initialize(  # noqa: PLR0913 - independent authority, provider identities and epoch are explicit
    ledger: ConnectLedger,
    store: Store,
    approved: object,
    *,
    helper: str,
    server: str,
    authority: Authority,
    now: datetime,
) -> dict[str, object]:
    selected = request(approved)
    server = account_identity(server)
    vaults = strings(selected["vaults"])
    if (
        revision(helper) != selected["helper_revision"]
        or server == selected["shared_server"]
        or ledger.vault != vaults["journal"]
        or ledger.anchor != selected["anchor"]
        or ledger.anchor_sha256 != selected["anchor_sha256"]
    ):
        raise LifecycleError("Connect genesis helper or independent server differs")
    authority.require(now + LIFETIME)
    initial = strings(selected["initial"])
    shared = validate(selected["shared_probe"])
    shared_forgery = validate(selected["shared_forgery_probe"])
    probe = validate(selected["independent_probe"])
    before = [record for record in ledger.records() if not acknowledgement(record)]
    prior = {str(record["event_id"]): digest(record) for record in before if record != probe}
    if (
        prior != initial
        or any(record["kind"] == "intent" for record in before)
        or ledger.authors(shared) != {selected["shared_author"]}
        or ledger.authors(shared_forgery) != {selected["shared_author"]}
    ):
        raise LifecycleError("Connect genesis inventory or shared provenance differs")
    # Trying to forge the other server's author must not survive native readback.
    # A lost response is reconciled from the original event; it is never replayed.
    author = discover_author(ledger, probe, shared_author=str(selected["shared_author"]))
    records = [record for record in ledger.records() if not acknowledgement(record)]
    complete = {**initial, str(probe["event_id"]): digest(probe)}
    if {str(record["event_id"]): digest(record) for record in records} != complete or fields(
        shared_forgery["payload"], {"format", "epoch", "actor", "claimed_author"}
    )["claimed_author"] != author:
        raise LifecycleError("Connect cannot prove distinct immutable native authors")
    checkpoint = Checkpoint(
        store, epoch=str(selected["epoch"]), genesis=None, initial=complete, initialize=True
    )
    checkpoint.restore()
    if checkpoint.head is not None and (
        checkpoint.sequence != 1 or checkpoint.records != {str(r["event_id"]): r for r in records}
    ):
        raise LifecycleError("Connect genesis already progressed; never initialize it again")
    genesis = checkpoint.persist(records)
    # Receipt installation binds the complete encrypted genesis, not a caller's
    # smaller minimum set. No ordinary worker may initialize a missing registry.
    return {
        "format": RECEIPT_FORMAT,
        "request_sha256": digest(selected),
        "epoch": selected["epoch"],
        "helper_revision": helper,
        "registry_revision": selected["registry_revision"],
        "initial": complete,
        "genesis": {"identity": genesis.identity, "sha256": genesis.sha256},
        "independent_server": server,
        "independent_author": author,
        "shared_author": selected["shared_author"],
        "authority_sha256": authority.identity_sha256,
        "authority_expires_at": stamp(authority.valid_until),
        "observed_at": stamp(now),
        "forged_author_ignored": True,
        "shared_forged_author_ignored": True,
        "provider_children_created": False,
    }
