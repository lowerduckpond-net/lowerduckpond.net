"""Explicit genesis binds the full off-host inventory and actual native authors."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_connect_checkpoint import StoreDouble
from infrastructure.test_m3_11_connect_journal import Case as JournalCase
from infrastructure.test_m3_11_connect_journal import sync
from infrastructure.test_m3_11_connect_ledger import (
    ANCHOR,
    LOCAL_AUTHOR,
    REMOTE_AUTHOR,
    REMOTE_SERVER,
    VAULT,
    ledger,
)
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint
from scripts.m3_11_unattended.connect_genesis import PROBE_FORMAT, REQUEST_FORMAT, initialize
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import Authority, LifecycleError, digest


class Case:
    def __init__(self, tmp_path: Path, *, claimed_author: str = REMOTE_AUTHOR) -> None:
        self.journal = JournalCase(tmp_path)
        self.now = datetime.now(UTC)
        self.authority = Authority("a" * 64, self.now + timedelta(days=7))
        self.epoch = self.journal.witness.epoch
        shared = event(
            "run", self.epoch, {"format": PROBE_FORMAT, "epoch": self.epoch, "actor": "shared"}
        )
        self.journal.controller.append(shared)
        shared_forgery = event(
            "run",
            self.epoch,
            {
                "format": PROBE_FORMAT,
                "epoch": self.epoch,
                "actor": "shared-forgery",
                "claimed_author": claimed_author,
            },
        )
        self.journal.controller.ledger.stage(shared_forgery, claimed_author=claimed_author)
        sync(self.journal.shared, self.journal.remote)
        records = self.journal.controller.records()
        self.approved: dict[str, object] = {
            "format": REQUEST_FORMAT,
            "epoch": self.epoch,
            "helper_revision": self.journal.witness.helper,
            "registry_revision": "b" * 40,
            "vaults": {
                "journal": VAULT,
                "provision": "p" * 26,
                "cleanup": "c" * 26,
                "production": "d" * 26,
            },
            "anchor": ANCHOR,
            "anchor_sha256": digest(self.journal.anchor),
            "initial": {str(record["event_id"]): digest(record) for record in records},
            "shared_server": "Q" * 26,
            "shared_author": LOCAL_AUTHOR,
            "shared_probe": shared,
            "shared_forgery_probe": shared_forgery,
            "independent_probe": event(
                "run",
                self.epoch,
                {"format": PROBE_FORMAT, "epoch": self.epoch, "actor": "independent"},
            ),
            "targets_sha256": "e" * 64,
        }
        self.store = StoreDouble()
        self.ledger = ledger(self.journal.remote, tmp_path / "genesis", self.journal.anchor)

    def initialize(self) -> dict[str, object]:
        return initialize(
            self.ledger,
            self.store,
            self.approved,
            helper=self.journal.witness.helper,
            server=REMOTE_SERVER,
            authority=self.authority,
            now=self.now,
        )


def test_initial_inventory_matches_all_recoverable_genesis_records_and_native_authors(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    result = case.initialize()
    assert result["shared_author"] == LOCAL_AUTHOR
    assert result["independent_author"] == REMOTE_AUTHOR
    assert result["forged_author_ignored"] is True
    assert result["shared_forged_author_ignored"] is True
    assert result["provider_children_created"] is False
    latest = case.store.latest()
    assert latest is not None
    records = cast(list[dict[str, object]], case.store.read(latest)["records"])
    assert result["initial"] == {str(record["event_id"]): digest(record) for record in records}
    count = case.journal.remote.posts
    assert case.initialize() == result
    assert case.journal.remote.posts == count and len(case.store.values) == 1


@pytest.mark.parametrize(
    "fault",
    ["missing-event", "extra-event", "same-author", "same-cache", "helper", "anchor", "lifetime"],
)
def test_genesis_refuses_ambiguous_inventory_identity_and_cleanup_lifetime(
    tmp_path: Path, fault: str
) -> None:
    case = Case(tmp_path)
    if fault == "missing-event":
        cast(dict[str, object], case.approved["initial"]).pop(str(case.journal.anchor["event_id"]))
    elif fault == "extra-event":
        case.journal.controller.append(event("run", case.epoch, {"unexpected": True}))
        sync(case.journal.shared, case.journal.remote)
    elif fault == "same-author":
        # Native metadata is authoritative; self-declared actor labels cannot fix this.
        case.approved["shared_author"] = REMOTE_AUTHOR
    elif fault == "same-cache":
        case.ledger.client = case.journal.shared
    elif fault == "helper":
        case.approved["helper_revision"] = "f" * 40
    elif fault == "anchor":
        case.approved["anchor"] = "z" * 26
    else:
        case.authority = Authority("a" * 64, case.now + timedelta(hours=14))
    with pytest.raises(LifecycleError):
        case.initialize()
    assert not case.store.values


def test_lost_native_creation_reply_reconciles_without_another_provenance_item(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    case.journal.remote.fail = "after"
    result = case.initialize()
    assert result["forged_author_ignored"] is True
    count = case.journal.remote.posts
    case.journal.remote.fail = ""
    assert case.initialize() == result and case.journal.remote.posts == count


def test_lost_checkpoint_reply_reconciles_exact_genesis_and_never_rolls_over_epoch(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    case.store.failure = "after-upload"
    with pytest.raises(LifecycleError):
        case.initialize()
    case.store.failure = ""
    assert case.initialize()["epoch"] == case.epoch
    assert len(case.store.values) == 1


def test_existing_progress_cannot_be_reinitialized_as_an_empty_genesis(tmp_path: Path) -> None:
    case = Case(tmp_path)
    result = case.initialize()
    checkpoint = Checkpoint(
        case.store,
        epoch=case.epoch,
        genesis=case.store.latest(),
        initial=cast(dict[str, str], result["initial"]),
    )
    checkpoint.restore()
    checkpoint.persist([*checkpoint.records.values(), event("run", case.epoch, {"later": True})])
    before = copy.deepcopy(case.store.values)
    with pytest.raises(LifecycleError, match="progressed"):
        case.initialize()
    assert case.store.values == before


def test_shared_endpoint_accepting_the_independent_author_cannot_install_genesis(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    forged = cast(dict[str, object], case.approved["shared_forgery_probe"])
    for replica in (case.journal.shared, case.journal.remote):
        for item in replica.items.values():
            fields = cast(list[dict[str, str]], item["fields"])
            if json.loads(fields[0]["value"])["event_id"] == forged["event_id"]:
                item["lastEditedBy"] = REMOTE_AUTHOR
                replica.version += 1
    with pytest.raises(LifecycleError, match="shared provenance"):
        case.initialize()
    assert not case.store.values


def test_shared_probe_must_claim_the_actual_independent_author(tmp_path: Path) -> None:
    case = Case(tmp_path, claimed_author="X" * 26)
    with pytest.raises(LifecycleError, match="distinct immutable native authors"):
        case.initialize()
    assert not case.store.values
