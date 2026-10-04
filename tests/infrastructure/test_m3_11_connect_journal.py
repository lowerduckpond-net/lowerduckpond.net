"""Exercise creation and revocation across two caches and independent checkpoints."""

from __future__ import annotations

import copy
import uuid
from pathlib import Path
from typing import override

import pytest

from infrastructure.test_m3_11_connect_checkpoint import StoreDouble
from infrastructure.test_m3_11_connect_ledger import (
    ANCHOR,
    REMOTE_AUTHOR,
    REMOTE_SERVER,
    Replica,
    ledger,
    note,
)
from infrastructure.test_m3_11_unattended_lifecycle import Case as LifecycleCase
from scripts.m3_11_unattended.connect_api import Response
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint
from scripts.m3_11_unattended.connect_journal import ConnectJournal, IndependentJournal, Witness
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import LifecycleError, digest


class RemoteReplica(Replica):
    def __init__(self, anchor: dict[str, object]) -> None:
        super().__init__(anchor)
        self.posts = 1000  # Different provider-assigned item IDs from the shared cache double.

    @override
    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        try:
            response = super().request(method, path, body)
        finally:
            if method == "POST":
                for key, value in self.items.items():
                    if key != ANCHOR and int(key) > 1000:  # noqa: PLR2004 - remote provider IDs
                        value["lastEditedBy"] = REMOTE_AUTHOR
                if self.late is not None:
                    self.late[1]["lastEditedBy"] = REMOTE_AUTHOR
        if method == "POST" and isinstance(response.body, dict):
            return Response(response.status, copy.deepcopy(self.items[str(response.body["id"])]))
        return response


def sync(source: Replica, target: Replica) -> None:
    for key, value in source.items.items():
        if key not in target.items:
            target.items[key] = copy.deepcopy(value)
            target.version += 1


class Case:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.anchor = event("run", str(uuid.uuid7()), {"initial": True})
        self.shared, self.remote = Replica(self.anchor), RemoteReplica(self.anchor)
        self.initial = {str(self.anchor["event_id"]): digest(self.anchor)}
        self.store = StoreDouble()
        epoch = str(uuid.uuid7())
        checkpoint = Checkpoint(
            self.store, epoch=epoch, genesis=None, initial=self.initial, initialize=True
        )
        genesis = checkpoint.persist([self.anchor])
        self.witness = Witness(epoch, "a" * 40, REMOTE_SERVER, REMOTE_AUTHOR, genesis)
        self.controller = self.local()
        self.github = self.independent()

    def local(self) -> ConnectJournal:
        return ConnectJournal(
            ledger(self.shared, self.path / "controller", self.anchor),
            self.witness,
            wait_seconds=0,
        )

    def independent(self, *, directory: str = "github") -> IndependentJournal:
        return IndependentJournal(
            ledger(self.remote, self.path / directory, self.anchor),
            Checkpoint(
                self.store,
                epoch=self.witness.epoch,
                genesis=self.witness.genesis,
                initial=self.initial,
            ),
            self.witness,
        )

    def witness_once(self) -> None:
        sync(self.shared, self.remote)
        self.github.acknowledge(run_id=10, attempt=1)
        sync(self.remote, self.shared)


def test_provider_creation_waits_for_independent_checkpoint(tmp_path: Path) -> None:
    case = Case(tmp_path)
    runtime = LifecycleCase(tmp_path / "unused-local-double")
    runtime.lifecycle.journal = case.controller
    with pytest.raises(LifecycleError, match="independent persistence"):
        runtime.create()
    assert runtime.provider.creates == 0
    assert len(case.store.values) == 1
    case.witness_once()
    intents = [value for value in case.controller.records() if value["kind"] == "intent"]
    assert len(intents) == 1 and case.controller.confirmed(intents[0])
    # A failed attempt cannot restart creation even after a late ACK arrives.
    with pytest.raises(LifecycleError, match="cannot be replayed"):
        runtime.create()
    assert runtime.provider.creates == 0


def test_live_lifecycle_logic_uses_durable_intents_ids_and_denial_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    case.controller.wait_seconds = 1
    monkeypatch.setattr(
        "scripts.m3_11_unattended.connect_journal.time.sleep", lambda _seconds: case.witness_once()
    )
    runtime = LifecycleCase(tmp_path / "unused-local-double")
    runtime.lifecycle.journal = case.controller

    def before_create() -> None:
        persisted = case.store.values[max(case.store.values)]["records"]
        assert isinstance(persisted, list)
        assert any(row["kind"] == "intent" for row in persisted)

    runtime.provider.on_create = before_create
    intent, credential = runtime.create()
    assert runtime.provider.creates == 1
    runtime.lifecycle.request_revocation(runtime.run_id)
    assert runtime.lifecycle.reconcile(intent, credential).status == "verified"
    assert not runtime.provider.items
    persisted = case.store.values[max(case.store.values)]["records"]
    assert isinstance(persisted, list)
    assert {"intent", "created", "cleanup", "resolved"} <= {row["kind"] for row in persisted}
    assert credential.secret not in repr(case.store.values)
    assert credential.secret not in repr(case.shared.items)
    runtime.lifecycle.require_clear()


def test_delayed_stage_retry_preserves_original_event_across_restart(tmp_path: Path) -> None:
    case = Case(tmp_path)
    original = event("created", str(case.anchor["run_id"]), {"credential_id": "owned-double"})
    case.shared.fail = "before"
    with pytest.raises(LifecycleError):
        case.controller.persist(original)
    restarted = case.local()
    retry = event("created", str(case.anchor["run_id"]), {"credential_id": "owned-double"})
    with pytest.raises(LifecycleError, match="no duplicate"):
        restarted.persist(retry)
    assert case.shared.posts == 1
    assert case.shared.late is not None
    case.shared.items[case.shared.late[0]] = case.shared.late[1]
    case.shared.version += 1
    case.witness_once()
    assert restarted.persist(retry) == original
    assert case.shared.posts == 1


def test_checkpoint_failure_never_acknowledges_a_shared_write(tmp_path: Path) -> None:
    case = Case(tmp_path)
    record = event("intent", str(case.anchor["run_id"]), {"name": "owned-double"})
    case.controller.append(record)
    case.store.failure = "before-upload"
    with pytest.raises(LifecycleError):
        case.witness_once()
    assert not case.controller.confirmed(record)
    assert case.remote.posts == 1000  # noqa: PLR2004 - unchanged initial provider counter


def test_independent_restart_recovers_id_with_empty_replica_and_keeps_readiness_false(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    record = event("created", str(case.anchor["run_id"]), {"credential_id": "recovered-owned"})
    case.github.persist(record)
    case.remote.items.clear()
    restarted = case.independent(directory="github-restarted")
    assert record in restarted.records()
    assert not restarted.cache_complete
    with pytest.raises(LifecycleError, match="incomplete"):
        restarted.acknowledge(run_id=11, attempt=1)
    # Recovery can continue recording exact provider removal while the cache is down.
    proof = event("resolved", str(record["run_id"]), {"provider_readback": "absent"})
    assert restarted.persist(proof) == proof
    assert proof in restarted.checkpoint.records.values()
    assert not restarted.cache_complete


def test_restarted_independent_writer_never_mistakes_partial_replica_for_complete(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    record = event("created", str(case.anchor["run_id"]), {"credential_id": "recovered-owned"})
    case.github.persist(record)
    case.remote.items = {ANCHOR: note(case.anchor, ANCHOR)}
    case.remote.version += 1
    restarted = case.independent(directory="github-restarted")
    assert record in restarted.records()
    assert not restarted.cache_complete
    with pytest.raises(LifecycleError, match="incomplete"):
        restarted.acknowledge(run_id=11, attempt=1)
    restarted.persist(record)
    assert record in restarted.records() and restarted.cache_complete


def test_acknowledgements_never_generate_a_recursive_checkpoint_or_ack(tmp_path: Path) -> None:
    case = Case(tmp_path)
    record = event("result", str(case.anchor["run_id"]), {"outcome": "failed"})
    case.controller.append(record)
    case.witness_once()
    checkpoints, posts = len(case.store.values), case.remote.posts
    case.witness_once()
    assert len(case.store.values) == checkpoints
    assert case.remote.posts == posts


def test_cancelled_wait_does_not_accept_an_unconfirmed_record(tmp_path: Path) -> None:
    case = Case(tmp_path)

    def cancelled() -> None:
        raise LifecycleError("cancelled")

    case.controller.check_cancelled = cancelled
    with pytest.raises(LifecycleError, match="cancelled"):
        case.controller.persist(event("run", str(uuid.uuid7()), {"binding": "double"}))
