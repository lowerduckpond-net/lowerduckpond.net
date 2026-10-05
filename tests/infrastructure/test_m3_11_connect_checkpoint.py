"""Off-host checkpoint fault boundaries; caches cannot authorize forgotten obligations."""

from __future__ import annotations

import copy
import uuid

import pytest

from scripts.m3_11_unattended.connect_checkpoint import Checkpoint, Stored
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import LifecycleError, digest


class StoreDouble:
    def __init__(self) -> None:
        self.values: dict[int, dict[str, object]] = {}
        self.registry: list[Stored] = []
        self.failure = ""
        self.stale: int | None = None

    def latest(self) -> Stored | None:
        history = self.lineage()
        return history[-1] if history else None

    def lineage(self) -> tuple[Stored, ...]:
        if self.failure == "inventory":
            raise LifecycleError("registry unavailable")
        history = tuple(self.registry)
        if self.stale is not None:
            index = next(i for i, item in enumerate(history) if item.identity == self.stale)
            return history[: index + 1]
        return history

    def read(self, stored: Stored) -> dict[str, object]:
        if self.failure == "download":
            raise LifecycleError("checkpoint unavailable")
        if stored.identity not in self.values:
            raise LifecycleError("checkpoint unavailable")
        value = copy.deepcopy(self.values[stored.identity])
        if self.failure == "wrong-download":
            value["records"] = []
        return value

    def create(self, document: dict[str, object]) -> Stored:
        if self.failure == "before-upload":
            raise LifecycleError("upload unavailable")
        key = 10_000 - len(self.registry)
        self.values[key] = copy.deepcopy(document)
        self.registry.append(Stored(key, digest(document)))
        if self.failure == "after-upload":
            raise LifecycleError("upload outcome uncertain")
        return Stored(key, digest(document))


class Case:
    def __init__(self) -> None:
        self.store = StoreDouble()
        self.epoch = str(uuid.uuid7())
        self.run = event("run", str(uuid.uuid7()), {"binding": {"helper_revision": "a" * 40}})
        self.intent = event("intent", str(self.run["run_id"]), {"name": "unique-owned-double"})
        self.initial = {str(self.run["event_id"]): digest(self.run)}
        self.checkpoint = self.open(initialize=True)

    def open(self, *, initialize: bool = False, genesis: Stored | None = None) -> Checkpoint:
        return Checkpoint(
            self.store,
            epoch=self.epoch,
            genesis=genesis,
            initial=self.initial,
            initialize=initialize,
        )


def test_empty_registry_needs_explicit_initialization() -> None:
    case = Case()
    with pytest.raises(LifecycleError, match="missing"):
        case.open().restore()
    genesis = case.checkpoint.persist([case.run])
    restarted = case.open(genesis=genesis)
    restarted.restore()
    assert restarted.records == {case.run["event_id"]: case.run}


def test_ack_can_only_follow_independent_checkpoint_readback() -> None:
    case = Case()
    case.checkpoint.persist([case.run])
    published = []

    def persist_then_ack() -> None:
        stored = case.checkpoint.persist([case.run, case.intent])
        # This represents the actual external observer at the ACK boundary.
        observed = case.store.read(stored)["records"]
        assert isinstance(observed, list) and case.intent in observed
        published.append(stored)

    case.store.failure = "before-upload"
    with pytest.raises(LifecycleError):
        persist_then_ack()
    assert published == []
    case.store.failure = ""
    persist_then_ack()
    assert len(published) == 1


def test_lost_upload_reply_is_recovered_without_losing_records() -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    case.store.failure = "after-upload"
    with pytest.raises(LifecycleError):
        case.checkpoint.persist([case.run, case.intent])
    case.store.failure = ""
    restarted = case.open(genesis=genesis)
    restarted.restore()
    assert restarted.records[str(case.intent["event_id"])] == case.intent
    count = len(case.store.values)
    restarted.persist([case.run, case.intent])
    assert len(case.store.values) == count


@pytest.mark.parametrize("fault", ["inventory", "download", "wrong-download", "missing"])
def test_checkpoint_failure_never_falls_back_to_old_success(fault: str) -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    case.checkpoint.persist([case.run, case.intent])
    if fault == "missing":
        case.store.values.clear()
    else:
        case.store.failure = fault
    with pytest.raises(LifecycleError):
        case.open(genesis=genesis).restore()
    assert case.checkpoint.records[str(case.intent["event_id"])] == case.intent


def test_stable_old_connect_snapshot_cannot_replace_acknowledged_obligation() -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    case.checkpoint.persist([case.run, case.intent])
    restarted = case.open(genesis=genesis)
    restarted.restore()
    with pytest.raises(LifecycleError, match="lost"):
        restarted.persist([case.run])
    assert restarted.merge([case.run]) == [case.run, case.intent]


def test_registry_rollback_below_retained_identity_is_rejected() -> None:
    case = Case()
    old = case.checkpoint.persist([case.run])
    current = case.checkpoint.persist([case.run, case.intent])
    case.store.stale = old.identity
    with pytest.raises(LifecycleError, match="backwards"):
        case.checkpoint.restore()
    with pytest.raises(LifecycleError, match="backwards"):
        case.open(genesis=current).restore()


def test_recovered_provider_id_survives_replica_and_process_loss() -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run, case.intent])
    recovered = event(
        "created",
        str(case.run["run_id"]),
        {
            "intent_sha256": digest(case.intent["payload"]),
            "credential_id": "owned-lost-response-id",
        },
    )
    # Reconciliation may DELETE only after this returns. The next process can
    # reconstruct the exact ID even if the provider no longer lists it.
    case.checkpoint.persist([case.run, case.intent, recovered])
    restarted = case.open(genesis=genesis)
    restarted.restore()
    assert recovered in restarted.merge([case.run])


def test_checkpoint_does_not_adopt_changed_known_record() -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run, case.intent])
    restarted = case.open(genesis=genesis)
    restarted.restore()
    altered = {**case.intent, "payload": {"name": "different-existing-production-key"}}
    with pytest.raises(LifecycleError, match="disagree"):
        restarted.merge([case.run, altered])
    with pytest.raises(LifecycleError, match="changed"):
        restarted.persist([case.run, altered])


def test_lower_id_successor_recovers_original_genesis_and_exact_records() -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    current = case.checkpoint.persist([case.run, case.intent])
    assert current.identity < genesis.identity
    restarted = case.open(genesis=genesis)
    restarted.restore()
    assert restarted.history == (genesis, current)
    assert restarted.sequence == len((genesis, current))
    assert restarted.persist([case.run, case.intent]) == current
    assert tuple(case.store.registry) == (genesis, current)


@pytest.mark.parametrize("fault", ["sequence", "parent", "genesis", "replay", "fork"])
def test_lineage_must_extend_the_exact_retained_history(fault: str) -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    current = case.checkpoint.persist([case.run, case.intent])
    if fault in {"sequence", "parent"}:
        # An otherwise correctly hashed latest payload cannot invent its position.
        value = case.store.values[current.identity]
        value["sequence" if fault == "sequence" else "previous"] = (
            3 if fault == "sequence" else {"identity": 99, "sha256": genesis.sha256}
        )
        case.store.registry[-1] = Stored(current.identity, digest(value))
    elif fault == "genesis":
        case.store.registry[0] = Stored(genesis.identity, "f" * 64)
    elif fault == "replay":
        case.store.registry.append(genesis)
    else:
        case.store.registry[-1] = Stored(999_999, current.sha256)
        case.store.values[999_999] = copy.deepcopy(case.store.values[current.identity])
    # Fresh processes require genesis/sequence/parent proof; a retained process
    # must additionally refuse a sibling fork at the same sequence.
    observer = case.checkpoint if fault == "fork" else case.open(genesis=genesis)
    with pytest.raises(LifecycleError):
        observer.restore()


def test_failed_download_still_remembers_the_observed_new_head() -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    observer = case.open(genesis=genesis)
    observer.restore()
    case.checkpoint.persist([case.run, case.intent])
    case.store.failure = "download"
    with pytest.raises(LifecycleError, match="unavailable"):
        observer.restore()
    case.store.failure = ""
    case.store.stale = genesis.identity
    with pytest.raises(LifecycleError, match="backwards"):
        observer.restore()


@pytest.mark.parametrize("fault", ["reused-id", "missing-registration", "fork"])
def test_creation_requires_exact_history_extension(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case()
    genesis = case.checkpoint.persist([case.run])
    create = case.store.create

    def changed(document: dict[str, object]) -> Stored:
        created = create(document)
        if fault == "reused-id":
            return Stored(genesis.identity, created.sha256)
        if fault == "missing-registration":
            case.store.registry.pop()
        else:
            case.store.registry[0] = Stored(1, genesis.sha256)
        return created

    monkeypatch.setattr(case.store, "create", changed)
    with pytest.raises(LifecycleError, match=r"unverified|registry readback"):
        case.checkpoint.persist([case.run, case.intent])
    assert case.checkpoint.head == genesis
