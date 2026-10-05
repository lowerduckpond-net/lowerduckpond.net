"""Exercise creation and revocation across two caches and independent checkpoints."""

from __future__ import annotations

import copy
import time
import uuid
from datetime import UTC, datetime, timedelta
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
from infrastructure.test_m3_11_unattended_controller import subject
from infrastructure.test_m3_11_unattended_lifecycle import Case as LifecycleCase
from scripts.m3_11_unattended import cleanup
from scripts.m3_11_unattended.cleanup import require_independent_ready, status_document
from scripts.m3_11_unattended.connect_api import TIMEOUT_SECONDS, Response
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint
from scripts.m3_11_unattended.connect_journal import (
    ACK_POLL_SECONDS,
    ACK_WAIT_SECONDS,
    ConnectJournal,
    IndependentJournal,
    Witness,
)
from scripts.m3_11_unattended.github_checkpoint import MINIMUM_START_CAPACITY
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import ROLES, LifecycleError, digest, stamp


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
        self.github.acknowledge(run_id=10, attempt=1, allow=lambda _record: True)
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
        persisted = case.store.read(case.store.registry[-1])["records"]
        assert isinstance(persisted, list)
        assert any(row["kind"] == "intent" for row in persisted)

    runtime.provider.on_create = before_create
    intent, credential = runtime.create()
    assert runtime.provider.creates == 1
    runtime.lifecycle.request_revocation(runtime.run_id)
    assert runtime.lifecycle.reconcile(intent, credential).status == "verified"
    assert not runtime.provider.items
    persisted = case.store.read(case.store.registry[-1])["records"]
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
        restarted.acknowledge(run_id=11, attempt=1, allow=lambda _record: True)
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
        restarted.acknowledge(run_id=11, attempt=1, allow=lambda _record: True)
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


@pytest.mark.parametrize(
    "fault", ["none", "local-author", "capacity", "stale", "helper", "cache", "epoch", "hash"]
)
def test_readiness_needs_independent_authorship_freshness_and_reserved_capacity(
    tmp_path: Path,
    fault: str,
) -> None:
    case = Case(tmp_path)
    now = datetime.now(UTC)
    case.controller.append(event("run", str(uuid.uuid7()), {"lower-id-readiness": True}))
    case.witness_once()
    case.github.capacity = lambda: MINIMUM_START_CAPACITY + 1
    connect = case.github.readiness()
    pointer = connect["checkpoint"]
    assert isinstance(pointer, dict)
    assert int(str(pointer["identity"])) < case.witness.genesis.identity
    value: dict[str, object] = {
        "actor": "github",
        "helper_revision": case.witness.helper,
        "observed_at": stamp(now),
        "status": "ready",
        "overdue": 0,
        "results": [],
        "connect": connect,
    }
    if fault == "capacity":
        connect["remaining_capacity"] = MINIMUM_START_CAPACITY - 1
    elif fault == "stale":
        value["observed_at"] = stamp(now - timedelta(hours=2))
    elif fault == "helper":
        value["helper_revision"] = "b" * 40
    elif fault == "cache":
        connect["cache_complete"] = False
    elif fault == "epoch":
        connect["epoch"] = str(uuid.uuid7())
    elif fault == "hash":
        connect["checkpoint"] = {"identity": case.witness.genesis.identity, "sha256": "f" * 64}
    heartbeat = event("heartbeat", str(uuid.uuid7()), value)
    if fault == "local-author":
        case.controller.append(heartbeat)
        case.witness_once()
        assert case.controller.confirmed(heartbeat)  # An ACK alone is insufficient.
    else:
        case.github.persist(heartbeat)
        case.witness_once()
    if fault == "none":
        require_independent_ready(case.controller, helper=case.witness.helper, now=now)
        assert (
            status_document(case.controller, helper=case.witness.helper, now=now)["new_start"]
            == "eligible-for-preflight"
        )
    else:
        with pytest.raises(LifecycleError):
            require_independent_ready(case.controller, helper=case.witness.helper, now=now)
        assert (
            status_document(case.controller, helper=case.witness.helper, now=now)["new_start"]
            == "blocked"
        )


def test_sanitized_status_cannot_treat_a_staged_denial_as_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = Case(tmp_path)
    runtime = LifecycleCase(tmp_path / "unused-local-double")
    runtime.lifecycle.journal = case.controller
    case.controller.wait_seconds = 1
    monkeypatch.setattr(
        "scripts.m3_11_unattended.connect_journal.time.sleep", lambda _seconds: case.witness_once()
    )
    intent, credential = runtime.create()
    case.controller.wait_seconds = 0
    runtime.lifecycle.request_revocation(runtime.run_id)
    assert runtime.lifecycle.reconcile(intent, credential).status == "unresolved"
    case.witness_once()  # Persist the authentication marker.
    assert runtime.lifecycle.reconcile(intent, credential).status == "unresolved"
    assert not runtime.provider.items
    assert any(record["kind"] == "resolved" for record in case.controller.records())
    now = datetime.now(UTC)
    assert status_document(case.controller, helper=case.witness.helper, now=now)["outstanding"] == 1
    case.witness_once()
    assert status_document(case.controller, helper=case.witness.helper, now=now)["outstanding"] == 0


@pytest.mark.parametrize("fault", ["none", "result-staged", "receipt-staged", "local-author"])
def test_rehearsal_gate_needs_durable_result_and_independently_authored_revocation_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path / "connect")
    selected, runtime = subject(tmp_path, monkeypatch)
    selected.helper = case.witness.helper
    owned = [runtime.create(role=role)[0].sha256 for role in ROLES]
    for record in runtime.journal.records():
        case.controller.append(record)
    result = event(
        "result",
        runtime.run_id,
        {
            "approval_sha256": selected.request["approval_sha256"],
            "qualification": "rehearsal-interrupted",
            "credential_cleanup": "verified",
        },
    )
    if fault != "result-staged":
        case.controller.append(result)
    case.witness_once()
    receipt = event(
        "heartbeat",
        str(uuid.uuid7()),
        {
            "actor": "github",
            "helper_revision": selected.helper,
            "results": [{"intent_sha256": value, "status": "verified"} for value in owned],
        },
    )
    if fault in {"receipt-staged", "local-author"}:
        case.controller.append(receipt)
    else:
        case.github.persist(receipt)
    if fault != "receipt-staged":
        case.witness_once()
    if fault == "result-staged":
        case.controller.append(result)
        assert not case.controller.confirmed(result)
    if fault == "none":
        selected._require_rehearsal(case.controller)
    else:
        with pytest.raises(LifecycleError):
            selected._require_rehearsal(case.controller)


def pending_readiness(case: Case, *, fault: str = "none") -> None:
    case.github.capacity = lambda: MINIMUM_START_CAPACITY + 1
    now = datetime.now(UTC)
    value = {
        "actor": "github",
        "helper_revision": case.witness.helper,
        "observed_at": stamp(now),
        "status": "ready",
        "overdue": 0,
        "results": [],
        "connect": case.github.readiness(),
    }
    if fault == "unresolved":
        value["status"] = "unresolved"
    elif fault == "helper":
        value["helper_revision"] = "f" * 40
    elif fault == "stale":
        value["observed_at"] = stamp(now - timedelta(hours=2))
    elif fault == "malformed":
        value["extra"] = "never-export-canary"
    case.github.persist(event("heartbeat", str(uuid.uuid7()), value))
    sync(case.remote, case.shared)


def test_new_native_readiness_waits_for_its_ack_without_falling_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    case.witness_once()
    require_independent_ready(case.controller, helper=case.witness.helper, now=datetime.now(UTC))
    pending_readiness(case)
    with pytest.raises(cleanup.ReadinessPendingError):
        require_independent_ready(
            case.controller, helper=case.witness.helper, now=datetime.now(UTC)
        )
    waits = []

    def acknowledge(seconds: float) -> None:
        waits.append(seconds)
        case.witness_once()

    monkeypatch.setattr(time, "sleep", acknowledge)
    cleanup.wait_independent_ready(
        case.controller,
        helper=case.witness.helper,
        deadline=time.monotonic() + 30,
        check_cancelled=lambda: None,
    )
    assert waits == [ACK_POLL_SECONDS]


@pytest.mark.parametrize("fault", ["unresolved", "helper", "stale", "malformed"])
def test_new_adverse_readiness_is_never_waited_past_or_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    case.witness_once()
    pending_readiness(case, fault=fault)
    monkeypatch.setattr(time, "sleep", lambda *_args: pytest.fail("adverse receipt must fail"))
    with pytest.raises((LifecycleError, ValueError)) as error:
        cleanup.wait_independent_ready(
            case.controller,
            helper=case.witness.helper,
            deadline=time.monotonic() + 30,
            check_cancelled=lambda: None,
        )
    assert not isinstance(error.value, cleanup.ReadinessPendingError)


@pytest.mark.parametrize("cancel", [True, False])
def test_readiness_wait_preserves_original_deadline_and_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    clock = [0.0]
    limit = 3.0
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def cancelled() -> None:
        if cancel and clock[0] >= limit:
            raise LifecycleError("cancelled")

    with pytest.raises(LifecycleError, match="cancelled" if cancel else "acknowledgement wait"):
        cleanup.wait_independent_ready(
            case.controller,
            helper=case.witness.helper,
            deadline=limit,
            check_cancelled=cancelled,
        )
    assert clock[0] == limit


def test_readiness_snapshot_reads_share_one_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    case.witness_once()
    clock = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    request, item = case.shared.request, case.shared.item
    observed: list[tuple[float, float]] = []

    def consume() -> None:
        budget = case.shared._request_timeout
        observed.append((clock[0], budget))
        clock[0] += min(20, budget)

    def slow_request(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        consume()
        return request(method, path, body)

    def slow_item(vault: str, selected_item: str) -> dict[str, object]:
        consume()
        return item(vault, selected_item)

    monkeypatch.setattr(case.shared, "request", slow_request)
    monkeypatch.setattr(case.shared, "item", slow_item)
    with pytest.raises(LifecycleError, match="deadline elapsed"):
        cleanup.wait_independent_ready(
            case.controller,
            helper=case.witness.helper,
            deadline=600,
            check_cancelled=lambda: None,
        )
    assert observed == [(0, 30), (20, 30), (40, 30), (60, 30), (80, 30), (100, 20)]
    assert clock[0] == ACK_WAIT_SECONDS
    assert case.controller.ledger._read_deadline is None
    assert case.shared._request_timeout == TIMEOUT_SECONDS


def test_readiness_rejects_late_success_after_complete_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    case.witness_once()
    clock = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    records = case.controller.ledger.records

    def delayed_result() -> list[dict[str, object]]:
        snapshot = records()
        clock[0] += ACK_WAIT_SECONDS + 1
        return snapshot

    monkeypatch.setattr(case.controller.ledger, "records", delayed_result)
    with pytest.raises(cleanup.ReadinessPendingError, match="acknowledgement wait"):
        cleanup.wait_independent_ready(
            case.controller,
            helper=case.witness.helper,
            deadline=600,
            check_cancelled=lambda: None,
        )


def test_readiness_cancellation_stops_snapshot_io_and_leaves_cleanup_uncancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    case.witness_once()
    cancelled = False
    calls = 0
    request = case.shared.request
    original_check = case.controller.check_cancelled

    def check() -> None:
        if cancelled:
            raise LifecycleError("controller cancelled during readiness")

    def cancel_after_read(
        method: str, path: str, body: dict[str, object] | None = None
    ) -> Response:
        nonlocal cancelled, calls
        calls += 1
        result = request(method, path, body)
        cancelled = True
        return result

    monkeypatch.setattr(case.shared, "request", cancel_after_read)
    with pytest.raises(LifecycleError, match="cancelled during readiness"):
        cleanup.wait_independent_ready(
            case.controller,
            helper=case.witness.helper,
            deadline=time.monotonic() + 600,
            check_cancelled=check,
        )
    assert calls == 1
    assert case.controller.check_cancelled is original_check
    assert case.controller.ledger._read_deadline is None
    case.github.ledger.check_cancelled()
    revoke = event("revoke", str(case.anchor["run_id"]), {"reason": "terminal-path"})
    assert case.github.persist(revoke) == revoke
    # The admission observation must not poison this same reader for cleanup.
    assert case.controller.records()


@pytest.mark.parametrize("acknowledged", [True, False])
def test_readiness_and_ack_use_one_complete_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, acknowledged: bool
) -> None:
    case = Case(tmp_path)
    pending_readiness(case)
    if acknowledged:
        case.witness_once()
    records = case.controller.ledger.records
    calls = 0

    def newer_receipt_after_snapshot() -> list[dict[str, object]]:
        nonlocal calls
        snapshot = records()
        calls += 1
        if calls == 1:
            case.witness_once()
            pending_readiness(case, fault="unresolved")
        return snapshot

    monkeypatch.setattr(case.controller.ledger, "records", newer_receipt_after_snapshot)
    if acknowledged:
        require_independent_ready(
            case.controller, helper=case.witness.helper, now=datetime.now(UTC)
        )
    else:
        # A later ACK must not confirm a candidate from an earlier snapshot
        # while overlooking the adverse receipt accompanying that later ACK.
        with pytest.raises(cleanup.ReadinessPendingError):
            require_independent_ready(
                case.controller, helper=case.witness.helper, now=datetime.now(UTC)
            )
    assert calls == 1
    with pytest.raises(LifecycleError, match="stale, overdue"):
        require_independent_ready(
            case.controller, helper=case.witness.helper, now=datetime.now(UTC)
        )
    assert calls == 2  # noqa: PLR2004 - one snapshot per readiness check
