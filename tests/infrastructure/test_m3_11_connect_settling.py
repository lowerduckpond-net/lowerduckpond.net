"""Delayed native readback must settle without replaying a mutation or authorizing it."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from infrastructure.test_m3_11_connect_action import reconcile
from infrastructure.test_m3_11_connect_activate import Case as ActivationCase
from infrastructure.test_m3_11_connect_admission import Case as AdmissionCase
from infrastructure.test_m3_11_connect_journal import Case, sync
from infrastructure.test_m3_11_connect_ledger import (
    ANCHOR,
    CANARY,
    Replica,
    confirmed,
    ledger,
    note,
)
from infrastructure.test_m3_11_unattended_lifecycle import Case as LifecycleCase
from infrastructure.test_m3_11_unattended_lifecycle import ProviderDouble
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended import connect_journal, connect_ledger
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.connect_admission import run_digest
from scripts.m3_11_unattended.connect_api import TIMEOUT_SECONDS, Response
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import LifecycleError


class Clock:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.tick: Callable[[], None] = lambda: None
        clock = SimpleNamespace(monotonic=lambda: self.now, sleep=self.sleep)
        monkeypatch.setattr(connect_ledger, "time", clock)
        monkeypatch.setattr(connect_journal, "time", clock)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        self.tick()


def delayed_posts(
    cache: Replica,
    monkeypatch: pytest.MonkeyPatch,
    *,
    only: Callable[[dict[str, object]], bool] | None = None,
) -> Callable[[], None]:
    """Successful POST replies arrive before the new item and version reach inventory."""
    request = cache.request
    pending: dict[str, dict[str, object]] = {}

    def delayed(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        response = request(method, path, body)
        if method == "POST":
            assert isinstance(response.body, dict)
            fields = cast(list[dict[str, object]], response.body["fields"])
            record = json.loads(str(fields[0]["value"]))
            if only is not None and not only(record):
                return response
            item = str(response.body["id"])
            pending[item] = cache.items.pop(item)
            cache.version -= 1
        return response

    monkeypatch.setattr(cache, "request", delayed)

    def publish() -> None:
        cache.items.update(copy.deepcopy(pending))
        cache.version += len(pending)
        pending.clear()

    return publish


@pytest.mark.parametrize("movement", ["none", "version", "count-ahead"])
def test_accepted_write_waits_for_complete_stable_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, movement: str
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 5
    clock = Clock(monkeypatch)
    publish = delayed_posts(case.shared, monkeypatch)
    record = event("intent", str(case.anchor["run_id"]), {"scope": CANARY})
    request = case.shared.request

    def ahead(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        response = request(method, path, body)
        if method == "POST" and movement == "count-ahead":
            case.shared.reported_count = len(case.shared.items) + 1
        return response

    monkeypatch.setattr(case.shared, "request", ahead)

    def tick() -> None:
        # The returned ID is retained before any readback wait begins.
        assert read_private(selected.spool / (str(record["event_id"]) + ".returned.json"))
        publish()
        case.shared.move_during_read = movement == "version" and len(clock.sleeps) == 1

    clock.tick = tick
    selected.stage(record)
    assert case.shared.posts == 1
    assert len(clock.sleeps) == (2 if movement == "version" else 1)
    assert record in selected.records()
    assert not confirmed(selected, record)


@pytest.mark.parametrize("moving", [False, True])
def test_lost_reply_arrives_during_restart_readback_without_reposting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moving: bool
) -> None:
    case = Case(tmp_path)
    record = event("intent", str(case.anchor["run_id"]), {"scope": CANARY})
    case.shared.fail = "before"
    with pytest.raises(LifecycleError, match="readback"):
        case.controller.ledger.stage(record)
    restarted = ledger(case.shared, tmp_path / "controller", case.anchor)
    restarted.readback_seconds = 5
    case.shared.move_during_read = moving
    clock = Clock(monkeypatch)

    def deliver() -> None:
        assert case.shared.late is not None
        key, item = case.shared.late
        case.shared.items[key] = item
        case.shared.version += 1
        case.shared.move_during_read = False

    clock.tick = deliver
    restarted.stage(record)
    assert case.shared.posts == 1
    assert record in restarted.records()
    assert not confirmed(restarted, record)


def test_changed_retained_intent_is_rejected_even_when_original_is_visible(tmp_path: Path) -> None:
    case = Case(tmp_path)
    record = event("intent", str(case.anchor["run_id"]), {"scope": CANARY})
    selected = case.controller.ledger
    selected.stage(record)
    path = selected.spool / (str(record["event_id"]) + ".json")
    path.write_bytes(canonical_bytes({**record, "payload": {"scope": "changed"}}))
    with pytest.raises(LifecycleError, match="stage intent changed"):
        selected.stage(record)
    assert case.shared.posts == 1


@pytest.mark.parametrize("fault", ["missing-write", "moving", "missing-known"])
def test_readback_timeout_preserves_uncertainty_and_never_accepts_missing_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 3
    clock = Clock(monkeypatch)
    record = event("created", str(case.anchor["run_id"]), {"credential_id": CANARY})
    prior = event("intent", str(case.anchor["run_id"]), {"scope": CANARY})
    case.shared.items["b" * 26] = note(prior, "b" * 26)
    selected.records()
    publish = delayed_posts(case.shared, monkeypatch)

    def tick() -> None:
        if fault != "missing-write":
            publish()
        if fault == "moving":
            case.shared.move_during_read = True
        if fault == "missing-known":
            case.shared.items.pop("b" * 26, None)

    clock.tick = tick
    with pytest.raises(LifecycleError, match=r"uncertain.*no duplicate") as error:
        selected.stage(record)
    assert CANARY not in str(error.value)
    assert clock.now == selected.readback_seconds
    assert case.shared.posts == 1
    assert read_private(selected.spool / (str(record["event_id"]) + ".json")) == record
    assert read_private(selected.spool / (str(record["event_id"]) + ".returned.json"))


def test_corrupt_metadata_is_fatal_without_waiting_or_retrying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    case.controller.ledger.readback_seconds = 5
    case.shared.corrupt_after_post = True
    clock = Clock(monkeypatch)
    with pytest.raises(LifecycleError, match="metadata"):
        case.controller.ledger.stage(event("intent", str(case.anchor["run_id"]), {}))
    assert case.shared.posts == 1
    assert clock.sleeps == []


@pytest.mark.parametrize("cached", [True, False])
def test_short_inventory_cannot_hide_malformed_present_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cached: bool
) -> None:
    case = Case(tmp_path)
    case.controller.ledger.readback_seconds = 5
    clock = Clock(monkeypatch)
    request = case.shared.request

    def malformed(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        response = request(method, path, body)
        if method == "POST":
            case.shared.reported_count = len(case.shared.items) + 1
        if method == "GET" and case.shared.posts and path.endswith("/items"):
            assert isinstance(response.body, list)
            for row in response.body:
                if (row["id"] == ANCHOR) == cached:
                    row["version"] = 0
        return response

    monkeypatch.setattr(case.shared, "request", malformed)
    with pytest.raises(LifecycleError, match="metadata is invalid"):
        case.controller.ledger.stage(event("intent", str(case.anchor["run_id"]), {}))
    assert case.shared.posts == 1
    assert clock.sleeps == []


def test_late_success_cannot_extend_the_readback_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 5
    clock = Clock(monkeypatch)
    records = selected.records

    def slow() -> list[dict[str, object]]:
        values = records()
        if case.shared.posts:
            clock.now += selected.readback_seconds + 1
        return values

    monkeypatch.setattr(selected, "records", slow)
    with pytest.raises(LifecycleError, match="uncertain"):
        selected.stage(event("intent", str(case.anchor["run_id"]), {}))
    assert case.shared.posts == 1
    assert clock.sleeps == []


def test_snapshot_io_receives_only_remaining_budget_and_stops_at_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 60
    clock = Clock(monkeypatch)
    request, item = case.shared.request, case.shared.item
    observed: list[tuple[str, float, float]] = []

    def consume(kind: str) -> None:
        if not case.shared.posts:
            return
        budget = case.shared._request_timeout
        observed.append((kind, clock.now, budget))
        clock.now += min(25, budget)
        if budget <= 25:  # noqa: PLR2004 - bounded slow-response double
            raise LifecycleError("bounded read timed out")

    def slow_request(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if method == "GET":
            consume("request")
        return request(method, path, body)

    def slow_item(vault: str, selected_item: str) -> dict[str, object]:
        consume("item")
        return item(vault, selected_item)

    monkeypatch.setattr(case.shared, "request", slow_request)
    monkeypatch.setattr(case.shared, "item", slow_item)
    with pytest.raises(LifecycleError, match="timed out"):
        selected.stage(event("intent", str(case.anchor["run_id"]), {}))
    assert observed == [("request", 0, 30), ("request", 25, 30), ("item", 50, 10)]
    assert clock.now == selected.readback_seconds
    assert case.shared.posts == 1
    assert selected._read_deadline is None
    assert case.shared._request_timeout == TIMEOUT_SECONDS


def test_cancellation_interrupts_readback_without_cancelling_independent_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    clock = Clock(monkeypatch)
    case.controller.ledger.readback_seconds = 5
    publish = delayed_posts(case.shared, monkeypatch)
    cancelled = False

    def check() -> None:
        if cancelled:
            raise LifecycleError("controller cancelled")

    def tick() -> None:
        nonlocal cancelled
        publish()
        cancelled = True

    clock.tick = tick
    case.controller.check_cancelled = check
    runtime = LifecycleCase(tmp_path / "provider")
    runtime.lifecycle.journal = case.controller
    with pytest.raises(LifecycleError, match="controller cancelled"):
        runtime.create()
    assert runtime.provider.creates == 0
    assert case.shared.posts == 1
    case.github.ledger.check_cancelled()  # Cleanup has its own uncancelled reader.
    sync(case.shared, case.remote)
    revoked = event("revoke", runtime.run_id, {"reason": "terminal-path"})
    assert case.github.persist(revoked) == revoked
    assert case.controller.ledger._read_deadline is None


def test_cancellation_during_successful_confirmation_prevents_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    cancelled = False

    def check() -> None:
        if cancelled:
            raise LifecycleError("controller cancelled after confirmation")

    def confirmed_then_cancelled(_record: dict[str, object]) -> bool:
        nonlocal cancelled
        cancelled = True
        return True

    case.controller.check_cancelled = check
    monkeypatch.setattr(case.controller, "confirmed", confirmed_then_cancelled)
    runtime = LifecycleCase(tmp_path / "provider")
    runtime.lifecycle.journal = case.controller
    with pytest.raises(LifecycleError, match="cancelled after confirmation"):
        runtime.create()
    assert runtime.provider.creates == 0


def test_unstable_precreation_inventory_still_prevents_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    case.controller.ledger.readback_seconds = 5
    case.shared.move_during_read = True
    clock = Clock(monkeypatch)
    with pytest.raises(LifecycleError, match="snapshot observation deadline"):
        case.controller.ledger.stage(event("intent", str(case.anchor["run_id"]), {}))
    assert case.shared.posts == 0
    assert clock.now == case.controller.ledger.readback_seconds
    assert clock.sleeps == [1] * case.controller.ledger.readback_seconds
    assert ANCHOR in case.shared.items


@pytest.mark.parametrize("entry", ["records", "original", "stage", "confirmed", "clear"])
def test_normal_controller_reads_wait_for_growth_without_replaying_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    case = Case(tmp_path)
    record = event("heartbeat", str(case.anchor["run_id"]), {"format": "local-double"})
    if entry == "confirmed":
        case.controller.append(record)
        case.witness_once()
    selected = case.controller.ledger
    selected.readback_seconds = 5
    clock = Clock(monkeypatch)
    case.shared.move_during_read = True
    clock.tick = lambda: setattr(case.shared, "move_during_read", False)
    if entry == "records":
        assert case.controller.records()
    elif entry == "original":
        assert case.controller._original(record) == record
    elif entry == "stage":
        selected.stage(record)
    elif entry == "confirmed":
        assert case.controller.confirmed(record)
    else:
        Lifecycle(case.controller, {}).require_clear()
    assert clock.sleeps == [1]
    assert case.shared.posts == (1 if entry in {"stage", "confirmed"} else 0)
    assert selected._read_deadline is None
    assert selected.minimum.items() <= selected._known.items()


@pytest.mark.parametrize("readback", [0, 5])
def test_actual_ack_arrival_during_confirmation_waits_without_restaging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, readback: int
) -> None:
    case = Case(tmp_path)
    record = event("intent", str(case.anchor["run_id"]), {"scope": "local-double"})
    case.controller.append(record)
    sync(case.shared, case.remote)
    case.github.acknowledge(run_id=42, attempt=1, allow=lambda _row: True)
    case.controller.ledger.readback_seconds = readback
    case.controller.wait_seconds = 30
    clock = Clock(monkeypatch)
    native = case.shared.request
    original_confirmed = case.controller.confirmed
    confirming = False
    reads = 0

    def arrive(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        if confirming and method == "GET" and path.endswith("/items"):
            reads += 1
            if reads == 2:  # noqa: PLR2004 - inject between inventory reads of confirmation
                sync(case.remote, case.shared)
        return native(method, path, body)

    def confirm(row: dict[str, object]) -> bool:
        nonlocal confirming
        confirming = True
        try:
            return original_confirmed(row)
        finally:
            confirming = False

    monkeypatch.setattr(case.shared, "request", arrive)
    monkeypatch.setattr(case.controller, "confirmed", confirm)
    assert case.controller.persist(record) == record
    assert clock.sleeps == [1 if readback else connect_journal.ACK_POLL_SECONDS]
    assert case.shared.posts == 1
    assert original_confirmed(record)
    assert case.controller.ledger._read_deadline is None


@pytest.mark.parametrize("cancel", [True, False])
def test_unstable_ack_observation_preserves_deadline_and_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    case = Case(tmp_path)
    record = event("intent", str(case.anchor["run_id"]), {"scope": "local-double"})
    case.controller.append(record)
    clock = Clock(monkeypatch)
    case.controller.wait_seconds = 3
    case.controller.ledger.readback_seconds = 60
    confirmed = case.controller.confirmed

    def moving(row: dict[str, object]) -> bool:
        case.shared.move_during_read = True
        return confirmed(row)

    def cancelled() -> None:
        if cancel and clock.sleeps:
            raise LifecycleError("cancelled ACK wait")

    monkeypatch.setattr(case.controller, "confirmed", moving)
    case.controller.check_cancelled = cancelled
    with pytest.raises(LifecycleError, match="cancelled ACK" if cancel else "deadline elapsed"):
        case.controller.persist(record)
    assert clock.now <= case.controller.wait_seconds
    assert case.shared.posts == 1
    assert case.controller.ledger._read_deadline is None
    assert case.shared._request_timeout == TIMEOUT_SECONDS
    case.github.ledger.check_cancelled()


@pytest.mark.parametrize("readback", [0, 60])
def test_nested_readback_never_replaces_an_outer_observation_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, readback: int
) -> None:
    case = Case(tmp_path)
    record = event("created", str(case.anchor["run_id"]), {"credential_id": "double"})
    case.controller.append(record)
    selected = case.controller.ledger
    selected.readback_seconds = readback
    clock = Clock(monkeypatch)
    request = case.shared.request
    budgets = []

    def slow(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        budgets.append(case.shared._request_timeout)
        clock.now += case.shared._request_timeout
        return request(method, path, body)

    monkeypatch.setattr(case.shared, "request", slow)
    limit = 2
    with selected.read_budget(deadline=limit, check_cancelled=lambda: None):
        with pytest.raises(LifecycleError, match="deadline elapsed"):
            selected._readback(record)
        assert selected._read_deadline == limit
    assert clock.now == limit and budgets == [limit]
    assert getattr(selected, "_read_deadline") is None  # noqa: B009 - context manager restores the narrowed attribute
    assert case.shared.posts == 1
    assert read_private(selected.spool / (str(record["event_id"]) + ".returned.json"))


@pytest.mark.parametrize("new_item", [True, False])
@pytest.mark.parametrize(
    "field", ["version", "lastEditedBy", "createdAt", "tags", "category", "vault", "state", "title"]
)
def test_stability_wait_cannot_hide_malformed_metadata_in_the_second_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new_item: bool, field: str
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 5
    clock = Clock(monkeypatch)
    native = case.shared.request
    reads = 0

    def malformed(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        response = native(method, path, body)
        if path.endswith("/items"):
            reads += 1
            if reads == 2:  # noqa: PLR2004 - only the verification inventory is malformed
                assert isinstance(response.body, list)
                if new_item:
                    response.body.append(note(case.anchor, "b" * 26))
                response.body[-1][field] = 0 if field == "version" else CANARY
        return response

    monkeypatch.setattr(case.shared, "request", malformed)
    with pytest.raises(LifecycleError) as failure:
        case.controller.records()
    assert not isinstance(failure.value, connect_ledger.SnapshotChangedError)
    assert clock.sleeps == [] and case.shared.posts == 0
    assert CANARY not in str(failure.value)


def test_stability_wait_rejects_valid_but_changed_metadata_of_an_immutable_item(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    case.controller.ledger.readback_seconds = 5
    clock = Clock(monkeypatch)
    native = case.shared.request
    reads = 0

    def changed(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        response = native(method, path, body)
        if path.endswith("/items"):
            reads += 1
            if reads == 2:  # noqa: PLR2004 - valid author, changed only in second inventory
                assert isinstance(response.body, list)
                response.body[0]["lastEditedBy"] = "R" * 26
        return response

    monkeypatch.setattr(case.shared, "request", changed)
    with pytest.raises(LifecycleError, match="metadata changed"):
        case.controller.records()
    assert clock.sleeps == [] and case.shared.posts == 0


def test_retry_cannot_forget_an_event_decoded_before_snapshot_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 5
    record = event("heartbeat", str(case.anchor["run_id"]), {"status": "unresolved"})
    case.shared.items["b" * 26] = note(record, "b" * 26)
    clock = Clock(monkeypatch)
    native = case.shared.request
    reads = 0

    def missing(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        if path.endswith("/items"):
            reads += 1
            if reads == 2:  # noqa: PLR2004 - decoded event disappears during verification
                case.shared.items.pop("b" * 26)
                case.shared.version += 1
        return native(method, path, body)

    monkeypatch.setattr(case.shared, "request", missing)
    with pytest.raises(LifecycleError, match="snapshot observation deadline"):
        case.controller.records()
    assert str(record["event_id"]) in selected._known
    assert clock.now == selected.readback_seconds and case.shared.posts == 0
    case.shared.items["b" * 26] = note(record, "b" * 26)
    assert record in case.controller.records()


@pytest.mark.parametrize("delivered", [True, False])
def test_new_verification_summary_must_be_decoded_before_a_snapshot_can_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delivered: bool
) -> None:
    case = Case(tmp_path)
    selected = case.controller.ledger
    selected.readback_seconds = 5
    record = event("heartbeat", str(case.anchor["run_id"]), {"status": "unresolved"})
    item = note(record, "b" * 26)
    clock = Clock(monkeypatch)
    native = case.shared.request
    reads = 0

    def summary(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        response = native(method, path, body)
        if path.endswith("/items"):
            reads += 1
            if reads == 2:  # noqa: PLR2004 - a new row appears only in verification inventory
                assert isinstance(response.body, list)
                response.body.append({key: value for key, value in item.items() if key != "fields"})
        return response

    monkeypatch.setattr(case.shared, "request", summary)
    if delivered:
        clock.tick = lambda: case.shared.items.update({"b" * 26: item})
        assert record in case.controller.records()
        assert clock.sleeps == [1]
    else:
        with pytest.raises(LifecycleError, match="snapshot observation deadline"):
            case.controller.records()
        assert clock.now == selected.readback_seconds
    assert str(record["event_id"]) in selected._known
    assert case.shared.posts == 0


def test_lifecycle_delayed_writes_still_need_independent_checkpoint_and_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    clock = Clock(monkeypatch)
    shared_publish = delayed_posts(case.shared, monkeypatch)
    remote_publish = delayed_posts(case.remote, monkeypatch)
    case.controller.ledger.readback_seconds = case.github.ledger.readback_seconds = 5
    case.controller.wait_seconds = 30
    runtime = LifecycleCase(tmp_path / "provider")
    runtime.lifecycle.journal = case.controller
    witnessing = False

    def tick() -> None:
        nonlocal witnessing
        shared_publish()
        remote_publish()
        if not witnessing:
            witnessing = True
            try:
                case.witness_once()
            finally:
                witnessing = False

    clock.tick = tick

    def before_create() -> None:
        persisted = case.store.read(case.store.registry[-1])["records"]
        assert isinstance(persisted, list)
        assert any(row["kind"] == "intent" for row in persisted)

    runtime.provider.on_create = before_create
    intent, credential = runtime.create()
    runtime.lifecycle.request_revocation(runtime.run_id)
    assert runtime.lifecycle.reconcile(intent, credential).status == "verified"
    assert runtime.provider.creates == 1
    assert not runtime.provider.items
    runtime.lifecycle.require_clear()
    assert credential.secret not in repr(case.store.values)
    assert credential.secret not in repr(case.shared.items)
    assert clock.sleeps


def test_activation_and_readiness_complete_with_delayed_writes_on_both_replicas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = ActivationCase(tmp_path, monkeypatch)
    clock = Clock(monkeypatch)
    shared_publish = delayed_posts(case.shared, monkeypatch)
    remote_publish = delayed_posts(case.remote, monkeypatch)

    def tick() -> None:
        shared_publish()
        remote_publish()

    clock.tick = tick
    case.activation().activate(case.output)
    configured = Configuration.load(case.output)
    assert configured.provision.connect_settings is not None
    selected = json.loads(case.github.values[control.SETTING])
    assert selected["stage"] == "active"
    assert selected["receipt"]["forged_author_ignored"] is True
    assert selected["receipt"]["shared_forged_author_ignored"] is True
    assert case.provider.creates == 0
    assert all(receipt["status"] == "ready" for receipt in case.github.receipts.values())
    assert clock.sleeps


def test_dispatched_witness_handles_delayed_reservation_readiness_and_acknowledgements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = AdmissionCase(tmp_path)
    clock = Clock(monkeypatch)
    case.journal.github.ledger.readback_seconds = 5
    clock.tick = delayed_posts(case.journal.remote, monkeypatch)
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    result = reconcile(case, ProviderDouble(), expected=run_digest(case.run_id, case.payload))
    sync(case.journal.remote, case.journal.shared)
    assert result["status"] == "ready"
    assert case.journal.controller.confirmed(case.run)
    ready = [
        record
        for record in case.journal.controller.records()
        if cast(dict[str, object], record["payload"]).get("format") == action.READY_FORMAT
    ]
    assert len(ready) == 1 and case.journal.controller.confirmed(ready[0])
    assert clock.sleeps


def test_delayed_earlier_ack_does_not_admit_next_intent_after_reservation_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = AdmissionCase(tmp_path)
    started = case.now.replace(microsecond=0)
    case.acknowledge(case.reserve())
    case.now = started + timedelta(seconds=599)
    earlier = event("result", case.run_id, {"outcome": "double-only"})
    case.journal.controller.append(earlier)
    sync(case.journal.shared, case.journal.remote)
    intent = case.intent()
    clock = Clock(monkeypatch)
    clock.now = 599
    case.journal.github.ledger.readback_seconds = 5
    publish = delayed_posts(
        case.journal.remote,
        monkeypatch,
        only=lambda record: (
            cast(dict[str, object], record["payload"]).get("event_id") == earlier["event_id"]
        ),
    )

    def tick() -> None:
        if len(clock.sleeps) >= 2:  # noqa: PLR2004 - cross the original reservation boundary
            publish()

    clock.tick = tick

    class CurrentTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> CurrentTime:
            return cls.fromtimestamp(
                (started + timedelta(seconds=clock.now)).timestamp(), tz or UTC
            )

    monkeypatch.setattr(action, "datetime", CurrentTime)
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    reconcile(case, ProviderDouble(), expected=run_digest(case.run_id, case.payload))
    sync(case.journal.remote, case.journal.shared)
    assert clock.now > 600  # noqa: PLR2004 - immutable ten-minute provisioning window
    assert not case.journal.controller.confirmed(intent)
    # Cleanup/result acknowledgements remain valid after creation admission ends.
    assert case.journal.controller.confirmed(earlier)
