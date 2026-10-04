"""A fresh dispatched attempt, capacity reserve and native author precede CREATE ACKs."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from infrastructure.test_m3_11_connect_journal import Case as JournalCase
from infrastructure.test_m3_11_connect_journal import sync
from infrastructure.test_m3_11_unattended_lifecycle import TARGETS
from infrastructure.test_m3_11_unattended_lifecycle import Case as LifecycleCase
from scripts.m3_11_unattended.connect_admission import FORMAT, WINDOW, Admission, run_digest
from scripts.m3_11_unattended.github_checkpoint import MINIMUM_START_CAPACITY
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import Authority, LifecycleError, stamp


class Case:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.journal = JournalCase(path / "connect")
        self.now = datetime.now(UTC)
        self.authority = Authority("d" * 64, self.now + timedelta(days=7))
        self.run_id = str(uuid.uuid7())
        self.payload: dict[str, object] = {
            "binding": {
                "managed_run_id": self.run_id,
                "source_revision": self.journal.witness.helper,
                "helper_revision": self.journal.witness.helper,
                "artifact_sha256": "a" * 64,
                "qualification_inputs_sha256": "b" * 64,
                "storage_target_sha256": TARGETS.storage_digest,
            },
            "mode": "rehearsal",
            "approval_sha256": "c" * 64,
        }
        self.run = event("run", self.run_id, self.payload)
        self.run["recorded_at"] = stamp(self.now)
        self.journal.controller.append(self.run)
        sync(self.journal.shared, self.journal.remote)
        self.journal.github.capacity = lambda: MINIMUM_START_CAPACITY + 10

    def admission(self) -> Admission:
        return Admission(self.journal.github, targets=TARGETS, now=self.now)

    def reserve(self) -> Admission:
        admission = self.admission()
        assert admission.reserve(run_digest(self.run_id, self.payload), self.authority)
        return admission

    def acknowledge(self, admission: Admission) -> None:
        self.journal.github.acknowledge(run_id=20, attempt=1, allow=admission.allow)
        sync(self.journal.remote, self.journal.shared)

    def intent(self) -> dict[str, object]:
        runtime = LifecycleCase(self.path / "unused-provider-double")
        runtime.now, runtime.run_id = self.now, self.run_id
        runtime.authority = self.authority
        intent = dataclasses.replace(
            runtime.create()[0],
            source_revision=self.journal.witness.helper,
            helper_revision=self.journal.witness.helper,
        )
        value = event("intent", self.run_id, intent.document())
        self.journal.controller.append(value)
        sync(self.journal.shared, self.journal.remote)
        return value


def test_without_exact_dispatch_neither_run_nor_intent_gets_an_independent_ack(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    intent = case.intent()
    admission = case.admission()
    assert not admission.reserve("0" * 64, case.authority)
    case.acknowledge(admission)
    assert not case.journal.controller.confirmed(case.run)
    assert not case.journal.controller.confirmed(intent)


def test_capacity_and_native_reservation_persist_before_run_and_creation_ack(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    admission = case.reserve()
    case.acknowledge(admission)
    assert case.journal.controller.confirmed(case.run)
    intent = case.intent()
    case.acknowledge(case.admission())
    assert case.journal.controller.confirmed(intent)
    count = len(case.journal.store.values)
    case.reserve()  # Restart does not renew the original reservation.
    assert len(case.journal.store.values) == count


@pytest.mark.parametrize("fault", ["capacity", "stale", "future", "authority", "target"])
def test_new_attempt_rechecks_capacity_and_cleanup_lifetime_instead_of_trusting_heartbeat(
    tmp_path: Path, fault: str
) -> None:
    case = Case(tmp_path)
    admission = case.admission()
    if fault == "capacity":
        case.journal.github.capacity = lambda: MINIMUM_START_CAPACITY - 1
    elif fault == "stale":
        admission.now += timedelta(minutes=3)
    elif fault == "future":
        admission.now -= timedelta(seconds=1)
    elif fault == "authority":
        case.authority = Authority("d" * 64, case.now + timedelta(hours=14))
    else:
        admission.targets = dataclasses.replace(TARGETS, archive_bucket="different-approved-target")
    with pytest.raises(LifecycleError):
        admission.reserve(run_digest(case.run_id, case.payload), case.authority)
    assert not case.journal.controller.confirmed(case.run)


def test_capacity_checkpoint_failure_does_not_acknowledge_run(tmp_path: Path) -> None:
    case = Case(tmp_path)
    case.journal.store.failure = "before-upload"
    with pytest.raises(LifecycleError):
        case.reserve()
    assert not case.journal.controller.confirmed(case.run)


def test_controller_authored_capacity_receipt_cannot_authorize_creation_even_if_durable(
    tmp_path: Path,
) -> None:
    case = Case(tmp_path)
    forged = event(
        "heartbeat",
        case.run_id,
        {
            "format": FORMAT,
            "run_sha256": run_digest(case.run_id, case.payload),
            "witness": case.journal.witness.binding(),
            "accepted_at": stamp(case.now),
            "create_before": stamp(case.now + WINDOW),
            "authority_expires_at": stamp(case.authority.valid_until),
            "provider_authorities": dict.fromkeys(
                ("spaces", "cloudflare-account", "cloudflare-user"), "d" * 64
            ),
            "reserved_capacity": MINIMUM_START_CAPACITY,
        },
    )
    case.journal.controller.append(forged)
    sync(case.journal.shared, case.journal.remote)
    case.journal.github.persist(forged)
    case.acknowledge(case.admission())
    assert case.journal.controller.confirmed(forged)
    assert not case.journal.controller.confirmed(case.run)


def test_reservation_window_cannot_extend_when_worker_restarts(tmp_path: Path) -> None:
    case = Case(tmp_path)
    case.reserve()
    intent = case.intent()
    case.now += WINDOW + timedelta(seconds=1)
    restarted = case.reserve()
    assert not restarted.allow(case.run) and not restarted.allow(intent)
    assert restarted.allow(event("resolved", case.run_id, {"cleanup": "verified"}))


@pytest.mark.parametrize(
    "field", ["source_revision", "helper_revision", "cleanup_authority_sha256"]
)
def test_creation_intent_must_match_exact_reserved_authority_and_revision(
    tmp_path: Path, field: str
) -> None:
    case = Case(tmp_path)
    case.reserve()
    intent = case.intent()
    payload = intent["payload"]
    assert isinstance(payload, dict)
    payload[field] = "0" * (64 if field == "cleanup_authority_sha256" else 40)
    assert not case.admission().allow(intent)
