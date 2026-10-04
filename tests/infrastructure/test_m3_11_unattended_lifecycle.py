"""Provider-double coverage of durable obligations and interruption boundaries."""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import override

import pytest

from scripts.m3_11_unattended import cleanup
from scripts.m3_11_unattended.journal import FileJournal, event
from scripts.m3_11_unattended.lifecycle import Lifecycle, intents, pending_authentication
from scripts.m3_11_unattended.model import (
    LIFETIME,
    Authority,
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    Targets,
    stamp,
)

NOW = datetime(2026, 10, 3, 20, tzinfo=UTC)
TARGETS = Targets(
    "nyc3", "example-archive", "example-backup", "a" * 32, "b" * 32, "c" * 32, "d" * 32
)
SCOPE: dict[str, object] = {"grants": [{"bucket": "example-archive", "permission": "readwrite"}]}
CANARY = "not-a-real-secret-CANARY-never-export-9cd8"


class ProviderDouble:
    kind: ProviderKind = "spaces"
    authority_sha256 = "d" * 64

    def __init__(self) -> None:
        self.items: dict[str, dict[str, object]] = {}
        self.creates = 0
        self.deletes: list[str] = []
        self.lose_response = False
        self.fail_delete = False
        self.fail_read = False
        self.keep_deleted = False
        self.still_authenticates = False
        self.wrong_scope = False
        self.inactive = False
        self.expired = False
        self.on_create: Callable[[], None] = lambda: None

    def inventory(self) -> list[dict[str, object]]:
        if self.fail_read:
            raise LifecycleError(CANARY)
        return list(self.items.values())

    def create(self, intent: Intent) -> Credential:
        self.on_create()
        self.creates += 1
        key = f"credential{self.creates:08d}"
        record: dict[str, object] = {
            "id": key,
            "name": intent.name,
            "created_at": intent.requested_at,
            "scope": {} if self.wrong_scope else intent.scope,
            "status": "inactive" if self.inactive else "active",
        }
        self.items[key] = record
        if self.lose_response:
            raise LifecycleError(CANARY)
        return Credential(key, CANARY, record)

    def inspect(self, identifier: str) -> dict[str, object] | None:
        if self.fail_read:
            raise LifecycleError(CANARY)
        return self.items.get(identifier)

    def delete(self, identifier: str) -> None:
        if self.fail_delete:
            raise LifecycleError(CANARY)
        self.deletes.append(identifier)
        if not self.keep_deleted:
            self.items.pop(identifier, None)

    def verify(self, intent: Intent, credential: Credential, *, now: datetime) -> None:
        if self.expired:
            raise LifecycleError(CANARY)

    def denied(self, intent: Intent, credential: Credential) -> bool:
        if self.fail_read:
            raise LifecycleError(CANARY)
        return credential.identifier not in self.items and not self.still_authenticates


class Case:
    def __init__(self, path: Path) -> None:
        self.now = NOW
        self.run_id = str(uuid.uuid7())
        self.provider = ProviderDouble()
        self.journal = FileJournal(path)
        self.lifecycle = Lifecycle(self.journal, {"spaces": self.provider}, clock=lambda: self.now)
        self.authority = Authority("d" * 64, NOW + timedelta(days=7))

    def create(self, *, role: str = "archive") -> tuple[Intent, Credential]:
        return self.lifecycle.provision(
            run_id=self.run_id,
            role=role,
            source="e" * 40,
            helper="f" * 40,
            targets=TARGETS,
            provider="spaces",
            scope=SCOPE,
            authority=self.authority,
        )


class DelayedPersistence(FileJournal):
    """A Connect cache may read its own write before independent cleanup can."""

    pending_kind: str = ""

    @override
    def persist(self, record: dict[str, object]) -> dict[str, object]:
        self.append(record)
        if record["kind"] == self.pending_kind:
            raise LifecycleError("independent acknowledgement unavailable")
        return record


def test_staged_negative_marker_blocks_probe_until_independently_persisted(tmp_path: Path) -> None:
    case = Case(tmp_path)
    journal = DelayedPersistence(tmp_path)
    case.lifecycle.journal = journal
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    journal.pending_kind = "cleanup"
    probes = []
    original = case.provider.denied

    def denied(intent: Intent, credential: Credential) -> bool:
        probes.append(credential.identifier)
        return original(intent, credential)

    case.provider.denied = denied  # type: ignore[method-assign] # observe the real probe boundary
    assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
    assert case.provider.deletes == [credential.identifier]
    assert probes == []
    assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
    assert len([record for record in journal.records() if record["kind"] == "cleanup"]) == 1
    journal.pending_kind = ""
    assert case.lifecycle.reconcile(intent, credential).status == "verified"
    assert probes == [credential.identifier]


def test_staged_denial_keeps_closure_pending_and_reuses_exact_proof(tmp_path: Path) -> None:
    case = Case(tmp_path)
    journal = DelayedPersistence(tmp_path)
    case.lifecycle.journal = journal
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    journal.pending_kind = "resolved"
    assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
    originals = [row for row in journal.records() if row["kind"] in {"cleanup", "resolved"}]
    assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
    assert [row for row in journal.records() if row["kind"] in {"cleanup", "resolved"}] == originals
    # A delayed ACK cannot replace the required fresh provider absence checks.
    journal.pending_kind = ""
    case.provider.fail_read = True
    assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
    case.provider.fail_read = False
    assert case.lifecycle.reconcile(intent, credential).status == "verified"
    assert [row for row in journal.records() if row["kind"] in {"cleanup", "resolved"}] == originals


def test_lost_creation_response_recovery_id_is_persisted_before_delete(tmp_path: Path) -> None:
    case = Case(tmp_path)
    journal = DelayedPersistence(tmp_path)
    case.lifecycle.journal = journal
    case.provider.lose_response = True
    with pytest.raises(LifecycleError):
        case.create()
    intent = intents(journal)[0]
    case.lifecycle.request_revocation(case.run_id)
    journal.pending_kind = "created"
    assert case.lifecycle.reconcile(intent).status == "unresolved"
    assert case.provider.deletes == []
    # A restarted actor must not mistake the cache's recovered ID for durability.
    case.lifecycle = Lifecycle(journal, {"spaces": case.provider}, clock=lambda: case.now)
    assert case.lifecycle.reconcile(intent).status == "unresolved"
    assert case.provider.deletes == []
    journal.pending_kind = ""
    assert case.lifecycle.reconcile(intent).status == "verified"
    assert len(case.provider.deletes) == 1
    assert len([row for row in journal.records() if row["kind"] == "created"]) == 1


def test_intent_is_external_before_creation_and_secret_never_journaled(tmp_path: Path) -> None:
    case = Case(tmp_path)

    def observe() -> None:
        original = intents(FileJournal(tmp_path))
        assert len(original) == 1
        assert original[0].scope == SCOPE
        assert original[0].deadline == stamp(NOW + LIFETIME)

    case.provider.on_create = observe
    intent, credential = case.create()
    assert CANARY not in repr(credential)
    assert all(CANARY not in path.read_text() for path in tmp_path.iterdir())
    with pytest.raises(LifecycleError, match="cannot be replayed"):
        case.create()
    assert case.provider.creates == 1
    assert case.lifecycle.reconcile(intent, credential).status == "not-due"
    with pytest.raises(LifecycleError, match="outstanding"):
        case.lifecycle.require_clear()


def test_unacknowledged_intent_prevents_provider_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)

    def refuse(record: dict[str, object]) -> None:
        raise LifecycleError("external journal unavailable")

    monkeypatch.setattr(case.journal, "append", refuse)
    with pytest.raises(LifecycleError):
        case.create()
    assert case.provider.creates == 0


def test_lost_creation_response_reconciles_exact_owned_id_without_reissue(tmp_path: Path) -> None:
    case = Case(tmp_path)
    case.provider.lose_response = True
    with pytest.raises(LifecycleError):
        case.create()
    intent = intents(case.journal)[0]
    case.lifecycle.request_revocation(case.run_id)
    result = case.lifecycle.reconcile(intent)
    assert result.status == "verified"
    assert result.negative_authentication == "unavailable"
    assert case.provider.creates == 1
    assert case.provider.deletes == ["credential00000001"]
    assert [record for record in case.journal.records() if record["kind"] == "created"]


@pytest.mark.parametrize("fault", ["wrong_scope", "inactive", "expired"])
def test_mismatched_created_credential_remains_owned_and_gets_revoked(
    tmp_path: Path, fault: str
) -> None:
    case = Case(tmp_path)
    setattr(case.provider, fault, True)
    with pytest.raises(LifecycleError):
        case.create()
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.sweep()[0].status == "verified"
    assert case.provider.deletes == ["credential00000001"]


@pytest.mark.parametrize(
    "fault", ["fail_delete", "fail_read", "keep_deleted", "still_authenticates"]
)
def test_failed_revocation_blocks_closure_and_new_start(tmp_path: Path, fault: str) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    setattr(case.provider, fault, True)
    result = case.lifecycle.reconcile(intent, credential)
    assert result.status == "unresolved"
    assert CANARY not in repr(result)
    assert not any(record["kind"] == "resolved" for record in case.journal.records())
    retained = case.journal.records()
    for _ in range(2):
        assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
        assert case.journal.records() == retained
    with pytest.raises(LifecycleError):
        case.lifecycle.require_clear()
    setattr(case.provider, fault, False)
    assert case.lifecycle.reconcile(intent, credential).status == "verified"


def test_cleanup_restarts_with_no_controller_or_local_secrets(tmp_path: Path) -> None:
    case = Case(tmp_path)
    intent, _ = case.create()
    # No terminal cleanup: the independent actor uses only remote obligations.
    independent = Lifecycle(
        FileJournal(tmp_path), {"spaces": case.provider}, clock=lambda: NOW + LIFETIME
    )
    assert independent.sweep()[0].status == "verified"
    assert independent.reconcile(intent).status == "verified"
    independent.require_clear()


def test_cleanup_interrupted_after_delete_requires_new_provider_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    intent, secret = case.create()
    case.lifecycle.request_revocation(case.run_id)
    original = case.journal.append

    def interrupt(record: dict[str, object]) -> None:
        if record["kind"] == "resolved":
            raise OSError(CANARY)
        original(record)

    monkeypatch.setattr(case.journal, "append", interrupt)
    assert case.lifecycle.reconcile(intent, secret).status == "unresolved"
    assert not case.provider.items
    monkeypatch.setattr(case.journal, "append", original)
    result = case.lifecycle.reconcile(intent, secret)
    assert result.status == "verified"
    assert result.negative_authentication == "denied"


def test_stale_independent_resolution_cannot_hide_failed_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    intent, secret = case.create()
    case.lifecycle.request_revocation(case.run_id)
    independent = Lifecycle(FileJournal(tmp_path), {"spaces": case.provider}, clock=lambda: NOW)
    inventory = case.provider.inventory
    started = False

    def interleave() -> list[dict[str, object]]:
        nonlocal started
        if not started:
            started = True
            case.provider.still_authenticates = True
            assert case.lifecycle.reconcile(intent, secret).status == "unresolved"
        return inventory()

    monkeypatch.setattr(case.provider, "inventory", interleave)
    # This actor began before the probe marker existed. Its stale completion
    # must not discharge that separate, explicit authentication obligation.
    independent.reconcile(intent)
    assert any(record["kind"] == "resolved" for record in case.journal.records())
    assert independent.reconcile(intent).status == "unresolved"
    with pytest.raises(LifecycleError, match="outstanding"):
        independent.require_clear()
    status = cleanup.status_document(case.journal, helper="f" * 40, now=NOW + LIFETIME)
    assert status["outstanding"] == 1
    assert status["overdue"] == 0  # exact deadline; overdue is strictly later
    case.provider.still_authenticates = False
    assert case.lifecycle.reconcile(intent, secret).status == "verified"
    independent.require_clear()
    assert cleanup.status_document(case.journal, helper="f" * 40, now=NOW)["outstanding"] == 0


def test_denied_proof_covers_explicit_markers_without_clock_ordering() -> None:
    run = str(uuid.uuid7())
    proof_value: dict[str, object] = {"negative_authentication": "denied"}
    proof = event("resolved", run, proof_value)
    # The marker sorts after its proof, as can happen across corrected clocks.
    marker = event("cleanup", run, {"proof_binding": "event-id"})
    assert str(proof["event_id"]) < str(marker["event_id"])
    assert pending_authentication([proof, marker]) == {marker["event_id"]}
    proof_value["negative_authentication_markers"] = [marker["event_id"]]
    assert pending_authentication([proof, marker]) == set()
    later = event("cleanup", run, {"proof_binding": "event-id"})
    stale = event("resolved", run, {"negative_authentication": "unavailable"})
    assert pending_authentication([proof, marker, later, stale]) == {later["event_id"]}


def test_legacy_denied_proof_cannot_cover_new_explicit_marker() -> None:
    run = str(uuid.uuid7())
    legacy = event("cleanup", run, {"negative_authentication": "required"})
    explicit = event("cleanup", run, {"proof_binding": "event-id"})
    proof = event("resolved", run, {"negative_authentication": "denied"})
    assert pending_authentication([legacy, explicit, proof]) == {explicit["event_id"]}


def test_unknown_creation_absence_cannot_manufacture_resolution_after_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)

    def interrupt(intent: Intent) -> Credential:
        raise LifecycleError("interrupted before request")

    monkeypatch.setattr(case.provider, "create", interrupt)
    with pytest.raises(LifecycleError):
        case.create()
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.sweep()[0].status == "creation-uncertain"
    case.now += timedelta(minutes=6)
    assert case.lifecycle.sweep()[0].status == "creation-uncertain"
    case.now += timedelta(days=1)
    with pytest.raises(LifecycleError, match="outstanding"):
        case.lifecycle.require_clear()


def test_preexisting_and_similarly_named_credentials_are_never_deleted(tmp_path: Path) -> None:
    case = Case(tmp_path)
    prior: dict[str, object] = {"id": "production000001", "name": "ldp-m311-older-archive"}
    case.provider.items["production000001"] = prior
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.reconcile(intent, credential).status == "verified"
    assert case.provider.items == {"production000001": prior}


@pytest.mark.parametrize("change", ["id", "name", "created_at"])
def test_changed_ownership_cannot_authorize_deletion(tmp_path: Path, change: str) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    case.provider.items[credential.identifier][change] = "foreign-production-identity"
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.reconcile(intent, credential).status == "unresolved"
    assert not case.provider.deletes


def test_ambiguous_lost_creation_keeps_all_candidates_and_obligation(tmp_path: Path) -> None:
    case = Case(tmp_path)
    case.provider.lose_response = True
    with pytest.raises(LifecycleError):
        case.create()
    intent = intents(case.journal)[0]
    case.provider.items["duplicate000001"] = {
        **case.provider.items["credential00000001"],
        "id": "duplicate000001",
    }
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.reconcile(intent).status == "unresolved"
    assert not case.provider.deletes


def test_cleanup_authority_expiry_refuses_before_intent_and_creation(tmp_path: Path) -> None:
    case = Case(tmp_path)
    case.authority = dataclasses.replace(case.authority, valid_until=NOW + LIFETIME)
    with pytest.raises(LifecycleError, match="authority"):
        case.create()
    assert not case.journal.records()
    assert not case.provider.creates


def test_partial_provisioning_revokes_each_created_role(tmp_path: Path) -> None:
    case = Case(tmp_path)
    first, secret = case.create()
    case.provider.lose_response = True
    with pytest.raises(LifecycleError):
        case.create(role="backup")
    case.lifecycle.request_revocation(case.run_id)
    results = case.lifecycle.sweep({first.sha256: secret})
    assert [result.status for result in results] == ["verified", "verified"]
    assert case.provider.deletes == ["credential00000001", "credential00000002"]


def test_another_account_or_replaced_cleanup_authority_cannot_prove_absence(tmp_path: Path) -> None:
    case = Case(tmp_path)
    intent, _credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    other = ProviderDouble()
    other.authority_sha256 = "a" * 64
    independent = Lifecycle(case.journal, {"spaces": other}, clock=lambda: case.now)
    assert independent.reconcile(intent).status == "unresolved"
    assert not other.deletes
    assert case.provider.items
    with pytest.raises(LifecycleError, match="outstanding"):
        independent.require_clear()


def test_late_provider_creation_is_not_hidden_by_past_resolution(tmp_path: Path) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    original = dict(credential.metadata)
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.reconcile(intent).status == "verified"
    case.provider.items[credential.identifier] = original
    case.provider.fail_delete = True
    with pytest.raises(LifecycleError, match="outstanding"):
        case.lifecycle.require_clear()


def test_journal_rejects_duplicate_creation_intents(tmp_path: Path) -> None:
    case = Case(tmp_path)
    intent, _ = case.create()
    case.journal.append(event("intent", case.run_id, intent.document()))
    with pytest.raises(LifecycleError, match="ambiguous"):
        intents(case.journal)
