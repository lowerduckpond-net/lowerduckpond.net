"""Create once, journal first, and reconcile exact owned credentials until revoked."""

from __future__ import annotations

import hashlib
import re
import signal
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Protocol, cast

from scripts import qualification_deadline
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import historical_absence
from scripts.m3_11_unattended.creation_outcome import is_abort, select_abort, valid_resolution
from scripts.m3_11_unattended.inventory import Inventory, fact, require_confirmation
from scripts.m3_11_unattended.journal import CreationJournal, Journal, event
from scripts.m3_11_unattended.model import (
    CREATION_SETTLE,
    LIFETIME,
    PROVIDERS,
    ROLES,
    Authority,
    AuthorityGeneration,
    Credential,
    Intent,
    LeaseManifest,
    LeasePolicy,
    LifecycleError,
    ProviderKind,
    Targets,
    digest,
    identity,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState
from scripts.qualification_budget import MINIMUM_TOKEN_REMAINING
from scripts.qualification_timing import measure

CreationRecorder = Callable[[str, str | None], None]
CLEARANCE_SECONDS = 30
READBACK_WORKERS = 4


def _obligation_basis(records: list[dict[str, object]]) -> str:
    return digest(
        sorted(
            digest(record)
            for record in records
            if record["kind"] in {"intent", "created", "revoke", "cleanup", "resolved"}
            or is_abort(record)
            or historical_absence.is_receipt(record)
        )
    )


class Provider(Protocol):
    kind: ProviderKind
    authority_sha256: str

    def inventory(self) -> list[dict[str, object]]:
        """Complete bounded inventory; failures and partial pages must raise."""
        ...

    def create(self, intent: Intent, *, record: CreationRecorder) -> Credential: ...

    def inspect(self, identifier: str) -> dict[str, object] | None: ...

    def delete(self, identifier: str) -> None: ...

    def verify(self, intent: Intent, credential: Credential, *, now: datetime) -> None: ...

    def denied(self, intent: Intent, credential: Credential) -> bool:
        """True only for an explicit authentication rejection, never a network error."""
        ...


def identifier(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value) is None:
        raise LifecycleError("provider returned an invalid credential identity")
    return value


def intents(journal: Journal) -> list[Intent]:
    return _intents(journal.records())


def _intents(records: list[dict[str, object]]) -> list[Intent]:
    result = [Intent.parse(record["payload"]) for record in records if record["kind"] == "intent"]
    keys = [(intent.run_id, intent.role) for intent in result]
    if len(set(keys)) != len(keys):
        raise LifecycleError("credential creation intents are ambiguous")
    return result


def known_id(journal: Journal, intent: Intent) -> str | None:
    return _known_id(journal.records(), intent)


def _known_id(records: list[dict[str, object]], intent: Intent) -> str | None:
    matches: set[str] = set()
    intent_sha256 = intent.sha256
    for record in records:
        if record["kind"] != "created" or record["run_id"] != intent.run_id:
            continue
        payload = record["payload"]
        if not isinstance(payload, dict):
            raise LifecycleError("invalid credential identity record")
        if payload.get("intent_sha256") == intent_sha256:
            if set(payload) != {"intent_sha256", "credential_id"}:
                raise LifecycleError("invalid credential identity record")
            matches.add(identifier(payload["credential_id"]))
    if len(matches) > 1:
        raise LifecycleError("credential creation returned conflicting identities")
    return next(iter(matches), None)


def pending_authentication(observations: list[dict[str, object]]) -> set[str]:
    """Only a denied proof covering a marker can discharge its authentication check.

    An independent actor may finish a stale inventory read after another actor
    records a failed probe. Its secretless resolution cannot clear that marker.
    New proofs bind event IDs, so inter-host clocks do not decide coverage.
    """
    markers = {
        identity(record["event_id"]): record
        for record in observations
        if record["kind"] == "cleanup"
    }
    covered: set[str] = set()
    for record in observations:
        value = record["payload"]
        if (
            record["kind"] != "resolved"
            or not isinstance(value, dict)
            or value.get("negative_authentication") != "denied"
        ):
            continue
        if "negative_authentication_markers" in value:
            references = value["negative_authentication_markers"]
            if not isinstance(references, list):
                raise LifecycleError("authentication proof has invalid marker bindings")
            selected = {identity(reference) for reference in references}
            if not selected <= markers.keys() or len(selected) != len(references):
                raise LifecycleError("authentication proof has unknown or duplicate markers")
            covered.update(selected)
        else:
            # Preserve the original ordering interpretation only for legacy
            # markers. An older helper can never discharge a new explicit one.
            covered.update(
                key
                for key, marker in markers.items()
                if isinstance(marker["payload"], dict)
                and marker["payload"].get("proof_binding") is None
                and key < str(record["event_id"])
            )
    return markers.keys() - covered


def _owned(intent: Intent, metadata: dict[str, object], *, known: str | None) -> str:
    selected = identifier(metadata.get("id"))
    if (
        selected in intent.baseline_ids
        or (known is not None and selected != known)
        or metadata.get("name") != intent.name
        or not instant(intent.requested_at)
        <= instant(metadata.get("created_at"))
        <= instant(intent.create_before)
        or (known is None and metadata.get("scope") != intent.scope)
    ):
        raise LifecycleError("provider credential ownership is unproven")
    return selected


@dataclass(frozen=True)
class CleanupResult:
    intent_sha256: str
    status: str
    negative_authentication: str


@dataclass(frozen=True)
class _Historical:
    identifier: str
    created: dict[str, object]
    resolved: dict[str, object]


def _historical_details(client: Provider, identifiers: list[str]) -> list[bool]:
    """Join one bounded read-only wave before progress, inventory or deletion."""
    if not 0 < len(identifiers) <= READBACK_WORKERS:
        raise LifecycleError("historical readback wave exceeds its bound")
    pending = qualification_deadline.Interruption()
    guard = (
        qualification_deadline.interrupts()
        if threading.current_thread() is threading.main_thread()
        else nullcontext(pending)
    )
    try:
        # The provider bounds each whole exchange to 30 seconds. Record repeated
        # signals until shutdown has joined every GET, including on submission
        # or response failure; no fallback DELETE may race an unfinished read.
        with guard as pending, ThreadPoolExecutor(max_workers=READBACK_WORKERS) as executor:
            return [value is not None for value in executor.map(client.inspect, identifiers)]
    except RuntimeError:
        # Thread creation/submission can fail too. The executor has already
        # drained; ordinary reconciliation must still reach reappeared siblings.
        raise LifecycleError("historical credential readback failed") from None
    finally:
        # Preserve the caller's interruption behavior after restoring its handler.
        # Worker cleanup records signals; the independent action raises on them.
        if pending.signum is not None:
            signal.raise_signal(pending.signum)


class Lifecycle:
    def __init__(  # noqa: PLR0913 - persistence boundaries remain explicit
        self,
        journal: Journal,
        providers: Mapping[ProviderKind, Provider],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        remember: Callable[[Intent, Credential], None] | None = None,
        remember_intent: Callable[[Intent], None] | None = None,
        remember_created: Callable[[Intent, dict[str, object]], None] | None = None,
        remember_aborted: Callable[[Intent, dict[str, object]], None] | None = None,
        progress: Callable[[], None] = lambda: None,
    ) -> None:
        self.journal, self.providers, self.clock = journal, providers, clock
        self.remember = remember
        self.remember_intent = remember_intent
        self.remember_created = remember_created
        self.remember_aborted = remember_aborted
        self.progress = progress
        self._clearance: tuple[float, str] | None = None
        self._sweep_results: tuple[CleanupResult, ...] | None = None

    @measure("credential-created-persistence")
    def _record_creation(self, intent: Intent, selected: str, secret: str | None) -> None:
        record = event(
            "created",
            intent.run_id,
            {"intent_sha256": intent.sha256, "credential_id": identifier(selected)},
        )
        marker = None
        local_error = None
        try:
            if self.remember_created is not None:
                self.remember_created(intent, record)
            if secret is not None and self.remember is not None:
                self.remember(intent, Credential(selected, secret, {}))
                marker = _authentication_marker(intent)
        except Exception as error:
            local_error = error
        try:
            # A private delivery failure must not discard an acknowledged ID.
            # Conversely, retain its local record before a remote ACK can fail.
            if marker is not None and isinstance(self.journal, CreationJournal):
                self.journal.persist_creation(record, marker)
            else:
                self.journal.persist(record)
        except Exception as error:
            if local_error is not None:
                raise local_error from error
            raise
        if local_error is not None:
            raise local_error
        if marker is not None and not isinstance(self.journal, CreationJournal):
            # Backends without retained-write idempotence keep serial persistence.
            self.journal.persist(marker)

    def provision(  # noqa: PLR0912, PLR0913 - explicit authority and pre/post-I/O deadline gates
        self,
        *,
        run_id: str,
        role: str,
        source: str,
        helper: str,
        targets: Targets,
        provider: ProviderKind,
        scope: dict[str, object],
        authority: Authority,
        provisioning_deadline: datetime | None = None,
    ) -> tuple[Intent, Credential]:
        if provisioning_deadline is not None and self.clock() >= provisioning_deadline:
            raise LifecycleError("credential creation window elapsed before starting another role")
        if any(item.run_id == run_id and item.role == role for item in intents(self.journal)):
            raise LifecycleError(
                "credential creation cannot be replayed; reconcile the original intent"
            )
        # Both provider APIs may round creation timestamps to whole seconds.
        now = self.clock().replace(microsecond=0)
        deadline = now + LIFETIME
        authority.require(deadline)
        client = self.providers[provider]
        with measure("credential-provider-inventory"):
            inventory = client.inventory()
        name = f"ldp-m311-{uuid.UUID(run_id).hex}-{role}"
        if any(item.get("name") == name for item in inventory):
            raise LifecycleError(
                "credential name already exists; no creation or adoption is authorized"
            )
        intent = Intent(
            run_id=run_id,
            role=role,
            source_revision=source,
            helper_revision=helper,
            provider=provider,
            cleanup_authority_sha256=authority.provider_identity(provider),
            name=name,
            requested_at=stamp(now),
            create_before=stamp(now + CREATION_SETTLE),
            deadline=stamp(deadline),
            scope=deepcopy(scope),
            baseline_ids=tuple(sorted(identifier(item.get("id")) for item in inventory)),
            targets=targets,
        )
        intent_record = event("intent", run_id, intent.document())
        if provisioning_deadline is not None and self.clock() >= provisioning_deadline:
            raise LifecycleError(
                "credential creation window elapsed before retaining another intent"
            )
        try:
            if self.remember_intent is not None:
                self.remember_intent(intent)
            with measure("credential-intent-persistence"):
                intent_record = self.journal.persist(intent_record)
            before = instant(intent.create_before)
            if provisioning_deadline is not None:
                before = min(before, provisioning_deadline)
            if self.clock() >= before:
                raise LifecycleError("credential creation window elapsed before acknowledgement")
        except Exception as primary:
            if self.remember_aborted is not None:
                try:
                    self.remember_aborted(intent, intent_record)
                except Exception as secondary:
                    raise primary from secondary
            raise
        # Exactly one mutation. A timeout or lost response is an outstanding
        # obligation; no handler may call create again for this run and role.
        with measure("credential-provider-create"):
            credential = client.create(
                intent,
                record=lambda selected, secret: self._record_creation(intent, selected, secret),
            )
        if known_id(self.journal, intent) != credential.identifier:
            raise LifecycleError("creation response differs from its recorded identity")
        metadata = client.inspect(credential.identifier)
        if metadata is None:
            raise LifecycleError("new credential was not visible in provider readback")
        _owned(intent, metadata, known=credential.identifier)
        if metadata.get("scope") != intent.scope or metadata.get("status") != "active":
            raise LifecycleError("new credential has an unexpected scope or inactive status")
        client.verify(intent, credential, now=self.clock())
        return intent, credential

    def request_revocation(self, run_id: str) -> None:
        if not any(
            record["kind"] == "revoke" and record["run_id"] == run_id
            for record in self.journal.records()
        ):
            self.journal.append(event("revoke", run_id, {"reason": "terminal-path"}))

    def _due(self, intent: Intent, records: list[dict[str, object]] | None = None) -> bool:
        return self.clock() >= instant(intent.deadline) or any(
            record["kind"] == "revoke" and record["run_id"] == intent.run_id
            for record in (self.journal.records() if records is None else records)
        )

    def _historical(self, intent: Intent, records: list[dict[str, object]]) -> _Historical | None:
        """Select an unchanged, fully resolved obligation for read-only observation."""
        intent_sha256 = intent.sha256
        known = _known_id(records, intent)
        observations = sorted(
            (
                record
                for record in records
                if record["kind"] in {"cleanup", "resolved"}
                and isinstance(record["payload"], dict)
                and record["payload"].get("intent_sha256") == intent_sha256
            ),
            key=lambda record: str(record["event_id"]),
        )
        prior = next(
            (record for record in reversed(observations) if record["kind"] == "resolved"), None
        )
        if (
            not self._due(intent, records)
            or self.providers[intent.provider].authority_sha256 != intent.cleanup_authority_sha256
            or known is None
            or select_abort(intent, records) is not None
            or pending_authentication(observations)
            or prior is None
            or not isinstance(prior["payload"], dict)
            or prior["payload"].get("credential_id") != known
            or prior["payload"].get("provider_readback") != "absent"
            or prior["payload"].get("negative_authentication") not in {"denied", "unavailable"}
        ):
            return None
        created = next(
            (
                record
                for record in records
                if record["kind"] == "created"
                and record["run_id"] == intent.run_id
                and record["payload"] == {"intent_sha256": intent_sha256, "credential_id": known}
            ),
            None,
        )
        if created is None:
            raise LifecycleError("resolved credential creation evidence is missing")
        return _Historical(known, created, prior)

    @measure("credential-reconcile")
    def reconcile(  # noqa: PLR0911, PLR0912, PLR0915 - independent cleanup gates
        self, intent: Intent, credential: Credential | None = None
    ) -> CleanupResult:
        """Delete credentials only. No container, DNS record, backup or object deletion."""
        negative = "unavailable" if credential is None else "unverified"
        try:
            if not self._due(intent):
                return CleanupResult(intent.sha256, "not-due", negative)
            observations = sorted(
                (
                    record
                    for record in self.journal.records()
                    if record["kind"] in {"cleanup", "resolved"}
                    and isinstance(record["payload"], dict)
                    and record["payload"].get("intent_sha256") == intent.sha256
                ),
                key=lambda record: str(record["event_id"]),
            )
            pending = pending_authentication(observations)
            client = self.providers[intent.provider]
            if client.authority_sha256 != intent.cleanup_authority_sha256:
                raise LifecycleError("cleanup authority differs from the original obligation")
            known = known_id(self.journal, intent)
            abort = select_abort(intent, self.journal.records())
            prior = next(
                (record for record in reversed(observations) if record["kind"] == "resolved"), None
            )
            historical = (
                self._historical(intent, self.journal.records()) if credential is None else None
            )
            if historical is not None:
                # Historical absence needs no preliminary candidate inventory.
                # Preserve the durable ID, then retain the same fresh detail
                # followed by complete ID/name inventory used after deletion.
                # A visible ID falls through to the ordinary ownership checks.
                self.journal.persist(historical.created)
                if client.inspect(historical.identifier) is None:
                    if any(
                        item.get("id") == historical.identifier or item.get("name") == intent.name
                        for item in client.inventory()
                    ):
                        raise LifecycleError("resolved credential remains in inventory")
                    self.journal.persist(historical.resolved)
                    return CleanupResult(intent.sha256, "verified", negative)
            inventory = client.inventory()
            candidates = [
                item
                for item in inventory
                if item.get("name") == intent.name or item.get("id") == known
            ]
            if len(candidates) > 1:
                raise LifecycleError("credential inventory is ambiguous")
            abort_conflict = abort is not None and (
                known is not None
                or bool(candidates)
                or credential is not None
                or any(record["kind"] == "cleanup" for record in observations)
            )
            if abort is not None and not abort_conflict:
                self.journal.persist(abort)
                abort_proof = {
                    "intent_sha256": intent.sha256,
                    "credential_id": None,
                    "provider_readback": "absent",
                    "negative_authentication": "not-tested",
                    "creation_outcome": "not-submitted",
                    "abort_event_id": abort["event_id"],
                    "abort_event_sha256": digest(abort),
                }
                prior_abort = next(
                    (
                        record
                        for record in observations
                        if record["kind"] == "resolved" and record["payload"] == abort_proof
                    ),
                    None,
                )
                self.journal.persist(prior_abort or event("resolved", intent.run_id, abort_proof))
                return CleanupResult(intent.sha256, "verified", "not-tested")
            if candidates:
                selected = _owned(intent, candidates[0], known=known)
                known = selected
            if known is not None:
                # Even a locally visible recovery record may still be staged.
                # Persist its exact ID on every retry before DELETE or closure.
                payload: dict[str, object] = {
                    "intent_sha256": intent.sha256,
                    "credential_id": known,
                }
                recovered = next(
                    (
                        record
                        for record in self.journal.records()
                        if record["kind"] == "created"
                        and record["run_id"] == intent.run_id
                        and record["payload"] == payload
                    ),
                    None,
                )
                self.journal.persist(recovered or event("created", intent.run_id, payload))
            if candidates:
                # Inspect again with the exact ID immediately before deletion.
                current = client.inspect(selected)
                if current is not None:
                    _owned(intent, current, known=selected)
                    client.delete(selected)
            elif known is None:
                if credential is None and historical_absence.record_absence(self.journal, intent):
                    return CleanupResult(intent.sha256, historical_absence.STATUS, negative)
                # Neither API gives a server-side bound on a request whose reply
                # was lost. Empty inventory cannot prove that creation will never
                # commit, even after our five-minute submission window. Preserve
                # this uncertainty until an exact provider identity is observed.
                return CleanupResult(intent.sha256, "creation-uncertain", negative)
            if known is not None and client.inspect(known) is not None:
                raise LifecycleError("deleted credential remains visible")
            # DELETE success and a missing detail record alone are insufficient.
            # Require a fresh, complete inventory with neither identity nor name.
            if any(
                item.get("id") == known or item.get("name") == intent.name
                for item in client.inventory()
            ):
                raise LifecycleError("deleted credential remains in inventory")
            if credential is None and pending:
                raise LifecycleError("a failed authentication rejection still needs its credential")
            if credential is not None:
                if known != credential.identifier:
                    raise LifecycleError("retained credential identity differs from its obligation")
                if (
                    not pending
                    and not abort_conflict
                    and prior is not None
                    and isinstance(prior["payload"], dict)
                    and prior["payload"].get("credential_id") == known
                    and prior["payload"].get("negative_authentication") == "denied"
                ):
                    # A previous verified probe may only be waiting for external
                    # persistence. Recheck removal above, then finish that exact
                    # proof instead of generating another marker on every retry.
                    self.journal.persist(prior)
                    return CleanupResult(intent.sha256, "verified", "denied")
                # Losing this actor after DELETE must not let a later actor
                # discard a failed negative probe by omitting the retained key.
                # Reuse an outstanding marker; each retry still probes afresh.
                if not pending:
                    marker = _authentication_marker(intent)
                    marker = self.journal.persist(marker)
                    pending.add(identity(marker["event_id"]))
                else:
                    for marker in observations:
                        if marker["event_id"] in pending:
                            self.journal.persist(marker)
                if not client.denied(intent, credential):
                    raise LifecycleError(
                        "revoked credential still authenticates or rejection is unproven"
                    )
                negative = "denied"
            if abort_conflict:
                # Still delete an exactly owned credential and probe its retained
                # secret above. Contradictions forbid closure, not revocation.
                raise LifecycleError("creation evidence conflicts with pre-creation outcome")
            proof: dict[str, object] = {
                "intent_sha256": intent.sha256,
                "credential_id": known,
                "provider_readback": "absent",
                "negative_authentication": negative,
            }
            if credential is not None:
                proof["negative_authentication_markers"] = sorted(pending)
            if (
                credential is not None
                or prior is None
                or prior["kind"] != "resolved"
                or (
                    isinstance(prior["payload"], dict)
                    and prior["payload"].get("negative_authentication") != "denied"
                    and prior["payload"] != proof
                )
            ):
                proof_record = event("resolved", intent.run_id, proof)
            else:
                proof_record = prior
            # A secretless retry and a new-start check must not mistake a staged
            # proof for external closure either. The GitHub actor persists its
            # own proofs in recoverable off-host checkpoints before returning.
            self.journal.persist(proof_record)
            return CleanupResult(intent.sha256, "verified", negative)
        except LifecycleError, OSError, ValueError, KeyError, TypeError:
            # Never copy provider exception payloads into status or erase intent.
            return CleanupResult(intent.sha256, "unresolved", negative)

    def _historical_batch(
        self, selected: list[tuple[Intent, _Historical]]
    ) -> dict[str, CleanupResult]:
        """Share only the final complete inventory after all exact-ID observations."""
        unresolved = {
            intent.sha256: CleanupResult(intent.sha256, "unresolved", "unavailable")
            for intent, _ in selected
        }
        client = self.providers[selected[0][0].provider]
        try:
            for _, proof in selected:
                self.journal.persist(proof.created)
                self.progress()
            # Spaces has no separate key-detail read: inspect() is a complete
            # inventory plus ID lookup. Share that first ordered observation as
            # well; Cloudflare still needs its actual per-token detail endpoint.
            try:
                first = client.inventory() if selected[0][0].provider == "spaces" else None
            except LifecycleError, OSError, ValueError, KeyError, TypeError:
                return unresolved
            visible = False
            for offset in range(0, len(selected), READBACK_WORKERS):
                wave = selected[offset : offset + READBACK_WORKERS]
                present = (
                    [any(item.get("id") == proof.identifier for item in first) for _, proof in wave]
                    if first is not None
                    else _historical_details(client, [proof.identifier for _, proof in wave])
                )
                visible = any(present) or visible
                for _ in wave:
                    self.progress()
            if visible:
                # No shared observation survives an ordinary reconciliation,
                # which may delete an exactly owned credential.
                return {}
            try:
                inventory = client.inventory()
            except LifecycleError, OSError, ValueError, KeyError, TypeError:
                return unresolved
            if any(
                item.get("id") == proof.identifier or item.get("name") == intent.name
                for intent, proof in selected
                for item in inventory
            ):
                return unresolved
            observed = self.journal.records()
            if any(self._historical(intent, observed) != proof for intent, proof in selected):
                raise LifecycleError("historical cleanup eligibility changed during readback")
            for _, proof in selected:
                self.journal.persist(proof.resolved)
                self.progress()
            # Persistence/progress can expose a newer marker or conflicting ID.
            # An old resolution never discharges that newly observed obligation.
            observed = self.journal.records()
            if self.providers[selected[0][0].provider] is not client or any(
                self._historical(intent, observed) != proof for intent, proof in selected
            ):
                raise LifecycleError("historical cleanup eligibility changed during persistence")
            return {
                intent.sha256: CleanupResult(intent.sha256, "verified", "unavailable")
                for intent, _ in selected
            }
        except LifecycleError, OSError, ValueError, KeyError, TypeError:
            # A member-specific detail/persistence failure must not strand an
            # owned sibling that has reappeared. Discard all shared observations;
            # ordinary reconciliation isolates failures and verifies afresh.
            return {}

    def _historical_selection(
        self,
        original: list[Intent],
        available: Mapping[str, Credential],
        records: list[dict[str, object]],
    ) -> dict[ProviderKind, list[tuple[Intent, _Historical]]]:
        historical: dict[ProviderKind, list[tuple[Intent, _Historical]]] = {}
        for item in original:
            if item.sha256 in available:
                continue
            try:
                proof = self._historical(item, records)
            except LifecycleError, OSError, ValueError, KeyError, TypeError:
                continue  # Ordinary reconciliation retains the unresolved obligation.
            if proof is not None:
                historical.setdefault(item.provider, []).append((item, proof))
        return historical

    def _current_result(
        self, intent: Intent, result: CleanupResult, records: list[dict[str, object]]
    ) -> CleanupResult:
        """A later callback cannot leave an earlier result admitting new work."""
        try:
            if result.status == "not-due":
                if not self._due(intent, records):
                    return result
            elif result.status == historical_absence.STATUS:
                if historical_absence.receipts(intent, records):
                    return result
            elif result.status == "verified":
                known = _known_id(records, intent)
                intent_sha256 = intent.sha256
                observations = [
                    record
                    for record in records
                    if record["kind"] in {"cleanup", "resolved"}
                    and isinstance(record["payload"], dict)
                    and record["payload"].get("intent_sha256") == intent_sha256
                ]
                if not pending_authentication(observations) and any(
                    record["kind"] == "resolved"
                    and isinstance(record["payload"], dict)
                    and record["payload"].get("credential_id") == known
                    and record["payload"].get("provider_readback") == "absent"
                    and valid_resolution(record, intent, records)
                    for record in observations
                ):
                    return result
            else:
                return result
        except LifecycleError, OSError, ValueError, KeyError, TypeError:
            pass
        return CleanupResult(intent.sha256, "unresolved", "unavailable")

    def sweep(self, secrets: Mapping[str, Credential] | None = None) -> list[CleanupResult]:
        self._clearance = None
        self._sweep_results = None
        records = self.journal.records()
        before = _obligation_basis(records)
        available = secrets or {}
        original = intents(self.journal)
        historical = self._historical_selection(original, available, records)
        clients = {kind: self.providers[kind] for kind in historical}
        batched: dict[str, CleanupResult] = {}
        for selected in historical.values():
            batched.update(self._historical_batch(selected))
        results = []
        for item in original:
            results.append(
                batched[item.sha256]
                if item.sha256 in batched
                else self.reconcile(item, available.get(item.sha256))
            )
            self.progress()
        observed = self.journal.records()
        # Process one bounded frontier exposed by persistence/progress. An
        # admitted run's new child usually is not due; inventing an unresolved
        # result would suppress its ACK until the next periodic sweep. Ordinary
        # reconciliation still deletes due children and rejects unknown absence.
        present = {result.intent_sha256 for result in results}
        for item in _intents(observed):
            if item.sha256 not in present:
                results.append(self.reconcile(item, available.get(item.sha256)))
                present.add(item.sha256)
                self.progress()
        observed = self.journal.records()
        # Later providers and ordinary cleanup can expose changes too. Do not
        # merely withhold the cached clearance: inline callers use these results.
        for kind, selected in historical.items():
            for item, proof in selected:
                try:
                    unchanged = (
                        self.providers[kind] is clients[kind]
                        and self._historical(item, observed) == proof
                    )
                except LifecycleError, OSError, ValueError, KeyError, TypeError:
                    unchanged = False
                if not unchanged:
                    results = [
                        CleanupResult(item.sha256, "unresolved", "unavailable")
                        if result.intent_sha256 == item.sha256
                        else result
                        for result in results
                    ]
        # Further arrivals cannot extend this pass indefinitely or silently
        # fall outside its result set. They remain non-admitting until checked.
        for item in _intents(observed):
            if item.sha256 not in present:
                results.append(CleanupResult(item.sha256, "unresolved", "unavailable"))
                present.add(item.sha256)
        by_id = {item.sha256: item for item in _intents(observed)}
        results = [
            self._current_result(by_id[result.intent_sha256], result, observed)
            for result in results
        ]
        after = _obligation_basis(observed)
        if before == after and all(
            historical_absence.admits(result.intent_sha256, result.status) for result in results
        ):
            self._clearance = time.monotonic(), after
        self._sweep_results = tuple(results)
        return results

    def creation_clear(  # noqa: PLR0911 - each adverse fresh observation blocks creation
        self, observed: list[dict[str, object]], *, run_id: str
    ) -> bool:
        """Revalidate completed coverage against the exact fresh ACK snapshot."""
        if self._sweep_results is None or any(
            row["kind"] == "revoke" and row["run_id"] == run_id for row in observed
        ):
            return False
        try:
            current = _intents(observed)  # Reject duplicate run/role identities.
            proven = {value.intent_sha256: value for value in self._sweep_results}
            if not proven.keys() <= {item.sha256 for item in current}:
                return False
            for item in current:
                _known_id(observed, item)  # Reject conflicting returned IDs, even before due.
                if self.providers[item.provider].authority_sha256 != item.cleanup_authority_sha256:
                    return False
                proof = proven.get(item.sha256)
                if proof is None:
                    # The serial controller can stage its next child after this
                    # sweep. Only this exact active run may expose a not-due
                    # frontier; its binding/reservation is checked by Admission.
                    if item.run_id != run_id or select_abort(item, observed) is not None:
                        return False
                    proof = CleanupResult(item.sha256, "not-due", "not-tested")
                result = self._current_result(item, proof, observed)
                if result.status == "not-due":
                    if item.run_id != run_id or select_abort(item, observed) is not None:
                        return False
                elif not historical_absence.admits(result.intent_sha256, result.status):
                    return False
            return True
        except LifecycleError, OSError, ValueError, KeyError, TypeError:
            return False

    @measure("credential-clearance")
    def require_clear(self, *, observed: list[dict[str, object]] | None = None) -> None:
        clearance, self._clearance = self._clearance, None
        if observed is not None and clearance is not None:
            # Admission immediately following a successful sweep can reuse it
            # only while every relevant journal record remains identical. New
            # IDs, intents, revocations or authentication markers force a sweep.
            completed, basis = clearance
            if (
                time.monotonic() - completed < CLEARANCE_SECONDS
                and _obligation_basis(observed) == basis
            ):
                return
        # Recheck provider inventory even for a previously resolved intent. This
        # catches delayed creation responses without trusting old DELETE receipts.
        if any(
            not historical_absence.admits(result.intent_sha256, result.status)
            for result in self.sweep()
        ):
            raise LifecycleError("outstanding credential obligations block a new qualification")


def _authentication_marker(intent: Intent) -> dict[str, object]:
    return event(
        "cleanup",
        intent.run_id,
        {
            "intent_sha256": intent.sha256,
            "negative_authentication": "required",
            "proof_binding": "event-id",
        },
    )


def lease_manifest(  # noqa: PLR0913 - explicit approved authorities and inputs
    *,
    lease_id: str,
    source: str,
    helper: str,
    targets: Targets,
    policy: LeasePolicy,
    approved_policy_sha256: str,
    creator: AuthorityGeneration,
    cleanup: AuthorityGeneration,
    providers: Mapping[ProviderKind, Provider],
    cleanup_providers: Mapping[ProviderKind, Provider],
    scopes: Mapping[str, dict[str, object]],
    now: datetime,
) -> LeaseManifest:
    """Read all ownership baselines before retaining the one complete manifest."""
    now = now.replace(microsecond=0)
    policy.require_start(now=now, approved_sha256=approved_policy_sha256)
    if set(scopes) != ROLES or set(providers) != PROVIDERS or set(cleanup_providers) != PROVIDERS:
        raise LifecycleError("lease preparation requires all approved roles and providers")
    baseline: dict[ProviderKind, list[dict[str, object]]] = {}
    for kind, client in providers.items():
        if (
            client.authority_sha256 != creator.fingerprints[kind]
            or cleanup_providers[kind].authority_sha256 != cleanup.fingerprints[kind]
        ):
            raise LifecycleError("lease provider differs from its authority generation")
        original = client.inventory()
        independent = cleanup_providers[kind].inventory()
        if sorted(identifier(item.get("id")) for item in original) != sorted(
            identifier(item.get("id")) for item in independent
        ):
            raise LifecycleError("lease authorities observe different provider inventories")
        baseline[kind] = original
    selected = []
    for role in sorted(ROLES):
        kind = (
            "spaces"
            if role in {"archive", "backup", "operator"}
            else "cloudflare-user"
            if role == "page-rules"
            else "cloudflare-account"
        )
        name = f"ldp-m311-{uuid.UUID(lease_id).hex}-{role}"
        if any(item.get("name") == name for item in baseline[kind]):
            raise LifecycleError("lease name already exists; no credential may be adopted")
        selected.append(
            Intent(
                run_id=lease_id,
                role=role,
                source_revision=source,
                helper_revision=helper,
                provider=kind,
                cleanup_authority_sha256=cleanup.fingerprints[kind],
                name=name,
                requested_at=stamp(now),
                create_before=policy.issuance_before,
                deadline=stamp(policy.deadline(now)),
                scope=deepcopy(scopes[role]),
                baseline_ids=tuple(sorted(identifier(item.get("id")) for item in baseline[kind])),
                targets=targets,
                policy=policy,
            )
        )
    return LeaseManifest(
        lease_id, source, helper, stamp(now), policy, creator, cleanup, targets, tuple(selected)
    )


class LeaseLifecycle:
    """One uninterrupted issuer; immutable off-host facts and private child values."""

    def __init__(
        self,
        manifest: LeaseManifest,
        inventory: Inventory,
        state: LeaseState,
        *,
        providers: Mapping[ProviderKind, Provider],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.manifest, self.inventory, self.state = manifest, inventory, state
        self.providers, self.clock = providers, clock
        self.state.initialize(manifest)
        self._original_writer: str | None = None
        self._issue_entered = False

    def prepare(self, *, writer_sha256: str | None = None) -> None:
        if writer_sha256 is not None:
            self.state.claim_issuer(writer_sha256=writer_sha256)
            self._original_writer = writer_sha256
        self.inventory.publish(fact(self.manifest, "manifest", self.manifest.document()))

    def abandon_prepared(self) -> None:
        """Only the uninterrupted original preparer can attest no submission."""
        if self._original_writer is not None and not self._issue_entered:
            self._end_issuance(self._original_writer, set())
            self._original_writer = None

    def credentials(
        self, *, binding: dict[str, object]
    ) -> tuple[dict[str, Credential], dict[str, object]]:
        """Fresh validation binds a reused lease to a new immutable attempt."""
        from scripts.m3_11_unattended import inputs  # noqa: PLC0415

        observed = self.records()
        started = self.clock()
        deadline = self.manifest.policy.deadline(instant(self.manifest.created_at))
        if (
            "issuer-stopped" not in observed
            or deadline - started < MINIMUM_TOKEN_REMAINING
            or any(slot.startswith("close-") for slot in observed)
            or any(self.state.directory.glob("close-*.json"))
        ):
            raise LifecycleError("lease is closing, incomplete or lacks remaining validity")
        values: dict[str, Credential] = {}
        for intent in self.manifest.intents:
            credential = self.state.credential(intent)
            created = observed.get("created:" + intent.role)
            if (
                credential is None
                or created is None
                or created["payload"]
                != {"intent_sha256": intent.sha256, "credential_id": credential.identifier}
            ):
                raise LifecycleError("lease credential identity or private delivery is unavailable")
            client = self.providers[intent.provider]
            metadata = client.inspect(credential.identifier)
            if (
                metadata is None
                or metadata.get("scope") != intent.scope
                or metadata.get("status") != "active"
            ):
                raise LifecycleError("reused lease credential policy or status differs")
            _owned(intent, metadata, known=credential.identifier)
            client.verify(intent, credential, now=self.clock())
            values[intent.role] = credential
        if len({value.secret for value in values.values()}) != len(ROLES) or len(
            {value.identifier for value in values.values()}
        ) != len(ROLES):
            raise LifecycleError("reused lease credential identities are not separated")
        receipt = {
            "format": inputs.LEASE_FIXTURE_FORMAT,
            **fields(binding, inputs.BINDING),
            "lease_id": self.manifest.lease_id,
            "lease_manifest_sha256": self.manifest.sha256,
            "lease_policy": self.manifest.policy.document(),
            "lease_issued_at": self.manifest.created_at,
            "started_at": stamp(started),
            "completed_at": stamp(self.clock()),
            "deadline": stamp(deadline),
            "checks": inputs.FIXTURE_RESULT,
            "identities_sha256": {
                role: hashlib.sha256(value.identifier.encode()).hexdigest()
                for role, value in values.items()
            },
        }
        inputs.validate_receipt(receipt, binding=binding, kind="fixture", now=self.clock())
        return values, receipt

    def records(self) -> dict[str, dict[str, object]]:
        records = {
            str(record["slot"]): record
            for record in self.inventory.records()
            if record["lease_id"] == self.manifest.lease_id
        }
        if any(record["manifest_sha256"] != self.manifest.sha256 for record in records.values()):
            raise LifecycleError("lease inventory contains a conflicting manifest binding")
        return records

    def request_close(self, reason: str) -> None:
        record = fact(self.manifest, "close-" + reason, {})
        self.state.retain("close-" + reason + ".json", record)
        # This publication never takes the provider-cleanup lock. Its failure
        # leaves the local request intact and cannot authorize another CREATE.
        self.inventory.publish(record)

    def _before_create(self, check_cancelled: Callable[[], None]) -> None:
        check_cancelled()
        now = self.clock()
        if (
            now >= instant(self.manifest.policy.issuance_before)
            or self.manifest.policy.deadline(instant(self.manifest.created_at)) - now
            < MINIMUM_TOKEN_REMAINING
            or any(self.state.directory.glob("close-*.json"))
            or any(slot.startswith("close-") for slot in self.records())
        ):
            raise LifecycleError("lease creation is cancelled or outside its approved bounds")

    def _remember(self, intent: Intent, selected: str, secret: str | None) -> None:
        self.state.remember(intent, identifier(selected), secret)
        self.inventory.publish(
            fact(
                self.manifest,
                "created:" + intent.role,
                {
                    "intent_sha256": intent.sha256,
                    "credential_id": selected,
                },
            )
        )

    def _end_issuance(self, writer_sha256: str, submitted: set[str]) -> None:
        errors: list[Exception] = []
        for intent in self.manifest.intents:
            if intent.role in submitted:
                continue
            record = fact(
                self.manifest,
                "not-submitted:" + intent.role,
                {
                    "intent_sha256": intent.sha256,
                    "writer_sha256": writer_sha256,
                },
            )
            try:
                self.state.retain("not-submitted-" + intent.role + ".json", record)
                self.inventory.publish(record)
            except Exception as error:
                errors.append(error)
        # All synchronous provider exchanges have returned or their bounded
        # subprocess was reaped. This invocation has no further CREATE path.
        proof = self.state.finish_issuer(
            writer_sha256=writer_sha256, stopped_at=stamp(self.clock())
        )
        try:
            self.inventory.publish(fact(self.manifest, "issuer-stopped", proof))
        except Exception as error:
            errors.append(error)
        if errors:
            raise LifecycleError("lease issuance evidence remains unpublished") from errors[0]

    def issue(
        self,
        *,
        writer_sha256: str,
        approved_policy_sha256: str,
        independent_server_id: str,
        check_cancelled: Callable[[], None] = lambda: None,
    ) -> dict[str, Credential]:
        self.manifest.policy.require_start(now=self.clock(), approved_sha256=approved_policy_sha256)
        require_confirmation(
            self.inventory, self.manifest, independent_server_id=independent_server_id
        )
        if set(self.providers) != PROVIDERS:
            raise LifecycleError("issuance provider set is incomplete")
        for kind, client in self.providers.items():
            if (
                client.kind != kind
                or client.authority_sha256 != self.manifest.creator.fingerprints[kind]
            ):
                raise LifecycleError("issuance requires its original verified authority generation")
        self._before_create(check_cancelled)
        if self._original_writer is None:
            self.state.claim_issuer(writer_sha256=writer_sha256)
        elif self._original_writer != writer_sha256:
            raise LifecycleError("issuance does not belong to its uninterrupted preparer")
        self._issue_entered = True
        submitted: set[str] = set()
        credentials: dict[str, Credential] = {}
        try:
            for intent in self.manifest.intents:
                self._before_create(check_cancelled)
                self.state.submitting(intent, writer_sha256=writer_sha256)
                # From this point, any interruption leaves this role uncertain.
                # Never infer non-submission from absent provider inventory.
                submitted.add(intent.role)
                client = self.providers[intent.provider]
                credential = client.create(
                    intent,
                    record=partial(self._remember, intent),
                )
                metadata = client.inspect(credential.identifier)
                if metadata is None:
                    raise LifecycleError("issued lease credential is absent from provider readback")
                _owned(intent, metadata, known=credential.identifier)
                if metadata.get("scope") != intent.scope or metadata.get("status") != "active":
                    raise LifecycleError("issued lease credential scope or status differs")
                client.verify(intent, credential, now=self.clock())
                saved = self.state.credential(intent)
                if (
                    saved is None
                    or saved.identifier != credential.identifier
                    or saved.secret != credential.secret
                ):
                    raise LifecycleError("issued lease credential differs from private delivery")
                credentials[intent.role] = credential
            if len({entry.identifier for entry in credentials.values()}) != len(credentials) or len(
                {entry.secret for entry in credentials.values()}
            ) != len(credentials):
                raise LifecycleError("issued lease credentials are not separate identities")
            return credentials
        except BaseException:
            self.request_close("provisioning-failed")
            raise
        finally:
            self._end_issuance(writer_sha256, submitted)

    def _local_facts(self) -> list[dict[str, object]]:
        from scripts.m3_11_private_inputs import read_private  # noqa: PLC0415 - private recovery

        records = [read_private(path) for path in self.state.directory.glob("close-*.json")]
        for intent in self.manifest.intents:
            created = self.state.created(intent)
            if created is not None:
                records.append(fact(self.manifest, "created:" + intent.role, created))
            path = self.state.directory / ("not-submitted-" + intent.role + ".json")
            if path.exists():
                records.append(read_private(path))
        path = self.state.directory / "issuer-stopped.json"
        if path.exists():
            records.append(fact(self.manifest, "issuer-stopped", read_private(path)))
        return records

    def cleanup_generation(
        self,
        intent: Intent,
        observed: dict[str, dict[str, object]],
        available: Mapping[str, Mapping[ProviderKind, Provider]] | None = None,
    ) -> AuthorityGeneration:
        current = self.manifest.cleanup
        chain = [current]
        remaining = [
            row
            for slot, row in observed.items()
            if slot.startswith("handover:" + intent.role + ":")
        ]
        while remaining:
            matches = [
                row
                for row in remaining
                if isinstance(row["payload"], dict)
                and row["payload"]["previous_generation_sha256"] == digest(current.document())
            ]
            if len(matches) != 1:
                raise LifecycleError("cleanup authority handover history is ambiguous")
            row = matches[0]
            payload = cast(dict[str, object], row["payload"])
            created = observed.get("created:" + intent.role)
            if (
                payload["intent_sha256"] != intent.sha256
                or created is None
                or cast(dict[str, object], created["payload"])["credential_id"]
                != payload["credential_id"]
            ):
                raise LifecycleError("cleanup handover lacks its exact known credential")
            replacement = AuthorityGeneration.parse(payload["generation"])
            replacement.require_same_principal(current)
            current = replacement
            chain.append(current)
            remaining.remove(row)
        if available is not None:
            # During staged delivery, the old explicitly bound authority remains
            # valid for cleanup. Never infer equivalence from authentication or
            # an empty inventory; every fallback is in this verified chain.
            for candidate in reversed(chain):
                provider = available.get(candidate.generation_id, {}).get(intent.provider)
                if (
                    provider is not None
                    and provider.authority_sha256 == candidate.fingerprints[intent.provider]
                ):
                    return candidate
        return current

    def handover(
        self,
        replacement: AuthorityGeneration,
        providers: Mapping[ProviderKind, Provider],
        previous: Mapping[ProviderKind, Provider],
    ) -> None:
        """Positively read known children with both principals before recording handover.

        Unknown-ID obligations deliberately retain their original generation.
        Empty inventory is never a cross-generation capability proof.
        """
        replacement.require_same_principal(self.manifest.cleanup)
        replacement.require_coverage(
            policy=self.manifest.policy,
            deadline=self.manifest.policy.deadline(instant(self.manifest.created_at)),
        )
        observed = self.records()
        for intent in self.manifest.intents:
            selected = observed.get("created:" + intent.role)
            if selected is None:
                raise LifecycleError(
                    "unknown credential identity retains its original cleanup generation"
                )
            payload = cast(dict[str, object], selected["payload"])
            credential_id = identifier(payload["credential_id"])
            current = self.cleanup_generation(intent, observed)
            if current == replacement:
                continue
            for client, generation in (
                (previous[intent.provider], current),
                (providers[intent.provider], replacement),
            ):
                if client.authority_sha256 != generation.fingerprints[intent.provider]:
                    raise LifecycleError("cleanup handover uses an unverified authority")
                metadata = client.inspect(credential_id)
                if metadata is None:
                    raise LifecycleError(
                        "replacement must positively read each outstanding credential"
                    )
                _owned(intent, metadata, known=credential_id)
                if (
                    metadata.get("scope") != intent.scope
                    or metadata.get("status") != "active"
                    or (
                        intent.provider != "spaces"
                        and instant(metadata.get("expires_at")) != instant(intent.deadline)
                    )
                ):
                    raise LifecycleError("cleanup handover credential policy differs")
            record = fact(
                self.manifest,
                "handover:" + intent.role + ":" + replacement.generation_id,
                {
                    "intent_sha256": intent.sha256,
                    "credential_id": credential_id,
                    "previous_generation_sha256": digest(current.document()),
                    "generation": replacement.document(),
                    "observed_at": stamp(self.clock()),
                },
            )
            self.inventory.publish(record)

    def reconcile(
        self,
        cleanup_providers: Mapping[ProviderKind, Provider],
        *,
        generations: Mapping[str, Mapping[ProviderKind, Provider]] | None = None,
    ) -> list[CleanupResult]:
        """Readback and negative probes, independently of the qualification result.

        Publication failures do not suppress deletion of exactly owned children.
        They do suppress successful closure until the same facts are observed.
        """
        durable = True
        try:
            observed = self.records()
        except LifecycleError, OSError, ValueError:
            observed, durable = {}, False
        local = self._local_facts()
        for record in local:
            slot = str(record["slot"])
            if slot in observed and observed[slot] != record:
                raise LifecycleError("local lease recovery conflicts with the external inventory")
            observed[slot] = record
            try:
                self.inventory.publish(record)
            except LifecycleError, OSError, ValueError:
                durable = False
        due = self.clock() >= self.manifest.policy.deadline(
            instant(self.manifest.created_at)
        ) or any(slot.startswith("close-") for slot in observed)
        if not due:
            return [
                CleanupResult(
                    intent.sha256,
                    "not-due" if durable else "unresolved",
                    "not-tested" if durable else "unverified",
                )
                for intent in self.manifest.intents
            ]
        results = []
        for intent in self.manifest.intents:
            try:
                generation = self.cleanup_generation(intent, observed, generations)
                client = (
                    generations[generation.generation_id]
                    if generations is not None
                    else cleanup_providers
                )[intent.provider]
                if (
                    client.kind != intent.provider
                    or client.authority_sha256 != generation.fingerprints[intent.provider]
                ):
                    raise LifecycleError("cleanup provider differs from the lease authority")
                result = self._reconcile_role(intent, client, observed)
            except LifecycleError, OSError, ValueError, KeyError:
                result = CleanupResult(intent.sha256, "unresolved", "unverified")
            if not durable or "issuer-stopped" not in observed:
                result = CleanupResult(intent.sha256, "unresolved", result.negative_authentication)
            results.append(result)
        return results

    def _reconcile_role(  # noqa: PLR0912 - positive ownership/readback and closure gates
        self, intent: Intent, client: Provider, observed: dict[str, dict[str, object]]
    ) -> CleanupResult:
        known: str | None = None
        created = observed.get("created:" + intent.role)
        if created is not None:
            payload = cast(dict[str, object], created["payload"])
            if payload["intent_sha256"] != intent.sha256:
                raise LifecycleError("recorded credential differs from the lease intent")
            known = identifier(payload["credential_id"])
        candidates = [
            item
            for item in client.inventory()
            if item.get("name") == intent.name or item.get("id") == known
        ]
        if len(candidates) > 1:
            raise LifecycleError("lease credential inventory is ambiguous")
        if candidates:
            known = _owned(intent, candidates[0], known=known)
        unsent, stopped = (
            observed.get("not-submitted:" + intent.role),
            observed.get("issuer-stopped"),
        )
        conflict = unsent is not None and known is not None
        if known is None:
            if unsent is not None and stopped is not None:
                proof, fence = (
                    cast(dict[str, object], unsent["payload"]),
                    cast(dict[str, object], stopped["payload"]),
                )
                if (
                    proof["intent_sha256"] == intent.sha256
                    and proof["writer_sha256"] == fence["writer_sha256"]
                ):
                    return CleanupResult(intent.sha256, "verified", "not-tested")
            return CleanupResult(intent.sha256, "creation-uncertain", "unavailable")
        # Retain a recovered ID locally before deleting. A failed off-host write
        # leaves an explicit unresolved obligation, but cannot strand the key.
        self.state.remember(intent, known, None)
        identity_record = fact(
            self.manifest,
            "created:" + intent.role,
            {"intent_sha256": intent.sha256, "credential_id": known},
        )
        durable = True
        try:
            self.inventory.publish(identity_record)
        except LifecycleError, OSError, ValueError:
            durable = False
        current = client.inspect(known)
        if current is not None:
            _owned(intent, current, known=known)
            client.delete(known)
        if client.inspect(known) is not None or any(
            item.get("id") == known or item.get("name") == intent.name
            for item in client.inventory()
        ):
            raise LifecycleError("lease credential removal remains unverified")
        self.inventory.publish(
            fact(
                self.manifest,
                "removed:" + intent.role,
                {"intent_sha256": intent.sha256, "credential_id": known},
            )
        )
        credential = self.state.credential(intent)
        negative = "unavailable"
        if credential is not None:
            if credential.identifier != known or not client.denied(intent, credential):
                raise LifecycleError(
                    "revoked lease credential still authenticates or denial is unproven"
                )
            negative = "denied"
            self.inventory.publish(
                fact(
                    self.manifest,
                    "denied:" + intent.role,
                    {"intent_sha256": intent.sha256, "credential_id": known},
                )
            )
        elif (denied := observed.get("denied:" + intent.role)) is not None:
            if denied["payload"] != {"intent_sha256": intent.sha256, "credential_id": known}:
                raise LifecycleError("lease authentication proof differs from its identity")
            negative = "denied"
        elif stopped is not None and intent.role in cast(
            list[str], cast(dict[str, object], stopped["payload"])["retained_roles"]
        ):
            # A second actor cannot erase a failed or pending negative probe by
            # omitting the host's credential. Actual permanent secret loss needs
            # an explicit disposition; absence of a local file is not that proof.
            return CleanupResult(intent.sha256, "unresolved", "unavailable")
        if conflict or not durable:
            return CleanupResult(intent.sha256, "unresolved", negative)
        return CleanupResult(intent.sha256, "verified", negative)


def fixture_scopes(
    targets: Targets, providers: Mapping[ProviderKind, Provider]
) -> dict[str, dict[str, object]]:
    from scripts.m3_11_unattended.cloudflare import (  # noqa: PLC0415 - provider contracts
        Cloudflare,
    )

    scopes: dict[str, dict[str, object]] = {}
    for role in sorted(ROLES):
        if role in {"archive", "backup", "operator"}:
            scopes[role] = {
                "grants": [
                    {
                        "bucket": "" if role == "operator" else getattr(targets, role + "_bucket"),
                        "permission": "fullaccess" if role == "operator" else "readwrite",
                    }
                ]
            }
        else:
            client = providers["cloudflare-user" if role == "page-rules" else "cloudflare-account"]
            if not isinstance(client, Cloudflare):
                raise LifecycleError("fixture token scope reader is unavailable")
            scopes[role] = client.scope(role, targets)
    return scopes
