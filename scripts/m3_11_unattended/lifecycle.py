"""Create once, journal first, and reconcile exact owned credentials until revoked."""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from scripts.m3_11_unattended import historical_absence
from scripts.m3_11_unattended.creation_outcome import is_abort, select_abort
from scripts.m3_11_unattended.journal import CreationJournal, Journal, event
from scripts.m3_11_unattended.model import (
    CREATION_SETTLE,
    LIFETIME,
    Authority,
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    Targets,
    digest,
    identity,
    instant,
    stamp,
)
from scripts.qualification_timing import measure

CreationRecorder = Callable[[str, str | None], None]
CLEARANCE_SECONDS = 30


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
    result = [
        Intent.parse(record["payload"])
        for record in journal.records()
        if record["kind"] == "intent"
    ]
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

    def provision(  # noqa: PLR0913 - all approval and authority bindings are explicit
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
        if any(item.run_id == run_id and item.role == role for item in intents(self.journal)):
            raise LifecycleError(
                "credential creation cannot be replayed; reconcile the original intent"
            )
        # Both provider APIs may round creation timestamps to whole seconds.
        now = self.clock().replace(microsecond=0)
        deadline = now + LIFETIME
        authority.require(deadline)
        client = self.providers[provider]
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
        try:
            if self.remember_intent is not None:
                self.remember_intent(intent)
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
            for _, proof in selected:
                present = (
                    any(item.get("id") == proof.identifier for item in first)
                    if first is not None
                    else client.inspect(proof.identifier) is not None
                )
                visible = present or visible
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

    def sweep(self, secrets: Mapping[str, Credential] | None = None) -> list[CleanupResult]:
        self._clearance = None
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
        # Later providers and ordinary cleanup can expose changes too. Do not
        # merely withhold the cached clearance: inline callers use these results.
        for kind, selected in historical.items():
            for item, proof in selected:
                if item.sha256 not in batched:
                    continue
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
        present = {result.intent_sha256 for result in results}
        for record in observed:
            if record["kind"] == "intent":
                item = Intent.parse(record["payload"])
                if item.sha256 not in present:
                    results.append(CleanupResult(item.sha256, "unresolved", "unavailable"))
                    present.add(item.sha256)
        after = _obligation_basis(observed)
        if before == after and all(
            historical_absence.admits(result.intent_sha256, result.status) for result in results
        ):
            self._clearance = time.monotonic(), after
        return results

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
