"""Create once, journal first, and reconcile exact owned credentials until revoked."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from scripts.m3_11_unattended.journal import Journal, event
from scripts.m3_11_unattended.model import (
    CREATION_SETTLE,
    LIFETIME,
    Authority,
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    Targets,
    identity,
    instant,
    stamp,
)

CreationRecorder = Callable[[str, str | None], None]


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
    matches: set[str] = set()
    for record in journal.records():
        if record["kind"] != "created" or record["run_id"] != intent.run_id:
            continue
        payload = record["payload"]
        if not isinstance(payload, dict):
            raise LifecycleError("invalid credential identity record")
        if payload.get("intent_sha256") == intent.sha256:
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
    ) -> None:
        self.journal, self.providers, self.clock = journal, providers, clock
        self.remember = remember
        self.remember_intent = remember_intent
        self.remember_created = remember_created

    def _record_creation(self, intent: Intent, selected: str, secret: str | None) -> None:
        record = event(
            "created",
            intent.run_id,
            {"intent_sha256": intent.sha256, "credential_id": identifier(selected)},
        )
        try:
            if self.remember_created is not None:
                self.remember_created(intent, record)
            if secret is not None and self.remember is not None:
                self.remember(intent, Credential(selected, secret, {}))
        finally:
            # A private delivery failure must not discard an acknowledged ID.
            # Conversely, retain its local record before a remote ACK can fail.
            self.journal.persist(record)
        if secret is not None and self.remember is not None:
            self.journal.persist(_authentication_marker(intent))

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
            scope=scope,
            baseline_ids=tuple(sorted(identifier(item.get("id")) for item in inventory)),
            targets=targets,
        )
        if self.remember_intent is not None:
            self.remember_intent(intent)
        self.journal.persist(event("intent", run_id, intent.document()))
        before = instant(intent.create_before)
        if provisioning_deadline is not None:
            before = min(before, provisioning_deadline)
        if self.clock() >= before:
            raise LifecycleError("credential creation window elapsed before acknowledgement")
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
        if metadata.get("scope") != scope or metadata.get("status") != "active":
            raise LifecycleError("new credential has an unexpected scope or inactive status")
        client.verify(intent, credential, now=self.clock())
        return intent, credential

    def request_revocation(self, run_id: str) -> None:
        if not any(
            record["kind"] == "revoke" and record["run_id"] == run_id
            for record in self.journal.records()
        ):
            self.journal.append(event("revoke", run_id, {"reason": "terminal-path"}))

    def _due(self, intent: Intent) -> bool:
        return self.clock() >= instant(intent.deadline) or any(
            record["kind"] == "revoke" and record["run_id"] == intent.run_id
            for record in self.journal.records()
        )

    def reconcile(  # noqa: PLR0912, PLR0915 - separate ownership, removal, authentication and durability gates
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
            inventory = client.inventory()
            candidates = [
                item
                for item in inventory
                if item.get("name") == intent.name or item.get("id") == known
            ]
            if len(candidates) > 1:
                raise LifecycleError("credential inventory is ambiguous")
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
            prior = next(
                (record for record in reversed(observations) if record["kind"] == "resolved"), None
            )
            if credential is not None:
                if known != credential.identifier:
                    raise LifecycleError("retained credential identity differs from its obligation")
                if (
                    not pending
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

    def sweep(self, secrets: Mapping[str, Credential] | None = None) -> list[CleanupResult]:
        available = secrets or {}
        return [self.reconcile(item, available.get(item.sha256)) for item in intents(self.journal)]

    def require_clear(self) -> None:
        # Recheck provider inventory even for a previously resolved intent. This
        # catches delayed creation responses without trusting old DELETE receipts.
        if any(result.status != "verified" for result in self.sweep()):
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
