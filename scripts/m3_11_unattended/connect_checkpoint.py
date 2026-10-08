"""Recoverable off-host checkpoints must precede Connect acknowledgements.

The registry is authoritative for its latest identity. A missing, older or
unreadable checkpoint never permits fallback to a Connect cache or old file.
Only non-secret journal records enter the encrypted payload, never credentials.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.journal import MAX_EVENTS, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity
from scripts.qualification_timing import measure

FORMAT = "lowerduckpond-m3-11-connect-checkpoint-v1"


@dataclass(frozen=True)
class Stored:
    identity: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not int
            or self.identity < 1
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None
        ):
            raise LifecycleError("independent checkpoint reference is invalid")


class Store(Protocol):
    """An independent authenticated registry and encrypted immutable payloads."""

    def latest(self) -> Stored | None: ...

    def lineage(self) -> tuple[Stored, ...]:
        """Complete publication order, genesis first; identities carry no ordering."""
        ...

    def read(self, stored: Stored) -> dict[str, object]: ...

    def create(self, document: dict[str, object]) -> Stored:
        """Retain uncertain writes; do not overwrite or delete earlier checkpoints."""
        ...


@dataclass(frozen=True)
class Publication:
    """Exact plaintext and complete registry readback performed during publication."""

    stored: Stored
    history: tuple[Stored, ...]


@runtime_checkable
class VerifiedStore(Store, Protocol):
    def publish(self, document: dict[str, object]) -> Publication:
        """Return only after verifying this payload and its exact registry append."""
        ...


@runtime_checkable
class RecoveredStore(VerifiedStore, Protocol):
    def discard_recovered(self) -> None:
        """Discard the observation on every persistence exit, including no-op/error."""
        ...

    def publish_recovered(
        self, document: dict[str, object], *, history: tuple[Stored, ...]
    ) -> Publication:
        """Consume this call's recovered history; verify the full append after upload."""
        ...


def _records(value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_EVENTS:
        raise LifecycleError("independent checkpoint records are unavailable")
    result: dict[str, dict[str, object]] = {}
    for item in value:
        record = validate(item)
        key = identity(record["event_id"])
        if key in result:
            raise LifecycleError("independent checkpoint has duplicate events")
        result[key] = record
    return result


class Checkpoint:
    def __init__(
        self,
        store: Store,
        *,
        epoch: str,
        genesis: Stored | None,
        initial: Mapping[str, str],
        initialize: bool = False,
    ) -> None:
        self.store, self.epoch, self.genesis = store, identity(epoch), genesis
        self.initial = dict(initial)
        if not self.initial:
            raise LifecycleError("independent checkpoint needs an approved initial inventory")
        for key, value in self.initial.items():
            identity(key)
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise LifecycleError("independent checkpoint initial inventory is invalid")
        self.initialize = initialize
        self.head: Stored | None = None
        self.sequence = 0
        self.history: tuple[Stored, ...] = ()
        self.observed_history: tuple[Stored, ...] = ()
        self.records: dict[str, dict[str, object]] = {}
        self.verified_at: float | None = None

    @measure("checkpoint-recovery")
    def restore(self) -> None:
        self.verified_at = None
        history = self.store.lineage()
        if not history:
            if not self.initialize or self.genesis is not None or self.observed_history:
                raise LifecycleError(
                    "independent checkpoint is missing; cleanup remains unresolved"
                )
            return  # Only the explicit initialization ceremony may create genesis.
        if len({item.identity for item in history}) != len(history):
            raise LifecycleError("independent checkpoint history repeats an immutable identity")
        if (self.genesis is not None and history[0] != self.genesis) or (
            history[: len(self.observed_history)] != self.observed_history
        ):
            raise LifecycleError("independent checkpoint registry moved backwards")
        # Remember publication even if payload recovery fails. A later stale
        # registry response cannot make an observed obligation disappear.
        self.observed_history = history
        latest = history[-1]
        document = self.store.read(latest)
        if digest(document) != latest.sha256:
            raise LifecycleError("independent checkpoint readback changed")
        value = fields(document, {"format", "epoch", "sequence", "previous", "records"})
        sequence = value["sequence"]
        if (
            value["format"] != FORMAT
            or value["epoch"] != self.epoch
            or type(sequence) is not int
            or sequence != len(history)
        ):
            raise LifecycleError("independent checkpoint identity or sequence differs")
        if sequence == 1:
            if value["previous"] is not None:
                raise LifecycleError("independent genesis has an unexpected predecessor")
        else:
            previous = fields(value["previous"], {"identity", "sha256"})
            identifier, sha256 = previous["identity"], previous["sha256"]
            if type(identifier) is not int or not isinstance(sha256, str):
                raise LifecycleError("independent checkpoint predecessor is malformed")
            parent = Stored(identifier, sha256)
            if parent != history[-2]:
                raise LifecycleError("independent checkpoint predecessor differs from its history")
        records = _records(value["records"])
        self._require_extension(records)
        self.head, self.sequence, self.records = latest, sequence, records
        self.history = history
        self.observed_history = history
        self.verified_at = time.monotonic()

    def _require_extension(self, records: dict[str, dict[str, object]]) -> None:
        expected = {**self.initial, **{key: digest(value) for key, value in self.records.items()}}
        if not expected.keys() <= records.keys() or any(
            digest(records[key]) != value for key, value in expected.items()
        ):
            raise LifecycleError("independent checkpoint lost or changed an acknowledged event")

    @measure("checkpoint-persistence")
    def persist(self, records: list[dict[str, object]]) -> Stored:
        """Publish and verify the recoverable records before a caller may emit an ACK."""
        try:
            return self._persist(records)
        finally:
            if isinstance(self.store, RecoveredStore):
                self.store.discard_recovered()

    def _persist(self, records: list[dict[str, object]]) -> Stored:
        self.verified_at = None
        selected = _records(records)
        self.restore()
        verified, self.verified_at = self.verified_at, None
        self._require_extension(selected)
        if self.head is not None and selected == self.records:
            self.verified_at = verified
            return self.head
        document: dict[str, object] = {
            "format": FORMAT,
            "epoch": self.epoch,
            "sequence": self.sequence + 1,
            "previous": None
            if self.head is None
            else {
                "identity": self.head.identity,
                "sha256": self.head.sha256,
            },
            "records": [selected[key] for key in sorted(selected)],
        }
        # If the reply is lost, a later restore must find this immutable write.
        # Do not advance the in-memory head or acknowledge on a timeout.
        publication: Publication | None
        if self.history and isinstance(self.store, RecoveredStore):
            publication = self.store.publish_recovered(document, history=self.history)
        else:
            publication = (
                self.store.publish(document) if isinstance(self.store, VerifiedStore) else None
            )
        created = publication.stored if publication is not None else self.store.create(document)
        if created.sha256 != digest(document) or any(
            created.identity == item.identity for item in self.history
        ):
            raise LifecycleError("independent checkpoint creation is unverified")
        history = (*self.history, created)
        if publication is not None:
            verified = publication.history == history
        else:
            verified = self.store.read(created) == document and self.store.lineage() == history
        if not verified:
            raise LifecycleError("independent checkpoint creation has no exact registry readback")
        self.head, self.sequence, self.records = created, self.sequence + 1, selected
        self.history = history
        self.observed_history = history
        if self.genesis is None:
            self.genesis = created
        self.verified_at = time.monotonic()
        return created

    def merge(self, records: list[dict[str, object]]) -> list[dict[str, object]]:
        """Recover owned IDs even when a new Connect replica has not synchronized."""
        result = dict(self.records)
        for key, value in _records(records).items():
            if key in result and result[key] != value:
                raise LifecycleError("Connect and independent checkpoint disagree")
            result[key] = value
        return list(result.values())
