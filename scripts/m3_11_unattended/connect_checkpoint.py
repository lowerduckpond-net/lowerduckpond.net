"""Recoverable off-host checkpoints must precede Connect acknowledgements.

The registry is authoritative for its latest identity. A missing, older or
unreadable checkpoint never permits fallback to a Connect cache or old file.
Only non-secret journal records enter the encrypted payload, never credentials.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.journal import MAX_EVENTS, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity

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

    def read(self, stored: Stored) -> dict[str, object]: ...

    def create(self, document: dict[str, object]) -> Stored:
        """Retain uncertain writes; do not overwrite or delete earlier checkpoints."""
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
        self.records: dict[str, dict[str, object]] = {}

    def restore(self) -> None:
        latest = self.store.latest()
        if latest is None:
            if not self.initialize or self.genesis is not None or self.head is not None:
                raise LifecycleError(
                    "independent checkpoint is missing; cleanup remains unresolved"
                )
            return  # Only the explicit initialization ceremony may create genesis.
        if (self.genesis is not None and latest.identity < self.genesis.identity) or (
            self.head is not None and latest.identity < self.head.identity
        ):
            raise LifecycleError("independent checkpoint registry moved backwards")
        for pinned in (self.genesis, self.head):
            if pinned is not None and latest.identity == pinned.identity and latest != pinned:
                raise LifecycleError("an immutable independent checkpoint identity changed")
        document = self.store.read(latest)
        if digest(document) != latest.sha256:
            raise LifecycleError("independent checkpoint readback changed")
        value = fields(document, {"format", "epoch", "sequence", "previous", "records"})
        sequence = value["sequence"]
        if (
            value["format"] != FORMAT
            or value["epoch"] != self.epoch
            or type(sequence) is not int
            or sequence < max(1, self.sequence)
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
            if parent.identity >= latest.identity:
                raise LifecycleError("independent checkpoint predecessor does not precede it")
        records = _records(value["records"])
        self._require_extension(records)
        self.head, self.sequence, self.records = latest, sequence, records

    def _require_extension(self, records: dict[str, dict[str, object]]) -> None:
        expected = {**self.initial, **{key: digest(value) for key, value in self.records.items()}}
        if not expected.keys() <= records.keys() or any(
            digest(records[key]) != value for key, value in expected.items()
        ):
            raise LifecycleError("independent checkpoint lost or changed an acknowledged event")

    def persist(self, records: list[dict[str, object]]) -> Stored:
        """Publish and verify the recoverable records before a caller may emit an ACK."""
        selected = _records(records)
        self.restore()
        self._require_extension(selected)
        if self.head is not None and selected == self.records:
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
        created = self.store.create(document)
        if created.sha256 != digest(document) or (
            self.head is not None and created.identity <= self.head.identity
        ):
            raise LifecycleError("independent checkpoint creation is unverified")
        if self.store.read(created) != document or self.store.latest() != created:
            raise LifecycleError("independent checkpoint creation has no exact registry readback")
        self.head, self.sequence, self.records = created, self.sequence + 1, selected
        if self.genesis is None:
            self.genesis = created
        return created

    def merge(self, records: list[dict[str, object]]) -> list[dict[str, object]]:
        """Recover owned IDs even when a new Connect replica has not synchronized."""
        result = dict(self.records)
        for key, value in _records(records).items():
            if key in result and result[key] != value:
                raise LifecycleError("Connect and independent checkpoint disagree")
            result[key] = value
        return list(result.values())
