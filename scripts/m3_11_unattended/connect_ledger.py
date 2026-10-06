"""Immutable Connect staging and independently authored persistence acknowledgements.

This deliberately does not implement Journal.append: a successful cache write
is not the external durability guarantee required before provider creation.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.connect_api import TIMEOUT_SECONDS, Connect
from scripts.m3_11_unattended.connect_auth import identity as account_identity
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.journal import MAX_EVENTS, TAG, OpJournal, _note_content, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity, instant
from scripts.m3_11_unattended.state import private_directory

ACK_FORMAT = "lowerduckpond-m3-11-connect-ack-v1"
READBACK_SECONDS = 60
READBACK_POLL_SECONDS = 1
TITLE = re.compile(r"m3-11-([0-9a-f-]{36})-([0-9a-f]{64})")
ACK_FIELDS = {
    "format",
    "event_id",
    "event_sha256",
    "binding",
    "github_run_id",
    "github_run_attempt",
    "independent_server_id",
    "checkpoint",
}
ITEM_BINDING = (
    "title",
    "vault",
    "category",
    "tags",
    "version",
    "createdAt",
    "updatedAt",
    "lastEditedBy",
    "state",
)


def _item_identity(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9]{26}", value) is None:
        raise LifecycleError("Connect journal item identity is invalid")
    return value


class SnapshotChangedError(LifecycleError):
    """A complete inventory could not be held stable across a read."""


class ReadbackExpiredError(LifecycleError):
    """The retained write is unresolved; no further read may start in this attempt."""


class ConnectLedger:
    def __init__(  # noqa: PLR0913 - independent anchor and checkpoint bindings remain explicit
        self,
        client: Connect,
        vault: str,
        *,
        spool: Path,
        anchor: str,
        anchor_sha256: str,
        minimum: Mapping[str, str],
        readback_seconds: int = READBACK_SECONDS,
    ) -> None:
        self.client, self.vault = client, _item_identity(vault)
        self.spool, self.anchor, self.anchor_sha256 = spool, _item_identity(anchor), anchor_sha256
        if re.fullmatch(r"[0-9a-f]{64}", anchor_sha256) is None:
            raise LifecycleError("Connect journal anchor is unavailable")
        self.minimum = dict(minimum)
        if not 0 <= readback_seconds <= READBACK_SECONDS:
            raise LifecycleError("Connect readback wait exceeds its bound")
        self.readback_seconds = readback_seconds
        self._read_deadline: float | None = None
        self.check_cancelled: Callable[[], None] = lambda: None
        for key, value in self.minimum.items():
            identity(key)
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise LifecycleError("Connect journal checkpoint is invalid")
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(spool)
        self._metadata: dict[str, list[dict[str, object]]] = {}
        self._known: dict[str, str] = dict(minimum)
        self._items: dict[str, str] = {}
        self._cached_items: dict[str, tuple[dict[str, object], dict[str, object]]] = {}

    @contextmanager
    def read_budget(
        self, *, deadline: float, check_cancelled: Callable[[], None]
    ) -> Iterator[None]:
        """Bound a complete observation without changing subsequent cleanup reads."""
        previous, previous_check = self._read_deadline, self.check_cancelled
        self._read_deadline = min(previous, deadline) if previous is not None else deadline

        def check() -> None:
            previous_check()
            check_cancelled()

        self.check_cancelled = check
        try:
            yield
        finally:
            self._read_deadline, self.check_cancelled = previous, previous_check

    @contextmanager
    def _reading(self) -> Iterator[None]:
        if self._read_deadline is None:
            yield
            return
        self.check_cancelled()
        remaining = self._read_deadline - time.monotonic()
        if remaining <= 0:
            raise ReadbackExpiredError("Connect journal readback deadline elapsed")
        with self.client.timeout_budget(min(TIMEOUT_SECONDS, remaining)):
            yield
        self.check_cancelled()
        if time.monotonic() > self._read_deadline:
            raise ReadbackExpiredError("Connect journal readback deadline elapsed")

    def _vault_state(self) -> tuple[int, int]:
        with self._reading():
            response = self.client.request("GET", "/v1/vaults/" + self.vault)
        value = response.body
        if (
            response.status != HTTPStatus.OK
            or not isinstance(value, dict)
            or value.get("id") != self.vault
            or type(value.get("items")) is not int
            or type(value.get("contentVersion")) is not int
            or not 1 <= value["items"] <= MAX_EVENTS
            or value["contentVersion"] < 1
        ):
            raise LifecycleError("Connect journal has not reached a usable synchronized state")
        return value["items"], value["contentVersion"]

    def _read(self, item_id: str) -> tuple[dict[str, object], dict[str, object]]:
        with self._reading():
            item = self.client.item(self.vault, item_id)
        if (
            item.get("category") != "SECURE_NOTE"
            or item.get("tags") != [TAG]
            or item.get("state") is not None
            or type(item.get("version")) is not int
            or cast(int, item["version"]) < 1
        ):
            raise LifecycleError("Connect journal item metadata changed")
        account_identity(item.get("lastEditedBy"))
        content = _note_content(item.get("fields"))
        record = validate(json.loads(content))
        if (
            item.get("title") != OpJournal._title(record)
            or canonical_bytes(record).decode() != content
        ):
            raise LifecycleError("Connect journal item content changed")
        return record, item

    def _inventory(self) -> dict[str, dict[str, object]]:
        # Connect documents an unpaginated complete list. The vault aggregate
        # can lag an accepted write, so it is only a conservative lower bound.
        with self._reading():
            response = self.client.request("GET", "/v1/vaults/" + self.vault + "/items")
        if (
            response.status != HTTPStatus.OK
            or not isinstance(response.body, list)
            or len(response.body) > MAX_EVENTS
        ):
            raise LifecycleError("Connect journal inventory is partial or unavailable")
        inventory: dict[str, dict[str, object]] = {}
        for listed in response.body:
            if not isinstance(listed, dict):
                raise LifecycleError("Connect journal inventory is invalid")
            item_id = _item_identity(listed.get("id"))
            if item_id in inventory:
                raise LifecycleError("Connect journal inventory has duplicate items")
            title = listed.get("title")
            match = TITLE.fullmatch(title) if isinstance(title, str) else None
            if (
                listed.get("category") != "SECURE_NOTE"
                or listed.get("tags") != [TAG]
                or listed.get("state") is not None
                or type(listed.get("version")) is not int
                or cast(int, listed["version"]) < 1
                or not isinstance(listed.get("vault"), dict)
                or cast(dict[str, object], listed["vault"]).get("id") != self.vault
                or match is None
            ):
                raise LifecycleError("Connect journal inventory item metadata is invalid")
            identity(match[1])
            account_identity(listed.get("lastEditedBy"))
            instant(listed.get("createdAt"))
            instant(listed.get("updatedAt"))
            inventory[item_id] = {key: listed.get(key) for key in ITEM_BINDING}
        return inventory

    def records(self) -> list[dict[str, object]]:
        """A complete, stable cache snapshot; still not an independent-write receipt."""
        before = self._vault_state()
        inventory = self._inventory()
        records: dict[str, dict[str, object]] = {}
        metadata: dict[str, list[dict[str, object]]] = {}
        items: dict[str, str] = {}
        cached_items = {}
        for item_id, listed in inventory.items():
            cached = self._cached_items.get(item_id)
            record, item = cached if cached is not None else self._read(item_id)
            if any(listed.get(key) != item.get(key) for key in ITEM_BINDING):
                raise LifecycleError("Connect journal changed during readback")
            event_id = identity(record["event_id"])
            if event_id in records and records[event_id] != record:
                raise LifecycleError("Connect journal contains conflicting event identities")
            if event_id in self._known and self._known[event_id] != digest(record):
                raise LifecycleError("an immutable Connect journal event changed")
            if item_id == self.anchor and digest(record) != self.anchor_sha256:
                raise LifecycleError("Connect journal anchor changed")
            items[event_id] = item_id
            metadata.setdefault(event_id, []).append(item)
            records[event_id] = record
            cached_items[item_id] = record, item
        # Every decoded immutable event remains known even if the surrounding
        # snapshot is unstable. A retry cannot forget a newly seen obligation.
        self._known.update({key: digest(record) for key, record in records.items()})
        after = self._inventory()
        if any(after[key] != inventory[key] for key in after.keys() & inventory.keys()):
            raise LifecycleError("immutable Connect journal metadata changed during readback")
        for listed in after.values():
            advertised = TITLE.fullmatch(str(listed["title"]))
            if advertised is None:  # Already validated by _inventory; never accept an unbound row.
                raise LifecycleError("Connect inventory event binding is invalid")
            event_id, expected = advertised.groups()
            if event_id in self._known and self._known[event_id] != expected:
                raise LifecycleError("an immutable Connect journal event binding changed")
            # A new valid summary also establishes an expectation for the next
            # complete scan. It proves neither its contents nor durability yet.
            self._known[event_id] = expected
        # Validate both inventories before treating growth as transient. Changed
        # known metadata and malformed new summaries cannot be waited past.
        if (
            len(inventory) < before[0]
            or self.anchor not in inventory
            or not self._known.keys() <= items.keys()
            or after != inventory
            or self._vault_state() != before
        ):
            raise SnapshotChangedError(
                "Connect journal is not synchronized with its retained checkpoint"
            )
        self._metadata, self._items = metadata, items
        # An independent worker can recover the same event from its checkpoint
        # after losing a POST reply and its ephemeral spool. Exact immutable
        # copies share one logical event; conflicting copies still fail closed.
        self._cached_items = cached_items
        return sorted(records.values(), key=lambda row: str(row["event_id"]))

    def _readback(self, record: dict[str, object]) -> None:
        """Poll only reads after a retained POST; never resend or weaken the snapshot."""
        until = time.monotonic() + self.readback_seconds
        previous = self._read_deadline
        if previous is not None:
            until = min(until, previous)
        # A zero wait is the explicit single-read mode used by provider doubles.
        self._read_deadline = until if self.readback_seconds else previous
        try:
            self._await_readback(record, until=until)
        finally:
            self._read_deadline = previous

    def stable_records(self) -> list[dict[str, object]]:
        """Wait only for snapshot stability; preserve strict records() for recovery."""
        if not self.readback_seconds:
            return self.records()  # Explicit single-read mode for local provider doubles.
        until = time.monotonic() + self.readback_seconds
        if self._read_deadline is not None:
            until = min(until, self._read_deadline)
        with self.read_budget(deadline=until, check_cancelled=lambda: None):
            while True:
                self.check_cancelled()
                if time.monotonic() >= until:
                    raise ReadbackExpiredError("Connect snapshot observation deadline elapsed")
                try:
                    observed = self.records()
                except SnapshotChangedError:
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        raise
                    time.sleep(min(READBACK_POLL_SECONDS, remaining))
                    continue
                self.check_cancelled()
                if time.monotonic() >= until:
                    raise ReadbackExpiredError("Connect snapshot observation deadline elapsed")
                return observed

    def _await_readback(self, record: dict[str, object], *, until: float) -> None:
        first = True
        while first or time.monotonic() < until:
            first = False
            self.check_cancelled()
            try:
                matches = [row for row in self.records() if row["event_id"] == record["event_id"]]
            except SnapshotChangedError:
                matches = []
            if matches:
                if matches != [record]:
                    raise LifecycleError("Connect staged event differs from its original contents")
                if not self.readback_seconds or time.monotonic() <= until:
                    return
                break
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(READBACK_POLL_SECONDS, remaining))
        raise LifecycleError(
            "Connect creation remains uncertain after readback; no duplicate submitted"
        )

    def stage(self, record: dict[str, object], *, claimed_author: str | None = None) -> None:
        """Submit once and retain uncertainty; this never claims external persistence."""
        validate(record)
        event_id = identity(record["event_id"])
        intent = self.spool / (event_id + ".json")
        if intent.exists():
            if read_private(intent) != record:
                raise LifecycleError("Connect stage intent changed")
            self._readback(record)
            return
        existing = [value for value in self.stable_records() if value["event_id"] == event_id]
        if existing:
            if existing != [record]:
                raise LifecycleError("Connect staged event differs from its original contents")
            return
        write_private(intent, record)
        item: dict[str, object] = {
            "title": OpJournal._title(record),
            "category": "SECURE_NOTE",
            "vault": {"id": self.vault},
            "tags": [TAG],
            "fields": [
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "value": canonical_bytes(record).decode(),
                }
            ],
        }
        if claimed_author is not None:
            # Used only by the explicit provenance ceremony. Admission remains
            # disabled unless native readback proves this forged field was ignored.
            item["lastEditedBy"] = account_identity(claimed_author)
        try:
            # A grouped creation write may share an earlier record's deadline.
            # Retain uncertainty if this bounded POST times out; never resubmit.
            with self._reading():
                response = self.client.request("POST", "/v1/vaults/" + self.vault + "/items", item)
        except LifecycleError:
            response = None
        if (
            response is not None
            and response.status in {HTTPStatus.OK, HTTPStatus.CREATED}
            and isinstance(response.body, dict)
        ):
            returned = _item_identity(response.body.get("id"))
            # A returned ID is retained immediately even when later inspection fails.
            write_private(self.spool / (event_id + ".returned.json"), {"item_id": returned})
        self._readback(record)

    def confirmed(  # noqa: PLR0913 - native identities, lineage and observation remain explicit
        self,
        record: dict[str, object],
        *,
        independent_server: str,
        independent_author: str,
        binding: dict[str, object],
        genesis_checkpoint: Stored | None = None,
        observed: list[dict[str, object]] | None = None,
    ) -> bool:
        """Use native authors from a complete snapshot, optionally just read by the caller.

        A supplied snapshot must have no intervening ledger I/O so its native
        metadata and records describe the same observation.
        """
        account_identity(independent_server)
        account_identity(independent_author)
        original_id = identity(record["event_id"])
        if observed is None:
            observed = self.records()
        if not any(value == record for value in observed):
            return False
        for value in observed:
            payload = value["payload"]
            if (
                value["kind"] != "heartbeat"
                or not isinstance(payload, dict)
                or payload.get("format") != ACK_FORMAT
                or payload.get("event_id") != original_id
            ):
                continue
            proof = fields(payload, ACK_FIELDS)
            pointer = fields(proof["checkpoint"], {"identity", "sha256"})
            if type(pointer["identity"]) is not int or not isinstance(pointer["sha256"], str):
                raise LifecycleError("Connect acknowledgement checkpoint is invalid")
            checkpoint = Stored(pointer["identity"], pointer["sha256"])
            if (
                value["run_id"] == record["run_id"]
                and proof["event_sha256"] == digest(record)
                and proof["binding"] == binding
                and proof["independent_server_id"] == independent_server
                and self.authored(value, independent_author)
                # The independent author proves lineage before emitting this
                # exact genesis-bound ACK. Artifact IDs are opaque identities.
                and (
                    genesis_checkpoint is None
                    or (
                        binding.get("genesis")
                        == {
                            "identity": genesis_checkpoint.identity,
                            "sha256": genesis_checkpoint.sha256,
                        }
                        and (
                            checkpoint.identity != genesis_checkpoint.identity
                            or checkpoint == genesis_checkpoint
                        )
                    )
                )
                and all(
                    type(proof[key]) is int and cast(int, proof[key]) > 0
                    for key in ("github_run_id", "github_run_attempt")
                )
            ):
                return True
        return False

    def authored(self, record: dict[str, object], author: str) -> bool:
        """Inspect provider metadata from the most recent complete snapshot."""
        account_identity(author)
        return any(
            item["lastEditedBy"] == author
            and item["version"] == 1
            and item.get("createdAt") is not None
            and item.get("createdAt") == item.get("updatedAt")
            for item in self._metadata.get(identity(record["event_id"]), [])
        )

    def authors(self, record: dict[str, object]) -> set[str]:
        """Only immutable native metadata from the last complete snapshot counts."""
        return {
            account_identity(item["lastEditedBy"])
            for item in self._metadata.get(identity(record["event_id"]), [])
            if self.authored(record, account_identity(item["lastEditedBy"]))
        }
