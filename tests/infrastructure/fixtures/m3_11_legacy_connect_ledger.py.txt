"""Immutable Connect staging and independently authored persistence acknowledgements.

This deliberately does not implement Journal.append: a successful cache write
is not the external durability guarantee required before provider creation.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import Context, copy_context
from copy import deepcopy
from http import HTTPStatus
from itertools import chain
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.connect_api import (
    TIMEOUT_SECONDS,
    Connect,
    ConnectExchangeError,
    ConnectTimeoutError,
    exchange_diagnostic,
)
from scripts.m3_11_unattended.connect_auth import identity as account_identity
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.journal import MAX_EVENTS, TAG, OpJournal, _note_content, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity, instant
from scripts.m3_11_unattended.state import private_directory
from scripts.qualification_timing import measure

ACK_FORMAT = "lowerduckpond-m3-11-connect-ack-v1"
READBACK_SECONDS = 60
READBACK_POLL_SECONDS = 1
ITEM_READ_WORKERS = 8
STAGING_OBSERVATION_SECONDS = 5
type Item = tuple[dict[str, object], dict[str, object]]
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
        self._cached_items: dict[str, Item] = {}
        self._observed_records: list[dict[str, object]] | None = None
        self._staging = False
        self._stage_records: list[dict[str, object]] | None = None
        self._stage_until = 0.0

    @contextmanager
    def staging_observation(self) -> Iterator[None]:
        """Consume a canonicalization read once, before any further ledger I/O."""
        previous = self._staging
        self._staging, self._stage_records = True, None
        try:
            yield
        finally:
            self._staging, self._stage_records = previous, None

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
        self._stage_records = None
        if self._read_deadline is None:
            yield
            return
        self.check_cancelled()
        remaining = self._read_deadline - time.monotonic()
        if remaining <= 0:
            raise ReadbackExpiredError("Connect journal readback deadline elapsed")
        with self.client.timeout_budget(min(TIMEOUT_SECONDS, remaining)):
            try:
                yield
            except ConnectTimeoutError as error:
                error.exchange["caller_deadline_expired"] = time.monotonic() >= self._read_deadline
                raise
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

    def _read(self, item_id: str) -> Item:
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

    def _remember_inventory(self, inventory: Mapping[str, dict[str, object]]) -> None:
        for listed in inventory.values():
            advertised = TITLE.fullmatch(str(listed["title"]))
            if advertised is None:  # Already validated by _inventory; never accept an unbound row.
                raise LifecycleError("Connect inventory event binding is invalid")
            event_id, expected = advertised.groups()
            if event_id in self._known and self._known[event_id] != expected:
                raise LifecycleError("immutable Connect journal has conflicting event identities")
            # Pin every advertised event even if a later detail read fails.
            # A valid summary proves neither its contents nor durability yet.
            self._known[event_id] = expected

    @contextmanager
    def _details(
        self, inventory: Mapping[str, dict[str, object]]
    ) -> Iterator[Iterator[tuple[str, Item]]]:
        """Bound parallel GETs; join them before the enclosing deadline is restored."""
        cached = [(key, self._cached_items[key]) for key in inventory if key in self._cached_items]
        missing = [key for key in inventory if key not in self._cached_items]

        def read(job: tuple[Context, str]) -> tuple[str, Item]:
            context, key = job
            # Each worker inherits any narrower caller budget without sharing
            # mutable timeout state with other in-flight reads.
            return key, context.run(self._read, key)

        executor = ThreadPoolExecutor(max_workers=ITEM_READ_WORKERS)
        try:
            fresh = executor.map(
                read,
                ((copy_context(), key) for key in missing),
                buffersize=ITEM_READ_WORKERS,
            )
            yield chain(cached, fresh)
        finally:
            # Errors/cancellation discard queued reads. Running exchanges still
            # have their original process budgets and must finish before return.
            executor.shutdown(wait=True, cancel_futures=True)

    @measure("credential-journal-read")
    def records(self) -> list[dict[str, object]]:
        """A complete, stable cache snapshot; still not an independent-write receipt."""
        self._observed_records = None
        before = self._vault_state()
        inventory = self._inventory()
        self._remember_inventory(inventory)
        records: dict[str, dict[str, object]] = {}
        metadata: dict[str, list[dict[str, object]]] = {}
        items: dict[str, str] = {}
        with self._details(inventory) as details:
            for item_id, (record, item) in details:
                listed = inventory[item_id]
                if any(listed.get(key) != item.get(key) for key in ITEM_BINDING):
                    raise LifecycleError("Connect journal changed during readback")
                event_id = identity(record["event_id"])
                if event_id in records and records[event_id] != record:
                    raise LifecycleError("Connect journal contains conflicting event identities")
                record_sha256 = digest(record)
                if event_id in self._known and self._known[event_id] != record_sha256:
                    raise LifecycleError("an immutable Connect journal event changed")
                if item_id == self.anchor and record_sha256 != self.anchor_sha256:
                    raise LifecycleError("Connect journal anchor changed")
                items[event_id] = item_id
                metadata.setdefault(event_id, []).append(item)
                records[event_id] = record
                # Retain validated immutable details even if a later read fails
                # or the snapshot grows. This cannot publish a partial snapshot:
                # every retry checks current native bindings and both inventories.
                self._known[event_id] = record_sha256
                self._cached_items[item_id] = record, item
        after = self._inventory()
        if any(after[key] != inventory[key] for key in after.keys() & inventory.keys()):
            raise LifecycleError("immutable Connect journal metadata changed during readback")
        self._remember_inventory(after)
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
        self._cached_items = {key: self._cached_items[key] for key in inventory}
        self._observed_records = sorted(records.values(), key=lambda row: str(row["event_id"]))
        if self._staging:
            self._stage_records = deepcopy(self._observed_records)
            self._stage_until = time.monotonic() + STAGING_OBSERVATION_SECONDS
        return list(self._observed_records)

    def observed_records(self) -> list[dict[str, object]]:
        """The latest completed read, including stage's pre-publication check."""
        if self._observed_records is None:
            raise LifecycleError("Connect has no complete current journal observation")
        return list(self._observed_records)

    def _readback(
        self, record: dict[str, object], *, publication_error: LifecycleError | None = None
    ) -> None:
        """Poll only reads after a retained POST; never resend or weaken the snapshot."""
        until = time.monotonic() + self.readback_seconds
        previous = self._read_deadline
        if previous is not None:
            until = min(until, previous)
        # A zero wait is the explicit single-read mode used by provider doubles.
        self._read_deadline = until if self.readback_seconds else previous
        try:
            try:
                self._await_readback(record, until=until)
            except LifecycleError as error:
                publication = (
                    publication_error.exchange
                    if isinstance(publication_error, ConnectExchangeError)
                    else self._publication(record)
                )
                if publication is not None:
                    # Keep both the first POST outcome and the readback's own
                    # cause. A sanitized proxy avoids overwriting the original
                    # transport exception or retaining response contents.
                    detail = ConnectExchangeError(publication)
                    detail.__cause__ = error.__cause__ or error.__context__
                    raise error from detail
                if (
                    publication_error is not None
                    and error.__cause__ is None
                    and error.__context__ is None
                ):
                    raise error from publication_error
                raise
        finally:
            self._read_deadline = previous

    def _publication(
        self, record: dict[str, object], diagnostic: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        """Retain the first POST outcome without changing the journal protocol."""
        path = self.spool / (identity(record["event_id"]) + ".exchange.json")
        try:
            if diagnostic is not None and not path.exists():
                write_private(
                    path,
                    {
                        "format": "lowerduckpond-connect-publication-v1",
                        "event_sha256": digest(record),
                        "exchange": exchange_diagnostic(diagnostic),
                    },
                )
            if path.exists():
                value = fields(read_private(path), {"format", "event_sha256", "exchange"})
                if value["format"] != "lowerduckpond-connect-publication-v1" or value[
                    "event_sha256"
                ] != digest(record):
                    return None
                return exchange_diagnostic(value["exchange"])
        except OSError, ValueError, TypeError, LifecycleError:
            pass  # Diagnostic failure cannot suppress readback or credential cleanup.
        return None

    def stable_records(self) -> list[dict[str, object]]:
        """Wait only for snapshot stability; preserve strict records() for recovery."""
        if not self.readback_seconds:
            return self.records()  # Explicit single-read mode for local provider doubles.
        until = time.monotonic() + self.readback_seconds
        if self._read_deadline is not None:
            until = min(until, self._read_deadline)
        last_observation: LifecycleError | None = None
        with self.read_budget(deadline=until, check_cancelled=lambda: None):
            while True:
                self.check_cancelled()
                if time.monotonic() >= until:
                    raise ReadbackExpiredError(
                        "Connect snapshot observation deadline elapsed"
                    ) from last_observation
                try:
                    observed = self.records()
                except (SnapshotChangedError, ConnectTimeoutError) as error:
                    last_observation = error
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        raise ReadbackExpiredError(
                            "Connect snapshot observation deadline elapsed"
                        ) from error
                    time.sleep(min(READBACK_POLL_SECONDS, remaining))
                    continue
                self.check_cancelled()
                if time.monotonic() >= until:
                    raise ReadbackExpiredError("Connect snapshot observation deadline elapsed")
                return observed

    def _await_readback(self, record: dict[str, object], *, until: float) -> None:
        first = True
        last_observation: LifecycleError | None = None
        while first or time.monotonic() < until:
            first = False
            self.check_cancelled()
            try:
                matches = [row for row in self.records() if row["event_id"] == record["event_id"]]
            except (SnapshotChangedError, ConnectTimeoutError) as error:
                last_observation = error
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
        raise ReadbackExpiredError(
            "Connect creation remains uncertain after readback; no duplicate submitted"
        ) from last_observation

    def stage(
        self,
        record: dict[str, object],
        *,
        claimed_author: str | None = None,
        admit: Callable[[], bool] | None = None,
    ) -> bool:
        """Submit once and retain uncertainty; this never claims external persistence."""
        validate(record)
        observed, self._stage_records = self._stage_records, None
        event_id = identity(record["event_id"])
        intent = self.spool / (event_id + ".json")
        if intent.exists():
            if read_private(intent) != record:
                raise LifecycleError("Connect stage intent changed")
            self._readback(record)
            return True
        self.check_cancelled()
        if (
            not self._staging
            or observed is None
            or time.monotonic() >= self._stage_until
            or (self._read_deadline is not None and time.monotonic() >= self._read_deadline)
        ):
            observed = self.stable_records()
        # A pre-read is single-use even if it required an ordinary fresh scan.
        self._stage_records = None
        existing = [value for value in observed if value["event_id"] == event_id]
        if existing:
            if existing != [record]:
                raise LifecycleError("Connect staged event differs from its original contents")
            return True
        if admit is not None and not admit():
            return False
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
        publication_error: LifecycleError | None = None
        try:
            # A grouped creation write may share an earlier record's deadline.
            # Retain uncertainty if this bounded POST times out; never resubmit.
            with self._reading():
                # The predicate performs no I/O. It includes the complete read
                # above and samples admission time after local preparation.
                # A cutoff crossed after intent persistence never submits this
                # ACK; its original transport evidence remains retained.
                if admit is not None and not admit():
                    return False
                response = self.client.request("POST", "/v1/vaults/" + self.vault + "/items", item)
        except LifecycleError as error:
            publication_error = error
            response = None
        if (
            response is not None
            and response.status in {HTTPStatus.OK, HTTPStatus.CREATED}
            and isinstance(response.body, dict)
        ):
            returned = _item_identity(response.body.get("id"))
            # A returned ID is retained immediately even when later inspection fails.
            write_private(self.spool / (event_id + ".returned.json"), {"item_id": returned})
        if response is not None and response.exchange is not None:
            self._publication(record, response.exchange)
        elif isinstance(publication_error, ConnectExchangeError):
            self._publication(record, publication_error.exchange)
        self._readback(record, publication_error=publication_error)
        return True

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
