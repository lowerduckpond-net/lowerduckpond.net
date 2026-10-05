"""Immutable Connect staging and independently authored persistence acknowledgements.

This deliberately does not implement Journal.append: a successful cache write
is not the external durability guarantee required before provider creation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from http import HTTPStatus
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import identity as account_identity
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.journal import MAX_EVENTS, TAG, OpJournal, _note_content, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity
from scripts.m3_11_unattended.state import private_directory

ACK_FORMAT = "lowerduckpond-m3-11-connect-ack-v1"
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
)


def _item_identity(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9]{26}", value) is None:
        raise LifecycleError("Connect journal item identity is invalid")
    return value


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
    ) -> None:
        self.client, self.vault = client, _item_identity(vault)
        self.spool, self.anchor, self.anchor_sha256 = spool, _item_identity(anchor), anchor_sha256
        if re.fullmatch(r"[0-9a-f]{64}", anchor_sha256) is None:
            raise LifecycleError("Connect journal anchor is unavailable")
        self.minimum = dict(minimum)
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

    def _vault_state(self) -> tuple[int, int]:
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

    def _inventory(self, minimum_count: int) -> dict[str, dict[str, object]]:
        # Connect documents an unpaginated complete list. The vault aggregate
        # can lag an accepted write, so it is only a conservative lower bound.
        response = self.client.request("GET", "/v1/vaults/" + self.vault + "/items")
        if (
            response.status != HTTPStatus.OK
            or not isinstance(response.body, list)
            or not minimum_count <= len(response.body) <= MAX_EVENTS
        ):
            raise LifecycleError("Connect journal inventory is partial or unavailable")
        inventory: dict[str, dict[str, object]] = {}
        for listed in response.body:
            if not isinstance(listed, dict):
                raise LifecycleError("Connect journal inventory is invalid")
            item_id = _item_identity(listed.get("id"))
            if item_id in inventory:
                raise LifecycleError("Connect journal inventory has duplicate items")
            inventory[item_id] = {key: listed.get(key) for key in ITEM_BINDING}
        return inventory

    def records(self) -> list[dict[str, object]]:
        """A complete, stable cache snapshot; still not an independent-write receipt."""
        before = self._vault_state()
        inventory = self._inventory(before[0])
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
        if (
            self.anchor not in inventory
            or not self._known.keys() <= items.keys()
            or self._inventory(before[0]) != inventory
            or self._vault_state() != before
        ):
            raise LifecycleError("Connect journal is not synchronized with its retained checkpoint")
        self._metadata, self._items = metadata, items
        self._known.update({key: digest(record) for key, record in records.items()})
        # An independent worker can recover the same event from its checkpoint
        # after losing a POST reply and its ephemeral spool. Exact immutable
        # copies share one logical event; conflicting copies still fail closed.
        self._cached_items = cached_items
        return sorted(records.values(), key=lambda row: str(row["event_id"]))

    def stage(self, record: dict[str, object], *, claimed_author: str | None = None) -> None:
        """Submit once and retain uncertainty; this never claims external persistence."""
        validate(record)
        event_id = identity(record["event_id"])
        existing = [value for value in self.records() if value["event_id"] == event_id]
        if existing:
            if existing != [record]:
                raise LifecycleError("Connect staged event differs from its original contents")
            return
        intent = self.spool / (event_id + ".json")
        if intent.exists():
            if read_private(intent) != record:
                raise LifecycleError("Connect stage intent changed")
            raise LifecycleError("Connect item creation is uncertain; no duplicate submitted")
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
        matches = [value for value in self.records() if value["event_id"] == event_id]
        if matches != [record]:
            raise LifecycleError("Connect staged event has no matching readback")

    def confirmed(
        self,
        record: dict[str, object],
        *,
        independent_server: str,
        independent_author: str,
        binding: dict[str, object],
        minimum_checkpoint: Stored | None = None,
    ) -> bool:
        """Require the provider's read-only author identity, not a self-asserted actor tag."""
        account_identity(independent_server)
        account_identity(independent_author)
        original_id = identity(record["event_id"])
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
                and (
                    minimum_checkpoint is None
                    or checkpoint.identity > minimum_checkpoint.identity
                    or checkpoint == minimum_checkpoint
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
