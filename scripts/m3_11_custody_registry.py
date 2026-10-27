"""Application-immutable retirement facts in the existing external journal.

Connect is not a compare-and-swap service. Destructive use additionally requires
the daemon-wide admission reservation and locks in the actual native volumes.
Unknown/conflicting facts fail closed; no fact is replaced or deleted here.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path
from typing import cast

from scripts.m3_11_custody_plan import authorization, plan, require
from scripts.m3_11_frozen_retirement import reserve
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_retirement_files import digest, directory
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.journal import _note_content
from scripts.m3_11_unattended.model import identity, instant

FORMAT = "lowerduckpond-m3-11-custody-exclusion-v1"
TAG = "ldp-m3-11-custody-exclusions-v1"
PREFIX = "m3-11-custody-exclusion-"
MAX_ITEMS = 10000
MAX_EXCLUSIONS = 8


def validate(raw: object) -> dict[str, object]:
    value = fields(raw, {"format", "fixture_id", "plan", "authorization", "reserved_at"})
    approved = plan(value["plan"])
    reserved = instant(value["reserved_at"])
    authorization(value["authorization"], approved, now=reserved)
    require(
        value["format"] == FORMAT and value["fixture_id"] == approved["fixture_id"],
        "external custody exclusion binding differs",
    )
    identity(value["fixture_id"])
    return value


class Registry:
    def __init__(
        self, reader: Connect, vault: str, *, guard: Callable[[], None] = lambda: None
    ) -> None:
        self.reader, self.vault = reader, Connect._identity(vault)
        self.guard = guard

    def _read(self, item_id: str, *, published: bool = False) -> dict[str, object]:
        read = self.reader.published_item if published else self.reader.item
        self.guard()
        item = read(self.vault, item_id)
        require(
            item.get("category") == "SECURE_NOTE"
            and item.get("tags") == [TAG]
            and item.get("state") is None,
            "external custody exclusion is unavailable",
        )
        content = _note_content(item.get("fields"))
        try:
            value = validate(json.loads(content))
        except ValueError, TypeError, KeyError:
            raise ValueError("external custody exclusion is malformed") from None
        require(
            item.get("title") == PREFIX + str(value["fixture_id"])
            and content == canonical_bytes(value).decode(),
            "external custody exclusion identity differs",
        )
        return value

    def records(self) -> list[dict[str, object]]:
        self.guard()
        response = self.reader.request("GET", f"/v1/vaults/{self.vault}/items")
        rows = response.body
        require(
            response.status == HTTPStatus.OK and isinstance(rows, list) and len(rows) <= MAX_ITEMS,
            "external custody exclusion listing is incomplete",
        )
        result: list[dict[str, object]] = []
        seen: set[str] = set()
        fixtures: set[object] = set()
        for row in cast(list[dict[str, object]], rows):
            require(isinstance(row, dict), "external custody exclusion listing is malformed")
            require(isinstance(row.get("id"), str), "external custody item identity is malformed")
            item_id = Connect._identity(cast(str, row["id"]))
            require(item_id not in seen, "external custody exclusion listing repeats an item")
            seen.add(item_id)
            tags = row.get("tags") or []
            require(isinstance(tags, list), "external custody listing tags are malformed")
            if TAG in cast(list[object], tags) or str(row.get("title", "")).startswith(PREFIX):
                require(
                    len(result) < MAX_EXCLUSIONS,
                    "external custody inventory exceeds its read budget",
                )
                value = self._read(item_id)
                # Even identical duplicate notes are not a distributed election.
                require(
                    value["fixture_id"] not in fixtures,
                    "external custody exclusion repeats a fixture",
                )
                fixtures.add(value["fixture_id"])
                result.append(value)
        return result

    def selected(self, fixture_id: str) -> dict[str, object] | None:
        return next((row for row in self.records() if row["fixture_id"] == fixture_id), None)

    def publish_once(self, value: dict[str, object], *, spool: Path) -> None:
        value = validate(value)
        directory(spool)
        require(
            self.selected(str(value["fixture_id"])) is None,
            "fixture already has an external exclusion; no replay",
        )
        # A lost POST/readback is consumed. Never republish a pending spool.
        reserve(spool / (digest(value["fixture_id"]) + ".json"), value)
        item: dict[str, object] = {
            "title": PREFIX + str(value["fixture_id"]),
            "category": "SECURE_NOTE",
            "vault": {"id": self.vault},
            "tags": [TAG],
            "fields": [
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "value": canonical_bytes(value).decode(),
                }
            ],
        }
        self.guard()
        response = self.reader.request("POST", f"/v1/vaults/{self.vault}/items", item)
        require(
            response.status in {HTTPStatus.OK, HTTPStatus.CREATED}
            and isinstance(response.body, dict),
            "external custody exclusion publication uncertain; no replay",
        )
        body = cast(dict[str, object], response.body)
        require(
            isinstance(body.get("id"), str), "external custody publication identity is malformed"
        )
        item_id = Connect._identity(cast(str, body["id"]))
        require(
            self._read(item_id, published=True) == value,
            "external custody exclusion readback differs; no replay",
        )
