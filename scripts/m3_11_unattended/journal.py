"""Append-only obligations in a dedicated 1Password vault, outside the Docker host.

Every event is a separate immutable item. Independent cleanup never edits an
intent or overwrites a controller update. Provider secrets are never journaled.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.journal_cache import JournalCache
from scripts.m3_11_unattended.model import LifecycleError, digest, identity, instant, stamp

FORMAT = "lowerduckpond-m3-11-credential-journal-v1"
TAG = "ldp-m3-11-credential-obligations-v1"
MAX_EVENTS = 10000
MAX_OUTPUT = 16 * 1024 * 1024
KINDS = frozenset(
    {"intent", "created", "revoke", "resolved", "cleanup", "run", "result", "heartbeat"}
)


def event(kind: str, run_id: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "format": FORMAT,
        "event_id": str(uuid.uuid7()),
        "run_id": identity(run_id),
        "kind": kind,
        "recorded_at": stamp(datetime.now(UTC)),
        "payload": payload,
    }


def validate(value: object) -> dict[str, object]:
    record = fields(value, {"format", "event_id", "run_id", "kind", "recorded_at", "payload"})
    identity(record["event_id"])
    identity(record["run_id"])
    instant(record["recorded_at"])
    if (
        record["format"] != FORMAT
        or record["kind"] not in KINDS
        or not isinstance(record["payload"], dict)
    ):
        raise LifecycleError("credential journal contains an invalid record")
    return record


class Journal(Protocol):
    def append(self, record: dict[str, object]) -> None:
        """Return only after independent storage readback matches the exact bytes."""
        ...

    def records(self) -> list[dict[str, object]]: ...


class FileJournal:
    """Local provider-double adapter; never selected for live provisioning."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = directory

    def append(self, record: dict[str, object]) -> None:
        validate(record)
        path = self.directory / f"{record['event_id']}.json"
        if not path.exists():
            write_private(path, record)
        if read_private(path) != record:
            raise LifecycleError("credential journal readback mismatch")

    def records(self) -> list[dict[str, object]]:
        paths = sorted(self.directory.glob("*.json"))
        if len(paths) > MAX_EVENTS:
            raise LifecycleError("credential journal inventory exceeds its bound")
        return [validate(read_private(path)) for path in paths]


class OnePassword:
    def __init__(self, token: str, *, environment: Mapping[str, str] | None = None) -> None:
        if not token or "\n" in token:
            raise LifecycleError("1Password service account is unavailable")
        ambient = os.environ if environment is None else environment
        executable = shutil.which("op", path=ambient.get("PATH"))
        if executable is None:
            raise LifecycleError("1Password CLI is unavailable")
        self.executable = executable
        # Neither user sessions nor a second service account can bleed into op.
        self.environment = {
            key: ambient[key] for key in ("PATH", "HOME", "SSL_CERT_FILE") if key in ambient
        }
        self.environment.update(OP_SERVICE_ACCOUNT_TOKEN=token, OP_CACHE="false")

    def journal_cache(self, path: Path, vault: str) -> JournalCache:
        return JournalCache(path, token=self.environment["OP_SERVICE_ACCOUNT_TOKEN"], vault=vault)

    def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
        try:
            result = subprocess.run(  # noqa: S603 - fixed op operations, secrets only in stdin/env
                [self.executable, *arguments],
                input=stdin,
                env=self.environment,
                capture_output=True,
                timeout=60,
                check=False,
            )
        except OSError, subprocess.SubprocessError:
            raise LifecycleError("1Password operation failed; retain the obligation") from None
        if result.returncode or len(result.stdout) > MAX_OUTPUT:
            raise LifecycleError("1Password operation failed; retain the obligation")
        return result.stdout

    def read(self, reference: str) -> str:
        # Require immutable vault/item IDs, not an ambiguous user-visible title.
        if re.fullmatch(r"op://[a-z0-9]{26}/[a-z0-9]{26}/[A-Za-z0-9_/-]+", reference) is None:
            raise LifecycleError("1Password reference must use explicit vault and item identities")
        raw = self.command("read", "--no-newline", reference)
        if not 1 <= len(raw) <= 65536:  # noqa: PLR2004 - bounded secret input
            raise LifecycleError("1Password field exceeds its input bound")
        return raw.decode("utf-8")


def _note_content(value: object) -> str:
    if not isinstance(value, list) or any(not isinstance(entry, dict) for entry in value):
        raise LifecycleError("credential journal item content is unavailable")
    notes = [entry for entry in value if entry.get("id") == "notesPlain"]
    if len(notes) == 2:  # noqa: PLR2004 - exact legacy op representation
        # The original writer omitted purpose, so op added an empty built-in
        # note beside its custom notesPlain field. Preserve those immutable
        # entries, accepting only that exact, unambiguous representation.
        blank = [
            entry
            for entry in notes
            if entry.get("purpose") == "NOTES"
            and entry.get("type") == "STRING"
            and entry.get("section") is None
            and entry.get("value") in (None, "")
        ]
        custom = [
            entry
            for entry in notes
            if entry.get("purpose") is None
            and entry.get("type") == "STRING"
            and entry.get("section") is None
        ]
        if len(blank) != 1 or len(custom) != 1:
            raise LifecycleError("credential journal item content is ambiguous")
        notes = custom
    if len(notes) != 1 or not isinstance(content := notes[0].get("value"), str):
        raise LifecycleError("credential journal item content is unavailable")
    return content


class OpJournal:
    def __init__(self, op: OnePassword, vault: str) -> None:
        if re.fullmatch(r"[a-z0-9]{26}", vault) is None:
            raise LifecycleError("credential journal needs its dedicated vault identity")
        self.op, self.vault = op, vault
        self._records: list[dict[str, object]] | None = None
        self._items: dict[str, tuple[str, dict[str, object]]] = {}
        self._cache: JournalCache | None = None

    def use_cache(self, path: Path) -> None:
        self._cache = self.op.journal_cache(path, self.vault)
        saved = self._cache.read()
        if len(saved) > MAX_EVENTS:
            raise LifecycleError("credential journal cache exceeds its bound")
        for item_id, value in saved.items():
            selected = fields(value, {"version", "record"})
            version = selected["version"]
            if re.fullmatch(r"[a-z0-9]{26}", item_id) is None or (
                not isinstance(version, str) or re.fullmatch(r"[0-9a-f]{64}", version) is None
            ):
                raise LifecycleError("credential journal cache identity is invalid")
            self._items[item_id] = (version, validate(selected["record"]))

    def _inventory(self) -> list[dict[str, object]]:
        value = json.loads(
            self.op.command("item", "list", "--vault", self.vault, "--format", "json")
        )
        if (
            not isinstance(value, list)
            or len(value) > MAX_EVENTS
            or any(not isinstance(item, dict) for item in value)
        ):
            raise LifecycleError("credential journal inventory is unavailable")
        return cast(list[dict[str, object]], value)

    def _read(self, item_id: object) -> dict[str, object]:
        if not isinstance(item_id, str) or re.fullmatch(r"[a-z0-9]{26}", item_id) is None:
            raise LifecycleError("credential journal item identity is invalid")
        item = json.loads(
            self.op.command("item", "get", item_id, "--vault", self.vault, "--format", "json")
        )
        if (
            not isinstance(item, dict)
            or item.get("id") != item_id
            or not isinstance(item.get("vault"), dict)
            or item["vault"].get("id") != self.vault
            or item.get("category") != "SECURE_NOTE"
            or item.get("tags") != [TAG]
        ):
            raise LifecycleError("credential journal item metadata changed")
        content = _note_content(item.get("fields"))
        record = validate(json.loads(content))
        if item.get("title") != self._title(record) or canonical_bytes(record).decode() != content:
            raise LifecycleError("credential journal item content changed")
        return record

    @staticmethod
    def _title(record: dict[str, object]) -> str:
        return f"m3-11-{record['event_id']}-{digest(record)}"

    def records(self) -> list[dict[str, object]]:
        if self._records is not None:
            return list(self._records)
        # Dedicated vault: silently filtering malformed/foreign obligations could
        # hide a credential. Unrelated configuration belongs in separate vaults.
        records = []
        inventory = self._inventory()
        if set(self._items) - {item.get("id") for item in inventory}:
            raise LifecycleError("an immutable credential journal item disappeared")
        for item in inventory:
            item_id = item.get("id")
            if not isinstance(item_id, str):
                raise LifecycleError("credential journal item identity is invalid")
            version = digest(
                {
                    key: item.get(key)
                    for key in ("id", "title", "vault", "updated_at", "version", "tags", "category")
                }
            )
            cached = self._items.get(item_id)
            if cached is None:
                cached = (version, self._read(item_id))
                self._items[item_id] = cached
            if cached[0] != version or item.get("title") != self._title(cached[1]):
                raise LifecycleError("an immutable credential journal item was edited")
            records.append(cached[1])
        ids = [record["event_id"] for record in records]
        if len(set(ids)) != len(ids):
            raise LifecycleError("credential journal has ambiguous duplicate identities")
        self._records = records
        if self._cache is not None:
            self._cache.write(
                {
                    item_id: {"version": version, "record": record}
                    for item_id, (version, record) in self._items.items()
                }
            )
        return list(records)

    def append(self, record: dict[str, object]) -> None:
        validate(record)
        title = self._title(record)
        item = {
            "title": title,
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
        # A lost item-creation response is reconciled by exact immutable content;
        # never retry the mutation or create multiple intents after uncertainty.
        response: object = None
        with suppress(LifecycleError, ValueError):
            response = json.loads(
                self.op.command(
                    "item", "create", "--format", "json", "-", stdin=canonical_bytes(item)
                )
            )
        if isinstance(response, dict) and isinstance(response.get("id"), str):
            selected = response["id"]
        else:
            matches = [entry for entry in self._inventory() if entry.get("title") == title]
            if len(matches) != 1:
                raise LifecycleError("credential obligation was not durably acknowledged")
            selected = matches[0].get("id")
        if self._read(selected) != record:
            raise LifecycleError("credential obligation was not durably acknowledged")
        if self._records is not None:
            self._records.append(record)

    def refresh(self) -> None:
        """One consistent remote snapshot per bounded provisioning/cleanup pass."""
        self._records = None
