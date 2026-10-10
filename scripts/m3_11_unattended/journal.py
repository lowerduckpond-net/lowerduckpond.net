"""Append-only obligations in a dedicated 1Password vault, outside the Docker host.

Every event is a separate immutable item. Independent cleanup never edits an
intent or overwrites a controller update. Provider secrets are never journaled.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
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


def record_title(record: dict[str, object]) -> str:
    return f"m3-11-{record['event_id']}-{digest(record)}"


class Journal(Protocol):
    def append(self, record: dict[str, object]) -> None:
        """Stage one immutable record with exact readback; this may be a local cache."""
        ...

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        """Return the original event after independent storage confirms its exact bytes."""
        ...

    def records(self) -> list[dict[str, object]]: ...


@runtime_checkable
class CreationJournal(Protocol):
    """Optional idempotent publication of related post-creation obligations."""

    def persist_creation(self, created: dict[str, object], marker: dict[str, object]) -> None:
        """Retain both records immediately under their original ACK deadline.

        Ordinary journals confirm before returning. The invocation-local Connect
        provisioning adapter confirms at its next intent barrier or final flush;
        provisional credentials must remain inside that invocation until then.
        """
        ...


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

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        # This adapter is only for local doubles, never live provisioning.
        self.append(record)
        return record


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


MIGRATION_FORMAT = "lowerduckpond-m3-11-legacy-import-v1"
MIGRATION_TAG = "ldp-m3-11-legacy-import-v1"


def migration(value: object) -> dict[str, object]:  # noqa: PLR0912 - complete reviewed obligation schema
    """An approved import is an inventory of obligations, never a success receipt.

    Exact old records, retained private-file digests and update intents remain
    bound even when their original code path is retired. The operator's stopped
    issuer attestation is part of the reviewed cutover input, not inferred from
    an empty provider response or a liveness timeout.
    """
    from scripts.m3_11_unattended.model import fingerprint, strings  # noqa: PLC0415

    selected = fields(
        value,
        {
            "format",
            "records",
            "obligations",
            "retained_files",
            "expiry_updates",
            "issuers",
            "approved_at",
            "approval_reference",
        },
    )
    if selected["format"] != MIGRATION_FORMAT:
        raise LifecycleError("legacy import format is unsupported")
    instant(selected["approved_at"])
    approval = selected["approval_reference"]
    if not isinstance(approval, str) or not approval or len(approval) > 256:  # noqa: PLR2004
        raise LifecycleError("legacy import requires explicit approval")
    for key, expected in strings(selected["records"]).items():
        identity(key)
        fingerprint(expected)
    for path, expected in strings(selected["retained_files"]).items():
        if not path or len(path) > 4096 or any(ord(char) < 32 for char in path):  # noqa: PLR2004
            raise LifecycleError("legacy retained-file mapping is invalid")
        fingerprint(expected)
    obligations = selected["obligations"]
    if not isinstance(obligations, dict):
        raise LifecycleError("legacy obligation mapping is missing")
    for key, raw in obligations.items():
        fingerprint(key)
        row = fields(raw, {"generation_id", "provider_id", "original_status"})
        identity(row["generation_id"])
        if row["provider_id"] is not None and (
            not isinstance(row["provider_id"], str)
            or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", row["provider_id"]) is None
        ):
            raise LifecycleError("legacy provider ID mapping is invalid")
        if row["original_status"] not in {
            "unresolved",
            "verified",
            "not-submitted",
            "operator-accepted-uncertainty",
        }:
            raise LifecycleError("legacy original status is invalid")
    if not isinstance(selected["expiry_updates"], list):
        raise LifecycleError("legacy expiry update inventory is missing")
    for raw in selected["expiry_updates"]:
        row = fields(raw, {"plan", "plan_sha256", "generation_id", "result_files"})
        if digest(row["plan"]) != fingerprint(row["plan_sha256"]):
            raise LifecycleError("legacy expiry intent digest differs")
        identity(row["generation_id"])
        for path, expected in strings(row["result_files"]).items():
            if strings(selected["retained_files"]).get(path) != fingerprint(expected):
                raise LifecycleError("legacy expiry evidence was not retained")
    issuers = selected["issuers"]
    if not isinstance(issuers, list) or (selected["records"] and not issuers):
        raise LifecycleError("legacy import lacks stopped issuer evidence")
    for raw in issuers:
        row = fields(
            raw,
            {
                "container_id",
                "daemon_sha256",
                "stopped_at",
                "running",
                "restart_policy",
                "issuance_disabled",
            },
        )
        fingerprint(row["container_id"])
        fingerprint(row["daemon_sha256"])
        instant(row["stopped_at"])
        if (
            row["running"] is not False
            or row["restart_policy"] != "no"
            or row["issuance_disabled"] is not True
        ):
            raise LifecycleError("legacy issuer may still execute or restart")
    return selected


class ConnectObligations:
    """Cleanup-only reader of original journal records plus monotonic outcomes.

    There is no service-account access, witness, checkpoint, or new legacy intent.
    The reviewed import's exact minimum inventory may never disappear. New old-
    format issuance after cutover is a hard error, even when its creator is gone.
    """

    def __init__(self, client: object, vault: str, *, spool: Path, expected: str) -> None:
        from scripts.m3_11_unattended.connect_api import Connect  # noqa: PLC0415
        from scripts.m3_11_unattended.model import fingerprint  # noqa: PLC0415
        from scripts.m3_11_unattended.state import private_directory  # noqa: PLC0415

        if not isinstance(client, Connect):
            raise LifecycleError("legacy import requires its authenticated Connect reader")
        self.client, self.vault, self.expected = (
            client,
            Connect._identity(vault),
            fingerprint(expected),
        )
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(spool)
        self.spool = spool
        self.mapping: dict[str, object] | None = None

    def _items(self) -> list[dict[str, object]]:
        response = self.client.request("GET", f"/v1/vaults/{self.vault}/items")
        if (
            response.status != HTTPStatus.OK
            or not isinstance(response.body, list)
            or len(response.body) > MAX_EVENTS
        ):
            raise LifecycleError("legacy Connect inventory is unavailable or incomplete")
        result = []
        seen: set[str] = set()
        for raw in response.body:
            if not isinstance(raw, dict):
                raise LifecycleError("legacy Connect inventory is malformed")
            if not isinstance(raw.get("id"), str):
                raise LifecycleError("legacy Connect item identity is invalid")
            item_id = self.client._identity(str(raw["id"]))
            if item_id in seen:
                raise LifecycleError("legacy Connect inventory repeats an item")
            seen.add(item_id)
            result.append(raw)
        return result

    def _read(self, item: dict[str, object], *, tag: str) -> dict[str, object]:
        full = self.client.item(self.vault, str(item["id"]))
        if (
            full.get("category") != "SECURE_NOTE"
            or full.get("tags") != [tag]
            or full.get("state") is not None
        ):
            raise LifecycleError("legacy Connect record metadata differs")
        raw = _note_content(full.get("fields"))
        value = json.loads(raw)
        if not isinstance(value, dict) or canonical_bytes(value).decode() != raw:
            raise LifecycleError("legacy Connect record content is ambiguous")
        expected_title = (
            "m3-11-import-" + digest(migration(value))
            if tag == MIGRATION_TAG
            else record_title(validate(value))
        )
        if full.get("title") != expected_title or item.get("title") != expected_title:
            raise LifecycleError("legacy Connect record identity differs")
        return cast(dict[str, object], value)

    def records(self) -> list[dict[str, object]]:
        items = self._items()
        imports = [row for row in items if row.get("title") == "m3-11-import-" + self.expected]
        if len(imports) != 1:
            raise LifecycleError("approved legacy import is missing or ambiguous")
        mapping = migration(self._read(imports[0], tag=MIGRATION_TAG))
        if digest(mapping) != self.expected:
            raise LifecycleError("legacy import changed after approval")
        values: dict[str, dict[str, object]] = {}
        for item in items:
            tags = item.get("tags")
            if (
                not (isinstance(tags, list) and TAG in tags)
                and re.fullmatch(r"m3-11-[0-9a-f-]{36}-[0-9a-f]{64}", str(item.get("title")))
                is None
            ):
                continue
            record = self._read(item, tag=TAG)
            key = str(record["event_id"])
            if key in values and values[key] != record:
                raise LifecycleError("legacy record identity is ambiguous")
            values[key] = record
        minimum = cast(dict[str, str], mapping["records"])
        if any(
            key not in values or digest(values[key]) != expected
            for key, expected in minimum.items()
        ):
            raise LifecycleError("an imported legacy obligation disappeared or changed")
        if any(
            row["kind"] in {"intent", "run"} and key not in minimum for key, row in values.items()
        ):
            raise LifecycleError("obsolete issuance appeared after legacy import")
        from scripts.m3_11_unattended.lifecycle import _intents, _known_id  # noqa: PLC0415

        records = list(values.values())
        originals = [values[key] for key in minimum]
        obligations = cast(dict[str, dict[str, object]], mapping["obligations"])
        intents = _intents(originals)
        if set(obligations) != {intent.sha256 for intent in intents} or any(
            obligations[intent.sha256]["provider_id"] != _known_id(originals, intent)
            for intent in intents
        ):
            raise LifecycleError("legacy import does not cover every original obligation")
        self.mapping = mapping
        return records

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        validate(record)
        records = self.records()
        matches = [row for row in records if row["event_id"] == record["event_id"]]
        if matches:
            if matches != [record]:
                raise LifecycleError("legacy cleanup observation conflicts")
            return record
        if record["kind"] in {"intent", "run"}:
            raise LifecycleError("obsolete credential issuance is permanently disabled")
        # Identical observations reuse their original immutable event ID.
        previous = next(
            (
                row
                for row in records
                if all(row[key] == record[key] for key in ("kind", "run_id", "payload"))
            ),
            None,
        )
        if previous is not None:
            return previous
        semantic = {key: record[key] for key in ("kind", "run_id", "payload")}
        pending = self.spool / (digest(semantic) + ".json")
        if pending.exists():
            original = read_private(pending)
            if any(original.get(key) != value for key, value in semantic.items()):
                raise LifecycleError("legacy pending observation conflicts")
            raise LifecycleError("legacy cleanup observation remains unobserved")
        write_private(pending, record)
        item: dict[str, object] = {
            "title": record_title(record),
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
        response = self.client.request("POST", f"/v1/vaults/{self.vault}/items", item)
        if response.status not in {200, 201} or not isinstance(response.body, dict):
            raise LifecycleError("legacy cleanup observation was not acknowledged")
        if not isinstance(response.body.get("id"), str):
            raise LifecycleError("legacy cleanup acknowledgement identity is invalid")
        readback: dict[str, object] = {
            "id": self.client._identity(str(response.body["id"])),
            "title": item["title"],
        }
        if self._read(readback, tag=TAG) != record:
            raise LifecycleError("legacy cleanup observation readback differs")
        return record

    def append(self, record: dict[str, object]) -> None:
        self.persist(record)
