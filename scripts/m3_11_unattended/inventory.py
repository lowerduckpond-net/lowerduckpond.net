"""Compact immutable lease facts in the existing private Connect vault.

Only the complete manifest needs independent visibility before issuance. Later
facts improve reconciliation; no per-event witness, checkpoint or election exists.
A local readback is deliberately not an independent manifest confirmation.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Protocol

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.connect_api import Connect, ConnectResponseError
from scripts.m3_11_unattended.connect_auth import identity as connect_identity
from scripts.m3_11_unattended.journal import _note_content
from scripts.m3_11_unattended.model import (
    ROLES,
    AuthorityGeneration,
    LeaseManifest,
    LifecycleError,
    digest,
    fingerprint,
    identity,
    instant,
)
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-lease-inventory-v1"
TAG = "ldp-m3-11-leases-v1"
PREFIX = "m3-11-lease-"
MAX_ITEMS = 10000
ROLE_FACTS = {"created", "not-submitted", "removed", "denied"}
CLOSE_REASONS = {"cancel", "finish", "expiry", "provisioning-failed", "disclosure"}


def _positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def _connect_id(value: object) -> str:
    if not isinstance(value, str):
        raise LifecycleError("lease inventory item identity is invalid")
    return Connect._identity(value)


def validate(raw: object) -> dict[str, object]:  # noqa: PLR0912, PLR0915 - closed immutable fact schemas
    record = fields(raw, {"format", "lease_id", "slot", "manifest_sha256", "payload"})
    identity(record["lease_id"])
    fingerprint(record["manifest_sha256"])
    slot = record["slot"]
    if record["format"] != FORMAT or not isinstance(slot, str):
        raise LifecycleError("lease inventory record is invalid")
    payload = record["payload"]
    if slot == "manifest":
        manifest = LeaseManifest.parse(payload)
        if manifest.lease_id != record["lease_id"] or manifest.sha256 != record["manifest_sha256"]:
            raise LifecycleError("lease inventory manifest binding differs")
    elif slot == "confirmed":
        value = fields(
            payload,
            {
                "helper_revision",
                "independent_server_id",
                "observed_at",
                "github_run_id",
                "github_run_attempt",
                "cleanup_access_expires_at",
            },
        )
        revision(value["helper_revision"])
        instant(value["observed_at"])
        instant(value["cleanup_access_expires_at"])
        connect_identity(value["independent_server_id"])
        if any(
            not _positive_integer(value[key]) for key in ("github_run_id", "github_run_attempt")
        ):
            raise LifecycleError("independent manifest confirmation is invalid")
    elif slot.startswith("close-") and slot.removeprefix("close-") in CLOSE_REASONS:
        fields(payload, set())
    elif slot == "issuer-stopped":
        value = fields(payload, {"writer_sha256", "stopped_at", "retained_roles"})
        fingerprint(value["writer_sha256"])
        instant(value["stopped_at"])
        roles = value["retained_roles"]
        if (
            not isinstance(roles, list)
            or any(not isinstance(role, str) or role not in ROLES for role in roles)
            or len(roles) != len(set(roles))
        ):
            raise LifecycleError("issuer credential-retention evidence is invalid")
    elif slot == "closed":
        value = fields(payload, {"results"})
        results = value["results"]
        if not isinstance(results, list) or len(results) != len(ROLES):
            raise LifecycleError("lease closure does not cover the complete manifest")
        identities = set()
        for row in results:
            result = fields(row, {"intent_sha256", "status", "negative_authentication"})
            identities.add(fingerprint(result["intent_sha256"]))
            if result["status"] != "verified" or result["negative_authentication"] not in {
                "denied",
                "unavailable",
                "not-tested",
            }:
                raise LifecycleError("lease closure contains unresolved obligations")
        if len(identities) != len(ROLES):
            raise LifecycleError("lease closure repeats an obligation")
    elif slot.startswith("handover:"):
        _, role, generation_id = slot.split(":")
        identity(generation_id)
        value = fields(
            payload,
            {
                "intent_sha256",
                "credential_id",
                "previous_generation_sha256",
                "generation",
                "observed_at",
            },
        )
        fingerprint(value["intent_sha256"])
        fingerprint(value["previous_generation_sha256"])
        instant(value["observed_at"])
        generation = AuthorityGeneration.parse(value["generation"])
        if (
            role not in ROLES
            or generation.role != "cleanup"
            or generation.generation_id != generation_id
        ):
            raise LifecycleError("cleanup handover generation is invalid")
        if (
            not isinstance(value["credential_id"], str)
            or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value["credential_id"]) is None
        ):
            raise LifecycleError("cleanup handover credential identity is invalid")
    else:
        kind, separator, role = slot.partition(":")
        if separator != ":" or kind not in ROLE_FACTS or role not in ROLES:
            raise LifecycleError("lease inventory slot is unsupported")
        value = fields(
            payload,
            {"intent_sha256", "writer_sha256"}
            if kind == "not-submitted"
            else {"intent_sha256", "credential_id"},
        )
        fingerprint(value["intent_sha256"])
        if kind == "not-submitted":
            fingerprint(value["writer_sha256"])
        elif (
            not isinstance(value["credential_id"], str)
            or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value["credential_id"]) is None
        ):
            raise LifecycleError("lease inventory credential identity is invalid")
    return deepcopy(record)


def fact(manifest: LeaseManifest, slot: str, payload: dict[str, object]) -> dict[str, object]:
    return validate(
        {
            "format": FORMAT,
            "lease_id": manifest.lease_id,
            "slot": slot,
            "manifest_sha256": manifest.sha256,
            "payload": payload,
        }
    )


def title(record: dict[str, object]) -> str:
    return PREFIX + str(record["lease_id"]) + "-" + str(record["slot"])


def confirmation_binding(
    record: dict[str, object], manifest: LeaseManifest, *, now: datetime
) -> None:
    """Validate every observation before any equivalent provenance is reduced."""
    value = record["payload"]
    if (
        record["manifest_sha256"] != manifest.sha256
        or record["lease_id"] != manifest.lease_id
        or not isinstance(value, dict)
        or value["helper_revision"] != manifest.helper_revision
        or instant(value["observed_at"]) < instant(manifest.created_at)
        or instant(value["observed_at"]) > now
        or instant(value["cleanup_access_expires_at"])
        < manifest.policy.deadline(instant(manifest.created_at))
        + timedelta(seconds=manifest.policy.cleanup_reserve_seconds)
    ):
        raise LifecycleError("independent manifest confirmation has the wrong binding")


def confirmation_identity(record: dict[str, object]) -> dict[str, object]:
    """Only these three truthful provenance fields may vary, only for confirmed."""
    if record["slot"] != "confirmed" or not isinstance(record["payload"], dict):
        raise LifecycleError("confirmation equivalence requires a confirmation")
    return {
        **record,
        "payload": {
            key: value
            for key, value in record["payload"].items()
            if key not in {"observed_at", "github_run_id", "github_run_attempt"}
        },
    }


def confirmation_order(record: dict[str, object]) -> tuple[object, ...]:
    value = record["payload"]
    if not isinstance(value, dict):
        raise LifecycleError("confirmation payload is unavailable")
    return (
        instant(value["observed_at"]),
        value["github_run_id"],
        value["github_run_attempt"],
        digest(record),
    )


def _collect(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Identical lost-response duplicates are one fact; conflicting facts fail."""
    if len(records) > MAX_ITEMS:
        raise LifecycleError("lease inventory exceeds its bound")
    validated = [validate(raw) for raw in records]
    now = datetime.now(UTC)
    manifests: dict[str, LeaseManifest] = {}
    for record in validated:
        if record["slot"] == "manifest":
            manifest = LeaseManifest.parse(record["payload"])
            previous = manifests.setdefault(manifest.lease_id, manifest)
            if previous != manifest:
                raise LifecycleError("lease inventory contains conflicting immutable facts")
    selected: dict[str, dict[str, object]] = {}
    for record in validated:
        if record["slot"] == "confirmed":
            bound_manifest = manifests.get(str(record["lease_id"]))
            if bound_manifest is None:
                raise LifecycleError("complete lease manifest is not visible")
            confirmation_binding(record, bound_manifest, now=now)
        key = title(record)
        if key in selected and selected[key] != record:
            if record["slot"] != "confirmed" or confirmation_identity(
                selected[key]
            ) != confirmation_identity(record):
                raise LifecycleError("lease inventory contains conflicting immutable facts")
            selected[key] = min((selected[key], record), key=confirmation_order)
        else:
            selected[key] = record
    return [selected[key] for key in sorted(selected)]


class InventoryReader(Protocol):
    def records(self) -> list[dict[str, object]]: ...


class Inventory(InventoryReader, Protocol):
    def publish(self, record: dict[str, object]) -> None: ...


class LocalInventory:
    """Private synthetic-provider adapter; live configuration cannot select it."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(directory)
        self.directory = directory

    def records(self) -> list[dict[str, object]]:
        paths = sorted(self.directory.glob("*.json"))
        if len(paths) > MAX_ITEMS:
            raise LifecycleError("lease inventory exceeds its bound")
        return _collect([read_private(path) for path in paths])

    def publish(self, record: dict[str, object]) -> None:
        record = validate(record)
        path = self.directory / (digest(title(record)) + ".json")
        if not path.exists():
            write_private(path, record)
        if read_private(path) != record:
            raise LifecycleError("lease inventory fact cannot be replaced")


class ConnectInventoryReader:
    """Read native immutable facts without a publication spool or write authority."""

    def __init__(self, client: Connect, vault: str) -> None:
        self.client, self.vault = client, Connect._identity(vault)

    def _read(self, item_id: str, *, published: bool = False) -> dict[str, object]:
        read = self.client.published_item if published else self.client.item
        item = read(self.vault, item_id)
        if (
            item.get("category") != "SECURE_NOTE"
            or item.get("tags") != [TAG]
            or item.get("state") is not None
        ):
            raise LifecycleError("lease inventory item is unavailable or changed")
        content = _note_content(item.get("fields"))
        try:
            record = validate(json.loads(content))
        except ValueError, TypeError, KeyError:
            raise LifecycleError("lease inventory content is invalid") from None
        if item.get("title") != title(record) or content != canonical_bytes(record).decode():
            raise LifecycleError("lease inventory content differs from its identity")
        return record

    def records(self) -> list[dict[str, object]]:
        response = self.client.request("GET", f"/v1/vaults/{self.vault}/items")
        if (
            response.status != HTTPStatus.OK
            or not isinstance(response.body, list)
            or len(response.body) > MAX_ITEMS
        ):
            raise ConnectResponseError(
                response, "inventory-list", "lease inventory listing is incomplete or unavailable"
            )
        records = []
        seen: set[str] = set()
        for item in response.body:
            if not isinstance(item, dict):
                raise LifecycleError("lease inventory listing is invalid")
            item_id = _connect_id(item.get("id"))
            if item_id in seen:
                raise LifecycleError("lease inventory listing repeats an item")
            seen.add(item_id)
            # Historical journal items are handled by the migration reader.
            # A malformed item advertising this format cannot be skipped.
            if TAG in (item.get("tags") or []) or str(item.get("title", "")).startswith(PREFIX):
                records.append(self._read(item_id))
        return _collect(records)


class ConnectInventory(ConnectInventoryReader):
    def __init__(self, client: Connect, vault: str, *, spool: Path) -> None:
        super().__init__(client, vault)
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(spool)
        self.spool = spool

    def publish(self, record: dict[str, object]) -> None:
        record = validate(record)
        records = self.records()
        existing = [entry for entry in records if title(entry) == title(record)]
        if record["slot"] == "confirmed":
            # Validate the candidate as well as every existing observation, even if no POST
            # is needed. This also checks a manifest appearing/disappearing at publication.
            _collect([*records, record])
        if existing:
            if existing != [record] and not (
                record["slot"] == "confirmed"
                and confirmation_identity(existing[0]) == confirmation_identity(record)
            ):
                raise LifecycleError("lease inventory fact cannot be replaced")
            return
        pending = self.spool / (digest(title(record)) + ".json")
        if pending.exists() or pending.is_symlink():
            if read_private(pending) != record:
                raise LifecycleError("lease inventory pending write conflicts")
            # A lost reply may already have committed. Retry reads in a later
            # reconciliation; never POST this pending write again.
            raise LifecycleError("lease inventory write remains unobserved")
        write_private(pending, record)
        item: dict[str, object] = {
            "title": title(record),
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
        if response.status not in {HTTPStatus.OK, HTTPStatus.CREATED} or not isinstance(
            response.body, dict
        ):
            raise ConnectResponseError(
                response, "publication-response", "lease inventory write was not acknowledged"
            )
        try:
            selected = _connect_id(response.body.get("id"))
        except LifecycleError:
            raise ConnectResponseError(
                response, "publication-id", "lease inventory write returned an invalid identity"
            ) from None
        if self._read(selected, published=True) != record:
            raise LifecycleError("lease inventory write readback differs")


def require_confirmation(
    inventory: InventoryReader, manifest: LeaseManifest, *, independent_server_id: str
) -> None:
    records = inventory.records()
    expected = fact(manifest, "manifest", manifest.document())
    if expected not in records:
        raise LifecycleError("complete lease manifest is not visible")
    matches = [
        record
        for record in records
        if record["lease_id"] == manifest.lease_id and record["slot"] == "confirmed"
    ]
    if len(matches) != 1:
        raise LifecycleError("independent manifest confirmation is unavailable")
    selected = matches[0]
    confirmation_binding(selected, manifest, now=datetime.now(UTC))
    value = selected["payload"]
    if not isinstance(value, dict) or value["independent_server_id"] != independent_server_id:
        raise LifecycleError("independent manifest confirmation has the wrong binding")


def require_clear(inventory: InventoryReader, *, current_lease: str | None = None) -> None:
    """An ambiguous or active earlier set blocks a competing manifest."""
    records = inventory.records()
    manifests = [
        LeaseManifest.parse(record["payload"]) for record in records if record["slot"] == "manifest"
    ]
    known = {manifest.lease_id for manifest in manifests}
    if any(record["lease_id"] not in known for record in records):
        raise LifecycleError("lease inventory contains outcomes without their manifest")
    for manifest in manifests:
        if manifest.lease_id == current_lease:
            continue
        own = {
            str(record["slot"]): record
            for record in records
            if record["lease_id"] == manifest.lease_id
        }
        closed = own.get("closed")
        if (
            closed is None
            or "issuer-stopped" not in own
            or closed["manifest_sha256"] != manifest.sha256
        ):
            raise LifecycleError("an active or unresolved lease blocks another credential set")
        payload = closed["payload"]
        if not isinstance(payload, dict) or {
            row["intent_sha256"] for row in payload["results"]
        } != {intent.sha256 for intent in manifest.intents}:
            raise LifecycleError("lease closure differs from its original obligations")
