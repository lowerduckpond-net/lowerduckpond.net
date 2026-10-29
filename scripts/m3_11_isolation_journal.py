"""Diagnostic-only immutable Connect records and native-volume reservation.

Connect is durable storage, not compare-and-swap. A live issuer must also hold
the native global admission and consume its run marker in the verified volume.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path
from typing import Protocol, cast

from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS

from scripts import m3_11_isolation_preparation as preparation
from scripts.m3_11_isolation_contract import RESULT_FORMAT, ROLES, provider_id
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import identity as connect_identity
from scripts.m3_11_unattended.journal import _note_content
from scripts.m3_11_unattended.model import digest, fingerprint, identity, instant, strings
from scripts.m3_11_unattended.state import private_directory

FORMAT = "lowerduckpond-isolated-public-ca-journal-v1"
CORE_FORMAT = "lowerduckpond-isolated-public-ca-obligation-v1"
TAG = "ldp-m3-11-public-ca-obligations-v1"
PREFIX = "m3-11-public-ca-"
MAX_ITEMS = 10000
MAX_RECORDS = 256
CORE = frozenset(
    {"reservation", "intents", "entered", "created", "issued", "cleanup-pending", "closed"}
)


class Reservation(Protocol):
    def consume(self, manifest: Manifest, value: dict[str, object]) -> None: ...


def _role_ids(raw: object) -> dict[str, str]:
    values = strings(fields(raw, set(ROLES)))
    if len(set(values.values())) != len(ROLES):
        raise ValueError("isolated journal credential identities are not separated")
    for value in values.values():
        provider_id(value)
    return values


def github(raw: object, manifest: Manifest) -> dict[str, object]:
    value = fields(
        raw,
        {
            "run_id",
            "run_attempt",
            "event",
            "helper_revision",
            "observed_at",
            "independent_server_id",
            "authentication_sha256",
        },
    )
    if (
        any(
            type(value[key]) is not int or cast(int, value[key]) < 1
            for key in ("run_id", "run_attempt")
        )
        or value["event"] not in {"workflow_dispatch", "schedule"}
        or value["helper_revision"] != manifest.plan.source_revision
        or value["independent_server_id"] != manifest.independent_server_id
    ):
        raise ValueError("isolated GitHub actor differs from its manifest")
    instant(value["observed_at"])
    fingerprint(value["authentication_sha256"])
    return value


def validate(raw: object, manifest: Manifest) -> dict[str, object]:  # noqa: PLR0912, PLR0915 - closed record schema
    row = fields(raw, {"format", "manifest_sha256", "kind", "payload"})
    if row["format"] != FORMAT or row["manifest_sha256"] != manifest.sha256:
        raise ValueError("isolated journal record belongs to another manifest")
    kind, payload = row["kind"], row["payload"]
    hashes = {item.sha256 for item in manifest.intents}
    by_role = {item.role: item.sha256 for item in manifest.intents}
    if kind == "manifest":
        if payload != manifest.document():
            raise ValueError("isolated manifest journal record changed")
    elif kind == "reservation":
        value = fields(payload, {"reservation_id", "intents"})
        identity(value["reservation_id"])
        if value["intents"] != by_role:
            raise ValueError("isolated reservation intent binding differs")
    elif kind == "intents":
        value = fields(payload, {"intents"})
        if value["intents"] != [item.document() for item in manifest.intents]:
            raise ValueError("isolated journal intents differ")
    elif kind in {"entered", "created"}:
        value = fields(
            payload, {"intent_sha256"} | ({"credential_id"} if kind == "created" else set())
        )
        if value["intent_sha256"] not in hashes:
            raise ValueError("isolated record contains a foreign intent")
        if kind == "created":
            provider_id(value["credential_id"])
    elif kind == "issued":
        _role_ids(fields(payload, {"ids"})["ids"])
    elif kind in {"closed", "cleanup-pending"}:
        value = fields(payload, {"plan_sha256", "roles"})
        roles = fields(value["roles"], set(ROLES))
        if value["plan_sha256"] != manifest.plan.sha256:
            raise ValueError("isolated cleanup record plan differs")
        for raw_outcome in roles.values():
            outcome = raw_outcome
            if outcome == {"creation": "not-submitted"}:
                continue
            if (
                isinstance(outcome, dict)
                and set(outcome) == {"cleanup", "error_type"}
                and kind == "cleanup-pending"
            ):
                if (
                    outcome["cleanup"] != "pending"
                    or not isinstance(outcome["error_type"], str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", outcome["error_type"]) is None
                ):
                    raise ValueError("isolated cleanup error classification is invalid")
                continue
            outcome = fields(outcome, {"credential_id", "provider_absent", "authentication"})
            provider_id(outcome["credential_id"])
            if outcome["provider_absent"] is not True or outcome["authentication"] != "denied":
                raise ValueError("isolated cleanup contains an unproven outcome")
    elif kind in {"confirmed", "covered"}:
        github(payload, manifest)
    elif kind == "prepared":
        preparation.require(payload, manifest.plan)
    elif kind == "context":
        value = fields(
            payload,
            {
                "format",
                "plan_sha256",
                "run_id",
                "captured_at",
                "source_fixture_sha256",
                "actors",
                "topology",
                "guest_program_sha256",
                "preparation_sha256",
                "credentials",
            },
        )
        if value["plan_sha256"] != manifest.plan.sha256:
            raise ValueError("isolated context plan differs")
    elif kind == "phase-started":
        value = fields(payload, {"context_sha256", "started_at", "deadline_at"})
        fingerprint(value["context_sha256"])
        started, deadline = instant(value["started_at"]), instant(value["deadline_at"])
        if (
            not instant(manifest.intents[0].requested_at)
            <= started
            < deadline
            <= instant(manifest.intents[0].expires_at)
            or (deadline - started).total_seconds() > COORDINATOR_SECONDS
        ):
            raise ValueError("isolated public phase acquired a renewed deadline")
    elif kind == "stop-requested":
        github(payload, manifest)
    elif kind == "quiesced":
        value = fields(payload, {"context_sha256", "public_phase", "actors", "observed_at"})
        if value["context_sha256"] is not None:
            fingerprint(value["context_sha256"])
        if value["public_phase"] not in {"entered", "not-started"}:
            raise ValueError("isolated public phase disposition is invalid")
        instant(value["observed_at"])
        actors = fields(value["actors"], {"source", "destination", "acme", "archive", "controller"})
        for name, raw_actor in actors.items():
            actor = fields(raw_actor, {"id", "name", "image", "owner", "running", "restart_policy"})
            fingerprint(actor["id"])
            expected = "sha256:" + (
                manifest.plan.controller_sha256
                if name == "controller"
                else manifest.plan.archive_image_sha256
                if name == "archive"
                else manifest.plan.fixture_image_sha256
            )
            suffix = "host" if name == "source" else name
            expected_name = (
                "/ldp-m311-public-ca-" + manifest.plan.run_id.replace("-", "")
                if name == "controller"
                else f"/ldp-m3-{manifest.plan.run_id.replace('-', '')}-{suffix}"
            )
            if (
                actor["running"] is not False
                or actor["restart_policy"] != "no"
                or actor["image"] != expected
                or actor["owner"] != manifest.plan.run_id.replace("-", "")
                or actor["name"] != expected_name
            ):
                raise ValueError("isolated consumer is not positively owned and stopped")
        if len({cast(dict[str, object], actor)["id"] for actor in actors.values()}) != len(actors):
            raise ValueError("isolated consumer identities repeat")
    elif kind == "dns-clean":
        value = fields(
            payload, {"context_sha256", "basis", "observation", "observation_sha256", "observed_at"}
        )
        if value["context_sha256"] is not None:
            fingerprint(value["context_sha256"])
        if (
            value["basis"] not in {"observed-absent", "public-not-started"}
            or digest(value["observation"]) != value["observation_sha256"]
        ):
            raise ValueError("isolated DNS cleanup proof basis differs")
        fingerprint(value["observation_sha256"])
        instant(value["observed_at"])
    elif kind == "functional":
        value = fields(
            payload,
            {
                "format",
                "qualification_authority",
                "plan_sha256",
                "context_sha256",
                "observations_sha256",
                "network",
                "functional_recovery",
                "cleanup",
            },
        )
        if (
            value["format"] != RESULT_FORMAT
            or value["qualification_authority"] != "none"
            or value["plan_sha256"] != manifest.plan.sha256
            or value["network"] != manifest.plan.network.document()
            or value["functional_recovery"] != "passed"
            or value["cleanup"] != "pending-independent-closure"
        ):
            raise ValueError("isolated functional observation differs")
        fingerprint(value["context_sha256"])
        fingerprint(value["observations_sha256"])
    elif kind == "readback":
        value = fields(payload, {"github", "closure_sha256", "status"})
        github(value["github"], manifest)
        fingerprint(value["closure_sha256"])
        if value["status"] != "provider-absence-and-host-denials-verified":
            raise ValueError("isolated independent closure is incomplete")
    else:
        raise ValueError("isolated journal record kind is unsupported")
    return row


def collect(records: list[dict[str, object]], manifest: Manifest) -> list[dict[str, object]]:  # noqa: PLR0912, PLR0915 - closed cross-record binding checks
    """Cross-bind facts; individual schemas alone do not establish provenance."""

    def single(kind: str, *, required: bool = False) -> dict[str, object] | None:
        values = [row["payload"] for row in records if row["kind"] == kind]
        if not values:
            if required:
                raise ValueError("isolated required control fact is missing")
            return None
        if not isinstance(values[0], dict) or any(value != values[0] for value in values):
            raise ValueError("isolated immutable control fact conflicts")
        return values[0]

    if not records:
        return []
    if single("manifest", required=True) != manifest.document():
        raise ValueError("isolated journal manifest differs")
    prepared = single("prepared")
    credential_facts = [row for row in records if row["kind"] in CORE]
    if credential_facts and (
        prepared is None or not any(row["kind"] == "confirmed" for row in records)
    ):
        raise ValueError("isolated creation lacks preparation and independent confirmation")
    created: dict[str, str] = {}
    entered = {
        cast(dict[str, object], row["payload"])["intent_sha256"]
        for row in records
        if row["kind"] == "entered"
    }
    for row in records:
        if row["kind"] == "created":
            payload = cast(dict[str, str], row["payload"])
            key, selected = payload["intent_sha256"], payload["credential_id"]
            if key not in entered or (key in created and created[key] != selected):
                raise ValueError("isolated created identity has no unique original entry")
            created[key] = selected
    issued = single("issued")
    if issued is not None and issued["ids"] != {
        item.role: created.get(item.sha256) for item in manifest.intents
    }:
        raise ValueError("isolated issued IDs differ from original acknowledged creations")
    closed = single("closed")
    if closed is not None:
        for item in manifest.intents:
            outcome = cast(dict[str, object], closed["roles"])[item.role]
            if outcome == {"creation": "not-submitted"}:
                if item.sha256 in entered or item.sha256 in created or issued is not None:
                    raise ValueError("isolated closure contradicts creation entry")
            elif cast(dict[str, object], outcome)["credential_id"] != created.get(item.sha256):
                raise ValueError("isolated closure differs from original creation")
    for row in records:
        if row["kind"] == "readback" and (
            closed is None
            or cast(dict[str, object], row["payload"])["closure_sha256"] != digest(closed)
        ):
            raise ValueError("isolated independent readback differs from original closure")
    public = single("context")
    if public is not None:
        if prepared is None or issued is None:
            raise ValueError("isolated public context predates exact credential issuance")
        preparation.context(
            public,
            prepared,
            manifest.plan,
            intents={item.role: item.sha256 for item in manifest.intents},
            ids=_role_ids(issued["ids"]),
            expires_at=manifest.intents[0].expires_at,
        )
    context_sha = None if public is None else digest(public)
    for kind in ("phase-started", "functional"):
        value = single(kind)
        if value is not None and (public is None or value["context_sha256"] != context_sha):
            raise ValueError("isolated phase result belongs to another context")
    stopped = single("quiesced")
    if stopped is not None:
        if prepared is None or stopped["context_sha256"] != context_sha:
            raise ValueError("isolated consumer stop has no matching prepared context")
        for name, original in cast(dict[str, dict[str, object]], prepared["actors"]).items():
            current = cast(dict[str, dict[str, object]], stopped["actors"])[name]
            if any(current[key] != original[key] for key in ("id", "name", "owner", "image")):
                raise ValueError("isolated stopped actor differs from its exact prepared identity")
        phase_entered = single("phase-started") is not None
        if stopped["public_phase"] != ("entered" if phase_entered else "not-started"):
            raise ValueError("isolated stop contradicts public phase entry")
    clean = single("dns-clean")
    if clean is not None:
        if clean["context_sha256"] != context_sha:
            raise ValueError("isolated DNS cleanup belongs to another context")
        if clean["basis"] == "public-not-started":
            if (
                single("phase-started") is not None
                or prepared is None
                or clean["observation"] != prepared["restore"]
            ):
                raise ValueError("isolated no-public-action proof contradicts original preparation")
        else:
            observation = fields(
                clean["observation"],
                {
                    "format",
                    "context_sha256",
                    "names_sha256",
                    "kind",
                    "sequence",
                    "started_at",
                    "completed_at",
                    "zones",
                },
            )
            names = {
                "format": "lowerduckpond-isolated-public-ca-names-v1",
                "plan_sha256": manifest.plan.sha256,
                "nonce": manifest.plan.nonce,
            }
            if (
                public is None
                or observation["context_sha256"] != context_sha
                or observation["names_sha256"] != digest(names)
                or observation["kind"] != "teardown"
                or observation["format"] != "lowerduckpond-m3-11-private-dns-observation-v1"
            ):
                raise ValueError("isolated DNS absence observation context differs")
            zones = fields(observation["zones"], set(manifest.plan.zones))
            for domain, zone in manifest.plan.zones.items():
                expected = {
                    "zone_id": zone,
                    "name": "_acme-challenge.m3-11-"
                    + manifest.plan.nonce.replace("-", "")
                    + "."
                    + domain,
                    "records": [],
                }
                if zones[domain] != expected:
                    raise ValueError("isolated DNS cleanup does not prove exact two-name absence")
    if single("closed") is not None and stopped is None:
        raise ValueError("isolated closure lacks positive owned consumer stop")
    return records


class Journal:
    """Real Connect adapter. Publication never replays an uncertain POST."""

    def __init__(
        self,
        client: Connect,
        manifest: Manifest,
        *,
        spool: Path | None = None,
        reservation: Reservation | None = None,
        guard: Callable[[], None] = lambda: None,
    ) -> None:
        self.client, self.manifest, self.spool = client, manifest, spool
        self.reservation, self.guard = reservation, guard
        if spool is not None:
            spool.mkdir(mode=0o700, parents=True, exist_ok=True)
            private_directory(spool)

    def _title(self, value: dict[str, object]) -> str:
        return PREFIX + self.manifest.plan.run_id + "-" + digest(value)

    def _read(self, item_id: str, *, published: bool = False) -> dict[str, object]:
        self.guard()
        item = (self.client.published_item if published else self.client.item)(
            self.manifest.journal_vault, item_id
        )
        if (
            item.get("category") != "SECURE_NOTE"
            or item.get("tags") != [TAG]
            or item.get("state") is not None
        ):
            raise ValueError("isolated journal item metadata differs")
        content = _note_content(item.get("fields"))
        value = validate(json.loads(content), self.manifest)
        if content != canonical_bytes(value).decode() or item.get("title") != self._title(value):
            raise ValueError("isolated journal item content or identity differs")
        return value

    def all_records(self) -> list[dict[str, object]]:
        self.guard()
        response = self.client.request("GET", f"/v1/vaults/{self.manifest.journal_vault}/items")
        if (
            response.status != HTTPStatus.OK
            or not isinstance(response.body, list)
            or len(response.body) > MAX_ITEMS
        ):
            raise ValueError("isolated journal listing is unavailable or incomplete")
        result: dict[str, dict[str, object]] = {}
        seen: set[str] = set()
        prefix = PREFIX + self.manifest.plan.run_id + "-"
        for item in response.body:
            if not isinstance(item, dict):
                raise ValueError("isolated journal listing is invalid")
            selected = connect_identity(item.get("id"))
            if selected in seen:
                raise ValueError("isolated journal listing repeats an item")
            seen.add(selected)
            tags, title = item.get("tags") or [], str(item.get("title", ""))
            if not isinstance(tags, list):
                raise ValueError("isolated journal listing tags are invalid")
            if not title.startswith(prefix):
                continue
            if tags != [TAG]:
                raise ValueError("isolated journal namespace contains a foreign record")
            value = self._read(selected)
            key = digest(value)
            if item.get("title") != self._title(value):
                raise ValueError("isolated listed journal identity differs")
            result[key] = value  # Identical duplicate POST outcomes are one fact.
            if len(result) > MAX_RECORDS:
                raise ValueError("isolated journal exceeds its per-run record bound")
        return collect([result[key] for key in sorted(result)], self.manifest)

    def records(self) -> list[dict[str, object]]:
        return [
            {
                "format": CORE_FORMAT,
                "plan_sha256": self.manifest.plan.sha256,
                "kind": row["kind"],
                "payload": row["payload"],
            }
            for row in self.all_records()
            if row["kind"] in CORE
        ]

    def put(self, kind: str, payload: object) -> None:
        value = validate(
            {
                "format": FORMAT,
                "manifest_sha256": self.manifest.sha256,
                "kind": kind,
                "payload": payload,
            },
            self.manifest,
        )
        existing = self.all_records()
        if value in existing:
            return
        collect([*existing, value], self.manifest)
        if self.spool is None:
            raise ValueError("isolated journal publication needs its private pending spool")
        pending = self.spool / (digest(value) + ".json")
        if pending.exists() or pending.is_symlink():
            if read_private(pending) != value:
                raise ValueError("isolated pending journal fact changed")
            raise ValueError(
                "isolated journal publication remains unobserved; POST is not replayed"
            )
        write_private(pending, value)
        item: dict[str, object] = {
            "title": self._title(value),
            "category": "SECURE_NOTE",
            "vault": {"id": self.manifest.journal_vault},
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
        response = self.client.request(
            "POST", f"/v1/vaults/{self.manifest.journal_vault}/items", item
        )
        if response.status not in {HTTPStatus.OK, HTTPStatus.CREATED} or not isinstance(
            response.body, dict
        ):
            raise ValueError("isolated journal publication was not acknowledged")
        selected = connect_identity(response.body.get("id"))
        if self._read(selected, published=True) != value:
            raise ValueError("isolated exact journal readback differs")

    def persist(self, value: dict[str, object]) -> None:
        fields(value, {"format", "plan_sha256", "kind", "payload"})
        if (
            value["format"] != CORE_FORMAT
            or value["plan_sha256"] != self.manifest.plan.sha256
            or value["kind"] not in CORE
        ):
            raise ValueError("isolated credential fact escaped its manifest")
        self.put(str(value["kind"]), value["payload"])

    def reserve(self, run_id: str, value: dict[str, object]) -> None:
        if run_id != self.manifest.plan.run_id or self.reservation is None:
            raise ValueError("isolated creation needs its native global reservation")
        self.reservation.consume(self.manifest, value)
        self.persist(value)
