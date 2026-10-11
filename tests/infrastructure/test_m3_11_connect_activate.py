"""Cutover preflight verifies preserved obligations and staged configuration bytes."""

from __future__ import annotations

import calendar
import dataclasses
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import cleanup, cleanup_expiry, historical_absence, setup
from scripts.m3_11_unattended import connect_activate as activation
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare
from scripts.m3_11_unattended.config import LeaseBootstrap, LeaseConfiguration, UnavailableProvider
from scripts.m3_11_unattended.connect_renewal import handover
from scripts.m3_11_unattended.connect_setup import prepare
from scripts.m3_11_unattended.creation_outcome import FORMAT as ABORT_FORMAT
from scripts.m3_11_unattended.creation_outcome import original_abort
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.journal import MIGRATION_TAG, TAG, event, record_title
from scripts.m3_11_unattended.lifecycle import Provider
from scripts.m3_11_unattended.model import (
    MONTHS_PER_YEAR,
    PROVIDERS,
    LifecycleError,
    ProviderKind,
    digest,
    stamp,
)

from .test_m3_11_connect_action import Case
from .test_m3_11_connect_setup import CANARY, independent_reader
from .test_m3_11_lease_inventory import LeaseProviderDouble
from .test_m3_11_lease_migration import ImportDocker, expiry_update, note
from .test_m3_11_unattended_lifecycle import Case as LegacyCase


def stage(case: Case, monkeypatch: pytest.MonkeyPatch) -> Path:
    output = case.root / "staged"
    prepare(
        case.config.document(),
        independent_reader(case.config.independent_server_id),
        {"synthetic": CANARY},
        output=output,
    )
    monkeypatch.setattr(setup, "reader", lambda _value: case.client)
    return output


def test_active_lease_allows_staging_while_preserving_cleanup_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    output = stage(case, monkeypatch)
    case.execute()
    case.issue()
    receipt = activation.activate(output)
    assert receipt["status"] == "ready"
    for field, filename in (
        ("controller_sha256", "controller-connect.json"),
        ("independent_sha256", "github-connect.json"),
    ):
        assert receipt[field] == hashlib.sha256((output / filename).read_bytes()).hexdigest()
    assert activation.activate(output) == receipt
    assert read_private(output / "activation.json") == receipt
    assert all(provider.items for provider in case.providers["cleanup"].values())


@pytest.mark.parametrize("fault", ["missing-migration", "provider-unavailable", "orphan"])
def test_preflight_never_approves_unresolved_or_lost_obligations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    output = stage(case, monkeypatch)
    if fault == "missing-migration":
        del case.client.items[next(iter(case.client.items))]
    elif fault == "provider-unavailable":

        def fail(*_args: object, **_kwargs: object) -> None:
            raise LifecycleError("synthetic inaccessible approved authority")

        monkeypatch.setattr(activation, "validate", fail)
    else:
        case.lifecycle.request_close("cancel")
        case.client.items = {
            key: value
            for key, value in case.client.items.items()
            if "-manifest-" not in str(value["title"])
        }
        # Find and remove the actual manifest note by its canonical content.
        case.client.items = {
            key: value
            for key, value in case.client.items.items()
            if '"slot":"manifest"' not in str(value["fields"])
        }
    with pytest.raises(LifecycleError):
        activation.activate(output)
    assert not (output / "activation.json").exists()


def replacement(case: Case, monkeypatch: pytest.MonkeyPatch) -> LeaseConfiguration:
    now = datetime.now(UTC).replace(microsecond=0)
    year = now.year + (now.month == MONTHS_PER_YEAR)
    month = now.month % MONTHS_PER_YEAR + 1
    generation_id = str(uuid.uuid7())
    updated = {}
    maps = {}
    for role, old in case.config.generations[case.config.active_generation].items():
        generation = dataclasses.replace(
            old.generation,
            generation_id=generation_id,
            introduced_at=stamp(now),
            rotation_due_at=stamp(
                now.replace(
                    year=year,
                    month=month,
                    day=min(now.day, calendar.monthrange(year, month)[1]),
                )
            ),
            fingerprints={kind: digest([generation_id, role, kind]) for kind in PROVIDERS},
        )
        updated[role] = dataclasses.replace(old, generation=generation)
        maps[role] = {
            kind: LeaseProviderDouble(kind, generation.fingerprints[kind]) for kind in PROVIDERS
        }
        for kind in PROVIDERS:
            maps[role][kind].items = case.providers[role][kind].items
    config = dataclasses.replace(
        case.config,
        active_generation=generation_id,
        generations={**case.config.generations, generation_id: updated},
    )

    def providers(bootstrap: LeaseBootstrap, **_kwargs: object) -> dict[ProviderKind, Provider]:
        return dict(
            (maps if bootstrap.generation.generation_id == generation_id else case.providers)[
                bootstrap.generation.role
            ]
        )

    monkeypatch.setattr(LeaseBootstrap, "providers", providers)
    return config


@pytest.mark.parametrize("unknown", [False, True])
def test_rotation_keeps_old_cleanup_during_staging_and_requires_coverage_before_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unknown: bool
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.execute()
    if unknown:
        case.providers["provision"]["spaces"].lose_response = True
        with pytest.raises(LifecycleError):
            case.issue()
    else:
        case.issue()
    updated = replacement(case, monkeypatch)
    result = handover(case.config, updated, case.inventory, root=case.root / "handover-leases")
    assert result["results"] == [
        {
            "lease_id": case.manifest.lease_id,
            "status": "retained-original" if unknown else "transferred",
        }
    ]
    only_new = dataclasses.replace(
        updated,
        generations={updated.active_generation: updated.generations[updated.active_generation]},
    )
    case.config = only_new
    output = stage(case, monkeypatch)
    if unknown:
        with pytest.raises(LifecycleError, match="removed required cleanup"):
            activation.activate(output)
    else:
        assert activation.activate(output)["status"] == "ready"
        # Before any replacement is deployed, the old independent actor still
        # owns verified cleanup authority along the explicit handover chain.
        case.lifecycle.request_close("finish")
        assert all(
            row.status == "verified"
            for row in case.lifecycle.reconcile(
                case.providers["cleanup"],
                generations={case.manifest.cleanup.generation_id: case.providers["cleanup"]},
            )
        )
        assert all(not provider.items for provider in case.providers["cleanup"].values())


@pytest.mark.parametrize("retired", [False, True])
@pytest.mark.parametrize("outcome", ["unresolved", "verified", "not-submitted", "uncertainty"])
def test_import_activation_and_sweeps_preserve_terminal_evidence_after_authority_retirement(  # noqa: PLR0915 - exercise the complete cutover boundary
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired: bool, outcome: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    old = LegacyCase(tmp_path / "legacy")
    intent, credential = old.lifecycle.provision(
        run_id=old.run_id,
        role="archive",
        source="e" * 40,
        helper="f" * 40,
        targets=case.config.targets,
        provider="spaces",
        scope={"synthetic": "archive"},
        authority=old.authority,
    )
    old.lifecycle.request_revocation(old.run_id)
    completed = outcome != "unresolved"
    expected_status = "verified"
    negative = "denied"
    if outcome == "verified":
        assert old.lifecycle.reconcile(intent, credential).status == "verified"
    records = old.journal.records()
    provider_id: str | None = credential.identifier
    if outcome in {"not-submitted", "uncertainty"}:
        original = next(row for row in records if row["kind"] == "intent")
        records = [original]
        provider_id = None
        if outcome == "not-submitted":
            run = event(
                "run",
                intent.run_id,
                {
                    "binding": {
                        "managed_run_id": intent.run_id,
                        "source_revision": intent.source_revision,
                        "helper_revision": intent.helper_revision,
                        "storage_target_sha256": intent.targets.storage_digest,
                        "artifact_sha256": "a" * 64,
                        "qualification_inputs_sha256": "b" * 64,
                    },
                    "mode": "qualification",
                    "approval_sha256": "c" * 64,
                    "creation_protocol": ABORT_FORMAT,
                },
            )
            records += [run, original_abort(intent, original, run)]
            negative = "not-tested"
        else:
            monkeypatch.setattr(historical_absence, "INTENT", intent.sha256)
            monkeypatch.setattr(historical_absence, "RUN", intent.run_id)
            payload = {**historical_absence.PAYLOAD, "intent_sha256": intent.sha256}
            monkeypatch.setattr(historical_absence, "PAYLOAD", payload)
            records.append(event("heartbeat", intent.run_id, dict(payload)))
            expected_status = historical_absence.STATUS
            negative = "unavailable"
    generation_id = str(uuid.uuid7())
    active = case.config.generations[case.config.active_generation]["cleanup"]
    expired = dataclasses.replace(
        active,
        generation=dataclasses.replace(
            active.generation,
            generation_id=generation_id,
            fingerprints={
                **active.generation.fingerprints,
                "spaces": old.provider.authority_sha256,
            },
            expires_at=dict.fromkeys(PROVIDERS, stamp(datetime.now(UTC) - timedelta(days=1))),
        ),
    )
    docker = ImportDocker()
    mapping = {
        **case.mapping,
        "records": {str(row["event_id"]): digest(row) for row in records},
        "obligations": {
            intent.sha256: {
                "generation_id": generation_id,
                "provider_id": provider_id,
                "original_status": historical_absence.STATUS
                if outcome == "uncertainty"
                else outcome,
            }
        },
        "issuers": [
            {
                "container_id": "b" * 64,
                "daemon_sha256": digest(docker.info()),
                "stopped_at": stamp(datetime.now(UTC)),
                "running": False,
                "restart_policy": "no",
                "issuance_disabled": True,
            }
        ],
    }
    for row in records:
        note(case.client, row, tag=TAG, title=record_title(row))
    approved = activation.publish_import(
        case.client,
        vault=case.client.vault,
        approved=mapping,
        spool=tmp_path / "import",
        docker=cast(Docker, docker),
    )
    case.config = dataclasses.replace(
        case.config,
        migration_sha256=approved,
        generations={
            **case.config.generations,
            **({} if retired else {generation_id: {"cleanup": expired}}),
        },
    )
    accesses: list[str] = []

    def providers(bootstrap: LeaseBootstrap, **_kwargs: object) -> dict[ProviderKind, Provider]:
        if bootstrap.generation.generation_id == generation_id:
            accesses.append(generation_id)
            assert not completed, "terminal evidence must not reopen expired provider access"
            return {kind: UnavailableProvider(kind) for kind in PROVIDERS}
        return dict(case.providers[bootstrap.generation.role])

    monkeypatch.setattr(LeaseBootstrap, "providers", providers)
    output = stage(case, monkeypatch)
    if completed:
        assert activation.activate(output)["status"] == "ready"
        result = cleanup.sweep_legacy(case.config, case.client, root=tmp_path / "sweep")
        assert result["status"] == "ready"
        assert result["results"] == [
            {
                "intent_sha256": intent.sha256,
                "status": expected_status,
                "negative_authentication": negative,
            }
        ]
        full = cleanup.sweep_leases(
            case.config,
            case.inventory,
            root=tmp_path / "lease-sweep",
            actor="watchdog",
            connect_client=case.client,
        )
        assert cast(dict[str, object], full["legacy"])["status"] == "ready"
        assert not accesses
        # Later contradictory evidence must invalidate the preserved outcome.
        conflict = event(
            "created",
            intent.run_id,
            {"intent_sha256": intent.sha256, "credential_id": "conflicting-credential"},
        )
        note(case.client, conflict, tag=TAG, title=record_title(conflict))
    with pytest.raises(LifecycleError):
        activation.activate(output)
    if completed:
        with pytest.raises(LifecycleError):
            cleanup.sweep_legacy(case.config, case.client, root=tmp_path / "conflict-sweep")
    else:
        result = cleanup.sweep_legacy(case.config, case.client, root=tmp_path / "pending-sweep")
        assert result["status"] == "unresolved"


@pytest.mark.parametrize("readback_matches", [False, True])
def test_completed_live_expiry_readback_is_durable_after_authority_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, readback_matches: bool
) -> None:
    case = Case(tmp_path, monkeypatch)
    update = expiry_update(tmp_path)
    plan = cast(dict[str, object], update["plan"])
    plan["targets_sha256"] = digest(dataclasses.asdict(case.config.targets))
    update.update(
        plan_sha256=digest(plan), generation_id=case.config.active_generation, result_files={}
    )
    del update["result_contents"]
    case.mapping.update(
        expiry_updates=[update],
        issuers=[
            {
                "container_id": "b" * 64,
                "daemon_sha256": "c" * 64,
                "stopped_at": stamp(datetime.now(UTC)),
                "running": False,
                "restart_policy": "no",
                "issuance_disabled": True,
            }
        ],
    )
    case.config = dataclasses.replace(case.config, migration_sha256=digest(case.mapping))
    note(case.client, case.mapping, tag=MIGRATION_TAG, title="m3-11-import-" + digest(case.mapping))
    rows = cast(dict[str, dict[str, object]], plan["providers"])
    clients: dict[ProviderKind, Provider] = {}
    for kind, row in rows.items():
        api = Api(ORIGIN, "SYNTHETIC-EXPIRY-READBACK")
        api.credential_sha256 = str(row["authority_sha256"])
        provider = Cloudflare(
            api, account=case.config.targets.account_id if kind == "cloudflare-account" else None
        )
        clients[provider.kind] = provider
    requests: list[str] = []

    def readback(api: Api, method: str, path: str, body: object = None) -> Response:
        assert method == "GET" and body is None
        row = next(
            value for value in rows.values() if value["authority_sha256"] == api.credential_sha256
        )
        assert path.endswith("/" + str(row["id"]))
        requests.append(path)
        value = cast(dict[str, object], row["after" if readback_matches else "before"])
        return Response(200, {"success": True, "result": {**value, "id": row["id"]}})

    monkeypatch.setattr(Api, "request", readback)
    monkeypatch.setattr(LeaseBootstrap, "providers", lambda *_args, **_kwargs: clients)
    first = cleanup.sweep_legacy(case.config, case.client, root=tmp_path / "first")
    assert first["status"] == ("ready" if readback_matches else "unresolved")
    assert requests

    def unavailable(*_args: object, **_kwargs: object) -> dict[ProviderKind, Provider]:
        assert not readback_matches, "completed update must not require retired authority"
        return {}

    monkeypatch.setattr(LeaseBootstrap, "providers", unavailable)
    second = cleanup.sweep_legacy(case.config, case.client, root=tmp_path / "after-retirement")
    assert second["status"] == first["status"]
    if readback_matches:
        proof = cleanup_expiry.readback_proof(update)
        cast(dict[str, object], proof["readbacks"])["cloudflare-user"] = {}
        conflict = event("heartbeat", case.config.active_generation, proof)
        note(case.client, conflict, tag=TAG, title=record_title(conflict))
        with pytest.raises(LifecycleError, match="readback conflicts"):
            cleanup.sweep_legacy(case.config, case.client, root=tmp_path / "conflict")


def test_full_sweep_preserves_original_authority_during_staged_handover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    deployed = case.config
    updated = replacement(case, monkeypatch)
    result = handover(deployed, updated, case.inventory, root=tmp_path / "handover")
    assert result["results"] == [{"lease_id": case.manifest.lease_id, "status": "transferred"}]
    case.lifecycle.request_close("finish")
    result = cleanup.sweep_leases(
        deployed,
        case.inventory,
        root=case.state.directory.parent,
        actor="watchdog",
        connect_client=case.client,
    )
    assert result["status"] == "ready"
    assert all(row["status"] == "closed" for row in cast(list[dict[str, object]], result["leases"]))
    assert all(not provider.items for provider in case.providers["cleanup"].values())
