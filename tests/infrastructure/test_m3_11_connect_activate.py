"""Cutover preflight verifies preserved obligations and staged configuration bytes."""

from __future__ import annotations

import calendar
import dataclasses
import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import connect_activate as activation
from scripts.m3_11_unattended import setup
from scripts.m3_11_unattended.config import LeaseBootstrap, LeaseConfiguration
from scripts.m3_11_unattended.connect_renewal import handover
from scripts.m3_11_unattended.connect_setup import prepare
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
