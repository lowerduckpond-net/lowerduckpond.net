"""Attempt timeout and local admission failures do not consume a reusable lease."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import qualification_deadline
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import cleanup, watchdog, worker
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle
from scripts.m3_11_unattended.model import LifecycleError, digest, instant, stamp
from scripts.m3_11_unattended.state import RunState, replace_private

from .test_m3_11_connect_action import Case, attempt
from .test_m3_11_lease_configuration import document, mapping, reader_document
from .test_m3_11_unattended_controller import subject


@pytest.mark.parametrize("terminal_first", [False, True])
def test_timeout_during_drain_preserves_approved_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal_first: bool
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    directory, binding = attempt(case)
    state = RunState(directory)
    state.begin(binding)
    with case.state.use_lock():
        case.state.acquire_use(
            attempt_id=directory.name, binding_sha256=digest(binding), kind="attempt"
        )
    write_private(
        directory / "attempt-started.json",
        {"binding_sha256": digest(binding), "manifest_sha256": case.manifest.sha256},
    )
    started = read_private(directory / "attempt.json")
    started["started_at"] = stamp(
        datetime.now(UTC) - timedelta(seconds=qualification_deadline.LIVE_SECONDS + 1)
    )
    replace_private(directory / "attempt.json", started)
    docker = Mock()
    docker.owned.return_value = {"State": {"Running": True}}
    if terminal_first:
        state.finish_journey("failed", 124)
    watchdog.due_processes(directory.parent, cast(Docker, docker))
    assert not state.cancelled
    assert state.stopped is not terminal_first
    assert watchdog.prepare_lease_cleanup(directory.parent, cast(Docker, docker), case.inventory)
    assert not any(case.state.directory.glob("close-*.json"))
    if not terminal_first:
        state.finish_journey("interrupted", 124)
    assert watchdog.prepare_lease_cleanup(directory.parent, cast(Docker, docker), case.inventory)
    assert not any(case.state.directory.glob("close-*.json"))
    state.cancel()
    assert watchdog.prepare_lease_cleanup(directory.parent, cast(Docker, docker), case.inventory)
    assert "close-cancel" in case.lifecycle.records()


@pytest.mark.parametrize("remaining", [-1, 60])
def test_production_reader_needs_current_validity_not_child_lifetime(remaining: int) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    raw = document()
    mapping(raw["production"])["connect"] = reader_document(
        "production", now=now - timedelta(days=40) + timedelta(seconds=remaining)
    )
    config = LeaseConfiguration.parse(raw)
    if remaining < 0:
        with pytest.raises(LifecycleError, match="production reader expired"):
            config.require_issuance(now=now)
    else:
        config.require_issuance(now=now)


@pytest.mark.parametrize("fault", ["cutoff", "reader-expired-during-confirmation"])
def test_confirmation_rechecks_admission_before_first_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    (selected.lease_state.directory / "manifest.json").unlink()
    monkeypatch.setattr(case.inventory, "client", None, raising=False)
    monkeypatch.setattr(cleanup, "sweep_legacy", lambda *a, **k: {"status": "ready"})
    monkeypatch.setattr(worker, "require_clear", lambda *a, **k: None)
    monkeypatch.setattr(
        worker, "fixture_scopes", lambda *a: {i.role: i.scope for i in case.manifest.intents}
    )
    clock = instant(case.manifest.created_at)

    def prepare(*args: object, **kwargs: object) -> None:
        nonlocal clock
        if fault == "cutoff":
            clock = instant(selected.config.policy.start_before)

    def confirm(*args: object, **kwargs: object) -> None:
        raw = document()
        mapping(raw["production"])["connect"] = reader_document(
            "production", now=clock - timedelta(days=41)
        )
        selected.config = dataclasses.replace(
            selected.config, production=mapping(raw["production"])
        )

    monkeypatch.setattr(LeaseLifecycle, "prepare", prepare)
    monkeypatch.setattr(worker, "require_confirmation", confirm)
    monkeypatch.setattr(worker, "datetime", SimpleNamespace(now=lambda _zone: clock))
    with pytest.raises(LifecycleError, match=r"cutoff|production reader expired"):
        selected._provision()
    assert all(provider.creates == 0 for provider in case.providers.values())
