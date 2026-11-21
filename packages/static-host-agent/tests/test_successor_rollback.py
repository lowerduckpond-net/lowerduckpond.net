"""Filesystem effects, original selector recovery, and history fencing for P3."""

from __future__ import annotations

import os
from contextlib import nullcontext
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent import successor_rollback as rollback
from lowerduckpond_static_host_agent.caddy_admin import CaddyAdminError
from lowerduckpond_static_host_agent.platform_launch import INTENT, LAUNCH
from lowerduckpond_static_host_agent.repository import StateRepository

from scripts.m3_12_contracts import ValidationError, encode

PRIOR = "00000000-0000-7000-8000-000000000001"
CURRENT = "00000000-0000-7000-8000-000000000002"


def private(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.write_bytes(data)
    path.chmod(mode)


class CallerLostError(Exception):
    """The process lost its caller after publishing the requested selector."""


def test_physical_rollback_and_resume_keep_the_original_launch(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "authorization").mkdir(mode=0o700)
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)
    for name in (
        "locks",
        "platform",
        "tenants",
        "intents",
        "audit",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
    ):
        (state / name).mkdir(mode=0o700)
    for name in ("publication.lock", "tenant-state.lock"):
        private(state / "locks" / name, b"")
    config = authority / "publication.json"
    private(
        config,
        encode({"format": rollback.GATE_FORMAT, "static_publication_enabled": True}),
        mode=0o400,
    )
    launch = state.joinpath(*LAUNCH)
    intent = authority.joinpath(*INTENT)
    private(launch, b"original-launch\n")
    private(intent, b"original-intent\n")

    generations = {
        PRIOR: {"generation": PRIOR, "manifestSha256": "a" * 64},
        CURRENT: {"generation": CURRENT, "manifestSha256": "b" * 64},
    }
    selected = PRIOR
    running = PRIOR
    restart_calls = 0

    def open_generation(identifier: str) -> MagicMock:
        generation = MagicMock(manifest=SimpleNamespace(generation_id=identifier))
        generation.__enter__.return_value = generation
        return generation

    def select(identifier: str) -> None:
        nonlocal selected
        selected = identifier

    def verify(generation: SimpleNamespace) -> None:
        if running != generation.manifest.generation_id:
            raise CaddyAdminError("generation not loaded")

    def restart() -> None:
        nonlocal running, restart_calls
        restart_calls += 1
        running = selected
        if restart_calls == 1:
            raise CallerLostError

    runtime = MagicMock()
    runtime.using_held_publication_lock.return_value = nullcontext()
    runtime.read_active.side_effect = lambda: selected
    runtime.open_verified_generation.side_effect = open_generation
    runtime.select_active.side_effect = select
    monkeypatch.setattr(rollback, "verify_running_caddy", verify)
    monkeypatch.setattr(
        rollback,
        "_generation",
        lambda generation, **_: generations[generation.manifest.generation_id],
    )
    engine = rollback.PhysicalRollback(
        state,
        authority,
        config,
        runtime,
        require_lease=lambda: None,
        restart=restart,
        owner=os.geteuid(),
    )
    predecessor = engine.pin_predecessor()
    selected = running = CURRENT
    decision = {
        "action": "restore-platform-only",
        "precedingGenerationSha256": predecessor["manifestSha256"],
        "retainedLaunchSha256": sha256(launch.read_bytes()).hexdigest(),
        "retainedIntentSha256": sha256(intent.read_bytes()).hexdigest(),
    }
    with pytest.raises(CallerLostError):
        engine.reconcile(decision)
    assert selected == PRIOR
    assert engine.gate() is False
    with pytest.raises(ValidationError, match="successor-publication-fenced"):
        rollback.require_unfenced_publication(authority)

    premature = MagicMock()
    with pytest.raises(ValidationError, match="rollback-not-reconciled"):
        engine.reconcile({**decision, "action": "reactivate-same-policy"}, authorize=premature)
    premature.assert_not_called()

    restored = engine.reconcile(decision)
    assert restart_calls == 1
    runtime.select_active.assert_called_once_with(PRIOR)
    runtime.sync_active.assert_called_once_with(PRIOR)
    assert restored["desired"] == predecessor
    assert restored["source"] == generations[CURRENT]
    readmitted = engine.reconcile({**decision, "action": "reactivate-same-policy"})
    assert readmitted["desired"] == generations[CURRENT]
    assert selected == running == CURRENT
    assert engine.gate() is True
    assert launch.read_bytes() == b"original-launch\n"
    assert intent.read_bytes() == b"original-intent\n"
    rollback.require_unfenced_publication(authority)

    fixture = (
        Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted/audit-entry.json"
    )
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        repository.append_audit(decode_json_object(fixture.read_bytes()))
    with pytest.raises(ValidationError, match="rollback-history-or-work"):
        engine.reconcile(decision)
    assert engine.gate() is True
    assert selected == CURRENT
