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
from lowerduckpond_static_host_agent.caddy_bootstrap import ensure_platform_generation
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_GENERATION_ROOT_MODE,
    CaddyBinarySource,
    CaddyGenerationStore,
)
from lowerduckpond_static_host_agent.caddy_runtime import (
    CADDY_RUNTIME_ROOT_MODE,
    CaddyRuntime,
)
from lowerduckpond_static_host_agent.platform_launch import INTENT, LAUNCH
from lowerduckpond_static_host_agent.repository import StateRepository

from config.ansible.molecule.m3_8.tests.m3_12_caddy_witness import select_peer
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


def test_installed_witness_keeps_two_compatible_real_selectors(tmp_path: Path) -> None:
    owner, group = os.geteuid(), os.getegid()
    root = tmp_path / "caddy"
    root.mkdir()
    root.chmod(CADDY_RUNTIME_ROOT_MODE)
    generations = root / "generations"
    generations.mkdir()
    generations.chmod(CADDY_GENERATION_ROOT_MODE)
    lock = tmp_path / "publication.lock"
    lock.touch(mode=0o600)
    binary = tmp_path / "caddy-binary"
    private(binary, Path("/usr/bin/true").read_bytes(), mode=0o755)

    with (
        CaddyRuntime.open(
            root,
            lock,
            expected_owner=owner,
            expected_group=group,
            validation_uid=owner,
            validation_gid=group,
            expected_binary_sha256=sha256(binary.read_bytes()).hexdigest(),
            candidate_validator=lambda _, __: None,
        ) as runtime,
        CaddyGenerationStore.open(generations, expected_owner=owner, expected_group=group) as store,
    ):
        assert ensure_platform_generation(
            runtime,
            store,
            generation_id=PRIOR,
            binary=CaddyBinarySource(binary, owner=owner, group=group),
            environment=b"CLOUDFLARE_API_TOKEN=fixture-placeholder\n",
            origin_pull_ca_der=(b"fixture-ca",),
            origin_pull_required=True,
        )
        with runtime.locked():
            with runtime.open_verified_generation(PRIOR) as original:
                predecessor = rollback._generation(original, preceding=True)
                original_manifest = original.manifest.to_bytes()
                original_files = original.manifest.files
            assert select_peer(runtime, predecessor, CURRENT)
            assert runtime.read_active() == CURRENT
            with runtime.open_verified_generation(CURRENT) as candidate:
                assert candidate.manifest.files == original_files
                assert candidate.manifest.to_bytes() != original_manifest
            assert not select_peer(runtime, predecessor, CURRENT)
            runtime.select_active(PRIOR)
            assert runtime.read_active() == PRIOR
            with runtime.open_verified_generation(PRIOR) as restored:
                assert restored.manifest.to_bytes() == original_manifest
            runtime.select_active(CURRENT)
            assert runtime.read_active() == CURRENT
            assert store.list_verified() == (PRIOR, CURRENT)
