from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import lowerduckpond_static_host_agent.caddy_generation as caddy_generation_module
import lowerduckpond_static_host_agent.capacity as capacity_module
import pytest
from lowerduckpond_static_host_agent import (
    CADDY_ACTIVE_REFERENCE_MODE,
    CADDY_GENERATION_ROOT_MODE,
    CADDY_PUBLICATION_LOCK_MODE,
    CADDY_RUNTIME_ROOT_MODE,
    CaddyBinarySource,
    CaddyGenerationStore,
    CaddyRuntime,
    CaddyStartPhase,
    CaddyStartupStore,
    FilesystemCapacity,
    PlatformGenerationState,
    ensure_platform_generation,
    platform_generation_state,
    require_exact_file,
)

_GENERATION_A = "0198d17f-6f4a-7000-8000-000000000001"
_GENERATION_B = "0198d17f-6f4a-7000-8000-000000000002"


def _accept_candidate(_generation: object, _environment: object) -> None:
    pass


@pytest.fixture(autouse=True)
def _provide_inode_capacity_on_the_test_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    measure = capacity_module.measure_filesystem_capacity_descriptor

    def measure_with_inode_capacity(descriptor: int) -> FilesystemCapacity:
        filesystem = measure(descriptor)
        if filesystem.total_inodes == 0:
            return replace(
                filesystem,
                total_inodes=1_000_000,
                available_inodes=1_000_000,
            )
        return filesystem

    monkeypatch.setattr(
        caddy_generation_module,
        "measure_filesystem_capacity_descriptor",
        measure_with_inode_capacity,
    )


def test_bootstrap_selects_once_and_is_idempotent_for_exact_inputs(tmp_path: Path) -> None:
    owner = os.geteuid()
    group = os.getegid()
    root = tmp_path / "runtime"
    generations = root / "generations"
    intents = root / "intents"
    root.mkdir(mode=CADDY_RUNTIME_ROOT_MODE)
    generations.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    intents.mkdir(mode=0o700)
    lock = tmp_path / "publication.lock"
    lock.write_bytes(b"")
    lock.chmod(CADDY_PUBLICATION_LOCK_MODE)
    binary = tmp_path / "caddy"
    binary.write_bytes(Path("/usr/bin/true").read_bytes())
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    source = CaddyBinarySource(binary, owner=owner, group=group)
    environment = b"CLOUDFLARE_API_TOKEN=real-token\n"

    with (
        CaddyRuntime.open(
            root,
            lock,
            expected_owner=owner,
            expected_group=group,
            validation_uid=owner,
            validation_gid=group,
            expected_binary_sha256=digest,
            candidate_validator=_accept_candidate,
        ) as runtime,
        CaddyGenerationStore.open(
            generations,
            expected_owner=owner,
            expected_group=group,
        ) as store,
        CaddyStartupStore.open(intents, expected_owner=owner) as startup,
    ):
        assert ensure_platform_generation(
            runtime,
            store,
            generation_id=_GENERATION_A,
            binary=source,
            environment=environment,
            origin_pull_ca_der=(b"ca-a",),
            startup=startup,
        )
        assert not ensure_platform_generation(
            runtime,
            store,
            generation_id=_GENERATION_B,
            binary=source,
            environment=environment,
            origin_pull_ca_der=(b"ca-a",),
            startup=startup,
        )
        with runtime.locked():
            assert runtime.read_active() == _GENERATION_A

    assert sorted(path.name for path in generations.iterdir()) == [_GENERATION_A]
    assert (root / "active").stat().st_mode & 0o777 == CADDY_ACTIVE_REFERENCE_MODE


def test_bootstrap_selects_a_new_generation_when_bound_trust_changes(tmp_path: Path) -> None:
    owner = os.geteuid()
    group = os.getegid()
    root = tmp_path / "runtime"
    generations = root / "generations"
    intents = root / "intents"
    root.mkdir(mode=CADDY_RUNTIME_ROOT_MODE)
    generations.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    intents.mkdir(mode=0o700)
    lock = tmp_path / "publication.lock"
    lock.write_bytes(b"")
    lock.chmod(CADDY_PUBLICATION_LOCK_MODE)
    binary = tmp_path / "caddy"
    binary.write_bytes(Path("/usr/bin/true").read_bytes())
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    source = CaddyBinarySource(binary, owner=owner, group=group)

    with (
        CaddyRuntime.open(
            root,
            lock,
            expected_owner=owner,
            expected_group=group,
            validation_uid=owner,
            validation_gid=group,
            expected_binary_sha256=digest,
            candidate_validator=_accept_candidate,
        ) as runtime,
        CaddyGenerationStore.open(
            generations,
            expected_owner=owner,
            expected_group=group,
        ) as store,
        CaddyStartupStore.open(intents, expected_owner=owner) as startup,
    ):
        for generation_id, certificate in (
            (_GENERATION_A, b"ca-a"),
            (_GENERATION_B, b"ca-b"),
        ):
            assert ensure_platform_generation(
                runtime,
                store,
                generation_id=generation_id,
                binary=source,
                environment=b"CLOUDFLARE_API_TOKEN=real-token\n",
                origin_pull_ca_der=(certificate,),
                startup=startup,
            )
        with runtime.locked():
            assert runtime.read_active() == _GENERATION_B
        intent = startup.read()
        assert intent is not None
        assert intent.phase is CaddyStartPhase.RESTART_REQUIRED
        assert intent.candidate.generation_id == _GENERATION_B
        assert intent.previous is not None
        assert intent.previous.generation_id == _GENERATION_A
        assert not startup.inventory_is_empty()
        assert (
            platform_generation_state(
                runtime,
                store,
                binary=source,
                environment=b"CLOUDFLARE_API_TOKEN=real-token\n",
                origin_pull_ca_der=(b"ca-b",),
                startup=startup,
            )
            is PlatformGenerationState.PENDING
        )

    assert sorted(path.name for path in generations.iterdir()) == [
        _GENERATION_A,
        _GENERATION_B,
    ]


def test_exact_bootstrap_input_rejects_unsafe_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"value")
    source.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(source)

    with pytest.raises(RuntimeError, match="metadata is unsafe"):
        require_exact_file(
            source,
            owner=os.geteuid(),
            group=os.getegid(),
            modes=(0o400,),
            maximum_bytes=16,
        )
    with pytest.raises(OSError):
        require_exact_file(
            alias,
            owner=os.geteuid(),
            group=os.getegid(),
            modes=(0o600,),
            maximum_bytes=16,
        )
