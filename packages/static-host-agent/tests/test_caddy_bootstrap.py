from __future__ import annotations

import hashlib
import json
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
from lowerduckpond_static_host_agent.caddy_bootstrap import (
    empty_tenant_generation_matches_under_lock,
)
from lowerduckpond_static_host_agent.caddy_generation import CaddyGenerationPayload
from lowerduckpond_static_host_agent.caddy_routes import build_tenant_caddy_routes

_GENERATION_A = "0198d17f-6f4a-7000-8000-000000000001"
_GENERATION_B = "0198d17f-6f4a-7000-8000-000000000002"


@pytest.mark.parametrize("drift", ["none", "environment", "namespace", "origin-pull"])
def test_last_tenant_generation_remains_bound_to_every_installed_input(
    tmp_path: Path, drift: str
) -> None:
    owner, group = os.geteuid(), os.getegid()
    root = tmp_path / "runtime"
    root.mkdir(mode=CADDY_RUNTIME_ROOT_MODE)
    generations = root / "generations"
    generations.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    lock = tmp_path / "publication.lock"
    lock.touch(mode=CADDY_PUBLICATION_LOCK_MODE)
    binary = tmp_path / "caddy"
    binary.write_bytes(Path("/usr/bin/true").read_bytes())
    binary.chmod(0o755)
    source = CaddyBinarySource(binary, owner=owner, group=group)
    environment = b"CLOUDFLARE_API_TOKEN=fixture\n"
    fixture = (
        Path(__file__).parents[3]
        / "tests/static-publication/fixtures/accepted/platform-namespace.json"
    )
    namespace = json.loads(fixture.read_text())
    routes = build_tenant_caddy_routes(
        platform_namespace=namespace,
        tenants=(),
        runtime_generation_id=_GENERATION_B,
        origin_pull_ca_der=(b"ca-a",),
        origin_pull_required=True,
    )
    with (
        CaddyRuntime.open(
            root,
            lock,
            expected_owner=owner,
            expected_group=group,
            validation_uid=owner,
            validation_gid=group,
            expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            candidate_validator=_accept_candidate,
        ) as runtime,
        CaddyGenerationStore.open(generations, expected_owner=owner, expected_group=group) as store,
        runtime.locked(),
    ):
        store.publish(
            _GENERATION_B,
            CaddyGenerationPayload(
                binary=source,
                environment=environment,
                configuration=routes.configuration,
                route_metadata=routes.route_metadata,
            ),
        )
        runtime.select_active(_GENERATION_B)
        if drift == "environment":
            environment = b"CLOUDFLARE_API_TOKEN=other\n"
        if drift == "namespace":
            namespace["initializedAt"] = "2026-08-30T12:00:00Z"
        assert empty_tenant_generation_matches_under_lock(
            runtime,
            platform_namespace=namespace,
            binary=source,
            environment=environment,
            origin_pull_ca_der=(b"ca-a",),
            origin_pull_required=drift != "origin-pull",
        ) is (drift == "none")


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
            origin_pull_required=True,
            startup=startup,
        )
        assert not ensure_platform_generation(
            runtime,
            store,
            generation_id=_GENERATION_B,
            binary=source,
            environment=environment,
            origin_pull_ca_der=(b"ca-a",),
            origin_pull_required=True,
            startup=startup,
        )
        with runtime.locked():
            assert runtime.read_active() == _GENERATION_A

    assert sorted(path.name for path in generations.iterdir()) == [_GENERATION_A]
    assert (root / "active").stat().st_mode & 0o777 == CADDY_ACTIVE_REFERENCE_MODE


def test_bootstrap_selects_a_new_generation_when_bound_origin_pull_policy_changes(
    tmp_path: Path,
) -> None:
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
        for generation_id, certificate, required in (
            (_GENERATION_A, b"ca-a", False),
            (_GENERATION_B, b"ca-a", True),
        ):
            assert ensure_platform_generation(
                runtime,
                store,
                generation_id=generation_id,
                binary=source,
                environment=b"CLOUDFLARE_API_TOKEN=real-token\n",
                origin_pull_ca_der=(certificate,),
                origin_pull_required=required,
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
                origin_pull_ca_der=(b"ca-a",),
                origin_pull_required=True,
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
