"""One-time production-dark Caddy generation bootstrap."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_ROUTE_METADATA_NAME,
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.caddy_routes import build_platform_only_caddy_routes
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartIntent,
    CaddyStartMode,
    CaddyStartPhase,
    CaddyStartupError,
    CaddyStartupStore,
    start_target,
)

_READ_CHUNK_BYTES: Final = 64 * 1024


class PlatformGenerationState(StrEnum):
    """Read-only disposition of the complete platform generation."""

    CHANGED = "changed"
    PENDING = "pending"
    UNCHANGED = "unchanged"


def ensure_platform_generation(  # noqa: PLR0913
    runtime: CaddyRuntime,
    store: CaddyGenerationStore,
    *,
    generation_id: str,
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
    origin_pull_required: bool,
    startup: CaddyStartupStore | None = None,
) -> bool:
    """Publish and select the exact platform-only generation only when needed."""

    payload = _platform_payload(
        binary,
        environment,
        origin_pull_ca_der,
        origin_pull_required=origin_pull_required,
    )
    transaction_intent = None
    with runtime.locked():
        if startup is not None:
            startup.reconcile_temporaries()
        try:
            previous = runtime.read_active()
        except FileNotFoundError:
            previous = None
        if startup is not None and (intent := startup.read()) is not None:
            active = _require_resumable_transaction(runtime, store, payload, intent)
            if intent.previous is None:  # pragma: no cover - validation proves this
                raise CaddyStartupError("bootstrap intent has no preceding generation")
            if active == intent.previous.generation_id:
                runtime.select_active(intent.candidate.generation_id)
                active = intent.candidate.generation_id
            if active != intent.candidate.generation_id:
                raise CaddyStartupError("active generation disagrees with bootstrap intent")
            if intent.phase is CaddyStartPhase.CANDIDATE_PREPARED:
                startup.mark_restart_required(intent)
            store.prune_unreferenced(
                (intent.previous.generation_id, intent.candidate.generation_id)
            )
            return True
        retained = _prune_bootstrap_generations(store, previous)
        if _active_matches(runtime, payload):
            return False
        store.admit_candidate(payload, retained)
        manifest = store.publish(generation_id, payload)
        if startup is not None and previous is not None:
            with store.open_verified(previous) as preceding:
                transaction_intent = startup.begin_transaction(
                    candidate=start_target(generation_id, manifest.to_bytes()),
                    previous=start_target(previous, preceding.manifest.to_bytes()),
                )
        runtime.select_active(generation_id)
        if startup is not None and previous is not None:
            if transaction_intent is None:  # pragma: no cover - branch proves this
                raise CaddyStartupError("bootstrap failed to create startup intent")
            startup.mark_restart_required(transaction_intent)
        selected = (generation_id,) if previous is None else (generation_id, previous)
        store.prune_unreferenced(selected)
    return True


def platform_generation_matches(  # noqa: PLR0913
    runtime: CaddyRuntime,
    store: CaddyGenerationStore,
    *,
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
    origin_pull_required: bool,
    startup: CaddyStartupStore | None = None,
) -> bool:
    """Report whether active is the exact desired platform-only generation."""

    return (
        platform_generation_state(
            runtime,
            store,
            binary=binary,
            environment=environment,
            origin_pull_ca_der=origin_pull_ca_der,
            origin_pull_required=origin_pull_required,
            startup=startup,
        )
        is PlatformGenerationState.UNCHANGED
    )


def platform_generation_state(  # noqa: PLR0913
    runtime: CaddyRuntime,
    store: CaddyGenerationStore,
    *,
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
    origin_pull_required: bool,
    startup: CaddyStartupStore | None = None,
) -> PlatformGenerationState:
    """Classify exact current, safely resumable, and ordinary changed state."""

    with runtime.locked():
        return platform_generation_state_under_lock(
            runtime,
            store,
            binary=binary,
            environment=environment,
            origin_pull_ca_der=origin_pull_ca_der,
            origin_pull_required=origin_pull_required,
            startup=startup,
        )


def platform_generation_state_under_lock(  # noqa: PLR0913
    runtime: CaddyRuntime,
    store: CaddyGenerationStore,
    *,
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
    origin_pull_required: bool,
    startup: CaddyStartupStore | None = None,
) -> PlatformGenerationState:
    """Classify the platform generation while the caller holds publication."""

    payload = _platform_payload(
        binary,
        environment,
        origin_pull_ca_der,
        origin_pull_required=origin_pull_required,
    )
    if startup is not None and not startup.inventory_is_empty():
        intent = startup.read()
        if intent is None:
            raise CaddyStartupError("startup intent namespace is not resumable")
        _require_resumable_transaction(runtime, store, payload, intent)
        return PlatformGenerationState.PENDING
    if not _active_matches(runtime, payload):
        return PlatformGenerationState.CHANGED
    return (
        PlatformGenerationState.UNCHANGED
        if store.bootstrap_retention_matches(runtime.read_active())
        else PlatformGenerationState.CHANGED
    )


def _require_resumable_transaction(
    runtime: CaddyRuntime,
    store: CaddyGenerationStore,
    payload: CaddyGenerationPayload,
    intent: CaddyStartIntent,
) -> str:
    if intent.mode is not CaddyStartMode.TRANSACTIONAL or intent.phase not in {
        CaddyStartPhase.CANDIDATE_PREPARED,
        CaddyStartPhase.RESTART_REQUIRED,
    }:
        raise CaddyStartupError("bootstrap encountered an unrelated startup intent")
    if intent.previous is None:  # pragma: no cover - intent validation proves this
        raise CaddyStartupError("bootstrap intent has no preceding generation")
    with store.open_verified(intent.candidate.generation_id) as candidate:
        if (
            start_target(
                intent.candidate.generation_id,
                candidate.manifest.to_bytes(),
            )
            != intent.candidate
        ):
            raise CaddyStartupError("startup candidate manifest disagrees with intent")
        if not _generation_matches(candidate, payload):
            raise CaddyStartupError("startup candidate disagrees with host inputs")
    with store.open_verified(intent.previous.generation_id) as previous:
        if (
            start_target(
                intent.previous.generation_id,
                previous.manifest.to_bytes(),
            )
            != intent.previous
        ):
            raise CaddyStartupError("startup predecessor manifest disagrees with intent")
    active = runtime.read_active()
    admitted = (
        {intent.previous.generation_id, intent.candidate.generation_id}
        if intent.phase is CaddyStartPhase.CANDIDATE_PREPARED
        else {intent.candidate.generation_id}
    )
    if active not in admitted:
        raise CaddyStartupError("active generation disagrees with bootstrap intent")
    identifiers = store.list_verified()
    if (
        intent.previous.generation_id not in identifiers
        or intent.candidate.generation_id not in identifiers
    ):
        raise CaddyStartupError("bootstrap transaction generation is absent")
    return active


def _prune_bootstrap_generations(
    store: CaddyGenerationStore,
    active: str | None,
) -> tuple[str, ...]:
    store.remove_abandoned_temporaries()
    identifiers = store.list_verified()
    if active is None:
        protected: tuple[str, ...] = ()
    else:
        if active not in identifiers:
            raise RuntimeError("active Caddy generation is absent")
        preceding = tuple(identifier for identifier in identifiers if identifier != active)[-1:]
        protected = (*preceding, active)
    store.prune_unreferenced(protected)
    return tuple(sorted(protected))


def digest_path(path: Path) -> str:
    """Hash one fixed regular-file source without loading it all into memory."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _generation_matches(
    generation: PinnedCaddyGeneration,
    payload: CaddyGenerationPayload,
) -> bool:
    expected = {
        CADDY_BINARY_NAME: digest_path(payload.binary.path),
        CADDY_ENVIRONMENT_NAME: hashlib.sha256(payload.environment).hexdigest(),
        CADDY_CONFIGURATION_NAME: hashlib.sha256(
            canonical_json_bytes(payload.configuration)
        ).hexdigest(),
        CADDY_ROUTE_METADATA_NAME: hashlib.sha256(
            canonical_json_bytes(payload.route_metadata)
        ).hexdigest(),
    }
    return {item.name: item.sha256 for item in generation.manifest.files} == expected


def _active_matches(runtime: CaddyRuntime, payload: CaddyGenerationPayload) -> bool:
    try:
        selected = runtime.open_active_verified()
    except FileNotFoundError:
        return False
    with selected.generation as active:
        return _generation_matches(active, payload)


def _platform_payload(
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
    *,
    origin_pull_required: bool,
) -> CaddyGenerationPayload:
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=origin_pull_ca_der,
        origin_pull_required=origin_pull_required,
    )
    return CaddyGenerationPayload(
        binary=binary,
        environment=environment,
        configuration=routes.configuration,
        route_metadata=routes.route_metadata,
    )


def require_exact_file(
    path: Path,
    *,
    owner: int,
    group: int,
    modes: Sequence[int],
    maximum_bytes: int,
) -> bytes:
    """Read one no-follow root input with exact ownership and bounded metadata."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or metadata.st_gid != group
            or (metadata.st_mode & 0o7777) not in modes
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise RuntimeError("Caddy bootstrap input metadata is unsafe")
        data = os.pread(descriptor, maximum_bytes + 1, 0)
        if len(data) != metadata.st_size:
            raise RuntimeError("Caddy bootstrap input changed while being read")
        return data
    finally:
        os.close(descriptor)
