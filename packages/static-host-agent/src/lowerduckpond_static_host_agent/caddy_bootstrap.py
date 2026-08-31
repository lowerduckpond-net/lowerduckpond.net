"""One-time production-dark Caddy generation bootstrap."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Sequence
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

_READ_CHUNK_BYTES: Final = 64 * 1024


def ensure_platform_generation(  # noqa: PLR0913
    runtime: CaddyRuntime,
    store: CaddyGenerationStore,
    *,
    generation_id: str,
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
) -> bool:
    """Publish and select the exact platform-only generation only when needed."""

    payload = _platform_payload(binary, environment, origin_pull_ca_der)
    with runtime.locked():
        if _active_matches(runtime, payload):
            return False
        store.publish(generation_id, payload)
        runtime.select_active(generation_id)
    return True


def platform_generation_matches(
    runtime: CaddyRuntime,
    *,
    binary: CaddyBinarySource,
    environment: bytes,
    origin_pull_ca_der: tuple[bytes, ...],
) -> bool:
    """Report whether active is the exact desired platform-only generation."""

    payload = _platform_payload(binary, environment, origin_pull_ca_der)
    with runtime.locked():
        return _active_matches(runtime, payload)


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
) -> CaddyGenerationPayload:
    routes = build_platform_only_caddy_routes(origin_pull_ca_der=origin_pull_ca_der)
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
