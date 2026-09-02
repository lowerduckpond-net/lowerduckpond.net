"""Bounded running-Caddy verification and configuration-only reload."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import socket
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ENVIRONMENT_NAME,
    MAX_CADDY_BINARY_BYTES,
    MAX_CADDY_CONFIGURATION_BYTES,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.caddy_routes import CADDY_ADMIN_SOCKET

_MAXIMUM_ADMIN_RESPONSE_BYTES: Final = MAX_CADDY_CONFIGURATION_BYTES + 64 * 1024
_ADMIN_TIMEOUT_SECONDS: Final = 5

MainPidSource = Callable[[], str]
ExecutableDigestSource = Callable[[int], str]
ConfigurationSource = Callable[[], bytes]
GenerationVerifier = Callable[[PinnedCaddyGeneration], None]
GenerationLoader = Callable[[PinnedCaddyGeneration], None]
AdminRequester = Callable[[bytes], bytes]


class CaddyAdminError(RuntimeError):
    """The running Caddy process could not prove one exact configuration state."""


def verify_running_caddy(
    generation: PinnedCaddyGeneration,
    *,
    main_pid_source: MainPidSource | None = None,
    executable_digest_source: ExecutableDigestSource | None = None,
    configuration_source: ConfigurationSource | None = None,
) -> None:
    """Match the running executable and loaded config to one pinned generation."""

    if type(generation) is not PinnedCaddyGeneration:
        raise TypeError("running Caddy verification requires one pinned generation")
    expected = {item.name: item.sha256 for item in generation.manifest.files}
    raw_pid = (main_pid_source or _systemd_main_pid)()
    if not raw_pid.isascii() or not raw_pid.isdecimal() or int(raw_pid) <= 1:
        raise CaddyAdminError("Caddy main PID is invalid")
    process_digest = (executable_digest_source or _running_executable_digest)(int(raw_pid))
    if not secrets.compare_digest(process_digest, expected[CADDY_BINARY_NAME]):
        raise CaddyAdminError("running Caddy binary disagrees with its generation")
    response = (configuration_source or _read_caddy_admin_configuration)()
    configuration = decode_json_object(response, maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES)
    configuration_digest = hashlib.sha256(canonical_json_bytes(configuration)).hexdigest()
    if not secrets.compare_digest(
        configuration_digest,
        expected[CADDY_CONFIGURATION_NAME],
    ):
        raise CaddyAdminError("running Caddy configuration disagrees with its generation")


def load_caddy_configuration(
    generation: PinnedCaddyGeneration,
    *,
    requester: AdminRequester | None = None,
) -> None:
    """Send the exact pinned canonical configuration to Caddy's fixed admin socket."""

    if type(generation) is not PinnedCaddyGeneration:
        raise TypeError("Caddy configuration load requires one pinned generation")
    descriptor = generation.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
    try:
        configuration = os.pread(descriptor, MAX_CADDY_CONFIGURATION_BYTES + 1, 0)
    finally:
        os.close(descriptor)
    decoded = decode_json_object(
        configuration,
        maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES,
    )
    if canonical_json_bytes(decoded) != configuration:
        raise CaddyAdminError("Caddy configuration is not canonical")
    request = (
        b"POST /load HTTP/1.0\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(configuration)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + configuration
    )
    _response_body((requester or _send_admin_request)(request), maximum_bytes=64 * 1024)


def reload_caddy_generation(
    previous: PinnedCaddyGeneration,
    candidate: PinnedCaddyGeneration,
    *,
    verifier: GenerationVerifier = verify_running_caddy,
    loader: GenerationLoader = load_caddy_configuration,
) -> None:
    """Verify old, load new, then verify new for a config-only transition."""

    if type(previous) is not PinnedCaddyGeneration or type(candidate) is not PinnedCaddyGeneration:
        raise TypeError("Caddy reload requires two pinned generations")
    if previous.manifest.generation_id == candidate.manifest.generation_id:
        raise CaddyAdminError("Caddy reload generations must be distinct")
    previous_files = {item.name: item for item in previous.manifest.files}
    candidate_files = {item.name: item for item in candidate.manifest.files}
    for name in (CADDY_BINARY_NAME, CADDY_ENVIRONMENT_NAME):
        if previous_files[name] != candidate_files[name]:
            raise CaddyAdminError("Caddy reload attempted to change a host input")
    verifier(previous)
    loader(candidate)
    verifier(candidate)


def _systemd_main_pid() -> str:
    return subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=MainPID",
            "--value",
            "caddy.service",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=_ADMIN_TIMEOUT_SECONDS,
    ).stdout.strip()


def _read_caddy_admin_configuration() -> bytes:
    request = b"GET /config/ HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    return _response_body(
        _send_admin_request(request),
        maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES,
    )


def _send_admin_request(request: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(_ADMIN_TIMEOUT_SECONDS)
        client.connect(CADDY_ADMIN_SOCKET)
        client.sendall(request)
        chunks: list[bytes] = []
        total = 0
        while chunk := client.recv(64 * 1024):
            total += len(chunk)
            if total > _MAXIMUM_ADMIN_RESPONSE_BYTES:
                raise CaddyAdminError("Caddy admin response exceeds its bound")
            chunks.append(chunk)
    return b"".join(chunks)


def _response_body(response: bytes, *, maximum_bytes: int) -> bytes:
    if len(response) > _MAXIMUM_ADMIN_RESPONSE_BYTES:
        raise CaddyAdminError("Caddy admin response exceeds its bound")
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator or re.match(rb"HTTP/1\.[01] 200(?: |\r\n)", head) is None:
        raise CaddyAdminError("Caddy admin response is invalid")
    if len(body) > maximum_bytes:
        raise CaddyAdminError("Caddy admin response body exceeds its bound")
    return body


def _running_executable_digest(pid: int) -> str:
    path = Path(f"/proc/{pid}/exe")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or not 0 < before.st_size <= MAX_CADDY_BINARY_BYTES
        ):
            raise CaddyAdminError("running Caddy executable metadata is unsafe")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CaddyAdminError("running Caddy executable changed while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or _stat_snapshot(os.fstat(descriptor)) != _stat_snapshot(before):
            raise CaddyAdminError("running Caddy executable changed while reading")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _stat_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
