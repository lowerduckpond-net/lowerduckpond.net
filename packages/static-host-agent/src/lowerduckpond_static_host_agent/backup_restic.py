"""Bounded read-only Restic metadata, under the backup repository lock."""

from __future__ import annotations

import os
import re
import selectors
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

from lowerduckpond_static_contracts import ContractError, decode_json_object

from lowerduckpond_static_host_agent.backup_identity import (
    BackupIdentityError,
    RepositoryIdentity,
    canonical_locator,
)

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOTS = 16_384
METADATA_TIMEOUT_SECONDS = 300
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ENVIRONMENT = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_DEFAULT_REGION",
    "RESTIC_PASSWORD",
    "RESTIC_REPOSITORY",
    "RESTIC_CACHE_DIR",
)


def restic_metadata(
    arguments: tuple[str, ...], environment: Mapping[str, str], limit: int
) -> bytes:
    """Only fixed config/snapshot reads; never leak provider output into logs."""
    if arguments not in {("cat", "config"), ("snapshots", "--json")}:
        raise BackupIdentityError("unsupported repository discovery operation")
    with subprocess.Popen(  # noqa: S603 - fixed executable and allowlisted read-only arguments
        ("/usr/bin/restic", *arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            **{key: environment[key] for key in _ENVIRONMENT if key in environment},
        },
    ) as process:
        assert process.stdout is not None  # noqa: S101 - PIPE supplied above
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        output = bytearray()
        deadline = time.monotonic() + METADATA_TIMEOUT_SECONDS
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(descriptor, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise BackupIdentityError("repository discovery exceeded its deadline")
                    try:
                        chunk = os.read(descriptor, min(65536, limit + 1 - len(output)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > limit:
                        raise BackupIdentityError("repository discovery exceeds its output bound")
            if process.wait(timeout=max(0.0, deadline - time.monotonic())):
                raise BackupIdentityError("repository discovery failed")
            return bytes(output)
        except subprocess.TimeoutExpired as error:
            raise BackupIdentityError("repository discovery exceeded its deadline") from error
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def discover_repository(
    environment: Mapping[str, str],
) -> tuple[RepositoryIdentity, tuple[tuple[str, tuple[str, ...]], ...]]:
    try:
        config = decode_json_object(restic_metadata(("cat", "config"), environment, 16 * 1024))
        locator = environment["RESTIC_REPOSITORY"]
        if locator.startswith("/"):
            locator = str(Path(locator).resolve(strict=True))
        config_id = config["id"]
        if type(config_id) is not str:
            raise BackupIdentityError("invalid Restic repository identity")
        identity = RepositoryIdentity(
            config_id, environment["LOWERDUCKPOND_BACKUP_NODE_NAME"], canonical_locator(locator)
        )
        if type(config.get("version")) is not int or config["version"] != 2:  # noqa: PLR2004
            raise BackupIdentityError("unsupported Restic repository format")
        raw = restic_metadata(("snapshots", "--json"), environment, MAX_SNAPSHOT_BYTES)
        document = decode_json_object(
            b'{"snapshots":' + raw + b"}", maximum_bytes=MAX_SNAPSHOT_BYTES + 16
        )
        if set(document) != {"snapshots"}:
            raise BackupIdentityError("repository snapshot output is not one JSON array")
        entries = document["snapshots"]
        if type(entries) is not list or len(entries) > MAX_SNAPSHOTS:
            raise BackupIdentityError("repository snapshot inventory exceeds its bound")
        snapshots: list[tuple[str, tuple[str, ...]]] = []
        seen: set[str] = set()
        for entry in entries:
            if type(entry) is not dict:
                raise BackupIdentityError("invalid repository snapshot metadata")
            snapshot_id = entry.get("id")
            hostname = entry.get("hostname")
            tags = entry.get("tags", [])
            if (
                type(snapshot_id) is not str
                or _HEX.fullmatch(snapshot_id) is None
                or snapshot_id in seen
                or type(hostname) is not str
                or type(tags) is not list
                or len(tags) > 64  # noqa: PLR2004
                or any(type(tag) is not str or len(tag) > 256 for tag in tags)  # noqa: PLR2004
                or len(tags) != len(set(tags))
            ):
                raise BackupIdentityError("invalid repository snapshot metadata")
            seen.add(snapshot_id)
            snapshots.append((hostname, tuple(tags)))
        return identity, tuple(snapshots)
    except (ContractError, KeyError, TypeError, ValueError, OSError) as error:
        raise BackupIdentityError("repository discovery is unavailable or malformed") from error
