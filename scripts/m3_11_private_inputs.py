"""Bounded canonical private inputs retained once by the combined run controller."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import cast

from scripts.m3_11_qualification_evidence import MAX_BYTES, canonical_bytes

PRIVATE_FILE_MODE = 0o600


def read_private_bytes(path: Path, *, maximum: int = MAX_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != PRIVATE_FILE_MODE
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("combined private inputs have unsafe metadata")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) or len(raw) > maximum:
            raise ValueError("combined private inputs are ambiguous or changed")
        return raw
    finally:
        os.close(descriptor)


def read_private(path: Path, *, maximum: int = MAX_BYTES) -> dict[str, object]:
    raw = read_private_bytes(path, maximum=maximum)
    value = json.loads(raw)
    # Canonical equality also rejects duplicate fields at every depth.
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise ValueError("combined private inputs are ambiguous or changed")
    return cast(dict[str, object], value)


def write_private(path: Path, value: dict[str, object], *, maximum: int = MAX_BYTES) -> None:
    """Never replace original evidence, including a partial interrupted write."""
    raw = canonical_bytes(value)
    if len(raw) > maximum:
        raise ValueError("combined private inputs exceed their byte bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_bytes(path: Path, raw: bytes, *, staging_directory: Path | None = None) -> None:
    """Publish complete new bytes without replacing an existing directory entry."""
    from lowerduckpond_static_host_agent.durable import _rename_noreplace  # noqa: PLC0415

    with tempfile.NamedTemporaryFile(
        dir=staging_directory or path.parent, prefix=".publication-", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        source = os.open(temporary.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _rename_noreplace(source, temporary.name, path.name, destination_fd=descriptor)
            os.fsync(source)
        finally:
            os.close(source)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_private(
    path: Path,
    value: dict[str, object],
    *,
    maximum: int = MAX_BYTES,
    staging_directory: Path | None = None,
) -> None:
    raw = canonical_bytes(value)
    if len(raw) > maximum:
        raise ValueError("combined private inputs exceed their byte bound")
    publish_bytes(path, raw, staging_directory=staging_directory)
