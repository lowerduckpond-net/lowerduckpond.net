"""Bounded canonical private inputs retained once by the combined run controller."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import cast

from scripts.m3_11_qualification_evidence import MAX_BYTES, canonical_bytes

PRIVATE_FILE_MODE = 0o600


def read_private(path: Path) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != PRIVATE_FILE_MODE
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_BYTES
        ):
            raise ValueError("combined private inputs have unsafe metadata")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        value = json.loads(raw)
        after = os.fstat(descriptor)
        if (
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            != (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            or not isinstance(value, dict)
            or raw != canonical_bytes(value)
        ):
            # Canonical equality also rejects duplicate fields at every depth.
            raise ValueError("combined private inputs are ambiguous or changed")
        return cast(dict[str, object], value)
    finally:
        os.close(descriptor)


def write_private(path: Path, value: dict[str, object]) -> None:
    """Never replace original evidence, including a partial interrupted write."""
    raw = canonical_bytes(value)
    if len(raw) > MAX_BYTES:
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
