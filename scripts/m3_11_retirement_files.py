"""Private, bounded evidence files for the failed-fixture transaction."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from pathlib import Path

from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_qualification_evidence import MAX_BYTES, canonical_bytes

CHUNK = 1024 * 1024
RESERVE = 256 * CHUNK


class RetirementError(ValueError):
    """Fixed, credential-free explanation suitable for the operator summary."""


def legacy(path: Path) -> dict[str, object]:
    """Original framework records have whitespace; preserve their exact bytes."""
    directory(path.parent)
    return decode_json_object(read_private_bytes(path), maximum_bytes=MAX_BYTES)


def directory(path: Path) -> None:
    if path.resolve(strict=True) != path:
        raise RetirementError("retirement directory must be canonical")
    value = path.lstat()
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o700  # noqa: PLR2004
        or value.st_uid != os.geteuid()
    ):
        raise RetirementError("retirement directory is not private")


def sync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fingerprint(path: Path, maximum: int) -> dict[str, object]:
    directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600  # noqa: PLR2004
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise RetirementError("retirement evidence has unsafe metadata")
        hasher, remaining = hashlib.sha256(), before.st_size
        while remaining:
            block = stream.read(min(CHUNK, remaining))
            if not block:
                raise RetirementError("retirement evidence was truncated")
            hasher.update(block)
            remaining -= len(block)
        if stream.read(1):
            raise RetirementError("retirement evidence grew beyond its byte bound")
        digest = hasher.hexdigest()
        after = os.fstat(stream.fileno())
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
            raise RetirementError("retirement evidence was replaced during verification")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RetirementError("retirement evidence changed")
    return {"size": before.st_size, "sha256": digest}


def capacity(path: Path, size: int) -> None:
    usage = os.statvfs(path)
    # Filesystems with dynamically allocated inodes report f_files == 0.
    if usage.f_bavail * usage.f_frsize < size + RESERVE or (
        usage.f_files and usage.f_favail < 128  # noqa: PLR2004
    ):
        raise RetirementError("insufficient private evidence capacity")


def preserve(  # noqa: PLR0912 - one durable copy transaction
    path: Path, chunks: Iterator[bytes], size: int, digest: str | None = None
) -> dict[str, object]:
    """Only new transaction-owned partial files can be retried; final files are immutable."""
    directory(path.parent)
    if path.exists() or path.is_symlink():
        found = fingerprint(path, size)
        if found["size"] != size or (digest is not None and found["sha256"] != digest):
            raise RetirementError("retained evidence differs from expected bytes")
        count, hasher = 0, hashlib.sha256()
        for chunk in chunks:
            count += len(chunk)
            if len(chunk) > CHUNK or count > size:
                raise RetirementError("evidence stream exceeds its byte bound")
            hasher.update(chunk)
        if count != size or hasher.hexdigest() != found["sha256"]:
            raise RetirementError("preserved evidence differs from its original source")
        return found
    capacity(path.parent, size)
    temporary = path.with_name(path.name + ".partial")
    if temporary.exists() or temporary.is_symlink():
        # This name belongs exclusively to this transaction's bounded copy.
        # Reject links/foreign files even when they are incomplete.
        value = temporary.lstat()
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o600  # noqa: PLR2004
            or value.st_nlink != 1
        ):
            raise RetirementError("unsafe partial evidence")
        temporary.unlink()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    count = 0
    hasher = hashlib.sha256()
    with os.fdopen(fd, "wb") as stream:
        for chunk in chunks:
            count += len(chunk)
            if len(chunk) > CHUNK or count > size:
                raise RetirementError("evidence stream exceeds its byte bound")
            hasher.update(chunk)
            # State images are sparse; preserve holes without trusting tar paths.
            if chunk and not any(chunk):
                stream.seek(len(chunk), os.SEEK_CUR)
            else:
                stream.write(chunk)
        if count != size or (digest is not None and hasher.hexdigest() != digest):
            raise RetirementError("evidence stream does not match its original identity")
        stream.truncate(count)
        stream.flush()
        os.fsync(stream.fileno())
    observed = fingerprint(temporary, size)
    if observed != {"size": size, "sha256": hasher.hexdigest()}:
        raise RetirementError("private evidence reread differs")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _rename_noreplace(parent, temporary.name, path.name)
        os.fsync(parent)
    finally:
        os.close(parent)
    return observed


def record(path: Path, value: dict[str, object]) -> None:
    raw = canonical_bytes(value)
    if len(raw) > MAX_BYTES:
        raise RetirementError("retirement document exceeds its bound")
    if path.exists() or path.is_symlink():
        if read_private(path) != value:
            raise RetirementError("retirement document is immutable")
        return
    preserve(
        path,
        (raw[i : i + CHUNK] for i in range(0, len(raw), CHUNK)),
        len(raw),
        hashlib.sha256(raw).hexdigest(),
    )


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
