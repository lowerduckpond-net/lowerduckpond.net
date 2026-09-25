"""Publish only exact content-addressed controller code on the predecessor."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path("/run/lowerduckpond-m3-11")
MAX_BYTES = 256 * 1024
PUBLISHED_MODE = 0o400


def metadata(value: os.stat_result, owner: int, mode: int, *, directory: bool = False) -> None:
    if (
        value.st_uid != owner
        or stat.S_IMODE(value.st_mode) != mode
        or (not stat.S_ISDIR(value.st_mode) if directory else not stat.S_ISREG(value.st_mode))
        or (not directory and value.st_nlink != 1)
    ):
        raise ValueError("production helper metadata is unsafe")


def stage(directory: Path, raw: bytes, expected: str, *, owner: int) -> Path:
    if (
        not 0 < len(raw) <= MAX_BYTES
        or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        or hashlib.sha256(raw).hexdigest() != expected
    ):
        raise ValueError("production helper bytes disagree with their identity")
    directory.mkdir(mode=0o700, exist_ok=True)
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata(os.fstat(root), owner, 0o700, directory=True)
        lock = os.open(
            "stage.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root
        )
        try:
            metadata(os.fstat(lock), owner, 0o600)
            if os.fstat(lock).st_size:
                raise ValueError("production staging lock is invalid")
            fcntl.flock(lock, fcntl.LOCK_EX)
            return _publish(directory, root, lock, raw, expected, owner=owner)
        finally:
            os.close(lock)
    finally:
        os.close(root)


def _guard(directory: Path, root: int, lock: int, owner: int) -> None:
    for opened, named, mode, is_directory in (
        (os.fstat(root), directory.stat(follow_symlinks=False), 0o700, True),
        (os.fstat(lock), os.stat("stage.lock", dir_fd=root, follow_symlinks=False), 0o600, False),
    ):
        metadata(opened, owner, mode, directory=is_directory)
        metadata(named, owner, mode, directory=is_directory)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("production staging authority changed")


def _read(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) <= MAX_BYTES:
        block = os.read(fd, MAX_BYTES + 1 - len(result))
        if not block:
            break
        result.extend(block)
    return bytes(result)


def _publish(  # noqa: PLR0912,PLR0913,PLR0915 - pinned inputs and one resumable publication
    directory: Path, root: int, lock: int, raw: bytes, expected: str, *, owner: int
) -> Path:
    final, temporary = expected + ".pyz", "." + expected + ".partial"
    _guard(directory, root, lock, owner)
    try:
        fd = os.open(final, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    except FileNotFoundError:
        pass
    else:
        try:
            opened = os.fstat(fd)
            metadata(opened, owner, PUBLISHED_MODE)
            if _read(fd) != raw:
                raise ValueError("published production helper changed")
            named = os.stat(final, dir_fd=root, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise ValueError("published production helper was replaced")
            metadata(named, owner, PUBLISHED_MODE)
            _guard(directory, root, lock, owner)
            return directory / final
        finally:
            os.close(fd)
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | flags, 0o600, dir_fd=root)
    except PermissionError:
        fd = os.open(temporary, os.O_RDONLY | flags, dir_fd=root)
    try:
        current = os.fstat(fd)
        # A crash after chmod but before rename leaves a complete read-only
        # helper. Its same inode and bytes can still be published by root.
        mode = stat.S_IMODE(current.st_mode)
        if mode not in {PUBLISHED_MODE, 0o600}:
            raise ValueError("partial production helper mode is invalid")
        metadata(current, owner, mode)
        prefix = _read(fd)
        if not raw.startswith(prefix) or (mode == PUBLISHED_MODE and prefix != raw):
            raise ValueError("partial production helper differs from its identity")
        remaining = memoryview(raw)[len(prefix) :]
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise OSError("production helper short write")
            remaining = remaining[count:]
        os.fchmod(fd, PUBLISHED_MODE)
        os.fsync(fd)
        if _read(fd) != raw:
            raise ValueError("written production helper changed")
        _guard(directory, root, lock, owner)
        named = os.stat(temporary, dir_fd=root, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("partial production helper was replaced")
        metadata(named, owner, PUBLISHED_MODE)
        os.rename(temporary, final, src_dir_fd=root, dst_dir_fd=root)
        os.fsync(root)
    finally:
        os.close(fd)
    _guard(directory, root, lock, owner)
    return directory / final


def main() -> int:
    try:
        if os.geteuid() != 0 or len(sys.argv) != 2:  # noqa: PLR2004 - one expected SHA-256
            raise ValueError("invalid production helper staging invocation")
        result = stage(ROOT, sys.stdin.buffer.read(MAX_BYTES + 1), sys.argv[1], owner=0)
        print(result)
        return 0
    except OSError, ValueError:
        print("production_helper_staging_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
