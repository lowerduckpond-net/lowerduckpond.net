"""Linux filesystem behavior qualification probes."""

from __future__ import annotations

import errno
import fcntl
import os
import tempfile
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.report import CheckResult, EvidenceValue, run_check

NETWORK_FILESYSTEMS: Final = frozenset({"9p", "cifs", "fuse", "fuseblk", "nfs", "nfs4"})
MOUNT_POINT_FIELD_INDEX: Final = 4
EXPECTED_INITIAL_LINKS: Final = 2


def run_filesystem_checks(
    *, work_root: Path, expected_filesystem: str = "ext4"
) -> tuple[CheckResult, ...]:
    """Exercise publication primitives on the requested real filesystem."""
    work_root.mkdir(parents=True, exist_ok=True)
    filesystem_type = _filesystem_type(work_root)
    with tempfile.TemporaryDirectory(prefix="ldp-m3-", dir=work_root) as temporary_name:
        directory = Path(temporary_name)
        return (
            run_check(
                "m3.0.filesystem.type",
                lambda: _check_filesystem_type(filesystem_type, expected_filesystem),
            ),
            run_check("m3.0.filesystem.directory-fsync", lambda: _check_fsync(directory)),
            run_check("m3.0.filesystem.atomic-rename", lambda: _check_atomic_rename(directory)),
            run_check("m3.0.filesystem.hardlink", lambda: _check_hardlink(directory)),
            run_check("m3.0.filesystem.no-follow", lambda: _check_no_follow(directory)),
            run_check("m3.0.filesystem.flock", lambda: _check_flock(directory)),
        )


def _filesystem_type(path: Path) -> str:
    resolved = path.resolve()
    selected_mount = Path("/")
    selected_type = "unknown"
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        after_fields = after.split()
        if len(fields) <= MOUNT_POINT_FIELD_INDEX or not after_fields:
            continue
        mount = Path(fields[MOUNT_POINT_FIELD_INDEX].replace("\\040", " ")).resolve()
        try:
            resolved.relative_to(mount)
        except ValueError:
            continue
        if len(mount.parts) >= len(selected_mount.parts):
            selected_mount = mount
            selected_type = after_fields[0]
    return selected_type


def _check_filesystem_type(actual: str, expected: str) -> dict[str, EvidenceValue]:
    if actual != expected or actual in NETWORK_FILESYSTEMS:
        raise RuntimeError
    return {"filesystem": actual}


def _check_fsync(directory: Path) -> dict[str, EvidenceValue]:
    path = directory / "fsync-source"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"qualification")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(directory)
    return {"directory_synced": True, "file_synced": True}


def _check_atomic_rename(directory: Path) -> dict[str, EvidenceValue]:
    source = directory / "rename-source"
    destination = directory / "rename-destination"
    source.write_bytes(b"generation-a")
    source.replace(destination)
    _fsync_directory(directory)
    if source.exists() or destination.read_bytes() != b"generation-a":
        raise RuntimeError
    return {"same_filesystem": True}


def _check_hardlink(directory: Path) -> dict[str, EvidenceValue]:
    source = directory / "hardlink-source"
    link = directory / "hardlink-copy"
    source.write_bytes(b"immutable-release")
    os.link(source, link, follow_symlinks=False)
    source_stat = source.stat(follow_symlinks=False)
    link_stat = link.stat(follow_symlinks=False)
    if source_stat.st_ino != link_stat.st_ino or source_stat.st_nlink != EXPECTED_INITIAL_LINKS:
        raise RuntimeError
    source.unlink()
    _fsync_directory(directory)
    if link.read_bytes() != b"immutable-release" or link.stat().st_nlink != 1:
        raise RuntimeError
    return {"initial_links": 2, "remaining_links": 1}


def _check_no_follow(directory: Path) -> dict[str, EvidenceValue]:
    target = directory / "nofollow-target"
    symlink = directory / "nofollow-link"
    target.write_bytes(b"target")
    symlink.symlink_to(target.name)
    try:
        descriptor = os.open(symlink, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno != errno.ELOOP:
            raise
    else:
        os.close(descriptor)
        raise RuntimeError
    return {"symlink_rejected": True}


def _check_flock(directory: Path) -> dict[str, EvidenceValue]:
    path = directory / "flock"
    path.touch(mode=0o600)
    first = os.open(path, os.O_RDWR)
    second = os.open(path, os.O_RDWR)
    contender = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(first, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(second, fcntl.LOCK_SH | fcntl.LOCK_NB)
        _require_lock_blocked(contender, fcntl.LOCK_EX)
        fcntl.flock(first, fcntl.LOCK_UN)
        fcntl.flock(second, fcntl.LOCK_UN)
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        observer = os.open(path, os.O_RDWR)
        try:
            _require_lock_blocked(observer, fcntl.LOCK_SH)
        finally:
            os.close(observer)
    finally:
        for descriptor in (first, second, contender):
            os.close(descriptor)
    return {"exclusive_blocks_shared": True, "shared_blocks_exclusive": True}


def _require_lock_blocked(descriptor: int, lock_type: int) -> None:
    try:
        fcntl.flock(descriptor, lock_type | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    fcntl.flock(descriptor, fcntl.LOCK_UN)
    raise RuntimeError


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
