"""Fixed M3.11 sources and bounded, nonmutating authority-tree measurement."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

SOURCE_PATHS: Final = {
    "content": "/srv/lowerduckpond",
    "state": "/var/lib/lowerduckpond/static",
    "recovery": "/var/lib/lowerduckpond/recovery",
}
STAGED_PATHS: Final = {
    "database": "/var/cache/lowerduckpond-backup/staging/mariadb.sql.gz",
    "descriptor": "/var/cache/lowerduckpond-backup/staging/static-recovery.json",
}
EXCLUDE_PATHS: Final = (
    "/var/lib/lowerduckpond/static/intake",
    "/var/lib/lowerduckpond/static/exports",
    "/srv/lowerduckpond/sites/.staging",
    "/srv/lowerduckpond/lost+found",
    "/etc/caddy/generations",
    "/etc/caddy/environment",
    "/var/lib/caddy",
    "/var/lib/lowerduckpond/static/**/.ldp-state-*",
    "/var/lib/lowerduckpond/recovery/**/.ldp-state-*",
)
TREE_FORMAT: Final = "lowerduckpond-backup-tree-v1"
FILE_FORMAT: Final = "lowerduckpond-backup-file-v1"
POLICY_FORMAT: Final = "lowerduckpond-backup-source-policy-v1"
MAX_TREE_ENTRIES: Final = 800_000
MAX_TREE_BYTES: Final = 12 * 1024**3
MAX_FILE_BYTES: Final = 32 * 1024**2
MAX_INVENTORY_BYTES: Final = 1024**3
MAX_DEPTH: Final = 40
_CHUNK: Final = 64 * 1024
_TEMPORARY: Final = re.compile(r"\.ldp-state-[0-9a-f]{32}", re.ASCII)
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_EXCLUDED: Final = {("state", "intake"), ("state", "exports"), ("content", "sites", ".staging")}


def source_policy_digest() -> dict[str, str]:
    return framed_digest(
        POLICY_FORMAT,
        canonical_json_bytes(
            {
                "sources": SOURCE_PATHS,
                "stagedFiles": STAGED_PATHS,
                "exclusions": list(EXCLUDE_PATHS),
            }
        ),
    )


@dataclass(frozen=True)
class BackupTree:
    digest: dict[str, str]
    entries: int
    content_bytes: int


@dataclass
class _Walk:
    owner: int
    content_group: int
    stream: BinaryIO
    entries: int = 0
    content_bytes: int = 0

    def emit(self, row: dict[str, object]) -> None:
        self.entries += 1
        if self.entries > MAX_TREE_ENTRIES:
            raise BackupIdentityError("backup authority exceeds its inode bound")
        raw = canonical_json_bytes(row)
        if self.stream.tell() + len(raw) > MAX_INVENTORY_BYTES:
            raise BackupIdentityError("backup authority inventory exceeds its byte bound")
        self.stream.write(raw)

    def directory(self, descriptor: int, path: tuple[str, ...], device: int) -> None:
        if len(path) > MAX_DEPTH:
            raise BackupIdentityError("backup authority exceeds its depth bound")
        before = os.fstat(descriptor)
        self.validate(before, path, directory=True, device=device)
        _require_no_attributes(descriptor)
        self.emit(_row(path, before, "directory"))
        names: list[str] = []
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) + self.entries > MAX_TREE_ENTRIES:
                    raise BackupIdentityError("backup authority exceeds its inode bound")
        for name in sorted(names):
            child = (*path, name)
            if self.excluded(descriptor, child, device):
                continue
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _ignored_temporary(child, metadata, self.owner):
                continue
            directory = stat.S_ISDIR(metadata.st_mode)
            self.validate(metadata, child, directory=directory, device=device)
            opened = os.open(
                name, _DIRECTORY_FLAGS if directory else _FILE_FLAGS, dir_fd=descriptor
            )
            try:
                if _generation(metadata) != _generation(os.fstat(opened)):
                    raise BackupIdentityError("backup authority changed while opening")
                if directory:
                    self.directory(opened, child, device)
                else:
                    self.file(opened, child, metadata)
                if _generation(metadata) != _generation(
                    os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                ):
                    raise BackupIdentityError("backup authority name changed while reading")
            finally:
                os.close(opened)
        if _generation(before) != _generation(os.fstat(descriptor)):
            raise BackupIdentityError("backup authority directory changed while reading")

    def excluded(self, parent: int, path: tuple[str, ...], device: int) -> bool:
        if path == ("content", "lost+found"):
            self.empty_filesystem_directory(parent, path[-1], device)
            return True
        return path in _EXCLUDED

    def empty_filesystem_directory(self, parent: int, name: str, device: int) -> None:
        """Exclude only verified empty ext4 housekeeping at the content root."""
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            if (
                metadata.st_dev != device
                or metadata.st_uid != self.owner
                or metadata.st_gid != self.owner
                or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004 - root-private directory
            ):
                raise BackupIdentityError("backup filesystem directory is unsafe")
            _require_no_attributes(descriptor)
            with os.scandir(descriptor) as entries:
                if next(entries, None) is not None:
                    raise BackupIdentityError("backup filesystem directory is not empty")
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _generation(metadata) != _generation(named) or _generation(metadata) != _generation(
                os.fstat(descriptor)
            ):
                raise BackupIdentityError("backup filesystem directory changed while reading")
        finally:
            os.close(descriptor)

    def validate(
        self, metadata: os.stat_result, path: tuple[str, ...], *, directory: bool, device: int
    ) -> None:
        content = path[0] == "content"
        modes = (
            {0o711, 0o710, 0o750, 0o755}
            if content and directory
            else {0o640, 0o644}
            if content
            else {0o700}
            if directory
            else {0o600}
        )
        # Root executors run with primary group caddy for publication. Their
        # private state remains root-only through 0700/0600 modes; preserve the
        # actual root/caddy GID rather than rejecting ordinary durable writes.
        groups = {self.owner, self.content_group}
        if (
            metadata.st_dev != device
            or metadata.st_uid != self.owner
            or metadata.st_gid not in groups
            or stat.S_IMODE(metadata.st_mode) not in modes
            or (not directory and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1))
        ):
            raise BackupIdentityError("backup authority inode is unsafe")
        if not directory and metadata.st_size > MAX_FILE_BYTES:
            raise BackupIdentityError("backup authority file exceeds its bound")

    def file(self, descriptor: int, path: tuple[str, ...], before: os.stat_result) -> None:
        _require_no_attributes(descriptor)
        self.content_bytes += before.st_size
        if self.content_bytes > MAX_TREE_BYTES:
            raise BackupIdentityError("backup authority exceeds its content bound")
        digest = hashlib.sha256(
            FILE_FORMAT.encode("ascii") + b"\0" + before.st_size.to_bytes(8, "big")
        )
        read = 0
        while chunk := os.read(descriptor, min(_CHUNK, before.st_size + 1 - read)):
            read += len(chunk)
            if read > before.st_size:
                raise BackupIdentityError("backup authority grew while reading")
            digest.update(chunk)
        if read != before.st_size or _generation(before) != _generation(os.fstat(descriptor)):
            raise BackupIdentityError("backup authority changed while reading")
        self.emit(
            {
                **_row(path, before, "file"),
                "bytes": read,
                "digest": {
                    "format": FILE_FORMAT,
                    "algorithm": "sha256",
                    "value": digest.hexdigest(),
                },
            }
        )


def _ignored_temporary(path: tuple[str, ...], metadata: os.stat_result, owner: int) -> bool:
    if path[0] == "content" or not path[-1].startswith(".ldp-state-"):
        return False
    if (
        _TEMPORARY.fullmatch(path[-1]) is None
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner
        or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004 - private state record
        or metadata.st_nlink != 1
    ):
        raise BackupIdentityError("backup temporary is unsafe")
    return True


def _row(path: tuple[str, ...], metadata: os.stat_result, kind: str) -> dict[str, object]:
    return {
        "path": "/".join(path),
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_no_attributes(descriptor: int) -> None:
    if os.listxattr(descriptor):
        raise BackupIdentityError("backup authority has unclassified extended attributes")


def measure_backup_sources(
    roots: Mapping[str, Path],
    workspace: Path,
    *,
    locks: LockManager,
    expected_owner: int,
    content_group: int,
) -> BackupTree:
    """Caller retains both shared static locks through the later Restic capture.

    The private temporary contains only canonical path/mode/content-digest rows,
    sorted by source label and depth-first lexical path. H binds their exact
    total byte length and stream. It is never included in a backup.
    """
    locks.require_held(LockName.PUBLICATION, mode=LockMode.SHARED)
    locks.require_held(LockName.TENANT_STATE, mode=LockMode.SHARED)
    if set(roots) != set(SOURCE_PATHS):
        raise BackupIdentityError("backup source set is incomplete")
    with DurableDirectory.open(
        workspace, expected_owner=expected_owner, expected_directory_mode=0o700
    ) as directory:
        descriptor = directory.duplicate_descriptor()
        try:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(MAX_INVENTORY_BYTES, 1),
                measure_filesystem_capacity_descriptor(descriptor),
            )
        finally:
            os.close(descriptor)
    with tempfile.TemporaryFile(dir=workspace) as stream:
        walk = _Walk(expected_owner, content_group, stream)
        for label in sorted(roots):
            root = os.open(roots[label], _DIRECTORY_FLAGS)
            try:
                opened = os.fstat(root)
                if _generation(opened) != _generation(roots[label].stat(follow_symlinks=False)):
                    raise BackupIdentityError("backup source root changed")
                walk.directory(root, (label,), opened.st_dev)
                if _generation(opened) != _generation(roots[label].stat(follow_symlinks=False)):
                    raise BackupIdentityError("backup source root changed")
            finally:
                os.close(root)
        length = stream.tell()
        stream.seek(0)
        digest = hashlib.sha256(TREE_FORMAT.encode("ascii") + b"\0" + length.to_bytes(8, "big"))
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
        return BackupTree(
            {"format": TREE_FORMAT, "algorithm": "sha256", "value": digest.hexdigest()},
            walk.entries,
            walk.content_bytes,
        )
