"""Bounded complete private tree preservation, without following source links.

Caller holds exclusive fixture ownership. Original metadata and link targets are
data in the manifest; exported blobs are private regular files. No archive member
is extracted, and no unsupported source entry is silently omitted. The output
must be outside every disposal scope and is never removed by this module.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_retirement_files import (
    CHUNK,
    RetirementError,
    capacity,
    digest,
    directory,
)

FORMAT = "lowerduckpond-m3-11-complete-tree-export-v1"
MAX_MANIFEST = 32 * 1024 * 1024


@dataclass(frozen=True)
class Limits:
    bytes: int
    entries: int

    def __post_init__(self) -> None:
        if (
            type(self.bytes) is not int
            or type(self.entries) is not int
            or min(self.bytes, self.entries) < 1
        ):
            raise RetirementError("full evidence export bounds are invalid")


def metadata(value: os.stat_result) -> dict[str, object]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": value.st_mode,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "links": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _same(before: os.stat_result, after: os.stat_result) -> None:
    if metadata(before) != metadata(after):
        raise RetirementError("full evidence source identity changed")


@contextmanager
def child(parent: int, name: str, *, is_directory: bool) -> Iterator[int]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if is_directory else 0),
        dir_fd=parent,
    )
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def chunks(descriptor: int, size: int, guard: Callable[[], None]) -> Iterator[bytes]:
    remaining = size
    while remaining:
        guard()
        block = os.read(descriptor, min(CHUNK, remaining))
        if not block:
            raise RetirementError("full evidence source was truncated")
        remaining -= len(block)
        yield block
    if os.read(descriptor, 1):
        raise RetirementError("full evidence source exceeded its byte bound")


def _blob(parent: int, name: str, descriptor: int, size: int, guard: Callable[[], None]) -> str:
    guard()
    return _write(parent, name, chunks(descriptor, size, guard), size)


def _write(parent: int, name: str, blocks: Iterator[bytes], size: int) -> str:
    temporary = name + ".partial"
    output = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
    )
    hasher = hashlib.sha256()
    count = 0
    with os.fdopen(output, "wb") as stream:
        for block in blocks:
            count += len(block)
            if count > size:
                raise RetirementError("full evidence publication exceeds its byte bound")
            hasher.update(block)
            if not any(block):
                stream.seek(len(block), os.SEEK_CUR)
            else:
                stream.write(block)
        if count != size:
            raise RetirementError("full evidence publication was truncated")
        stream.truncate(size)
        stream.flush()
        os.fsync(stream.fileno())
    _rename_noreplace(parent, temporary, name)
    os.fsync(parent)
    return hasher.hexdigest()


def _plain(descriptor: int) -> None:
    if os.listxattr(descriptor):
        raise RetirementError("full evidence export cannot omit extended attributes or ACLs")


def _names(descriptor: int) -> list[str]:
    # Use a new directory description relative to the pinned inode. In
    # particular, do not reuse an enumeration cursor opened before publication.
    with child(descriptor, ".", is_directory=True) as current:
        return sorted(os.listdir(current))  # noqa: PTH208 - pinned descriptor, never a pathname


def _linked(parent: int, name: str, descriptor: int) -> None:
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    saved = os.fstat(descriptor)
    if (current.st_dev, current.st_ino, current.st_mode, current.st_uid) != (
        saved.st_dev,
        saved.st_ino,
        saved.st_mode,
        saved.st_uid,
    ):
        raise RetirementError("full evidence destination identity changed")


def _parent_linked(path: Path, descriptor: int) -> None:
    directory(path)
    current, saved = path.lstat(), os.fstat(descriptor)
    if (current.st_dev, current.st_ino) != (saved.st_dev, saved.st_ino):
        raise RetirementError("full evidence destination parent changed")


def _document(parent: int, name: str, value: dict[str, object]) -> None:
    raw = canonical_bytes(value)
    if len(raw) > MAX_MANIFEST:
        raise RetirementError("full evidence manifest exceeds its byte bound")
    _write(parent, name, iter([raw]), len(raw))
    if _read_document(parent, name) != value:
        raise RetirementError("full evidence manifest reread differs")


def _read_document(parent: int, name: str) -> dict[str, object]:
    with child(parent, name, is_directory=False) as descriptor:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600  # noqa: PLR2004
            or not 0 < before.st_size <= MAX_MANIFEST
        ):
            raise RetirementError("full evidence manifest has unsafe metadata")
        raw = b"".join(chunks(descriptor, before.st_size, lambda: None))
        _same(before, os.fstat(descriptor))
        _same(before, os.stat(name, dir_fd=parent, follow_symlinks=False))
    value = decode_json_object(raw, maximum_bytes=MAX_MANIFEST)
    if canonical_bytes(value) != raw:
        raise RetirementError("full evidence manifest is not canonical")
    return value


class Tree:
    def __init__(self, limits: Limits, guard: Callable[[], None]) -> None:
        self.limits, self.guard = limits, guard
        self.rows: list[dict[str, object]] = []
        self.total = 0

    def scan(self, root: Path, *, output: int | None = None) -> dict[str, object]:
        directory(root)
        before = root.lstat()
        self.rows, self.total = [], 0
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _same(before, os.fstat(descriptor))
            self._directory(descriptor, (), before.st_dev, output)
            _same(before, root.lstat())
        finally:
            os.close(descriptor)
        return {
            "root": str(root),
            "metadata": metadata(before),
            "entries": self.rows,
            "bytes": self.total,
        }

    def _directory(
        self, parent: int, parts: tuple[str, ...], device: int, output: int | None
    ) -> None:
        self.guard()
        before = os.fstat(parent)
        _plain(parent)
        names = _names(parent)
        if len(names) + len(self.rows) > self.limits.entries:
            raise RetirementError("full evidence export exceeds its entry bound")
        for name in names:
            if name in {"", ".", ".."} or "/" in name or len(name.encode("utf-8")) > 255:  # noqa: PLR2004
                raise RetirementError("full evidence export contains an unsafe name")
            path = (*parts, name)
            if len(path) > 64 or len("/".join(path).encode()) > 4096:  # noqa: PLR2004
                raise RetirementError("full evidence export exceeds its path bound")
            self._entry(parent, name, path, device, output)
        _same(before, os.fstat(parent))
        if _names(parent) != names:
            raise RetirementError("full evidence source entries changed")

    def _entry(
        self, parent: int, name: str, parts: tuple[str, ...], device: int, output: int | None
    ) -> None:
        self.guard()
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if before.st_dev != device or len(self.rows) >= self.limits.entries:
            raise RetirementError("full evidence source crosses a mount or entry bound")
        row: dict[str, object] = {"path": "/".join(parts), "metadata": metadata(before)}
        self.rows.append(row)
        if stat.S_ISDIR(before.st_mode):
            row["type"] = "directory"
            with child(parent, name, is_directory=True) as descriptor:
                _same(before, os.fstat(descriptor))
                self._directory(descriptor, parts, device, output)
        elif stat.S_ISLNK(before.st_mode):
            if os.listxattr(f"/proc/self/fd/{parent}/{name}", follow_symlinks=False):
                raise RetirementError("full evidence export cannot omit extended link attributes")
            target = os.readlink(name, dir_fd=parent)
            if len(target.encode("utf-8")) > 4096:  # noqa: PLR2004
                raise RetirementError("full evidence link target exceeds its bound")
            row.update({"type": "symlink", "target": target})
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            self.total += before.st_size
            if self.total > self.limits.bytes:
                raise RetirementError("full evidence export exceeds its byte bound")
            with child(parent, name, is_directory=False) as descriptor:
                _same(before, os.fstat(descriptor))
                _plain(descriptor)
                if output is None:
                    hasher = hashlib.sha256()
                    for block in chunks(descriptor, before.st_size, self.guard):
                        hasher.update(block)
                    checksum = hasher.hexdigest()
                else:
                    checksum = _blob(
                        output, digest(row["path"]), descriptor, before.st_size, self.guard
                    )
                _same(before, os.fstat(descriptor))
            row.update({"type": "file", "sha256": checksum})
        else:
            raise RetirementError("full evidence export rejects hardlinks and special files")
        _same(before, os.stat(name, dir_fd=parent, follow_symlinks=False))


def verify_blobs(blobs: int, manifest: dict[str, object], guard: Callable[[], None]) -> None:
    expected = set()
    for row in cast(list[dict[str, object]], manifest["entries"]):
        if row["type"] != "file":
            continue
        guard()
        name = digest(row["path"])
        expected.add(name)
        before = os.stat(name, dir_fd=blobs, follow_symlinks=False)
        saved = cast(dict[str, int], row["metadata"])
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600  # noqa: PLR2004
            or before.st_uid != os.geteuid()
            or before.st_size != saved["size"]
        ):
            raise RetirementError("full evidence preserved blob identity differs")
        with child(blobs, name, is_directory=False) as descriptor:
            _same(before, os.fstat(descriptor))
            _plain(descriptor)
            hasher = hashlib.sha256()
            for block in chunks(descriptor, before.st_size, guard):
                hasher.update(block)
            if hasher.hexdigest() != row["sha256"]:
                raise RetirementError("full evidence independent reread differs")
            _same(before, os.fstat(descriptor))
            _same(before, os.stat(name, dir_fd=blobs, follow_symlinks=False))
    if set(_names(blobs)) != expected:
        raise RetirementError("full evidence export blob inventory differs")


def preserve(
    root: Path, output: Path, *, limits: Limits, guard: Callable[[], None]
) -> dict[str, object]:
    """No removal: reserve a fresh private destination and independently reread."""
    directory(root)
    directory(output.parent)
    if output.is_relative_to(root) or root.is_relative_to(output):
        raise RetirementError("full evidence destination overlaps its disposal scope")
    original = Tree(limits, guard).scan(root)
    capacity(output.parent, cast(int, original["bytes"]))
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _parent_linked(output.parent, parent)
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        with child(parent, output.name, is_directory=True) as exported:
            os.mkdir("blobs", mode=0o700, dir_fd=exported)
            os.fsync(exported)
            with child(exported, "blobs", is_directory=True) as blobs:

                def current() -> None:
                    guard()
                    _parent_linked(output.parent, parent)
                    _linked(parent, output.name, exported)
                    _linked(exported, "blobs", blobs)

                current()
                copied = Tree(limits, current).scan(root, output=blobs)
                if copied != original:
                    raise RetirementError("full evidence source changed during preservation")
                verify_blobs(blobs, original, current)
                if Tree(limits, current).scan(root) != original:
                    raise RetirementError("full evidence source changed before publication")
                result = {"format": FORMAT, **original}
                current()
                _document(exported, "manifest.json", result)
                current()
                _document(
                    exported, "verified.json", {"manifest_sha256": digest(result), "complete": True}
                )
                current()
                return result
    finally:
        os.close(parent)


def verify(
    root: Path, output: Path, *, limits: Limits, guard: Callable[[], None]
) -> dict[str, object]:
    result = verify_preserved(output, limits=limits, guard=guard)
    if {"format": FORMAT, **Tree(limits, guard).scan(root)} != result:
        raise RetirementError("full evidence export no longer matches its original tree")
    return result


def verify_preserved(
    output: Path, *, limits: Limits, guard: Callable[[], None]
) -> dict[str, object]:
    """Reread complete retained bytes after original resources no longer exist."""
    directory(output)
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _parent_linked(output.parent, parent)
        with (
            child(parent, output.name, is_directory=True) as exported,
            child(exported, "blobs", is_directory=True) as blobs,
        ):

            def current() -> None:
                guard()
                _parent_linked(output.parent, parent)
                _linked(parent, output.name, exported)
                _linked(exported, "blobs", blobs)

            manifest = _read_document(exported, "manifest.json")
            if manifest.get("format") != FORMAT or _read_document(exported, "verified.json") != {
                "manifest_sha256": digest(manifest),
                "complete": True,
            }:
                raise RetirementError("full evidence retained manifest binding differs")
            rows = manifest.get("entries")
            if not isinstance(rows, list) or len(rows) > limits.entries:
                raise RetirementError("full evidence retained entry bound differs")
            names: set[str] = set()
            total = 0
            for row in rows:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("path"), str)
                    or row["path"] in names
                    or not row["path"]
                    or any(part in {"", ".", ".."} for part in row["path"].split("/"))
                    or row.get("type") not in {"file", "directory", "symlink"}
                ):
                    raise RetirementError("full evidence retained entry is invalid")
                names.add(row["path"])
                if row["type"] == "file":
                    saved = row.get("metadata")
                    if (
                        not isinstance(saved, dict)
                        or type(saved.get("size")) is not int
                        or saved["size"] < 0
                    ):
                        raise RetirementError("full evidence retained size is invalid")
                    total += saved["size"]
            if total != manifest.get("bytes") or total > limits.bytes:
                raise RetirementError("full evidence retained byte bound differs")
            verify_blobs(blobs, manifest, current)
            current()
            return manifest
    finally:
        os.close(parent)
