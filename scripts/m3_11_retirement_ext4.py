"""Read clean retained ext4 images offline, without mounts or journal replay."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from scripts.m3_11_retirement_files import RetirementError
from scripts.qualification_probe import bounded_command

MAX_RECORD = 1024 * 1024
MAX_ENTRIES = 10000
SUPERBLOCK_BYTES = 1024


def valid_path(path: str) -> None:
    if (
        not path.startswith("/")
        or re.fullmatch(r"/[A-Za-z0-9_./-]*", path) is None
        or (any(part in {".", "..", ""} for part in path.split("/")[1:]) and path != "/")
    ):
        raise RetirementError("invalid offline observation path")


def command(arguments: tuple[str, ...], maximum: int = MAX_RECORD) -> bytes:
    result = bounded_command(
        list(arguments),
        timeout=20,
        maximum=maximum,
        environment={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
    )
    if result is None:
        raise RetirementError("offline state observation failed")
    return result


class Ext4:
    def __init__(self, path: Path) -> None:
        self.path = path
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004
        ):
            raise RetirementError("unsafe retained state image")
        # Read fixed superblock fields directly; never ask e2fsck to repair it.
        with path.open("rb") as stream:
            stream.seek(SUPERBLOCK_BYTES)
            block = stream.read(SUPERBLOCK_BYTES)
        if (
            len(block) != SUPERBLOCK_BYTES
            or int.from_bytes(block[56:58], "little") != 0xEF53  # noqa: PLR2004
            or int.from_bytes(block[58:60], "little") != 1
            or int.from_bytes(block[96:100], "little") & 0x4
        ):
            raise RetirementError("retained state image is not clean ext4")

    def _listing(self, path: str) -> dict[str, tuple[str, int]]:
        valid_path(path)
        raw = command(("/usr/sbin/debugfs", "-R", "ls -p " + path, str(self.path)))
        result = {}
        for line in raw.decode("ascii").splitlines():
            if not line:
                continue
            parts = line.split("/")
            if len(parts) != 8 or parts[0] or parts[-1]:  # noqa: PLR2004
                raise RetirementError("malformed offline directory entry")
            inode, mode, uid, _gid, name, size = parts[1:7]
            if name in {".", ".."}:
                continue
            numeric_mode = int(mode, 8)
            if int(inode) < 1 or name in result or not name:
                raise RetirementError("unsafe offline directory entry")
            trusted = int(uid) == 0 and not numeric_mode & 0o022
            kind = (
                "directory"
                if trusted and stat.S_ISDIR(numeric_mode)
                else "regular"
                if trusted and stat.S_ISREG(numeric_mode)
                else "unsafe"
            )
            result[name] = (kind, int(size) if size else 0)
            if len(result) > MAX_ENTRIES:
                raise RetirementError("offline directory exceeds its entry bound")
        return result

    def _entry(self, path: str) -> tuple[str, int]:
        valid_path(path)
        parts = path.split("/")
        parent = "/"
        found = ("directory", 0)
        for name in parts[1:]:
            if found[0] != "directory":
                raise RetirementError("offline path crosses an unsafe inode")
            found = self._listing(parent)[name]
            parent = parent.rstrip("/") + "/" + name
        return found

    def read(self, path: str) -> bytes:
        kind, size = self._entry(path)
        if kind != "regular" or not 0 < size <= MAX_RECORD:
            raise RetirementError("offline record is unsafe or oversized")
        metadata = command(("/usr/sbin/debugfs", "-R", "stat " + path, str(self.path)))
        if re.search(rb"^Links: 1\s", metadata, re.MULTILINE) is None:
            raise RetirementError("offline record has multiple links")
        raw = command(("/usr/sbin/debugfs", "-R", "cat " + path, str(self.path)), size)
        if len(raw) != size:
            raise RetirementError("offline record is truncated")
        return raw

    def names(self, path: str) -> dict[str, str]:
        if self._entry(path)[0] != "directory":
            raise RetirementError("offline inventory is not a directory")
        return {name: kind for name, (kind, _) in self._listing(path).items()}
