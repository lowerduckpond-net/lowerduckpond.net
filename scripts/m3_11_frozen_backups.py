"""Preserve exact owned backup versions before separately approved remote cleanup.

All bodies are private, opaque retained evidence. This establishes byte
preservation, not a tested Restic restore or permission to discard another
prefix. Multipart uploads are rejected: their complete bytes are not available
through the version-bound preservation route.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

from scripts import m3_11_frozen_export as files
from scripts.m3_11_backup_fixture import Body
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_retirement_files import (
    CHUNK,
    RetirementError,
    capacity,
    digest,
    directory,
)


def _inventory(removal: Removal, expected: dict[str, object]) -> None:
    removal._validate_inventory(expected)
    if expected["uploads"] != []:
        raise RetirementError("remote closeout cannot preserve unfinished multipart bytes")
    if removal._observed() != expected:
        raise RetirementError("remote closeout exact backup inventory changed")
    removal._owner()


def _chunks(body: Body, size: int, guard: Callable[[], None]) -> Iterator[bytes]:
    remaining = size
    while remaining:
        guard()
        block = body.read(min(CHUNK, remaining))
        if not block or len(block) > remaining:
            raise RetirementError("backup evidence stream differs from its exact size")
        remaining -= len(block)
        yield block
    if body.read(1):
        raise RetirementError("backup evidence stream exceeded its exact size")


def capture(
    removal: Removal,
    expected: dict[str, object],
    output: Path,
    *,
    maximum_bytes: int,
    guard: Callable[[], None],
) -> dict[str, object]:
    """GET-only exact VersionId capture; immutable destination, no delete/replay."""
    directory(output.parent)
    _inventory(removal, expected)
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        files._parent_linked(output.parent, parent)
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        with files.child(parent, output.name, is_directory=True) as destination:

            def current() -> None:
                guard()
                files._parent_linked(output.parent, parent)
                files._linked(parent, output.name, destination)

            result = _capture(
                removal, expected, output, destination, maximum_bytes=maximum_bytes, guard=current
            )
            current()
            return result
    finally:
        os.close(parent)


def _capture(  # noqa: PLR0913 - exact version stream and pinned private destination
    removal: Removal,
    expected: dict[str, object],
    output: Path,
    destination: int,
    *,
    maximum_bytes: int,
    guard: Callable[[], None],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    total = 0
    for kind, key, version in cast(list[list[str]], expected["versions"]):
        if kind == "delete-marker":
            continue  # Its complete immutable identity is in the saved inventory.
        guard()
        response = removal.observer.get_object(
            Bucket=removal.target.backup_bucket,
            Key=key,
            VersionId=version,
        )
        body = cast(Body, response["Body"])
        try:
            size = response.get("ContentLength")
            if type(size) is not int or size < 0 or response.get("VersionId") != version:
                raise RetirementError("backup evidence lacks exact native version/size")
            total += size
            if total > maximum_bytes:
                raise RetirementError("backup evidence exceeds approved preservation capacity")
            capacity(output, size)
            filename = digest([key, version])
            checksum = files._write(destination, filename, _chunks(body, size, guard), size)
            guard()
            observed = {"size": size, "sha256": checksum}
            rows.append({"key": key, "version": version, "file": filename, **observed})
        finally:
            body.close()
    _inventory(removal, expected)
    result = {
        "format": "lowerduckpond-m3-11-backup-preservation-v1",
        "ownership": removal.target.manifest(removal.binding),
        "owner_version": removal.owner_version,
        "inventory": expected,
        "files": rows,
        "bytes": total,
    }
    guard()
    files._document(destination, "manifest.json", result)
    verify(removal, expected, output, maximum_bytes=maximum_bytes, guard=guard)
    return result


def verify(
    removal: Removal,
    expected: dict[str, object],
    output: Path,
    *,
    maximum_bytes: int,
    guard: Callable[[], None],
) -> dict[str, object]:
    """Independently reread all retained version bytes; this makes no provider call."""
    directory(output)
    removal._validate_inventory(expected)
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        files._parent_linked(output.parent, parent)
        with files.child(parent, output.name, is_directory=True) as destination:

            def current() -> None:
                guard()
                files._parent_linked(output.parent, parent)
                files._linked(parent, output.name, destination)

            value = _verify(
                removal, expected, destination, maximum_bytes=maximum_bytes, guard=current
            )
            current()
            return value
    finally:
        os.close(parent)


def _verify(
    removal: Removal,
    expected: dict[str, object],
    destination: int,
    *,
    maximum_bytes: int,
    guard: Callable[[], None],
) -> dict[str, object]:
    value = files._read_document(destination, "manifest.json")
    rows = value.get("files")
    if (
        value.get("format") != "lowerduckpond-m3-11-backup-preservation-v1"
        or value.get("ownership") != removal.target.manifest(removal.binding)
        or value.get("owner_version") != removal.owner_version
        or value.get("inventory") != expected
        or expected["uploads"] != []
        or not isinstance(rows, list)
    ):
        raise RetirementError("backup evidence differs from exact removal ownership")
    wanted = {
        (key, version)
        for kind, key, version in cast(list[list[str]], expected["versions"])
        if kind == "version"
    }
    seen: set[tuple[str, str]] = set()
    names = {"manifest.json"}
    total = 0
    for raw in rows:
        from scripts.m3_11_qualification_evidence import fields  # noqa: PLC0415

        row = fields(raw, {"key", "version", "file", "size", "sha256"})
        pair = (str(row["key"]), str(row["version"]))
        if pair not in wanted or pair in seen or row["file"] != digest(list(pair)):
            raise RetirementError("backup evidence contains missing or repeated exact versions")
        seen.add(pair)
        size = row["size"]
        if type(size) is not int or size < 0:
            raise RetirementError("backup evidence byte count is invalid")
        total += size
        if total > maximum_bytes:
            raise RetirementError("backup evidence exceeds approved byte bound")
        guard()
        filename = str(row["file"])
        names.add(filename)
        with files.child(destination, filename, is_directory=False) as descriptor:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600  # noqa: PLR2004
                or before.st_size != size
            ):
                raise RetirementError("backup evidence preserved file metadata differs")
            checksum = hashlib.sha256()
            for block in files.chunks(descriptor, size, guard):
                checksum.update(block)
            files._same(before, os.fstat(descriptor))
            files._same(before, os.stat(filename, dir_fd=destination, follow_symlinks=False))
            if checksum.hexdigest() != row["sha256"]:
                raise RetirementError("backup evidence independent reread differs")
    if seen != wanted or total != value.get("bytes") or set(files._names(destination)) != names:
        raise RetirementError("backup evidence export is incomplete or contains unbound files")
    return value
