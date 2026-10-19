"""Retain complete stopped actor root filesystems and private daemon metadata.

Docker export omits mounts. This narrow path therefore rejects every persistent
mount, including anonymous/named volumes and binds. Only stopped ephemeral
tmpfs mounts can be absent from the export. No export is a supported restart or
automatic restore route; it is private evidence preserved before disposal.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tarfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Protocol, cast

from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts import m3_11_frozen_export as files
from scripts.m3_11_frozen_context import actor, require
from scripts.m3_11_retirement_files import CHUNK, digest, directory

FORMAT = "lowerduckpond-m3-11-stopped-actor-export-v1"


class Reader(Protocol):
    def inspect_actor(self, selected: str) -> dict[str, object]: ...

    def actor_bytes(
        self, operation: str, selected: str, guard: Callable[[], None]
    ) -> Iterator[bytes]: ...


def require_exportable(raw: dict[str, object], expected: dict[str, object]) -> None:
    require(actor(raw) == expected, "actor evidence no longer matches original stopped identity")
    state, host, config = (
        cast(dict[str, object], raw[key]) for key in ("State", "HostConfig", "Config")
    )
    require(
        state.get("Pid") == 0
        and state.get("Running") is False
        and expected["restart_policy"] == "no",
        "actor export requires an unchanged stopped process",
    )
    mounts = raw.get("Mounts")
    require(
        isinstance(mounts, list)
        and all(isinstance(row, dict) and row.get("Type") == "tmpfs" for row in mounts)
        and not config.get("Volumes")
        and not host.get("Binds")
        and not host.get("VolumesFrom")
        and not host.get("Devices")
        and not host.get("DeviceRequests"),
        "actor export cannot omit persistent mounts, volumes or mapped devices",
    )
    require(
        all(
            row.get("Type") == "tmpfs"
            for row in cast(list[dict[str, object]], host.get("Mounts") or [])
        ),
        "actor export found an unpreserved configured mount",
    )


def _stream(
    destination: int, name: str, blocks: Iterator[bytes], *, maximum: int, guard: Callable[[], None]
) -> dict[str, object]:
    descriptor = os.open(
        name + ".partial",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=destination,
    )
    checksum, count = hashlib.sha256(), 0
    with os.fdopen(descriptor, "wb") as output:
        for block in blocks:
            guard()
            count += len(block)
            require(
                len(block) <= CHUNK and count <= maximum, "actor evidence exceeded its byte bound"
            )
            checksum.update(block)
            if block and not any(block):
                output.seek(len(block), os.SEEK_CUR)
            else:
                output.write(block)
        output.truncate(count)
        output.flush()
        os.fsync(output.fileno())
    guard()
    _rename_noreplace(destination, name + ".partial", name)
    os.fsync(destination)
    binding = {"size": count, "sha256": checksum.hexdigest()}
    _reread(destination, name, binding, guard=guard)
    return binding


def _reread(
    destination: int, name: str, binding: dict[str, object], *, guard: Callable[[], None]
) -> None:
    with files.child(destination, name, is_directory=False) as descriptor:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600  # noqa: PLR2004
            and before.st_size == binding["size"],
            "actor evidence file metadata differs",
        )
        checksum = hashlib.sha256()
        for block in files.chunks(descriptor, before.st_size, guard):
            checksum.update(block)
        require(
            checksum.hexdigest() == binding["sha256"], "actor evidence independent reread differs"
        )
        files._same(before, os.fstat(descriptor))
        files._same(before, os.stat(name, dir_fd=destination, follow_symlinks=False))


def capture(  # noqa: PLR0913 - native reader, actor and separate work bounds
    reader: Reader,
    expected: dict[str, object],
    output: Path,
    *,
    maximum_bytes: int,
    maximum_entries: int,
    guard: Callable[[], None],
) -> dict[str, object]:
    selected = str(expected["id"])
    before = reader.inspect_actor(selected)
    require_exportable(before, expected)
    directory(output.parent)
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

            current()
            files._document(destination, "inspect.json", before)
            rootfs = _stream(
                destination,
                "rootfs.tar",
                reader.actor_bytes("export", selected, current),
                maximum=maximum_bytes,
                guard=current,
            )
            logs = _stream(
                destination,
                "logs",
                reader.actor_bytes("logs", selected, current),
                maximum=maximum_bytes - cast(int, rootfs["size"]),
                guard=current,
            )
            with (
                files.child(destination, "rootfs.tar", is_directory=False) as archive,
                os.fdopen(os.dup(archive), "rb") as stream,
                tarfile.open(fileobj=stream, mode="r|") as tar,
            ):
                count = 0
                for _member in tar:
                    current()
                    count += 1
                    require(
                        count <= maximum_entries, "actor rootfs archive exceeds its entry bound"
                    )
                require(count > 0, "actor rootfs export is empty")
            require(
                reader.inspect_actor(selected) == before, "actor changed during complete export"
            )
            result = {
                "format": FORMAT,
                "actor": expected,
                "inspect_sha256": digest(before),
                "rootfs": rootfs,
                "logs": logs,
                "archive_entries": count,
                "persistent_mounts": "none",
                "automatic_recovery": False,
            }
            current()
            files._document(destination, "verified.json", result)
            current()
            return result
    finally:
        os.close(parent)


def verify(
    output: Path,
    expected: dict[str, object],
    *,
    maximum_bytes: int,
    maximum_entries: int,
    guard: Callable[[], None],
) -> dict[str, object]:
    directory(output)
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        files._parent_linked(output.parent, parent)
        with files.child(parent, output.name, is_directory=True) as destination:

            def current() -> None:
                guard()
                files._parent_linked(output.parent, parent)
                files._linked(parent, output.name, destination)

            value = files._read_document(destination, "verified.json")
            raw = files._read_document(destination, "inspect.json")
            require_exportable(raw, expected)
            require(
                value.get("format") == FORMAT
                and value.get("actor") == expected
                and value.get("inspect_sha256") == digest(raw)
                and value.get("persistent_mounts") == "none"
                and value.get("automatic_recovery") is False
                and type(value.get("archive_entries")) is int
                and 0 < cast(int, value["archive_entries"]) <= maximum_entries,
                "actor export proof differs from original identity",
            )
            total = 0
            for name, key in (("rootfs.tar", "rootfs"), ("logs", "logs")):
                binding = cast(dict[str, object], value[key])
                size = binding["size"]
                require(type(size) is int and size >= 0, "actor export byte count is invalid")
                total += cast(int, size)
                require(total <= maximum_bytes, "actor export exceeds approved byte bound")
                _reread(destination, name, binding, guard=current)
            require(
                set(files._names(destination))
                == {"inspect.json", "rootfs.tar", "logs", "verified.json"},
                "actor export contains unbound evidence",
            )
            current()
            return value
    finally:
        os.close(parent)
