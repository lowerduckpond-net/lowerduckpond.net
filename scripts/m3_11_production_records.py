"""Bounded exact-byte journal transport inside the leased production action."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path

from scripts import m3_11_production_journal as journal

ROOT = Path("/var/lib/lowerduckpond/convergence/m3-11")
FORMAT = "lowerduckpond-m3-11-production-records-v1"
MAX_RECORD_BYTES = journal.MAX_BYTES
MAX_WIRE_BYTES = 2 * len(journal.RECORDS) * journal.MAX_BYTES + 4096
DIRECTORY_MODE = 0o700


def encode(records: list[tuple[str, bytes]]) -> bytes:
    journal.validate(records)
    return journal.canonical(
        {
            "format": FORMAT,
            "records": [{"name": name, "raw": raw.decode("ascii")} for name, raw in records],
        }
    )


def decode(raw: bytes) -> list[tuple[str, bytes]]:
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError("production journal response exceeds its bound")
    document = json.loads(raw)
    if (
        type(document) is not dict
        or set(document) != {"format", "records"}
        or document["format"] != FORMAT
        or type(document["records"]) is not list
        or len(document["records"]) > len(journal.RECORDS)
    ):
        raise ValueError("production journal response is invalid")
    records = []
    for item in document["records"]:
        if (
            type(item) is not dict
            or set(item) != {"name", "raw"}
            or type(item["name"]) is not str
            or type(item["raw"]) is not str
        ):
            raise ValueError("production journal response record is invalid")
        records.append((item["name"], item["raw"].encode("ascii")))
    if encode(records) != raw:
        raise ValueError("production journal response changed its exact representation")
    return records


def operate(directory: Path, arguments: Sequence[str], raw: bytes, *, owner: int) -> bytes:
    """Read or publish one original proposal; never replay an invented chain.

    The remote entry point supplies the fixed path and requires execution inside
    the existing leased systemd action. The predecessor convergence directory
    must already exist, with its original private ownership and mode.
    """
    publish = len(arguments) == 2 and arguments[0] == "publish"  # noqa: PLR2004 - fixed wire shape
    if (
        (not publish and list(arguments) != ["read"])
        or len(raw) > journal.MAX_BYTES
        or (not publish and raw)
        or (publish and arguments[1] not in journal.RECORDS)
    ):
        raise ValueError("invalid production journal operation")
    parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(parent)
        if before.st_uid != owner or stat.S_IMODE(before.st_mode) != DIRECTORY_MODE:
            raise ValueError("production convergence directory is unsafe")
        try:
            directory.stat(follow_symlinks=False)
        except FileNotFoundError:
            if not publish:
                return encode([])
            if arguments[1] != "original":
                raise ValueError("production journal disappeared") from None
            # Reject malformed first authority before creating a durable root.
            journal.validate([("original", raw)])
            os.mkdir(directory.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        with journal.locked(
            directory, owner=owner, create=publish and arguments[1] == "original"
        ) as state:
            if publish:
                state.publish(arguments[1], raw)
            result = encode(state.records())
        after = directory.parent.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
        ):
            raise ValueError("production convergence directory changed")
        return result
    finally:
        os.close(parent)
