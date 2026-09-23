"""Recreate kernel locks only after root installation; retain durable cursors."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.durable import DurableDirectory, _rename_noreplace
from lowerduckpond_static_host_agent.host_restore_install import InstallHook
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.locks import LockName

SCHEMA = "lowerduckpond-host-restore-kernel-locks-v1"


def _inode(parent: int, name: str, owner: int) -> dict[str, int] | None:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
        )
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004
            or metadata.st_nlink != 1
            or metadata.st_size != 0
            or metadata.st_dev != os.fstat(parent).st_dev
        ):
            raise HostRestoreError("restore kernel lock has unsafe metadata")
        os.fsync(descriptor)
        return {"device": metadata.st_dev, "inode": metadata.st_ino}
    finally:
        os.close(descriptor)


def recreate_kernel_locks(
    store: RestoreStore,
    state: Path,
    private: Path,
    *,
    failure_hook: InstallHook | None = None,
) -> dict[str, object]:
    """The separately held coordinator lock remains untouched throughout.

    Every fresh and inert inode is recorded before any rename. Prior empty lock
    files remain in the private same-filesystem container; durable recovery
    cursors and lineage seals stay exactly where they were restored.
    """
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.RUNTIME_PREPARED:
        raise HostRestoreError("restore kernel locks lack installation authority")
    install = decode_json_object(store.read_bytes("root-install.json"))
    root = cast(dict[str, dict[str, object]], install["roots"])["state"]
    metadata = state.stat(follow_symlinks=False)
    if install["preparedJournalDigest"] != journal.digest or root["candidate"] != {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }:
        raise HostRestoreError("restore state root has not been installed")
    with (
        DurableDirectory.open(
            state / "locks", expected_owner=store.owner, expected_directory_mode=0o700
        ) as locks,
        DurableDirectory.open(
            private, expected_owner=store.owner, expected_directory_mode=0o700
        ) as retained,
    ):
        active_fd, private_fd = locks.duplicate_descriptor(), retained.duplicate_descriptor()
        try:
            return _replace_locks(store, active_fd, private_fd, failure_hook=failure_hook)
        finally:
            os.close(active_fd)
            os.close(private_fd)


def _lock_receipt(store: RestoreStore, active: int, private: int) -> dict[str, object]:
    try:
        raw = store.read_bytes("kernel-locks.json")
    except FileNotFoundError:
        rows: dict[str, object] = {}
        for lock in LockName:
            name = lock.filename
            original = _inode(active, name, store.owner)
            if original is None or _inode(private, "restored-" + name, store.owner) is not None:
                raise HostRestoreError("restore original kernel lock is unbound") from None
            with suppress(FileExistsError):
                descriptor = os.open(
                    "fresh-" + name,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=private,
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            rows[name] = {
                "original": original,
                "fresh": _inode(private, "fresh-" + name, store.owner),
            }
        os.fsync(private)
        raw = canonical_json_bytes({"schema": SCHEMA, "locks": rows})
        store.immutable("kernel-locks.json", raw)
    return _validate_receipt(raw)


def _validate_receipt(raw: bytes) -> dict[str, object]:
    receipt = exact_object(decode_json_object(raw), {"schema", "locks"})
    if receipt["schema"] != SCHEMA or canonical_json_bytes(receipt) != raw:
        raise HostRestoreError("restore kernel lock receipt is invalid")
    rows = exact_object(receipt["locks"], {lock.filename for lock in LockName})
    identities: set[tuple[int, int]] = set()
    for value in rows.values():
        row = exact_object(value, {"original", "fresh"})
        for identity in row.values():
            numbers = exact_object(identity, {"device", "inode"})
            if any(type(number) is not int or number <= 0 for number in numbers.values()):
                raise HostRestoreError("restore kernel lock identity is invalid")
            pair = (cast(int, numbers["device"]), cast(int, numbers["inode"]))
            if pair in identities:
                raise HostRestoreError("restore kernel lock identities overlap")
            identities.add(pair)
    return receipt


def verify_kernel_locks(store: RestoreStore, state: Path, private: Path) -> dict[str, object]:
    """Later phases verify the fresh locks; they never allocate replacements."""
    journal = store.read()
    if journal is None or PHASES.index(journal.phase) < PHASES.index(RestorePhase.INSTALLED):
        raise HostRestoreError("restore kernel locks are not installed")
    prepared = RestoreJournal.from_bytes(store.read_bytes("journal-runtime-prepared.json"))
    install = decode_json_object(store.read_bytes("root-install.json"))
    root = cast(dict[str, dict[str, object]], install["roots"])["state"]
    metadata = state.stat(follow_symlinks=False)
    if install["preparedJournalDigest"] != prepared.digest or root["candidate"] != {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }:
        raise HostRestoreError("restore kernel lock state root changed")
    receipt = _validate_receipt(store.read_bytes("kernel-locks.json"))
    with (
        DurableDirectory.open(
            state / "locks", expected_owner=store.owner, expected_directory_mode=0o700
        ) as locks,
        DurableDirectory.open(
            private, expected_owner=store.owner, expected_directory_mode=0o700
        ) as retained,
    ):
        active_fd, private_fd = locks.duplicate_descriptor(), retained.duplicate_descriptor()
        try:
            rows = cast(dict[str, dict[str, object]], receipt["locks"])
            for name, row in rows.items():
                if (
                    _inode(active_fd, name, store.owner) != row["fresh"]
                    or _inode(private_fd, "restored-" + name, store.owner) != row["original"]
                    or _inode(private_fd, "fresh-" + name, store.owner) is not None
                ):
                    raise HostRestoreError("restore installed kernel lock changed")
        finally:
            os.close(active_fd)
            os.close(private_fd)
    return receipt


def _replace_locks(
    store: RestoreStore,
    active: int,
    private: int,
    *,
    failure_hook: InstallHook | None,
) -> dict[str, object]:
    if os.fstat(active).st_dev != os.fstat(private).st_dev:
        raise HostRestoreError("restore locks cross filesystems")
    receipt = _lock_receipt(store, active, private)
    rows = exact_object(receipt["locks"], {lock.filename for lock in LockName})
    for name, value in rows.items():
        row = exact_object(value, {"original", "fresh"})
        original = _inode(active, name, store.owner)
        fresh = _inode(private, "fresh-" + name, store.owner)
        retained = _inode(private, "restored-" + name, store.owner)
        if original == row["fresh"] and fresh is None and retained == row["original"]:
            os.fsync(active)
            os.fsync(private)
            continue
        if fresh != row["fresh"]:
            raise HostRestoreError("restore fresh kernel lock changed")
        if original == row["original"] and retained is None:
            _rename_noreplace(active, name, "restored-" + name, destination_fd=private)
            if failure_hook is not None:
                failure_hook(name, "original-renamed")
            os.fsync(active)
            os.fsync(private)
            if failure_hook is not None:
                failure_hook(name, "original-synced")
            original, retained = None, row["original"]
        if original is not None or retained != row["original"]:
            raise HostRestoreError("restore kernel lock differs from rename authority")
        _rename_noreplace(private, "fresh-" + name, name, destination_fd=active)
        if failure_hook is not None:
            failure_hook(name, "fresh-renamed")
        os.fsync(active)
        os.fsync(private)
        if failure_hook is not None:
            failure_hook(name, "fresh-synced")
    return receipt
