"""Resume same-filesystem root swaps from immutable, pre-rename inode evidence."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.durable import _rename_noreplace
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
    exact_object,
)

ROOT_NAMES = frozenset({"state", "content", "caddy"})
INSTALL_SCHEMA = "lowerduckpond-host-restore-roots-v1"
InstallHook = Callable[[str, str], None]


@dataclass(frozen=True)
class RootSwap:
    name: str
    destination: Path
    restore_id: str
    mode: int
    group: int

    @property
    def container_name(self) -> str:
        validate_uuid7(self.restore_id)
        if self.name not in ROOT_NAMES:
            raise HostRestoreError("restore root name is unclassified")
        return f".restore-{self.restore_id}-{self.name}"

    @property
    def container(self) -> Path:
        return self.destination.parent / self.container_name

    @property
    def candidate_name(self) -> str:
        return self.container_name + "/candidate"

    @property
    def retained_name(self) -> str:
        return self.container_name + "/prior"

    @property
    def candidate(self) -> Path:
        return self.destination.parent / self.candidate_name


def _identity(parent: int, name: str, swap: RootSwap, owner: int) -> dict[str, int] | None:
    try:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_gid != swap.group
        or stat.S_IMODE(metadata.st_mode) != swap.mode
        or metadata.st_dev != os.fstat(parent).st_dev
    ):
        raise HostRestoreError("restore root has unsafe metadata or crosses a filesystem")
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _open_parent(swap: RootSwap, owner: int) -> int:
    descriptor = os.open(
        swap.destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    metadata = os.fstat(descriptor)
    if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) & 0o022:
        os.close(descriptor)
        raise HostRestoreError("restore parent permits untrusted mutation")
    try:
        _container_identity(descriptor, swap, owner)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _container_identity(parent: int, swap: RootSwap, owner: int) -> dict[str, int]:
    private = os.open(
        swap.container_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent,
    )
    try:
        metadata = os.fstat(private)
        if (
            metadata.st_uid != owner
            or metadata.st_gid != owner
            or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004
            or metadata.st_dev != os.fstat(parent).st_dev
        ):
            raise HostRestoreError("restore container is unsafe")
        os.fsync(private)
        return {"device": metadata.st_dev, "inode": metadata.st_ino}
    finally:
        os.close(private)


def _sync_parents(parent: int, swap: RootSwap, owner: int) -> None:
    _container_identity(parent, swap, owner)
    os.fsync(parent)


def prepare_root_install(store: RestoreStore, swaps: Mapping[str, RootSwap]) -> dict[str, object]:
    if set(swaps) != ROOT_NAMES or any(name != swap.name for name, swap in swaps.items()):
        raise HostRestoreError("restore root set is incomplete")
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.RUNTIME_PREPARED:
        raise HostRestoreError("restore installation is not prepared")
    if any(swap.restore_id != journal.restore_id for swap in swaps.values()):
        raise HostRestoreError("restore root belongs to another transaction")
    try:
        raw = store.read_bytes("root-install.json")
    except FileNotFoundError:
        roots: dict[str, object] = {}
        for name, swap in sorted(swaps.items()):
            parent = _open_parent(swap, store.owner)
            try:
                if _identity(parent, swap.retained_name, swap, store.owner) is not None:
                    raise HostRestoreError("restore predecessor exists without rename authority")
                candidate = _identity(parent, swap.candidate_name, swap, store.owner)
                if candidate is None:
                    raise HostRestoreError("restore candidate root is absent")
                roots[name] = {
                    "container": _container_identity(parent, swap, store.owner),
                    "candidate": candidate,
                    "prior": _identity(parent, swap.destination.name, swap, store.owner),
                }
            finally:
                os.close(parent)
        raw = canonical_json_bytes(
            {
                "schema": INSTALL_SCHEMA,
                "restoreId": journal.restore_id,
                "preparedJournalDigest": journal.digest,
                "roots": roots,
            }
        )
        store.immutable("root-install.json", raw)
    return _validate_evidence(raw, journal)


def _validate_evidence(raw: bytes, journal: RestoreJournal) -> dict[str, object]:
    evidence = exact_object(
        decode_json_object(raw),
        {
            "schema",
            "restoreId",
            "preparedJournalDigest",
            "roots",
        },
    )
    if (
        evidence["schema"] != INSTALL_SCHEMA
        or evidence["restoreId"] != journal.restore_id
        or evidence["preparedJournalDigest"] != journal.digest
        or canonical_json_bytes(evidence) != raw
    ):
        raise HostRestoreError("restore root evidence is unbound")
    rows = exact_object(evidence["roots"], set(ROOT_NAMES))
    for value in rows.values():
        row = exact_object(value, {"container", "candidate", "prior"})
        for name, identity in row.items():
            if name == "prior" and identity is None:
                continue
            for number in exact_object(identity, {"device", "inode"}).values():
                if type(number) is not int or number <= 0:
                    raise HostRestoreError("restore root identity is invalid")
    return evidence


def verify_installed_roots(store: RestoreStore, swaps: Mapping[str, RootSwap]) -> dict[str, object]:
    """Recheck installed identities on resumed TLS/verification without renaming."""
    journal = store.read()
    if journal is None or PHASES.index(journal.phase) < PHASES.index(RestorePhase.INSTALLED):
        raise HostRestoreError("restore roots are not installed")
    if (
        set(swaps) != ROOT_NAMES
        or any(name != swap.name for name, swap in swaps.items())
        or any(swap.restore_id != journal.restore_id for swap in swaps.values())
    ):
        raise HostRestoreError("restore root set is unbound")
    prepared = RestoreJournal.from_bytes(store.read_bytes("journal-runtime-prepared.json"))
    evidence = _validate_evidence(store.read_bytes("root-install.json"), prepared)
    roots = cast(dict[str, dict[str, object]], evidence["roots"])
    for name, swap in sorted(swaps.items()):
        parent = _open_parent(swap, store.owner)
        try:
            row = roots[name]
            if (
                _container_identity(parent, swap, store.owner) != row["container"]
                or _identity(parent, swap.destination.name, swap, store.owner) != row["candidate"]
                or _identity(parent, swap.retained_name, swap, store.owner) != row["prior"]
                or _identity(parent, swap.candidate_name, swap, store.owner) is not None
            ):
                raise HostRestoreError("restore installed root identity changed")
        finally:
            os.close(parent)
    return evidence


def install_roots(
    store: RestoreStore,
    swaps: Mapping[str, RootSwap],
    *,
    failure_hook: InstallHook | None = None,
) -> dict[str, object]:
    """No merging, deletion or overwrite of an unbound destination is possible.

    The caller has stopped every worker before entering; its separate fixed
    coordinator lock survives every swap. Fresh kernel locks are created only
    after all swaps and before the installed phase can admit Caddy.
    """
    evidence = prepare_root_install(store, swaps)
    roots = cast(dict[str, dict[str, object]], evidence["roots"])
    for name, swap in sorted(swaps.items()):
        row = roots[name]
        parent = _open_parent(swap, store.owner)
        try:
            if _container_identity(parent, swap, store.owner) != row["container"]:
                raise HostRestoreError("restore container identity changed")
            candidate = _identity(parent, swap.candidate_name, swap, store.owner)
            destination = _identity(parent, swap.destination.name, swap, store.owner)
            retained = _identity(parent, swap.retained_name, swap, store.owner)
            if destination == row["candidate"] and candidate is None and retained == row["prior"]:
                # Complete a possibly interrupted parent sync before advancing.
                _sync_parents(parent, swap, store.owner)
                continue
            if candidate != row["candidate"]:
                raise HostRestoreError("restore candidate identity changed")
            if retained is None and destination == row["prior"] and destination is not None:
                _rename_noreplace(parent, swap.destination.name, swap.retained_name)
                if failure_hook is not None:
                    failure_hook(name, "prior-renamed")
                _sync_parents(parent, swap, store.owner)
                if failure_hook is not None:
                    failure_hook(name, "prior-synced")
                destination, retained = None, row["prior"]
            if destination is not None or retained != row["prior"]:
                raise HostRestoreError("restore destination differs from rename authority")
            _rename_noreplace(parent, swap.candidate_name, swap.destination.name)
            if failure_hook is not None:
                failure_hook(name, "candidate-renamed")
            _sync_parents(parent, swap, store.owner)
            if failure_hook is not None:
                failure_hook(name, "candidate-synced")
        finally:
            os.close(parent)
    return evidence
