"""Bounded, immutable prior restore provenance, retained without rewriting it."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.backup_identity import framed_digest, require_digest
from lowerduckpond_static_host_agent.durable import DurableDirectory, _rename_noreplace
from lowerduckpond_static_host_agent.host_restore_journal import (
    GATE,
    JOURNAL,
    LOCK,
    MAX_RESTORE_BYTES,
    PHASES,
    RESTORE_SCHEMA,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
    exact_object,
)

INVENTORY_SCHEMA: Final = "lowerduckpond-host-restore-provenance-v1"
PRIOR_SCHEMA: Final = "lowerduckpond-host-restore-prior-v1"
INVENTORY_NAME: Final = "provenance.json"
PRIOR_NAME: Final = "prior-provenance.json"
MAX_INVENTORY_BYTES: Final = 2 * 1024 * 1024
MAX_FILES: Final = 8192
# Two directory components per generation, below the backup's depth-40 ceiling.
MAX_HISTORY: Final = 12
_DECISION_PREFIXES: Final = ("lifecycle-", "export-retirement-", "remote-cleanup-")
_UUID_RECEIPTS: Final = (*_DECISION_PREFIXES, "audit-source-", "source-fence-")
_LARGE: Final = {"runtime-inputs.json", "decisions.json", INVENTORY_NAME}
_FIXED: Final = {
    JOURNAL[0],
    *(f"journal-{phase.value}.json" for phase in PHASES),
    *(f"{phase.value}.json" for phase in PHASES[1:]),
    "root-install.json",
    "kernel-locks.json",
    "cold-storage.json",
    "runtime-inputs.json",
    "runtime-mapping.json",
    "decisions.json",
    "local-work.json",
    "local-done.json",
    "audit-done.json",
    "backup-descriptor.json",
    "trusted-inputs.json",
    "destination.json",
    *(f"materialize-{name}.json" for name in ("state", "content", "recovery", "staging", "caddy")),
    PRIOR_NAME,
    INVENTORY_NAME,
}
_EXCLUDED: Final = {JOURNAL[0], "complete.json", "journal-complete.json", INVENTORY_NAME}
_SHA: Final = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _classified(name: str) -> bool:
    if name in _FIXED:
        return True
    for prefix in _UUID_RECEIPTS:
        if name.startswith(prefix) and name.endswith(".json"):
            validate_uuid7(name[len(prefix) : -5])
            return True
    return False


def _read(store: RestoreStore, name: str) -> bytes:
    return store.directory.read_regular(
        (name,),
        expected_owner=store.owner,
        expected_mode=0o600,
        maximum_bytes=MAX_INVENTORY_BYTES if name in _LARGE else MAX_RESTORE_BYTES,
    )


def _names(  # noqa: PLR0912 - closed set of provenance inode classes
    store: RestoreStore, *, gate_allowed: bool = False
) -> set[str]:
    temporaries = store.directory.publication_temporaries(
        expected_owner=store.owner, expected_mode=0o600, maximum_entries=64
    )
    descriptor = store.directory.duplicate_descriptor()
    try:
        names: set[str] = set()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) >= MAX_FILES:
                    raise HostRestoreError("restore_provenance_file_bound")
                metadata = entry.stat(follow_symlinks=False)
                if metadata.st_uid != store.owner or metadata.st_gid != store.owner:
                    raise HostRestoreError("restore_provenance_owner_changed")
                if entry.name == "history":
                    if (
                        not stat.S_ISDIR(metadata.st_mode)
                        or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004
                    ):
                        raise HostRestoreError("restore_provenance_history_unsafe")
                    names.add(entry.name)
                    continue
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004
                    or metadata.st_nlink != 1
                ):
                    raise HostRestoreError("restore_provenance_file_unsafe")
                if entry.name in temporaries:
                    continue
                if entry.name == LOCK:
                    if metadata.st_size != 0:
                        raise HostRestoreError("restore_provenance_lock_nonempty")
                    continue
                if entry.name == GATE[0] and gate_allowed:
                    continue
                if not _classified(entry.name):
                    raise HostRestoreError("restore_provenance_unclassified")
                if metadata.st_size > (
                    MAX_INVENTORY_BYTES if entry.name in _LARGE else MAX_RESTORE_BYTES
                ):
                    raise HostRestoreError("restore_provenance_oversized")
                names.add(entry.name)
        return names
    finally:
        os.close(descriptor)


def _row(store: RestoreStore, name: str) -> dict[str, object]:
    raw = _read(store, name)
    maximum = MAX_INVENTORY_BYTES if name in _LARGE else MAX_RESTORE_BYTES
    document = decode_json_object(raw, maximum_bytes=maximum)
    if canonical_json_bytes(document, maximum_bytes=maximum) != raw:
        raise HostRestoreError("restore_provenance_noncanonical")
    schemas = {
        "root-install.json": "lowerduckpond-host-restore-roots-v1",
        "kernel-locks.json": "lowerduckpond-host-restore-kernel-locks-v1",
        "cold-storage.json": "lowerduckpond-host-restore-cold-storage-v1",
        "runtime-inputs.json": "lowerduckpond-host-restore-runtime-inputs-v1",
        "runtime-mapping.json": "lowerduckpond-host-restore-runtime-mapping-v1",
        "decisions.json": "lowerduckpond-host-restore-decisions-v1",
        "local-work.json": "lowerduckpond-host-restore-local-work-v1",
        "local-done.json": "lowerduckpond-host-restore-local-done-v1",
        "audit-done.json": "lowerduckpond-host-restore-audit-done-v1",
        "backup-descriptor.json": "lowerduckpond-static-backup-v1",
        "trusted-inputs.json": "lowerduckpond-host-restore-inputs-v1",
        "destination.json": "lowerduckpond-host-restore-destination-v1",
        PRIOR_NAME: PRIOR_SCHEMA,
    }
    expected = schemas.get(name)
    if name.startswith(_DECISION_PREFIXES):
        expected = "lowerduckpond-host-restore-decision-v1"
    elif name.startswith("materialize-"):
        expected = "lowerduckpond-host-restore-materialization-v1"
    elif name.startswith("audit-source-"):
        expected = "lowerduckpond-host-restore-audit-source-v1"
    elif name.startswith("source-fence-"):
        expected = "lowerduckpond-host-restore-source-fence-v1"
    if expected is not None and document.get("schema") != expected:
        raise HostRestoreError("restore_provenance_schema_invalid")
    return {"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _prior(store: RestoreStore) -> dict[str, object] | None:
    try:
        raw = store.read_bytes(PRIOR_NAME)
    except FileNotFoundError:
        return None
    value = exact_object(
        decode_json_object(raw),
        {"schema", "restoreId", "journalDigest", "inventoryDigest", "source", "identity"},
    )
    if value["schema"] != PRIOR_SCHEMA or canonical_json_bytes(value) != raw:
        raise HostRestoreError("restore_prior_provenance_invalid")
    validate_uuid7(value["restoreId"])
    require_digest(value["journalDigest"], RESTORE_SCHEMA)
    require_digest(value["inventoryDigest"], INVENTORY_SCHEMA)
    if type(value["source"]) is not str or not Path(value["source"]).is_absolute():
        raise HostRestoreError("restore_prior_provenance_source_invalid")
    identity = exact_object(value["identity"], {"device", "inode"})
    if any(type(number) is not int or number <= 0 for number in identity.values()):
        raise HostRestoreError("restore_prior_provenance_identity_invalid")
    return value


@contextmanager
def _previous(store: RestoreStore) -> Iterator[RestoreStore | None]:
    prior = _prior(store)
    try:
        descriptor = store.directory._open_directory(("history",))
    except FileNotFoundError:
        if prior is not None:
            raise HostRestoreError("restore_prior_provenance_missing") from None
        yield None
        return
    try:
        with os.scandir(descriptor) as entries:
            names = {entry.name for entry in entries}
        if prior is None or names != {prior["restoreId"]}:
            raise HostRestoreError("restore_prior_provenance_unclassified")
        child = store.directory._open_directory(("history", str(prior["restoreId"])))
    finally:
        os.close(descriptor)
    with DurableDirectory(
        child, expected_owner=store.owner, expected_directory_mode=0o700
    ) as directory:
        result = RestoreStore(directory, store.owner)
        journal = result.read()
        if (
            journal is None
            or journal.phase is not RestorePhase.COMPLETE
            or journal.restore_id != prior["restoreId"]
            or journal.digest != prior["journalDigest"]
            or framed_digest(INVENTORY_SCHEMA, _read(result, INVENTORY_NAME))
            != prior["inventoryDigest"]
        ):
            raise HostRestoreError("restore_prior_provenance_binding_changed")
        # Restic recreates inodes. The receipt's identity authorizes only the
        # original import rename; journal and content digests survive backups.
        yield result


def _inventory(store: RestoreStore, *, deep: bool, gate_allowed: bool = False) -> dict[str, str]:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore_provenance_incomplete")
    if gate_allowed:
        try:
            gate = store.read_bytes(GATE[0])
        except FileNotFoundError:
            pass
        else:
            if gate != canonical_json_bytes(
                {"schema": "lowerduckpond-host-restore-gate-v1", "restoreId": journal.restore_id}
            ):
                raise HostRestoreError("restore_provenance_gate_changed")
    raw = _read(store, INVENTORY_NAME)
    value = exact_object(
        decode_json_object(raw, maximum_bytes=MAX_INVENTORY_BYTES),
        {"schema", "verifiedJournalDigest", "files"},
    )
    digest = framed_digest(INVENTORY_SCHEMA, raw)
    complete = decode_json_object(store.read_bytes("complete.json"))
    if (
        canonical_json_bytes(value, maximum_bytes=MAX_INVENTORY_BYTES) != raw
        or value["schema"] != INVENTORY_SCHEMA
        or complete.get("provenanceInventory") != digest
        or value["verifiedJournalDigest"]
        != framed_digest(RESTORE_SCHEMA, store.read_bytes("journal-verified.json"))
        or type(value["files"]) is not list
        or len(value["files"]) > MAX_FILES
    ):
        raise HostRestoreError("restore_provenance_inventory_invalid")
    if deep:
        _decision_inventory(store)
    rows = []
    for item in value["files"]:
        row = exact_object(item, {"name", "size", "sha256"})
        name = row["name"]
        if (
            type(name) is not str
            or not _classified(name)
            or name in _EXCLUDED
            or type(row["size"]) is not int
            or not 0 < row["size"] <= (MAX_INVENTORY_BYTES if name in _LARGE else MAX_RESTORE_BYTES)
            or type(row["sha256"]) is not str
            or _SHA.fullmatch(row["sha256"]) is None
        ):
            raise HostRestoreError("restore_provenance_inventory_row_invalid")
        if deep and _row(store, name) != row:
            raise HostRestoreError("restore_provenance_content_changed")
        rows.append(name)
    if rows != sorted(set(rows)) or set(rows) != _names(
        store, gate_allowed=gate_allowed
    ) - _EXCLUDED - {"history"}:
        raise HostRestoreError("restore_provenance_inventory_incomplete")
    return digest


def _decision_inventory(store: RestoreStore) -> None:
    # Load a potentially large decision ledger once per full capture, not once
    # per retained decision. Ordinary readers verify only their requested row.
    from lowerduckpond_static_host_agent.host_restore_decisions import (  # noqa: PLC0415
        require_decision_inventory,
    )

    require_decision_inventory(store)


@contextmanager
def provenance_stores(
    store: RestoreStore,
    *,
    deep: bool = False,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> Iterator[tuple[RestoreStore, ...]]:
    """Oldest first, with every ancestor closed and bound to its parent.

    The current coordinator may be incomplete. Callers still enforce its phase
    before consuming decisions or mappings. Ancestors must always be complete.
    """
    journal = store.read()
    descriptor = store.directory.duplicate_descriptor()
    try:
        if os.fstat(descriptor).st_gid != store.owner:
            raise HostRestoreError("restore_provenance_root_group_changed")
    finally:
        os.close(descriptor)
    if journal is None:
        if _names(store):
            raise HostRestoreError("restore_provenance_lost_journal")
        yield ()
        return
    if depth >= MAX_HISTORY or journal.restore_id in seen:
        raise HostRestoreError("restore_provenance_history_bound")
    if journal.phase is RestorePhase.COMPLETE:
        _inventory(store, deep=deep, gate_allowed=depth == 0)
    elif depth:
        raise HostRestoreError("restore_prior_provenance_incomplete")
    with _previous(store) as previous:
        if previous is None:
            yield (store,)
        else:
            with provenance_stores(
                previous, deep=deep, depth=depth + 1, seen=seen | {journal.restore_id}
            ) as ancestors:
                yield (*ancestors, store)


def require_backup_provenance(root: Path, *, owner: int) -> None:
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        store = RestoreStore(directory, owner)
        try:
            store.read_bytes(GATE[0])
        except FileNotFoundError:
            pass
        else:
            raise HostRestoreError("backup_restore_provenance_gated")
        journal = store.read()
        if journal is not None and journal.phase is not RestorePhase.COMPLETE:
            raise HostRestoreError("backup_restore_provenance_incomplete")
        with provenance_stores(store, deep=True):
            pass


def seal_provenance(store: RestoreStore) -> dict[str, str]:
    """Seal before complete; the complete receipt binds this immutable inventory."""
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.VERIFIED:
        raise HostRestoreError("restore_provenance_requires_verified")
    with provenance_stores(store, deep=True):
        pass
    _decision_inventory(store)
    names = _names(store, gate_allowed=True) - _EXCLUDED - {"history"}
    raw = canonical_json_bytes(
        {
            "schema": INVENTORY_SCHEMA,
            "verifiedJournalDigest": journal.digest,
            "files": [_row(store, name) for name in sorted(names)],
        },
        maximum_bytes=MAX_INVENTORY_BYTES,
    )
    try:
        existing = _read(store, INVENTORY_NAME)
    except FileNotFoundError:
        store.directory.create_immutable((INVENTORY_NAME,), raw, mode=0o600)
    else:
        if existing != raw:
            raise HostRestoreError("restore_provenance_seal_changed")
    return framed_digest(INVENTORY_SCHEMA, raw)


def import_prior_provenance(  # noqa: PLR0912,PLR0915 - journaled single same-filesystem rename
    store: RestoreStore,
    source: Path,
    *,
    failure_hook: Callable[[str], None] = lambda _boundary: None,
) -> None:
    """Move the validated private recovery tree into one immutable ancestor.

    This preserves original receipt bytes and never replaces the live journal,
    gate, or lease. A resumed rename uses its prior durable inode authorization.
    """
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.VALIDATED:
        raise HostRestoreError("restore_prior_import_requires_validated")
    source = source.absolute()
    prior = _prior(store)
    if prior is None:
        require_backup_provenance(source, owner=store.owner)
        with DurableDirectory.open(
            source, expected_owner=store.owner, expected_directory_mode=0o700
        ) as directory:
            previous = RestoreStore(directory, store.owner)
            old = previous.read()
            if old is None:
                return
            with provenance_stores(previous, deep=True) as ancestors:
                if len(ancestors) >= MAX_HISTORY or any(
                    ancestor.read().restore_id == journal.restore_id  # type: ignore[union-attr]
                    for ancestor in ancestors
                ):
                    raise HostRestoreError("restore_provenance_history_bound")
            descriptor = directory.duplicate_descriptor()
            try:
                metadata = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            prior = {
                "schema": PRIOR_SCHEMA,
                "restoreId": old.restore_id,
                "journalDigest": old.digest,
                "inventoryDigest": framed_digest(INVENTORY_SCHEMA, _read(previous, INVENTORY_NAME)),
                "source": str(source),
                "identity": {"device": metadata.st_dev, "inode": metadata.st_ino},
            }
        store.immutable(PRIOR_NAME, canonical_json_bytes(prior))
        failure_hook("receipt")
    if prior["source"] != str(source):
        raise HostRestoreError("restore_prior_import_source_changed")
    parent = store.directory.duplicate_descriptor()
    try:
        with suppress(FileExistsError):
            os.mkdir("history", 0o700, dir_fd=parent)
        os.fsync(parent)
        target = store.directory._open_directory(("history",))
        try:
            with os.scandir(target) as entries:
                if any(entry.name != prior["restoreId"] for entry in entries):
                    raise HostRestoreError("restore_prior_provenance_unclassified")
            source_parent = os.open(
                source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            try:
                opened_parent = os.fstat(source_parent)
                if (
                    opened_parent.st_uid != store.owner
                    or stat.S_IMODE(opened_parent.st_mode) & 0o022
                ):
                    raise HostRestoreError("restore_prior_import_parent_unsafe")
                identities: list[dict[str, int] | None] = []
                for descriptor, name in (
                    (source_parent, source.name),
                    (target, str(prior["restoreId"])),
                ):
                    try:
                        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        identities.append(None)
                        continue
                    if (
                        not stat.S_ISDIR(metadata.st_mode)
                        or metadata.st_uid != store.owner
                        or metadata.st_gid != store.owner
                        or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004
                        or metadata.st_dev != os.fstat(target).st_dev
                    ):
                        raise HostRestoreError("restore_prior_import_root_unsafe")
                    identities.append({"device": metadata.st_dev, "inode": metadata.st_ino})
                if identities == [prior["identity"], None]:
                    _rename_noreplace(
                        source_parent, source.name, str(prior["restoreId"]), destination_fd=target
                    )
                    failure_hook("rename")
                elif identities != [None, prior["identity"]]:
                    raise HostRestoreError("restore_prior_import_identity_changed")
                os.fsync(source_parent)
                failure_hook("source-sync")
                os.fsync(target)
                failure_hook("target-sync")
            finally:
                os.close(source_parent)
        finally:
            os.close(target)
        os.fsync(parent)
        failure_hook("parent-sync")
    finally:
        os.close(parent)
    with provenance_stores(store, deep=True):
        pass
