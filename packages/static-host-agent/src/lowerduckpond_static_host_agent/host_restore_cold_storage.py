"""Prove cold Caddy storage once; never erase newly acquired state on retry."""

from __future__ import annotations

import os
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)

SCHEMA = "lowerduckpond-host-restore-cold-storage-v1"
NAME = "cold-storage.json"


def require_cold_storage(
    store: RestoreStore, path: Path, *, caddy_owner: int, caddy_group: int
) -> dict[str, object]:
    """The fresh bootstrap creates the empty correctly owned root, never Caddy.

    The inode is bound before runtime preparation. Installed startup may fill
    it; later attempts retain all certificate and ACME account evidence. Moving
    or replacing that root cannot silently authorize another cold attempt.
    """
    journal = store.read()
    if journal is None:
        raise HostRestoreError("restore_cold_storage_has_no_journal")
    prepared = RestoreJournal.from_bytes(store.read_bytes("journal-prepared.json"))
    with DurableDirectory.open(
        path, expected_owner=caddy_owner, expected_directory_mode=0o700
    ) as directory:
        descriptor = directory.duplicate_descriptor()
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_gid != caddy_group:
                raise HostRestoreError("restore_cold_storage_unsafe")
            expected: dict[str, object] = {
                "schema": SCHEMA,
                "preparedJournalDigest": prepared.digest,
                "path": str(path.absolute()),
                "owner": caddy_owner,
                "group": caddy_group,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
            try:
                raw = store.read_bytes(NAME)
            except FileNotFoundError:
                if journal.phase is not RestorePhase.PREPARED:
                    raise HostRestoreError(
                        "restore_cold_storage_missing_original_receipt"
                    ) from None
                raw = canonical_json_bytes(expected)
                with os.scandir(descriptor) as entries:
                    if next(entries, None) is not None:
                        raise HostRestoreError("restore_cold_storage_not_fresh") from None
                os.fsync(descriptor)
                store.immutable(NAME, raw)
            if raw != canonical_json_bytes(expected):
                raise HostRestoreError("restore_cold_storage_identity_changed")
            if PHASES.index(journal.phase) < PHASES.index(RestorePhase.INSTALLED):
                with os.scandir(descriptor) as entries:
                    if next(entries, None) is not None:
                        raise HostRestoreError("restore_cold_storage_started_before_installation")
            return decode_json_object(raw)
        finally:
            os.close(descriptor)
