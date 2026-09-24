"""Durable host-restore admission, independent of replaced tenant/kernel locks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import (
    GATE,
    JOURNAL,
    LOCK,
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
    exact_object,
)

RECOVERY_ROOT: Final = Path("/var/lib/lowerduckpond/recovery")
GATE_SCHEMA: Final = "lowerduckpond-host-restore-gate-v1"
INGRESS: Final = ("ingress-pending.json",)
INGRESS_SCHEMA: Final = "lowerduckpond-host-restore-ingress-v1"


def close_gate(store: RestoreStore, restore_id: str) -> None:
    """Persist before stopping services or materializing any recovered bytes."""
    store.immutable(
        GATE[0],
        canonical_json_bytes({"schema": GATE_SCHEMA, "restoreId": validate_uuid7(restore_id)}),
    )


def _read(directory: DurableDirectory, path: tuple[str, ...], owner: int) -> bytes:
    return directory.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RESTORE_BYTES
    )


def gate_pending(store: RestoreStore) -> bool:
    try:
        raw = store.read_bytes(GATE[0])
    except FileNotFoundError:
        return False
    journal = store.read()
    if journal is None or raw != canonical_json_bytes(
        {"schema": GATE_SCHEMA, "restoreId": journal.restore_id}
    ):
        raise HostRestoreError("restore gate belongs to another transaction")
    return True


def ingress_record(store: RestoreStore) -> bytes:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore ingress requires durable completion")
    return canonical_json_bytes(
        {"schema": INGRESS_SCHEMA, "completedJournalDigest": journal.digest}
    )


def ingress_pending(store: RestoreStore) -> bool:
    try:
        raw = store.read_bytes(INGRESS[0])
    except FileNotFoundError:
        return False
    if raw != ingress_record(store):
        raise HostRestoreError("restore ingress authorization changed")
    return True


def restore_admission(
    root: Path = RECOVERY_ROOT, *, owner: int = 0, caddy: bool = False, boot: bool = False
) -> bool:
    """Return permission only from a complete, canonical root-owned transaction.

    An incomplete gate may precede the first journal. Caddy alone is permitted
    at installed, behind the independent firewall gate, to acquire certificates
    through its ordinary invocation-fenced start. All mutation stays closed.
    """
    if not os.path.lexists(root):
        return True
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        try:
            gate_raw = _read(directory, GATE, owner)
        except FileNotFoundError:
            gate = None
        else:
            gate = exact_object(decode_json_object(gate_raw), {"schema", "restoreId"})
            if gate["schema"] != GATE_SCHEMA or canonical_json_bytes(gate) != gate_raw:
                raise HostRestoreError("restore gate is invalid")
            validate_uuid7(gate["restoreId"])
        try:
            journal = RestoreJournal.from_bytes(_read(directory, JOURNAL, owner))
        except FileNotFoundError:
            if gate is not None:
                return False
            descriptor = directory.duplicate_descriptor()
            try:
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        if entry.name != LOCK or _read(directory, (LOCK,), owner) != b"":
                            raise HostRestoreError("restore provenance lost its journal") from None
            finally:
                os.close(descriptor)
            return True
        # Read and bind every immutable phase receipt, even at complete.
        if RestoreStore(directory, owner).read() != journal:
            raise HostRestoreError("restore provenance changed while reading")
        if gate is None:
            pending = ingress_pending(RestoreStore(directory, owner))
            return journal.phase is RestorePhase.COMPLETE and not (boot and pending)
        if gate["restoreId"] != journal.restore_id:
            raise HostRestoreError("restore gate belongs to another transaction")
        return caddy and journal.phase in {
            RestorePhase.INSTALLED,
            RestorePhase.VERIFIED,
            RestorePhase.COMPLETE,
        }


def require_restore_admission(*, caddy: bool = False) -> None:
    if not restore_admission(caddy=caddy):
        raise HostRestoreError("host_restore_pending")


def open_gate(store: RestoreStore) -> None:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore completion is not durable")
    # Commit ordinary admission before opening public ingress. A separate
    # durable intent keeps unfinished firewall cleanup resumable across reboot.
    store.directory.remove(GATE, missing_ok=True)
