"""Immutable administrator decisions bound to the validated restore transaction."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.backup_identity import framed_digest, require_digest
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_history import (
    MAX_FILES,
    MAX_INVENTORY_BYTES,
    provenance_stores,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
    exact_object,
)

DECISION_FORMAT: Final = "lowerduckpond-host-restore-decision-v1"
LEDGER_FORMAT: Final = "lowerduckpond-host-restore-decisions-v1"
LEDGER_NAME: Final = "decisions.json"


def seal_decisions(store: RestoreStore) -> dict[str, str]:
    """Bind thousands of immutable decisions without growing the 256 KiB journal."""
    current = store.read()
    if current is None or current.phase is not RestorePhase.VALIDATED:
        raise HostRestoreError("restore_decision_requires_validated_state")
    descriptor = store.directory.duplicate_descriptor()
    try:
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if entry.name.startswith(("lifecycle-", "export-retirement-", "remote-cleanup-")):
                    names.append(entry.name)
                    if len(names) > MAX_FILES:
                        raise HostRestoreError("restore_decision_ledger_bound")
    finally:
        os.close(descriptor)
    rows = []
    for name in sorted(names):
        if _read_decision(store, name, private_reconciliation=True) is None:
            raise HostRestoreError("restore_decision_disappeared")
        rows.append(
            {"name": name, "digest": framed_digest(DECISION_FORMAT, store.read_bytes(name))}
        )
    raw = canonical_json_bytes(
        {"schema": LEDGER_FORMAT, "validatedJournalDigest": current.digest, "decisions": rows},
        maximum_bytes=MAX_INVENTORY_BYTES,
    )
    try:
        existing = _ledger_bytes(store)
    except FileNotFoundError:
        store.directory.create_immutable((LEDGER_NAME,), raw, mode=0o600)
    else:
        if existing != raw:
            raise HostRestoreError("restore_decision_ledger_changed")
    return framed_digest(LEDGER_FORMAT, raw)


def _ledger_bytes(store: RestoreStore) -> bytes:
    return store.directory.read_regular(
        (LEDGER_NAME,),
        expected_owner=store.owner,
        expected_mode=0o600,
        maximum_bytes=MAX_INVENTORY_BYTES,
    )


def _decisions(store: RestoreStore, reconciled: dict[str, object]) -> list[object]:
    if "decisionsDigest" not in reconciled:
        # Small receipts used by private component callers fit directly inside
        # the journal; the coordinator always uses the bounded external ledger.
        value = reconciled.get("decisions")
        if type(value) is not list:
            raise HostRestoreError("restore_decision_ledger_invalid")
        return value
    raw = _ledger_bytes(store)
    document = exact_object(
        decode_json_object(raw, maximum_bytes=MAX_INVENTORY_BYTES),
        {"schema", "validatedJournalDigest", "decisions"},
    )
    if (
        "decisions" in reconciled
        or document["schema"] != LEDGER_FORMAT
        or canonical_json_bytes(document, maximum_bytes=MAX_INVENTORY_BYTES) != raw
        or framed_digest(LEDGER_FORMAT, raw) != reconciled["decisionsDigest"]
        or document["validatedJournalDigest"]
        != framed_digest(
            "lowerduckpond-host-restore-v1", store.read_bytes("journal-validated.json")
        )
        or type(document["decisions"]) is not list
        or len(document["decisions"]) > MAX_FILES
    ):
        raise HostRestoreError("restore_decision_ledger_invalid")
    return cast(list[object], document["decisions"])


def require_decision_inventory(store: RestoreStore) -> None:
    """Validate the full decision set once when sealing or capturing provenance."""
    rows = _decisions(store, decode_json_object(store.read_bytes("reconciled.json")))
    validated = RestoreJournal.from_bytes(store.read_bytes("journal-validated.json"))
    seen = set()
    for item in rows:
        row = exact_object(item, {"name", "digest"})
        name = row["name"]
        prefix = next(
            (
                prefix
                for prefix in ("lifecycle-", "export-retirement-", "remote-cleanup-")
                if type(name) is str and name.startswith(prefix)
            ),
            None,
        )
        if type(name) is not str or prefix is None or not name.endswith(".json") or name in seen:
            raise HostRestoreError("restore_decision_inventory_invalid")
        validate_uuid7(name[len(prefix) : -5])
        seen.add(name)
        require_digest(row["digest"], DECISION_FORMAT)
        raw = store.read_bytes(name)
        _document(raw, validated)
        if framed_digest(DECISION_FORMAT, raw) != row["digest"]:
            raise HostRestoreError("restore_decision_binding_mismatch")
    descriptor = store.directory.duplicate_descriptor()
    try:
        with os.scandir(descriptor) as entries:
            actual = {
                entry.name
                for entry in entries
                if entry.name.startswith(("lifecycle-", "export-retirement-", "remote-cleanup-"))
            }
    finally:
        os.close(descriptor)
    if actual != seen:
        raise HostRestoreError("restore_decision_inventory_incomplete")


def _document(raw: bytes, validated: RestoreJournal) -> dict[str, object]:
    document = exact_object(
        decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES),
        {"schema", "validatedJournalDigest", "payload"},
    )
    if (
        canonical_json_bytes(document, maximum_bytes=MAX_RESTORE_BYTES) != raw
        or document["schema"] != DECISION_FORMAT
        or document["validatedJournalDigest"] != validated.digest
        or type(document["payload"]) is not dict
    ):
        raise HostRestoreError("restore_decision_binding_mismatch")
    return document


def commit_decision(
    store: RestoreStore, name: str, payload: dict[str, object]
) -> dict[str, object]:
    current = store.read()
    if current is None or current.phase is not RestorePhase.VALIDATED:
        raise HostRestoreError("restore_decision_requires_validated_state")
    document = {
        "schema": DECISION_FORMAT,
        "validatedJournalDigest": current.digest,
        "payload": payload,
    }
    raw = canonical_json_bytes(document, maximum_bytes=MAX_RESTORE_BYTES)
    store.immutable(name, raw)
    return {"name": name, "digest": framed_digest(DECISION_FORMAT, raw)}


def read_decision(
    root: Path,
    name: str,
    *,
    owner: int,
    private_reconciliation: bool = False,
) -> dict[str, object] | None:
    """Ordinary readers require the decision's committed reconciliation receipt.

    The explicit private coordinator can validate an interrupted decision before
    advancing its phase. Public worker entrypoints remain gated throughout it.
    """
    try:
        directory = DurableDirectory.open(root, expected_owner=owner, expected_directory_mode=0o700)
    except FileNotFoundError:
        return None
    with directory:
        store = RestoreStore(directory, owner)
        with provenance_stores(store) as stores:
            found: dict[str, object] | None = None
            for source in stores:
                payload = _read_decision(
                    source, name, private_reconciliation=private_reconciliation
                )
                if payload is not None:
                    if found is not None and found != payload:
                        raise HostRestoreError("restore_decision_history_conflicts")
                    found = payload
            return found


def _read_decision(
    store: RestoreStore, name: str, *, private_reconciliation: bool
) -> dict[str, object] | None:
    try:
        raw = store.read_bytes(name)
    except FileNotFoundError:
        return None
    current = store.read()
    if current is None:
        raise HostRestoreError("restore_decision_has_no_journal")
    validated = RestoreJournal.from_bytes(store.read_bytes("journal-validated.json"))
    document = _document(raw, validated)
    if PHASES.index(current.phase) < PHASES.index(RestorePhase.RECONCILED):
        if not private_reconciliation or current.phase is not RestorePhase.VALIDATED:
            raise HostRestoreError("restore_decision_is_uncommitted")
    else:
        reconciled = decode_json_object(
            store.read_bytes("reconciled.json"), maximum_bytes=MAX_RESTORE_BYTES
        )
        decisions = _decisions(store, reconciled)
        expected = {"name": name, "digest": framed_digest(DECISION_FORMAT, raw)}
        if type(decisions) is not list or decisions.count(expected) != 1:
            raise HostRestoreError("restore_decision_is_not_in_reconciled_history")
    return cast(dict[str, object], document["payload"])
