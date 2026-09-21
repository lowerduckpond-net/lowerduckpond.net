from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from test_audit_archive_admission import grant_protection
from test_audit_archive_formats import IDENTITY, LINEAGE, ROTATION
from test_audit_archive_store import rotation
from test_audit_archive_store import (
    state as state,  # noqa: PLC0414 - re-export shared pytest fixture
)


def maintenance() -> dict[str, object]:
    return {
        "schema": journal.MAINTENANCE_SCHEMA,
        "maintenanceId": ROTATION,
        "lineageId": LINEAGE,
        "repositoryBinding": IDENTITY.binding(),
        "expectedHeadDigest": framed_digest(formats.HEAD_FORMAT, b"component-head"),
        "protectedInventoryDigest": framed_digest(
            journal.PROTECTION_INVENTORY_FORMAT, b"component-inventory"
        ),
        "protectedSnapshotIds": ["c" * 64],
        "removeIds": ["a" * 64, "b" * 64],
        "phase": "prepared",
    }


@pytest.mark.parametrize("phase", ["prepared", "forgotten", "pruning", "checked"])
def test_maintenance_resume_keeps_exact_disjoint_full_id_sets(phase: str) -> None:
    record = maintenance()
    record["phase"] = phase
    assert journal.decode_maintenance_intent(canonical_json_bytes(record)) == record


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("phase", "repair"),
        ("removeIds", ["c" * 64]),
        ("removeIds", ["a" * 8]),
        ("removeIds", ["b" * 64, "a" * 64]),
        ("removeIds", ["a" * 64, "a" * 64]),
        ("protectedSnapshotIds", []),
        ("protectedSnapshotIds", ["c" * 64, "c" * 64]),
        ("extra", "unknown"),
        ("lineageId", "latest"),
        ("maintenanceId", "latest"),
        ("protectedInventoryDigest", framed_digest(formats.HEAD_FORMAT, b"wrong-domain")),
        ("expectedHeadDigest", framed_digest(formats.DESCRIPTOR_FORMAT, b"wrong-domain")),
    ],
)
def test_maintenance_rejects_ambiguous_or_destructive_authority(key: str, value: object) -> None:
    with pytest.raises(BackupIdentityError):
        journal.decode_maintenance_intent(canonical_json_bytes({**maintenance(), key: value}))


@pytest.mark.parametrize(
    "fault",
    [
        "number-not-string",
        "over-uint64",
        "wrong-size",
        "wrong-count",
        "leading-zero",
        "prepared-with-id",
        "verified-without-id",
        "unknown-phase",
    ],
)
def test_rotation_resume_requires_exact_source_and_phase_binding(state: Path, fault: str) -> None:
    record = rotation(state)
    generation = record["sourceGeneration"]
    assert type(generation) is list
    if fault == "number-not-string":
        generation[0] = 1
    elif fault == "over-uint64":
        generation[0] = str(1 << 64)
    elif fault == "wrong-size":
        generation[2] = "1"
    elif fault == "wrong-count":
        generation.pop()
    elif fault == "leading-zero":
        generation[0] = "01"
    elif fault == "prepared-with-id":
        record["snapshotIds"] = ["c" * 64]
    elif fault == "verified-without-id":
        record["phase"] = "verified"
    else:
        record["phase"] = "remove-anything"
    with pytest.raises(BackupIdentityError):
        journal.decode_rotation_intent(canonical_json_bytes(record))


@pytest.mark.parametrize(
    "fault",
    ["duplicate-descriptor", "reused-snapshot", "abbreviated-id", "unsorted", "empty-copies"],
)
def test_duplicate_inventory_cannot_hide_conflicting_snapshot_references(fault: str) -> None:
    digest = framed_digest(formats.DESCRIPTOR_FORMAT, b"component-descriptor")
    rows = [{"descriptorDigest": digest, "snapshotIds": ["c" * 64]}]
    if fault == "duplicate-descriptor":
        rows.append({"descriptorDigest": digest, "snapshotIds": ["d" * 64]})
    elif fault == "reused-snapshot":
        rows.append(
            {
                "descriptorDigest": framed_digest(formats.DESCRIPTOR_FORMAT, b"another"),
                "snapshotIds": ["c" * 64],
            }
        )
    elif fault == "abbreviated-id":
        rows[0]["snapshotIds"] = ["c" * 8]
    elif fault == "unsorted":
        rows[0]["snapshotIds"] = ["d" * 64, "c" * 64]
    else:
        rows[0]["snapshotIds"] = []
    record = {
        "schema": journal.DUPLICATES_SCHEMA,
        "lineageId": LINEAGE,
        "repositoryBinding": IDENTITY.binding(),
        "entries": rows,
    }
    with pytest.raises(BackupIdentityError):
        journal.decode_duplicates(canonical_json_bytes(record))


@pytest.mark.parametrize("record_kind", ["rotation", "maintenance", "protection", "duplicates"])
@pytest.mark.parametrize("fault", ["whitespace", "duplicate-key", "oversize"])
def test_every_journal_requires_canonical_bounded_json(
    state: Path, record_kind: str, fault: str
) -> None:
    decoder: Callable[[bytes], dict[str, object]]
    if record_kind == "rotation":
        record, decoder = rotation(state), journal.decode_rotation_intent
    elif record_kind == "maintenance":
        record, decoder = maintenance(), journal.decode_maintenance_intent
    elif record_kind == "protection":
        record, decoder = grant_protection(state), journal.decode_protection_status
    else:
        record = {
            "schema": journal.DUPLICATES_SCHEMA,
            "lineageId": LINEAGE,
            "repositoryBinding": IDENTITY.binding(),
            "entries": [],
        }
        decoder = journal.decode_duplicates
    raw = canonical_json_bytes(record)
    assert decoder(raw) == record
    if fault == "whitespace":
        raw = b" " + raw
    elif fault == "duplicate-key":
        raw = b'{"schema":"duplicate",' + raw[1:]
    else:
        raw += b" " * journal.MAX_JOURNAL_BYTES
    with pytest.raises(BackupIdentityError):
        decoder(raw)
