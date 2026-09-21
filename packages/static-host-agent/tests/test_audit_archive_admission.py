from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import audit_entry_digest, canonical_json_bytes
from lowerduckpond_static_host_agent import AuditError, LockManager, StateRepository
from lowerduckpond_static_host_agent import audit_archive_admission as admission
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.durable import DurableDirectory
from test_audit_archive_formats import IDENTITY, LINEAGE, entry
from test_audit_archive_store import put, read
from test_audit_archive_store import (
    state as state,  # noqa: PLC0414 - re-export shared pytest fixture
)

NOW = 1_800_000_000


def grant_protection(root: Path, *, timestamp: int = NOW) -> dict[str, object]:
    head = (root / "audit/archive/head.json").read_bytes()
    status = {
        "schema": journal.PROTECTION_SCHEMA,
        "lineageId": LINEAGE,
        "repositoryBinding": IDENTITY.binding(),
        "headDigest": framed_digest(formats.HEAD_FORMAT, head),
        "verifiedAt": datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protectedInventoryDigest": framed_digest(
            journal.PROTECTION_INVENTORY_FORMAT, b"component-proof"
        ),
        "protectedSnapshotCount": 1,
        "protectedBytes": 1,
        "category": "verified",
    }
    put(root, "audit/archive/protection-status.json", status)
    return status


def available_capacity(descriptor: int) -> FilesystemCapacity:
    return FilesystemCapacity(
        os.fstat(descriptor).st_dev, 4096, 25_000_000, 20_000_000, 2_000_000, 1_500_000
    )


@pytest.mark.parametrize(
    "fault",
    ["missing", "stale", "future", "failure", "wrong-head", "wrong-lineage", "wrong-repository"],
)
def test_ordinary_admission_requires_fresh_proof_for_current_authority(
    state: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(time, "time", lambda: NOW)
    status = grant_protection(state)
    if fault == "stale":
        status = grant_protection(state, timestamp=NOW - admission.MAX_PROTECTION_AGE_SECONDS - 1)
    elif fault == "future":
        status = grant_protection(state, timestamp=NOW + 1)
    elif fault == "failure":
        status.update(
            category="archive-unavailable", protectedInventoryDigest=None, protectedSnapshotCount=0
        )
    elif fault == "wrong-head":
        status["headDigest"] = framed_digest(formats.HEAD_FORMAT, b"another head")
    elif fault == "wrong-lineage":
        status["lineageId"] = "0198d17f-6f4a-7000-8000-000000000099"
    elif fault == "wrong-repository":
        status["repositoryBinding"] = framed_digest(
            IDENTITY.binding()["format"], b"another repository"
        )
    put(state, "audit/archive/protection-status.json", status)
    if fault == "missing":
        (state / "audit/archive/protection-status.json").unlink()
    with pytest.raises(admission.AuditProtectionError):
        admission.require_ordinary_protection(read(state))
    # Inspection remains available for administrator diagnosis; the cache never
    # substitutes for local index/witness verification or authorizes deletion.
    assert read(state).segments == ()


def test_freshness_boundary_and_headroom_preserve_fixed_production_limits(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", available_capacity)
    grant_protection(state, timestamp=NOW - admission.MAX_PROTECTION_AGE_SECONDS)
    with DurableDirectory.open(
        state / "audit", expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as directory:
        reservation = admission.rotation_reservation(directory)
        assert reservation.allocated_bytes > formats.MAX_SEGMENT_BYTES
        assert (
            admission.admit_archive_append(directory, read(state), 4096, entry_count=0)
            == reservation.allocated_bytes
        )


@pytest.mark.parametrize("boundary", ["blocks", "inodes", "percent"])
def test_rotation_headroom_cannot_cross_existing_filesystem_free_floors(
    state: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    monkeypatch.setattr(time, "time", lambda: NOW)
    grant_protection(state)
    with DurableDirectory.open(
        state / "audit", expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as directory:
        reservation = admission.rotation_reservation(directory)

        def tight_capacity(descriptor: int) -> FilesystemCapacity:
            available = available_capacity(descriptor)
            blocks = available.available_blocks
            inodes = available.available_inodes
            if boundary == "blocks":
                blocks = (5 * 1024**3 + reservation.allocated_bytes) // 4096 - 1
            elif boundary == "inodes":
                inodes = 100_000 + reservation.unique_inodes
            else:
                blocks = available.total_blocks // 10
            return FilesystemCapacity(
                available.device,
                4096,
                available.total_blocks,
                blocks,
                available.total_inodes,
                inodes,
            )

        monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", tight_capacity)
        with pytest.raises(admission.AuditArchiveCapacityError, match="free floors"):
            admission.admit_archive_append(directory, read(state), 4096, entry_count=0)


def test_missing_remote_proof_closes_ordinary_append_but_preserves_administrator_reserve(
    state: Path,
) -> None:
    with LockManager.initialize(state / "locks", expected_owner=os.geteuid()):
        pass
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        with pytest.raises(AuditError, match="requires protection"):
            repository.append_audit(entry())
        assert not (state / "audit/segment-00000000000000000000.jsonl").exists()
        result = repository.append_audit(entry(), administrator=True)
        assert result.state.entry_count == 1
    assert (
        state / "audit/segment-00000000000000000000.jsonl"
    ).read_bytes() == canonical_json_bytes(entry())


@pytest.mark.parametrize("count", [65535, 65536, 65537])
def test_complete_entry_count_boundary_applies_even_to_an_empty_archived_head(
    state: Path, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", available_capacity)
    grant_protection(state)
    prefix = read(state)
    assert prefix.head is not None and prefix.head["entryCount"] == 0
    with DurableDirectory.open(
        state / "audit", expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as directory:
        if count < formats.MAX_WITNESSED_ENTRIES:
            assert admission.admit_archive_append(directory, prefix, 4096, entry_count=count) > 0
        else:
            with pytest.raises(admission.AuditArchiveCapacityError):
                admission.admit_archive_append(directory, prefix, 4096, entry_count=count)


def test_append_counts_the_unarchived_suffix_and_preserves_administrator_reserve(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exercise the public append path with a small component ceiling, leaving
    # the installed 65,536-entry production limit unchanged.
    ceiling = 3
    monkeypatch.setattr(formats, "MAX_WITNESSED_ENTRIES", ceiling)
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", available_capacity)
    grant_protection(state)
    with LockManager.initialize(state / "locks", expected_owner=os.geteuid()):
        pass
    previous = None
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        for sequence in range(ceiling):
            document = entry(sequence, previous)
            repository.append_audit(document)
            previous = audit_entry_digest(document).to_dict()
        path = state / "audit/segment-00000000000000000000.jsonl"
        before = path.read_bytes()
        with pytest.raises(AuditError, match="reserve bounded"):
            repository.append_audit(entry(ceiling, previous))
        assert path.read_bytes() == before
        appended = repository.append_audit(entry(ceiling, previous), administrator=True)
        assert appended.state.entry_count == ceiling + 1
