from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, platform_state_digest
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_store as store
from lowerduckpond_static_host_agent.backup_identity import (
    LINEAGE_SCHEMA,
    BackupIdentityError,
    decode_lineage,
    framed_digest,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, StatePathError
from test_audit_archive_formats import FIXTURES, IDENTITY, LINEAGE, descriptor, entry, index_record


def put(root: Path, path: str, value: object) -> bytes:
    raw = (
        value
        if type(value) is bytes
        else canonical_json_bytes(value, maximum_bytes=journal.MAX_JOURNAL_BYTES)
    )
    target = root / path
    target.write_bytes(raw)
    target.chmod(0o600)
    return raw


@pytest.fixture
def state(tmp_path: Path) -> Path:
    root = tmp_path / "static"
    root.mkdir(mode=0o700)
    for name in ("platform", "locks", "audit", "audit/archive"):
        (root / name).mkdir(mode=0o700)
    namespace = json.loads((FIXTURES / "platform-namespace.json").read_bytes())
    put(root, "platform/namespace.json", namespace)
    lineage = {
        "schema": LINEAGE_SCHEMA,
        "lineageId": LINEAGE,
        "repository": IDENTITY.document(),
        "repositoryBinding": IDENTITY.binding(),
        "namespaceDigest": platform_state_digest(namespace).to_dict(),
        "initializedAt": "2026-09-21T12:00:00Z",
        "initialEntryCount": 0,
        "initialTerminalEntryDigest": None,
    }
    raw = put(root, "platform/audit-lineage.json", lineage)
    put(root, "locks/audit-lineage-genesis.json", raw)
    decode_lineage(raw)
    put(root, "audit/archive/head.json", store.head_for_indexes(lineage, ()))
    return root


def read(root: Path) -> store.ArchivePrefix:
    with DurableDirectory.open(
        root, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as directory:
        return store.read_archive_prefix(directory, expected_owner=os.geteuid())


def lineage(root: Path) -> dict[str, object]:
    return decode_lineage((root / "platform/audit-lineage.json").read_bytes())


def install(root: Path) -> tuple[dict[str, object], bytes]:
    segment = canonical_json_bytes(entry())
    record = descriptor(segment)
    index = index_record(record)
    witness = formats.inspect_segment(segment).witness
    put(root, "audit/archive/index-00000000000000000000.json", index)
    put(root, "audit/archive/witness-00000000000000000000.json", witness)
    put(root, "audit/archive/head.json", store.head_for_indexes(lineage(root), (index,)))
    return index, witness


def rotation(root: Path, phase: str = "prepared") -> dict[str, object]:
    segment = canonical_json_bytes(entry())
    return {
        "schema": journal.ROTATION_INTENT_SCHEMA,
        "descriptor": descriptor(segment),
        "expectedHeadDigest": framed_digest(
            formats.HEAD_FORMAT, canonical_json_bytes(store.head_for_indexes(lineage(root), ()))
        ),
        "sourceGeneration": ["1", "2", str(len(segment)), "3", "4"],
        "phase": phase,
        "snapshotIds": [] if phase == "prepared" else ["c" * 64],
    }


def test_empty_head_preserves_existing_lineage_without_inventing_history(state: Path) -> None:
    before = (state / "platform/audit-lineage.json").read_bytes()
    prefix = read(state)
    assert prefix.head == store.head_for_indexes(lineage(state), ())
    assert prefix.segments == ()
    assert prefix.allocated_bytes > 0
    assert prefix.inodes == 2  # noqa: PLR2004 - directory and head
    assert (state / "platform/audit-lineage.json").read_bytes() == before


def test_missing_archive_directory_is_legacy_but_existing_directory_requires_head(
    state: Path,
) -> None:
    (state / "audit/archive/head.json").unlink()
    with pytest.raises(BackupIdentityError, match="head is missing"):
        read(state)
    (state / "audit/archive").rmdir()
    assert read(state) == store.ArchivePrefix(None)


def test_immutable_index_and_witness_supply_exact_original_entry(state: Path) -> None:
    index, witness = install(state)
    prefix = read(state)
    assert prefix.segments == (store.ArchivedSegment(index, witness),)
    assert prefix.segments[0].data == canonical_json_bytes(entry())
    assert prefix.head is not None and prefix.head["entryCount"] == 1


@pytest.mark.parametrize(
    "path", ["platform/audit-lineage.json", "locks/audit-lineage-genesis.json"]
)
def test_archive_cannot_reinitialize_after_loss_of_either_lineage_record(
    state: Path, path: str
) -> None:
    install(state)
    (state / path).unlink()
    with pytest.raises(FileNotFoundError):
        read(state)
    assert not (state / path).exists()


@pytest.mark.parametrize(
    "fault",
    [
        "lineage",
        "repository",
        "head-count",
        "head-digest",
        "witness",
        "index-gap",
        "unknown",
        "missing-index",
        "missing-witness",
    ],
)
def test_corrupt_or_conflicting_archive_authority_fails_closed(state: Path, fault: str) -> None:
    index, witness = install(state)
    head = store.head_for_indexes(lineage(state), (index,))
    if fault == "lineage":
        head["lineageId"] = "0198d17f-6f4a-7000-8000-000000000099"
    elif fault == "repository":
        head["repositoryBinding"] = framed_digest(
            IDENTITY.binding()["format"], b"another repository"
        )
    elif fault == "head-count":
        head["entryCount"] = 2
    elif fault == "head-digest":
        head["lastIndexDigest"] = framed_digest(formats.INDEX_FORMAT, b"another index")
    elif fault == "witness":
        put(
            state,
            "audit/archive/witness-00000000000000000000.json",
            witness.replace(b"operator@example.test", b"attacker@example.test"),
        )
    elif fault == "index-gap":
        (state / "audit/archive/index-00000000000000000000.json").rename(
            state / "audit/archive/index-00000000000000000002.json"
        )
    elif fault == "unknown":
        put(state, "audit/archive/unreviewed-authority.json", {})
    else:
        name = "index" if fault == "missing-index" else "witness"
        (state / f"audit/archive/{name}-00000000000000000000.json").unlink()
    put(state, "audit/archive/head.json", head)
    with pytest.raises(BackupIdentityError):
        read(state)


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "mode", "directory"])
def test_unsafe_archive_inodes_never_become_authority(state: Path, fault: str) -> None:
    install(state)
    path = state / "audit/archive/witness-00000000000000000000.json"
    if fault == "mode":
        path.chmod(0o644)
    elif fault == "hardlink":
        os.link(path, state / "outside-hardlink")
    else:
        path.rename(state / "outside-witness")
        if fault == "symlink":
            path.symlink_to(state / "outside-witness")
        else:
            path.mkdir(mode=0o700)
    with pytest.raises((BackupIdentityError, StatePathError)):
        read(state)


def test_valid_temporary_remains_untouched_and_counts_against_metadata_capacity(
    state: Path,
) -> None:
    before = read(state)
    name = "audit/archive/.ldp-state-" + "a" * 32
    put(state, name, b"x" * 8192)
    after = read(state)
    assert (state / name).read_bytes() == b"x" * 8192
    assert after.allocated_bytes == before.allocated_bytes + (state / name).stat().st_blocks * 512
    assert after.inodes == before.inodes + 1


@pytest.mark.parametrize("bound", ["bytes", "inodes"])
def test_archive_metadata_bounds_include_directory_and_temporaries(
    state: Path, monkeypatch: pytest.MonkeyPatch, bound: str
) -> None:
    prefix = read(state)
    name = "MAX_ARCHIVE_METADATA_BYTES" if bound == "bytes" else "MAX_ARCHIVE_METADATA_INODES"
    value = prefix.allocated_bytes - 1 if bound == "bytes" else prefix.inodes - 1
    monkeypatch.setattr(formats, name, value)
    with pytest.raises(BackupIdentityError, match="bound"):
        read(state)


def test_pending_witness_and_index_never_advance_committed_prefix(state: Path) -> None:
    attempt = rotation(state)
    put(state, "audit/archive/rotation-intent.json", attempt)
    assert read(state).segments == ()
    attempt["phase"] = "verified"
    attempt["snapshotIds"] = ["c" * 64]
    put(state, "audit/archive/rotation-intent.json", attempt)
    segment = canonical_json_bytes(entry())
    witness = formats.inspect_segment(segment).witness
    put(state, "audit/archive/witness-00000000000000000000.json", witness)
    prefix = read(state)
    assert prefix.segments == () and prefix.pending_witness == witness
    index = index_record(descriptor(segment))
    put(state, "audit/archive/index-00000000000000000000.json", index)
    prefix = read(state)
    assert prefix.segments == () and prefix.pending_index == index
    put(state, "audit/archive/head.json", store.head_for_indexes(lineage(state), (index,)))
    prefix = read(state)
    assert len(prefix.segments) == 1 and prefix.pending_index is None
    attempt["phase"] = "indexed"
    put(state, "audit/archive/rotation-intent.json", attempt)
    assert len(read(state).segments) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "no-intent",
        "unverified",
        "wrong-head",
        "wrong-descriptor",
        "premature-indexed",
        "missing-witness",
    ],
)
def test_pending_records_require_same_verified_durable_attempt(state: Path, fault: str) -> None:
    index, _witness = install(state)
    put(state, "audit/archive/head.json", store.head_for_indexes(lineage(state), ()))
    attempt = rotation(state, "verified")
    if fault == "unverified":
        attempt["phase"] = "prepared"
        attempt["snapshotIds"] = []
    elif fault == "wrong-head":
        attempt["expectedHeadDigest"] = framed_digest(formats.HEAD_FORMAT, b"another head")
    elif fault == "wrong-descriptor":
        record = attempt["descriptor"]
        assert type(record) is dict
        record["rotationId"] = "0198d17f-6f4a-7000-8000-000000000099"
    elif fault == "premature-indexed":
        attempt["phase"] = "indexed"
    elif fault == "missing-witness":
        (state / "audit/archive/witness-00000000000000000000.json").unlink()
    if fault != "no-intent":
        put(state, "audit/archive/rotation-intent.json", attempt)
    with pytest.raises(BackupIdentityError):
        read(state)
    assert (
        formats.decode_index((state / "audit/archive/index-00000000000000000000.json").read_bytes())
        == index
    )


@pytest.mark.parametrize(
    "fault", [None, "unknown-descriptor", "selected-snapshot", "unknown-lineage"]
)
def test_duplicate_inventory_preserves_known_immutable_authority(
    state: Path, fault: str | None
) -> None:
    index, _witness = install(state)
    duplicate = {
        "schema": journal.DUPLICATES_SCHEMA,
        "lineageId": LINEAGE,
        "repositoryBinding": IDENTITY.binding(),
        "entries": [{"descriptorDigest": index["descriptorDigest"], "snapshotIds": ["d" * 64]}],
    }
    if fault == "unknown-descriptor":
        duplicate["entries"] = [
            {
                "descriptorDigest": framed_digest(formats.DESCRIPTOR_FORMAT, b"unknown"),
                "snapshotIds": ["d" * 64],
            }
        ]
    elif fault == "selected-snapshot":
        duplicate["entries"] = [
            {"descriptorDigest": index["descriptorDigest"], "snapshotIds": ["c" * 64]}
        ]
    elif fault == "unknown-lineage":
        duplicate["lineageId"] = "0198d17f-6f4a-7000-8000-000000000099"
    put(state, "audit/archive/duplicates.json", duplicate)
    if fault is None:
        assert read(state).duplicates == duplicate
    else:
        with pytest.raises(BackupIdentityError):
            read(state)
