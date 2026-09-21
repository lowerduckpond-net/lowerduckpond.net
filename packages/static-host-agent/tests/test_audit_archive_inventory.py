from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_inventory as inventory
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_workspace as workspace
from lowerduckpond_static_host_agent.audit_archive_restic import (
    SNAPSHOT_SOURCE,
    VerifiedAuditSnapshot,
)
from lowerduckpond_static_host_agent.audit_archive_store import ArchivePrefix
from lowerduckpond_static_host_agent.backup_identity import (
    BackupIdentityError,
    RepositoryIdentity,
    framed_digest,
)
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot, lineage_tags
from lowerduckpond_static_host_agent.durable import DurableDirectory
from test_audit_archive_admission import available_capacity
from test_audit_archive_formats import IDENTITY, descriptor, entry
from test_audit_archive_store import install, lineage, read
from test_audit_archive_store import (
    state as state,  # noqa: PLC0414 - shared private archive fixture
)

GENESIS = "e" * 64
FIRST = "c" * 64
SECOND = "d" * 64


class Remote:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.lineage = lineage(root)
        self.records: dict[str, VerifiedAuditSnapshot] = {}
        self.calls: list[str] = []
        self.workspace = root.parent / "verification"
        self.workspace.mkdir(mode=0o700)
        monkeypatch.setattr(workspace, "measure_filesystem_capacity_descriptor", available_capacity)
        monkeypatch.setattr(inventory, "repository_genesis", lambda *_: self.lineage)
        monkeypatch.setattr(inventory, "verify_audit_snapshot", self.verify)

    def add(self, snapshot_id: str, record: dict[str, object] | None = None) -> RepositorySnapshot:
        segment = canonical_json_bytes(entry())
        record = record or descriptor(segment)
        self.records[snapshot_id] = VerifiedAuditSnapshot(
            snapshot_id,
            record,
            canonical_json_bytes(record),
            segment,
            formats.inspect_segment(segment).witness,
        )
        return RepositorySnapshot(
            snapshot_id,
            IDENTITY.node_name,
            formats.required_archive_tags(record),
            (SNAPSHOT_SOURCE,),
        )

    def verify(
        self,
        snapshot: RepositorySnapshot,
        _identity: RepositoryIdentity,
        _lineage: str,
        _environment: Mapping[str, str],
        _directory: DurableDirectory,
        *,
        expected_owner: int,
        expected_group: int,
    ) -> VerifiedAuditSnapshot:
        assert expected_owner == os.geteuid() and expected_group == os.getegid()
        self.calls.append(snapshot.snapshot_id)
        record = self.records[snapshot.snapshot_id]
        if tuple(sorted(snapshot.tags)) != formats.required_archive_tags(record.descriptor):
            raise BackupIdentityError("test protected payload has changed tags")
        return record

    def proof(
        self, snapshots: tuple[RepositorySnapshot, ...], prefix: ArchivePrefix
    ) -> inventory.ProtectedProof:
        genesis = RepositorySnapshot(GENESIS, IDENTITY.node_name, lineage_tags(self.lineage))
        return inventory.verify_protected_inventory(
            IDENTITY,
            (*snapshots, genesis),
            self.lineage,
            prefix,
            {},
            workspace=self.workspace,
            expected_owner=os.geteuid(),
            expected_group=os.getegid(),
        )


def test_empty_prefix_still_requires_permanent_remote_genesis(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = Remote(state, monkeypatch)
    proof = remote.proof((), read(state))
    assert proof.snapshot_ids == (GENESIS,)
    assert proof.orphan is None and not remote.calls
    monkeypatch.setattr(inventory, "repository_genesis", lambda *_: None)
    with pytest.raises(BackupIdentityError, match="permanent"):
        remote.proof((), read(state))


def test_indexed_and_byte_identical_duplicates_are_all_restored_and_bound(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(state)
    remote = Remote(state, monkeypatch)
    first, second = remote.add(FIRST), remote.add(SECOND)
    proof = remote.proof((second, first), read(state))
    assert remote.calls == [FIRST, SECOND]
    assert proof.snapshot_ids == (FIRST, SECOND, GENESIS)
    assert proof.orphan is None
    assert proof.copies[0].snapshot_ids == (FIRST, SECOND)
    changed = remote.proof((first,), read(state))
    assert changed.inventory_digest != proof.inventory_digest
    assert changed.protected_bytes < proof.protected_bytes


def test_missing_indexed_snapshot_is_rejected_before_other_restores(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(state)
    remote = Remote(state, monkeypatch)
    with pytest.raises(BackupIdentityError, match="missing"):
        remote.proof((remote.add(SECOND),), read(state))
    assert not remote.calls


@pytest.mark.parametrize("tags", [(), ("scheduled",)])
def test_removed_all_archive_tags_cannot_hide_indexed_authority(
    state: Path, monkeypatch: pytest.MonkeyPatch, tags: tuple[str, ...]
) -> None:
    install(state)
    remote = Remote(state, monkeypatch)
    snapshot = replace(remote.add(FIRST), tags=tags, paths=("/unrelated",))
    with pytest.raises(BackupIdentityError):
        remote.proof((snapshot,), read(state))
    assert remote.calls == [FIRST]


def test_previously_recorded_duplicate_cannot_disappear(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(state)
    remote = Remote(state, monkeypatch)
    first = remote.add(FIRST)
    prefix = read(state)
    duplicates = {
        "schema": journal.DUPLICATES_SCHEMA,
        "lineageId": remote.lineage["lineageId"],
        "repositoryBinding": IDENTITY.binding(),
        "entries": [
            {
                "descriptorDigest": prefix.segments[0].index["descriptorDigest"],
                "snapshotIds": [SECOND],
            }
        ],
    }
    with pytest.raises(BackupIdentityError, match="missing"):
        remote.proof((first,), replace(prefix, duplicates=duplicates))


def test_orphan_discovery_chooses_smallest_equivalent_full_id_without_local_mutation(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = Remote(state, monkeypatch)
    before = sorted((path.name, path.read_bytes()) for path in (state / "audit/archive").iterdir())
    proof = remote.proof((remote.add(SECOND), remote.add(FIRST)), read(state))
    assert proof.orphan is not None and proof.orphan.snapshot_id == FIRST
    assert before == sorted(
        (path.name, path.read_bytes()) for path in (state / "audit/archive").iterdir()
    )


def test_competing_unindexed_attempts_fail_instead_of_choosing_newest(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = Remote(state, monkeypatch)
    first = remote.add(FIRST)
    record = descriptor(canonical_json_bytes(entry()))
    record["rotationId"] = "0198d17f-6f4a-7000-8000-000000000099"
    with pytest.raises(BackupIdentityError, match="competing"):
        remote.proof((first, remote.add(SECOND, record)), read(state))


def test_orphan_cannot_replace_a_different_durable_attempt(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = Remote(state, monkeypatch)
    first = remote.add(FIRST)
    record = descriptor(canonical_json_bytes(entry()))
    record["rotationId"] = "0198d17f-6f4a-7000-8000-000000000099"
    intent: dict[str, object] = {"descriptor": record, "snapshotIds": []}
    with pytest.raises(BackupIdentityError, match="durable"):
        remote.proof((first,), replace(read(state), rotation_intent=intent))


def test_recorded_snapshot_id_cannot_be_reused_for_a_different_descriptor(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(state)
    remote = Remote(state, monkeypatch)
    record = descriptor(canonical_json_bytes(entry()))
    record["rotationId"] = "0198d17f-6f4a-7000-8000-000000000099"
    assert (
        framed_digest(formats.DESCRIPTOR_FORMAT, canonical_json_bytes(record))
        != read(state).segments[0].index["descriptorDigest"]
    )
    with pytest.raises(BackupIdentityError, match="local descriptor"):
        remote.proof((remote.add(FIRST, record),), read(state))
