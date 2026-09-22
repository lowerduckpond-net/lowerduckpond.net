from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_inventory as inventory
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent import audit_archive_workspace as workspace
from lowerduckpond_static_host_agent import audit_rotation_coordinator as coordinator
from lowerduckpond_static_host_agent import audit_rotation_local as rotation
from lowerduckpond_static_host_agent import audit_rotation_stage as stage
from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.audit_archive_formats import (
    inspect_segment,
    required_archive_tags,
    validate_rotation,
    verify_segment,
)
from lowerduckpond_static_host_agent.audit_archive_restic import (
    SNAPSHOT_SOURCE,
    VerifiedAuditSnapshot,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot, lineage_tags
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, DurableDirectory
from test_audit_archive_admission import available_capacity
from test_audit_archive_formats import IDENTITY
from test_audit_archive_store import lineage, read
from test_audit_archive_store import state as state  # noqa: PLC0414 - shared private fixture
from test_audit_archived_history import FIRST_SEGMENT, LIMITS, TAIL_SEGMENT, history, projection

GENESIS = "e" * 64
SNAPSHOT = "c" * 64


@dataclass
class Remote:
    root: Path
    paths: coordinator.RotationPaths
    snapshots: dict[str, RepositorySnapshot]
    payloads: dict[str, VerifiedAuditSnapshot] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)
    creates: int = 0
    fault: str | None = None

    def network(self, event: str) -> None:
        with (self.root / "locks/tenant-state.lock").open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        self.events.append(event)

    def discover(
        self, _environment: Mapping[str, str]
    ) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
        self.network("discover")
        return IDENTITY, tuple(self.snapshots.values())

    def genesis(
        self,
        _identity: RepositoryIdentity,
        snapshots: tuple[RepositorySnapshot, ...],
        _environment: Mapping[str, str],
    ) -> dict[str, object] | None:
        self.network("genesis")
        return (
            lineage(self.root) if any(item.snapshot_id == GENESIS for item in snapshots) else None
        )

    def create(self, record: dict[str, object], _environment: Mapping[str, str]) -> str:
        self.network("snapshot")
        self.creates += 1
        intent = read(self.root).rotation_intent
        assert intent is not None and intent["phase"] == "prepared"
        assert intent["descriptor"] == record
        assert self.events.count("discover") >= 2  # noqa: PLR2004 - before and after durable prepare
        if self.fault == "before-snapshot":
            raise RuntimeError("snapshot child failed before effect")
        raw = (self.paths.source / "segment.jsonl").read_bytes()
        encoded = (self.paths.source / "descriptor.json").read_bytes()
        assert encoded == canonical_json_bytes(record)
        evidence = verify_segment(record, raw)
        self.payloads[SNAPSHOT] = VerifiedAuditSnapshot(
            SNAPSHOT, record, encoded, raw, evidence.witness
        )
        self.snapshots[SNAPSHOT] = RepositorySnapshot(
            SNAPSHOT, IDENTITY.node_name, required_archive_tags(record), (SNAPSHOT_SOURCE,)
        )
        if self.fault == "lost-response":
            raise RuntimeError("snapshot child response lost")
        return SNAPSHOT

    def restore(
        self,
        snapshot: RepositorySnapshot,
        identity: RepositoryIdentity,
        lineage_id: str,
        _environment: Mapping[str, str],
        _workspace: DurableDirectory,
        *,
        expected_owner: int,
        expected_group: int,
    ) -> VerifiedAuditSnapshot:
        self.network("restore")
        assert identity == IDENTITY
        assert expected_owner == os.geteuid() and expected_group == os.getegid()
        if self.fault == "restore":
            raise BackupIdentityError("remote restore failed")
        payload = self.payloads[snapshot.snapshot_id]
        assert payload.descriptor["lineageId"] == lineage_id
        assert snapshot.tags == required_archive_tags(payload.descriptor)
        verify_segment(payload.descriptor, payload.segment)
        return payload

    def rotate(self, hook: local.ArchiveFailureHook | None = None) -> bool:
        return coordinator.rotate_archive(
            self.paths,
            {},
            expected_owner=os.geteuid(),
            expected_group=os.getegid(),
            failure_hook=hook,
        )


@pytest.fixture
def remote(state: Path, monkeypatch: pytest.MonkeyPatch) -> Remote:
    history(state)
    paths = coordinator.RotationPaths(
        state, state.parent / "verification", state.parent / "snapshot"
    )
    paths.workspace.mkdir(mode=0o700)
    paths.source.mkdir(mode=0o700)
    result = Remote(
        state,
        paths,
        {GENESIS: RepositorySnapshot(GENESIS, IDENTITY.node_name, lineage_tags(lineage(state)))},
    )
    original = local.observe_archive

    def observe(
        root: DurableDirectory, record: dict[str, object], owner: int
    ) -> local.LocalArchive:
        return original(root, record, owner, limits=LIMITS)

    monkeypatch.setattr(local, "observe_archive", observe)
    for module in (local, rotation, stage, workspace):
        monkeypatch.setattr(module, "measure_filesystem_capacity_descriptor", available_capacity)
    monkeypatch.setattr(coordinator, "discover_repository", result.discover)
    monkeypatch.setattr(coordinator, "repository_genesis", result.genesis)
    monkeypatch.setattr(inventory, "repository_genesis", result.genesis)
    monkeypatch.setattr(inventory, "verify_audit_snapshot", result.restore)
    monkeypatch.setattr(coordinator, "create_rotation_snapshot", result.create)
    return result


def test_rotation_removes_only_verified_closed_source_and_preserves_exact_history(
    remote: Remote,
) -> None:
    before = (remote.root / FIRST_SEGMENT).read_bytes()
    tail = (remote.root / TAIL_SEGMENT).read_bytes()
    assert remote.rotate()
    prefix = read(remote.root)
    assert len(prefix.segments) == 1
    assert prefix.segments[0].data == before
    assert prefix.rotation_intent is None
    assert (
        prefix.protection_status is not None and prefix.protection_status["category"] == "verified"
    )
    assert not (remote.root / FIRST_SEGMENT).exists()
    assert (remote.root / TAIL_SEGMENT).read_bytes() == tail
    assert list(remote.paths.source.iterdir()) == []
    assert remote.creates == 1
    assert not remote.rotate()
    assert remote.creates == 1


PUBLICATIONS = [
    ("rotation-intent.json", 1),  # prepared
    ("snapshot/descriptor.json", 1),
    ("snapshot/segment.jsonl", 1),
    ("rotation-intent.json", 2),  # discovered
    ("rotation-intent.json", 3),  # verified
    ("witness-00000000000000000000.json", 1),
    ("index-00000000000000000000.json", 1),
    ("head.json", 1),
    ("rotation-intent.json", 4),  # indexed
    ("protection-status.json", 2),
]


@pytest.mark.parametrize("name,occurrence", PUBLICATIONS)
@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_every_durable_publication_interruption_resumes_without_duplicate_snapshot(
    remote: Remote, name: str, occurrence: int, boundary: DurabilityBoundary
) -> None:
    original = (remote.root / FIRST_SEGMENT).read_bytes()
    seen = 0

    def stop(record: str, current: DurabilityBoundary) -> None:
        nonlocal seen
        if record == name and current == boundary:
            seen += 1
            if seen == occurrence:
                raise RuntimeError("interrupted publication")

    with pytest.raises(RuntimeError, match="interrupted"):
        remote.rotate(stop)
    assert seen == occurrence
    assert (remote.root / FIRST_SEGMENT).read_bytes() == original
    remote.rotate()
    prefix = read(remote.root)
    assert len(prefix.segments) == 1 and prefix.segments[0].data == original
    assert prefix.rotation_intent is None
    assert not (remote.root / FIRST_SEGMENT).exists()
    assert remote.creates == 1


@pytest.mark.parametrize(
    "name",
    [
        "snapshot/descriptor.json",
        "snapshot/segment.jsonl",
        Path(FIRST_SEGMENT).name,
        "rotation-intent.json",
    ],
)
@pytest.mark.parametrize("boundary", [DurabilityBoundary.REMOVE, DurabilityBoundary.DIRECTORY_SYNC])
def test_every_removal_interruption_reverifies_before_finishing_cleanup(
    remote: Remote, name: str, boundary: DurabilityBoundary
) -> None:
    original = (remote.root / FIRST_SEGMENT).read_bytes()
    removing = False

    def stop(record: str, current: DurabilityBoundary) -> None:
        nonlocal removing
        if record == name and current == DurabilityBoundary.REMOVE:
            removing = True
        if removing and record == name and current == boundary:
            raise RuntimeError("interrupted removal")

    with pytest.raises(RuntimeError, match="interrupted removal"):
        remote.rotate(stop)
    prior_restores = remote.events.count("restore")
    remote.rotate()
    assert remote.events.count("restore") > prior_restores
    prefix = read(remote.root)
    assert prefix.rotation_intent is None
    assert prefix.segments[0].data == original
    assert not (remote.root / FIRST_SEGMENT).exists()
    assert not list(remote.paths.source.iterdir())
    assert remote.creates == 1


@pytest.mark.parametrize("fault", ["before-snapshot", "lost-response", "restore"])
def test_remote_failure_preserves_source_and_reuses_the_sealed_attempt(
    remote: Remote, fault: str
) -> None:
    original = (remote.root / FIRST_SEGMENT).read_bytes()
    remote.fault = fault
    with pytest.raises((RuntimeError, BackupIdentityError)):
        remote.rotate()
    intent = read(remote.root).rotation_intent
    assert intent is not None
    descriptor = intent["descriptor"]
    assert (remote.root / FIRST_SEGMENT).read_bytes() == original
    remote.fault = None
    remote.rotate()
    assert read(remote.root).segments[0].descriptor == descriptor
    assert remote.creates == (2 if fault == "before-snapshot" else 1)


def test_prepared_byte_proof_preserves_projections_and_rejects_changed_source(
    remote: Remote,
) -> None:
    source = remote.root / FIRST_SEGMENT
    original = source.read_bytes()
    records = [
        json.loads(row)
        for row in (original + (remote.root / TAIL_SEGMENT).read_bytes()).splitlines()
    ]
    before = projection(remote.root, records)
    remote.fault = "before-snapshot"
    with pytest.raises(RuntimeError, match="before effect"):
        remote.rotate()
    intent = read(remote.root).rotation_intent
    assert intent is not None and intent["phase"] == "prepared"
    assert projection(remote.root, records) == before
    # This schema-valid change keeps the path, inode and size. A prior cached
    # proof or sealed descriptor must not bless the newly read source bytes.
    changed = original.replace(b"operator@example.test", b"attacker@example.test")
    assert changed != original and len(changed) == len(original)
    source.write_bytes(changed)
    with pytest.raises(AuditError, match="pending audit rotation"):
        projection(remote.root, records)
    remote.fault = None
    with pytest.raises(AuditError, match="pending audit rotation"):
        remote.rotate()
    assert source.read_bytes() == changed
    assert read(remote.root).rotation_intent == intent
    assert not remote.payloads and remote.creates == 1


def stop_after_index(record: str, boundary: DurabilityBoundary) -> None:
    if record == "head.json" and boundary == DurabilityBoundary.DIRECTORY_SYNC:
        raise RuntimeError("indexed but not removed")


@pytest.mark.parametrize(
    "fault",
    [
        "missing-snapshot",
        "source-generation",
        "unknown-stage",
        "staging-corruption",
        "missing-witness",
    ],
)
def test_indexed_retry_preserves_remaining_evidence_when_proof_or_source_changed(
    remote: Remote, fault: str
) -> None:
    original = (remote.root / FIRST_SEGMENT).read_bytes()
    with pytest.raises(RuntimeError, match="indexed"):
        remote.rotate(stop_after_index)
    if fault == "missing-snapshot":
        del remote.snapshots[SNAPSHOT]
    elif fault == "source-generation":
        target = remote.root / FIRST_SEGMENT
        target.unlink()
        target.write_bytes(original)
        target.chmod(0o600)
    elif fault == "unknown-stage":
        (remote.paths.source / "unknown-evidence").write_bytes(b"preserve")
    elif fault == "staging-corruption":
        (remote.paths.source / "segment.jsonl").write_bytes(b"corrupt")
    else:
        (remote.root / "audit/archive/witness-00000000000000000000.json").unlink()
    with pytest.raises((BackupIdentityError, AuditError)):
        remote.rotate()
    assert (remote.root / FIRST_SEGMENT).read_bytes() == original
    assert remote.creates == 1
    if fault == "unknown-stage":
        assert (remote.paths.source / "unknown-evidence").read_bytes() == b"preserve"


def test_no_closed_successor_creates_no_snapshot_or_attempt(remote: Remote) -> None:
    (remote.root / TAIL_SEGMENT).unlink()
    assert not remote.rotate()
    assert remote.creates == 0
    assert read(remote.root).rotation_intent is None
    assert (remote.root / FIRST_SEGMENT).exists()


def test_new_equivalent_copy_does_not_replace_an_already_indexed_id(remote: Remote) -> None:
    with pytest.raises(RuntimeError, match="indexed"):
        remote.rotate(stop_after_index)
    earlier = "b" * 64
    remote.snapshots[earlier] = replace(remote.snapshots[SNAPSHOT], snapshot_id=earlier)
    remote.payloads[earlier] = replace(remote.payloads[SNAPSHOT], snapshot_id=earlier)
    assert remote.rotate()
    prefix = read(remote.root)
    assert prefix.segments[0].index["snapshotId"] == SNAPSHOT
    assert prefix.duplicates is not None
    rows = prefix.duplicates["entries"]
    assert type(rows) is list and rows[0]["snapshotIds"] == [earlier]
    assert {GENESIS, SNAPSHOT, earlier} == set(remote.snapshots)
    assert remote.creates == 1


def test_missing_remote_after_local_unlink_preserves_intent_and_successor(remote: Remote) -> None:
    def stop(record: str, boundary: DurabilityBoundary) -> None:
        if record == Path(FIRST_SEGMENT).name and boundary == DurabilityBoundary.REMOVE:
            raise RuntimeError("unlink before sync")

    with pytest.raises(RuntimeError, match="unlink"):
        remote.rotate(stop)
    tail = (remote.root / TAIL_SEGMENT).read_bytes()
    intent = read(remote.root).rotation_intent
    assert intent is not None and not (remote.root / FIRST_SEGMENT).exists()
    saved = remote.snapshots.pop(SNAPSHOT)
    with pytest.raises(BackupIdentityError, match="missing locally referenced"):
        remote.rotate()
    assert read(remote.root).rotation_intent == intent
    assert (remote.root / TAIL_SEGMENT).read_bytes() == tail
    remote.snapshots[SNAPSHOT] = saved
    assert remote.rotate()
    assert read(remote.root).rotation_intent is None and remote.creates == 1


def test_missing_genesis_cannot_initialize_new_rotation_authority(remote: Remote) -> None:
    del remote.snapshots[GENESIS]
    with pytest.raises(BackupIdentityError, match="permanent lineage"):
        remote.rotate()
    assert remote.creates == 0 and read(remote.root).rotation_intent is None


def test_discovery_adopts_response_lost_snapshot_without_requesting_another(remote: Remote) -> None:
    remote.fault = "lost-response"
    with pytest.raises(RuntimeError):
        remote.rotate()
    remote.fault = None
    captured = remote.payloads[SNAPSHOT]
    assert inspect_segment(captured.segment).witness == captured.witness
    intent = read(remote.root).rotation_intent
    assert intent is not None and validate_rotation(captured.descriptor) == intent["descriptor"]
    remote.events.clear()
    assert remote.rotate()
    assert "snapshot" not in remote.events
    assert remote.events[0] == "discover"
