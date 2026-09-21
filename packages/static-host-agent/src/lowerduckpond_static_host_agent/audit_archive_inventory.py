"""Fresh complete protected proofs, with one restored segment resident at a time."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent.audit_archive_restic import (
    SNAPSHOT_SOURCE,
    VerifiedAuditSnapshot,
    verify_audit_snapshot,
)
from lowerduckpond_static_host_agent.audit_archive_store import ArchivePrefix
from lowerduckpond_static_host_agent.audit_archive_workspace import verification_workspace
from lowerduckpond_static_host_agent.backup_identity import (
    BackupIdentityError,
    RepositoryIdentity,
    framed_digest,
    require_digest,
)
from lowerduckpond_static_host_agent.backup_lineage import require_repository_history
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    MAX_SNAPSHOT_BYTES,
    RepositorySnapshot,
    repository_genesis,
)


@dataclass(frozen=True, slots=True)
class ProtectedCopies:
    descriptor: dict[str, object]
    snapshot_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProtectedProof:
    snapshot_ids: tuple[str, ...]
    inventory_digest: dict[str, str]
    protected_bytes: int
    copies: tuple[ProtectedCopies, ...]
    orphan: VerifiedAuditSnapshot | None


def is_audit_snapshot(snapshot: RepositorySnapshot) -> bool:
    # A removed archive tag must not hide a snapshot from complete discovery.
    return (
        formats.ARCHIVE_TAG in snapshot.tags
        or any(tag.startswith("rotation-") for tag in snapshot.tags)
        or SNAPSHOT_SOURCE in snapshot.paths
    )


def referenced_snapshots(prefix: ArchivePrefix) -> dict[str, dict[str, str]]:
    referenced = {
        formats.full_snapshot_id(segment.index["snapshotId"]): require_digest(
            segment.index["descriptorDigest"], formats.DESCRIPTOR_FORMAT
        )
        for segment in prefix.segments
    }
    if prefix.duplicates is not None:
        entries = prefix.duplicates["entries"]
        assert type(entries) is list  # noqa: S101 - validated prefix
        for row in entries:
            for snapshot_id in journal.snapshot_ids(row["snapshotIds"]):
                referenced[snapshot_id] = require_digest(
                    row["descriptorDigest"], formats.DESCRIPTOR_FORMAT
                )
    if prefix.rotation_intent is not None:
        digest = framed_digest(
            formats.DESCRIPTOR_FORMAT, canonical_json_bytes(prefix.rotation_intent["descriptor"])
        )
        for snapshot_id in journal.snapshot_ids(prefix.rotation_intent["snapshotIds"]):
            if snapshot_id in referenced and referenced[snapshot_id] != digest:
                raise BackupIdentityError("protected snapshot has conflicting local references")
            referenced[snapshot_id] = digest
    return referenced


def verify_protected_inventory(  # noqa: PLR0913 - fixed repository, state and workspace boundaries
    identity: RepositoryIdentity,
    snapshots: tuple[RepositorySnapshot, ...],
    lineage: dict[str, object],
    prefix: ArchivePrefix,
    environment: Mapping[str, str],
    *,
    workspace: Path,
    expected_owner: int,
    expected_group: int,
) -> ProtectedProof:
    """Caller holds repository/selection leases and no tenant-state lease.

    This performs no local authority or repository mutations. An orphan is only
    a verified candidate; a later state transaction must prove its exact closed
    local segment and compare the captured head before adopting it.
    """
    require_repository_history(
        tuple((item.hostname, item.tags) for item in snapshots), identity, lineage
    )
    if repository_genesis(identity, snapshots, environment) != lineage:
        raise BackupIdentityError("protected inventory lacks its permanent lineage evidence")
    genesis = next(item for item in snapshots if LINEAGE_TAG in item.tags)
    referenced = referenced_snapshots(prefix)
    available = {item.snapshot_id: item for item in snapshots}
    if not set(referenced).issubset(available):
        raise BackupIdentityError("protected inventory is missing locally referenced snapshots")
    candidates = tuple(
        sorted(
            (
                item
                for item in snapshots
                if is_audit_snapshot(item) or item.snapshot_id in referenced
            ),
            key=lambda item: item.snapshot_id,
        )
    )
    descriptors: dict[int, dict[str, object]] = {}
    copies: dict[int, list[str]] = {}
    rows: list[dict[str, object]] = []
    orphan: VerifiedAuditSnapshot | None = None
    protected_bytes = len(canonical_json_bytes(lineage))
    lineage_id = lineage["lineageId"]
    assert type(lineage_id) is str  # noqa: S101 - validated lineage
    for snapshot in candidates:
        with verification_workspace(workspace, expected_owner=expected_owner) as directory:
            verified = verify_audit_snapshot(
                snapshot,
                identity,
                lineage_id,
                environment,
                directory,
                expected_owner=expected_owner,
                expected_group=expected_group,
            )
        descriptor = verified.descriptor
        digest = framed_digest(formats.DESCRIPTOR_FORMAT, verified.descriptor_bytes)
        if snapshot.snapshot_id in referenced and referenced[snapshot.snapshot_id] != digest:
            raise BackupIdentityError("protected snapshot conflicts with its local descriptor")
        number = formats.archive_count(
            descriptor["segmentNumber"], formats.MAX_ARCHIVED_SEGMENTS - 1
        )
        if number in descriptors and descriptors[number] != descriptor:
            raise BackupIdentityError("protected inventory has competing rotation attempts")
        if number < len(prefix.segments):
            archived = prefix.segments[number]
            if archived.descriptor != descriptor or archived.witness != verified.witness:
                raise BackupIdentityError("protected snapshot disagrees with its index or witness")
        elif number == len(prefix.segments):
            if (
                prefix.rotation_intent is not None
                and prefix.rotation_intent["descriptor"] != descriptor
            ):
                raise BackupIdentityError(
                    "unindexed snapshot disagrees with durable rotation authority"
                )
            if orphan is None:
                orphan = verified  # Sorted IDs choose the smallest equivalent candidate.
        else:
            raise BackupIdentityError("protected inventory has an unindexed prefix gap")
        descriptors[number] = descriptor
        copies.setdefault(number, []).append(snapshot.snapshot_id)
        rows.append({"snapshotId": snapshot.snapshot_id, "descriptorDigest": digest})
        protected_bytes += len(verified.descriptor_bytes) + len(verified.segment)
        # Do not retain restored copies of the complete archive history.
        del verified
    inventory = {"lineage": lineage, "genesisSnapshotId": genesis.snapshot_id, "archives": rows}
    digest = framed_digest(
        journal.PROTECTION_INVENTORY_FORMAT,
        canonical_json_bytes(inventory, maximum_bytes=MAX_SNAPSHOT_BYTES),
    )
    return ProtectedProof(
        tuple(sorted((genesis.snapshot_id, *(item.snapshot_id for item in candidates)))),
        digest,
        protected_bytes,
        tuple(
            ProtectedCopies(descriptors[number], tuple(copies[number])) for number in sorted(copies)
        ),
        orphan,
    )
