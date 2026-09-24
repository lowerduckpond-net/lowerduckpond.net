"""Discover complete protected history without extending a captured timeline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent.audit_archive_inventory import (
    ProtectedCopies,
    ProtectedProof,
    is_audit_snapshot,
    referenced_snapshots,
)
from lowerduckpond_static_host_agent.audit_archive_restic import (
    VerifiedAuditSnapshot,
    verify_audit_snapshot,
)
from lowerduckpond_static_host_agent.audit_archive_store import ArchivePrefix
from lowerduckpond_static_host_agent.audit_archive_workspace import verification_workspace
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.backup_lineage import require_repository_history
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    MAX_SNAPSHOT_BYTES,
    RepositorySnapshot,
    discover_repository,
    repository_genesis,
)
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot


def require_captured_timeline(
    descriptors: Sequence[dict[str, object]], backup: dict[str, object]
) -> None:
    lineage = cast(dict[str, object], backup["lineage"])
    audit = cast(dict[str, object], backup["audit"])
    boundary = cast(int, audit["entryCount"])
    previous: dict[str, object] | None = None
    for number, descriptor in enumerate(descriptors):
        formats.validate_rotation(descriptor)
        if (
            descriptor["lineageId"] != lineage["lineageId"]
            or descriptor["repositoryBinding"] != lineage["repositoryBinding"]
        ):
            raise HostRestoreError("restore_audit_lineage_mismatch")
        if descriptor["segmentNumber"] != number:
            raise HostRestoreError("restore_audit_prefix_gap")
        if cast(int, descriptor["lastSequence"]) >= boundary:
            # Even an identical prefix of a crossing segment proves future
            # events. Never truncate it and then branch the same audit lineage.
            raise HostRestoreError("restore_later_audit_timeline")
        if (
            descriptor["lastSequence"] == boundary - 1
            and descriptor["terminalEntryDigest"] != audit["terminalEntryDigest"]
        ):
            raise HostRestoreError("restore_audit_terminal_mismatch")
        if previous is not None and (
            descriptor["firstSequence"] != cast(int, previous["lastSequence"]) + 1
            or descriptor["predecessorEntryDigest"] != previous["terminalEntryDigest"]
            or descriptor["previousDescriptorDigest"]
            != framed_digest(formats.DESCRIPTOR_FORMAT, canonical_json_bytes(previous))
        ):
            raise HostRestoreError("restore_audit_prefix_fork")
        previous = descriptor


@dataclass(frozen=True)
class RestoreAuditProof:
    snapshots: tuple[RepositorySnapshot, ...]
    proof: ProtectedProof


def next_restore_segment(  # noqa: PLR0913 - same-invocation proof and private next prefix
    snapshot: RestoreSnapshot,
    discovered: RestoreAuditProof,
    prefix: ArchivePrefix,
    environment: Mapping[str, str],
    workspace: Path,
    *,
    owner: int,
    group: int,
) -> ProtectedProof:
    """Restore just the next segment under the same continuous repository lease.

    All copies were verified by discovery in this invocation; none are inferred
    from saved protection status. A final complete proof precedes completion.
    """
    number = len(prefix.segments)
    proof = discovered.proof
    if number >= len(proof.copies):
        return replace(proof, orphan=None)
    copies = proof.copies[number]
    if proof.orphan is not None and proof.orphan.descriptor == copies.descriptor:
        _require_local_reference(proof.orphan, prefix, referenced_snapshots(prefix))
        return proof
    selected = next(
        row for row in discovered.snapshots if row.snapshot_id == copies.snapshot_ids[0]
    )
    with verification_workspace(workspace, expected_owner=owner) as directory:
        verified = verify_audit_snapshot(
            selected,
            snapshot.identity,
            cast(str, snapshot.lineage["lineageId"]),
            environment,
            directory,
            expected_owner=owner,
            expected_group=group,
        )
    _require_local_reference(verified, prefix, referenced_snapshots(prefix))
    if verified.descriptor != copies.descriptor:
        raise HostRestoreError("restore_audit_inventory_changed")
    return replace(proof, orphan=verified)


def _require_local_reference(
    verified: VerifiedAuditSnapshot,
    prefix: ArchivePrefix,
    referenced: dict[str, dict[str, str]],
) -> None:
    digest = framed_digest(formats.DESCRIPTOR_FORMAT, verified.descriptor_bytes)
    if verified.snapshot_id in referenced and referenced[verified.snapshot_id] != digest:
        raise HostRestoreError("restore_audit_reference_mismatch")
    number = cast(int, verified.descriptor["segmentNumber"])
    if number < len(prefix.segments):
        archived = prefix.segments[number]
        if archived.descriptor != verified.descriptor or archived.witness != verified.witness:
            raise HostRestoreError("restore_audit_index_mismatch")
    elif number == len(prefix.segments) and (
        prefix.rotation_intent is not None
        and cast(dict[str, object], prefix.rotation_intent["descriptor"])["segmentNumber"] == number
        and prefix.rotation_intent["descriptor"] != verified.descriptor
    ):
        raise HostRestoreError("restore_audit_rotation_mismatch")


def discover_restore_audit(  # noqa: PLR0913 - independent repository and private state
    snapshot: RestoreSnapshot,
    prefix: ArchivePrefix,
    environment: Mapping[str, str],
    workspace: Path,
    *,
    owner: int,
    group: int,
) -> RestoreAuditProof:
    """Verify all copies, retaining only the next unindexed segment's bytes.

    Unlike ordinary rotation, several post-capture snapshots may cover the
    captured local suffix. They are accepted only as byte proofs of that suffix;
    the complete remote timeline is checked before any index can be extended.
    """
    identity, snapshots = discover_repository(environment)
    if (
        identity != snapshot.identity
        or repository_genesis(identity, snapshots, environment) != snapshot.lineage
    ):
        raise HostRestoreError("restore_audit_repository_mismatch")
    require_repository_history(
        tuple((row.hostname, row.tags) for row in snapshots), identity, snapshot.lineage
    )
    referenced = referenced_snapshots(prefix)
    if not set(referenced).issubset(row.snapshot_id for row in snapshots):
        raise HostRestoreError("restore_audit_snapshot_unavailable")
    genesis = next(row for row in snapshots if LINEAGE_TAG in row.tags)
    descriptors: dict[int, dict[str, object]] = {}
    copies: dict[int, list[str]] = {}
    rows: list[dict[str, object]] = []
    orphan: VerifiedAuditSnapshot | None = None
    protected_bytes = len(canonical_json_bytes(snapshot.lineage))
    for selected in sorted(snapshots, key=lambda row: row.snapshot_id):
        if not is_audit_snapshot(selected) and selected.snapshot_id not in referenced:
            continue
        with verification_workspace(workspace, expected_owner=owner) as directory:
            verified = verify_audit_snapshot(
                selected,
                identity,
                cast(str, snapshot.lineage["lineageId"]),
                environment,
                directory,
                expected_owner=owner,
                expected_group=group,
            )
        number = cast(int, verified.descriptor["segmentNumber"])
        _require_local_reference(verified, prefix, referenced)
        if number in descriptors and descriptors[number] != verified.descriptor:
            raise HostRestoreError("restore_audit_prefix_fork")
        descriptors[number] = verified.descriptor
        copies.setdefault(number, []).append(selected.snapshot_id)
        if number == len(prefix.segments) and orphan is None:
            orphan = verified
        protected_bytes += len(verified.descriptor_bytes) + len(verified.segment)
        rows.append(
            {
                "snapshotId": selected.snapshot_id,
                "descriptorDigest": framed_digest(
                    formats.DESCRIPTOR_FORMAT, verified.descriptor_bytes
                ),
            }
        )
        del verified
    ordered = [descriptors[number] for number in sorted(descriptors)]
    require_captured_timeline(ordered, decode_backup_descriptor(snapshot.descriptor))
    inventory = {
        "lineage": snapshot.lineage,
        "genesisSnapshotId": genesis.snapshot_id,
        "archives": rows,
    }
    digest = framed_digest(
        journal.PROTECTION_INVENTORY_FORMAT,
        canonical_json_bytes(inventory, maximum_bytes=MAX_SNAPSHOT_BYTES),
    )
    return RestoreAuditProof(
        snapshots,
        ProtectedProof(
            tuple(sorted((genesis.snapshot_id, *(str(row["snapshotId"]) for row in rows)))),
            digest,
            protected_bytes,
            tuple(
                ProtectedCopies(descriptors[number], tuple(copies[number]))
                for number in sorted(copies)
            ),
            orphan,
        ),
    )
