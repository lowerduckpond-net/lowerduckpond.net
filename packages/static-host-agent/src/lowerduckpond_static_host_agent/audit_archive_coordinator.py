"""Repository-serialized protection and interruption-safe ordinary retention."""

from __future__ import annotations

import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent import audit_archive_store as store
from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.audit_archive_admission import AuditArchiveCapacityError
from lowerduckpond_static_host_agent.audit_archive_inventory import (
    ProtectedProof,
    is_audit_snapshot,
    verify_protected_inventory,
)
from lowerduckpond_static_host_agent.audit_archive_restic import (
    check_repository,
    forget_exact_ids,
    ordinary_retention_ids,
    prune_repository,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    RepositorySnapshot,
    RepositoryUnavailableError,
    discover_repository,
    repository_genesis,
)
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.durable import StatePathError


@dataclass(frozen=True, slots=True)
class ProtectionPaths:
    root: Path = Path("/var/lib/lowerduckpond/static")
    workspace: Path = Path("/var/cache/lowerduckpond-backup/audit/verification")


@dataclass(frozen=True, slots=True)
class VerifiedArchive:
    identity: RepositoryIdentity
    snapshots: tuple[RepositorySnapshot, ...]
    local: local.LocalArchive
    proof: ProtectedProof


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify(  # noqa: PLR0913 - explicit repository, privilege and failure boundaries
    paths: ProtectionPaths,
    environment: Mapping[str, str],
    owner: int,
    group: int,
    *,
    initialize: bool = False,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> VerifiedArchive:
    identity, snapshots = discover_repository(environment)
    lineage = repository_genesis(identity, snapshots, environment)
    if lineage is None:
        raise BackupIdentityError("protected audit verification requires existing lineage evidence")
    with local.archive_transaction(paths.root, owner) as root:
        if initialize:
            local.initialize_empty_archive(
                root, lineage, snapshots, owner, failure_hook=failure_hook
            )
        captured = local.observe_archive(root, lineage, owner)
        local.head_digest(captured.prefix)
    proof = verify_protected_inventory(
        identity,
        snapshots,
        lineage,
        captured.prefix,
        environment,
        workspace=paths.workspace,
        expected_owner=owner,
        expected_group=group,
    )
    with local.archive_transaction(paths.root, owner) as root:
        current = local.observe_archive(root, lineage, owner)
        local.require_same_authority(captured, current)
        local.commit_protected_proof(root, current, proof, owner, _now(), failure_hook=failure_hook)
        committed = local.observe_archive(root, lineage, owner)
    return VerifiedArchive(identity, snapshots, committed, proof)


def _record_failure(paths: ProtectionPaths, owner: int, error: Exception) -> None:
    category = (
        "rotation-pending"
        if isinstance(error, local.AuditRotationPendingError)
        else "resource-exhaustion"
        if isinstance(error, (CapacityError, AuditArchiveCapacityError))
        else "index-corruption"
        if isinstance(error, (AuditError, StatePathError))
        else "archive-unavailable"
        if isinstance(error, RepositoryUnavailableError)
        else "protection"
    )
    # Preserve the primary failure if corrupt authority or exhausted storage also
    # prevents a status update. Those conditions independently close admission.
    try:
        with local.archive_transaction(paths.root, owner) as root:
            lineage = store._lineage(root, owner)
            current = local.observe_archive(root, lineage, owner)
            status = journal.decode_protection_status(
                canonical_json_bytes(
                    {
                        "schema": journal.PROTECTION_SCHEMA,
                        "lineageId": lineage["lineageId"],
                        "repositoryBinding": lineage["repositoryBinding"],
                        "headDigest": local.head_digest(current.prefix),
                        "verifiedAt": _now(),
                        "protectedInventoryDigest": None,
                        "protectedSnapshotCount": 0,
                        "protectedBytes": 0,
                        "category": category,
                    }
                )
            )
            local.publish_records(
                root,
                current,
                owner,
                [("protection-status.json", canonical_json_bytes(status), False)],
            )
    except Exception:
        return


def verify_archive(  # noqa: PLR0913 - public fixed root command boundaries
    paths: ProtectionPaths,
    environment: Mapping[str, str],
    *,
    expected_owner: int,
    expected_group: int,
    initialize: bool = False,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> VerifiedArchive:
    """Caller holds repository EX and selected-artifact SH until return/reaping."""
    try:
        return _verify(
            paths,
            environment,
            expected_owner,
            expected_group,
            initialize=initialize,
            failure_hook=failure_hook,
        )
    except Exception as error:
        _record_failure(paths, expected_owner, error)
        raise


def _require_maintenance_proof(intent: dict[str, object], verified: VerifiedArchive) -> None:
    if (
        intent["expectedHeadDigest"] != local.head_digest(verified.local.prefix)
        or intent["protectedInventoryDigest"] != verified.proof.inventory_digest
        or journal.snapshot_ids(intent["protectedSnapshotIds"]) != verified.proof.snapshot_ids
    ):
        raise BackupIdentityError("maintenance protection changed since its durable intent")
    protected = set(verified.proof.snapshot_ids)
    removals = set(journal.snapshot_ids(intent["removeIds"]))
    for snapshot in verified.snapshots:
        if snapshot.snapshot_id not in removals:
            continue
        if (
            snapshot.snapshot_id in protected
            or snapshot.hostname != verified.identity.node_name
            or "scheduled" not in snapshot.tags
            or is_audit_snapshot(snapshot)
            or LINEAGE_TAG in snapshot.tags
            or not snapshot.paths
        ):
            raise BackupIdentityError(
                "maintenance intent does not select ordinary snapshot authority"
            )


def _publish_intent(
    paths: ProtectionPaths,
    verified: VerifiedArchive,
    intent: dict[str, object],
    owner: int,
    failure_hook: local.ArchiveFailureHook | None,
) -> None:
    raw = canonical_json_bytes(intent, maximum_bytes=journal.MAX_JOURNAL_BYTES)
    journal.decode_maintenance_intent(raw)
    with local.archive_transaction(paths.root, owner) as root:
        current = local.observe_archive(root, verified.local.lineage, owner)
        local.require_same_authority(verified.local, current)
        local.publish_records(
            root,
            current,
            owner,
            [("maintenance-intent.json", raw, False)],
            failure_hook=failure_hook,
        )


def _refresh_local(
    paths: ProtectionPaths, verified: VerifiedArchive, owner: int
) -> VerifiedArchive:
    with local.archive_transaction(paths.root, owner) as root:
        current = local.observe_archive(root, verified.local.lineage, owner)
    return VerifiedArchive(verified.identity, verified.snapshots, current, verified.proof)


def _require_removed(intent: dict[str, object], verified: VerifiedArchive) -> None:
    if set(journal.snapshot_ids(intent["removeIds"])).intersection(
        item.snapshot_id for item in verified.snapshots
    ):
        raise BackupIdentityError("ordinary forget did not remove the exact selected snapshots")


def maintain_archive(
    paths: ProtectionPaths,
    environment: Mapping[str, str],
    *,
    expected_owner: int,
    expected_group: int,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> VerifiedArchive:
    """Never combines forget/prune, recomputes a resumed remove set, or repairs Restic."""
    try:
        return _maintain(paths, environment, expected_owner, expected_group, failure_hook)
    except Exception as error:
        _record_failure(paths, expected_owner, error)
        raise


def _maintain(
    paths: ProtectionPaths,
    environment: Mapping[str, str],
    owner: int,
    group: int,
    failure_hook: local.ArchiveFailureHook | None,
) -> VerifiedArchive:
    verified = _verify(paths, environment, owner, group, failure_hook=failure_hook)
    intent = verified.local.prefix.maintenance_intent
    if intent is None:
        removals = ordinary_retention_ids(
            verified.identity,
            verified.snapshots,
            frozenset(verified.proof.snapshot_ids),
            environment,
        )
        intent = journal.decode_maintenance_intent(
            canonical_json_bytes(
                {
                    "schema": journal.MAINTENANCE_SCHEMA,
                    "maintenanceId": generate_uuid7(
                        clock=lambda: time.time_ns() // 1_000_000,
                        entropy=_entropy,
                    ),
                    "lineageId": verified.local.lineage["lineageId"],
                    "repositoryBinding": verified.identity.binding(),
                    "expectedHeadDigest": local.head_digest(verified.local.prefix),
                    "protectedInventoryDigest": verified.proof.inventory_digest,
                    "protectedSnapshotIds": list(verified.proof.snapshot_ids),
                    "removeIds": list(removals),
                    "phase": "prepared",
                },
                maximum_bytes=journal.MAX_JOURNAL_BYTES,
            )
        )
        _publish_intent(paths, verified, intent, owner, failure_hook)
        verified = _refresh_local(paths, verified, owner)
    _require_maintenance_proof(intent, verified)
    if intent["phase"] == "prepared":
        present = {item.snapshot_id for item in verified.snapshots}
        remaining = tuple(
            value for value in journal.snapshot_ids(intent["removeIds"]) if value in present
        )
        forget_exact_ids(remaining, environment)
        # Restic can report partial remove errors without a failing exit. A fresh
        # complete inventory, not process success, proves every chosen ID absent.
        verified = _verify(paths, environment, owner, group, failure_hook=failure_hook)
        _require_maintenance_proof(intent, verified)
        _require_removed(intent, verified)
        intent = {**intent, "phase": "forgotten"}
        _publish_intent(paths, verified, intent, owner, failure_hook)
        verified = _refresh_local(paths, verified, owner)
    _require_removed(intent, verified)
    if intent["phase"] == "forgotten":
        intent = {**intent, "phase": "pruning"}
        _publish_intent(paths, verified, intent, owner, failure_hook)
        prune_repository(environment)
    # A resumed pruning/checked intent repeats integrity and content proof; it
    # never invokes prune again after an interrupted destructive child.
    check_repository(environment)
    verified = _verify(paths, environment, owner, group, failure_hook=failure_hook)
    _require_maintenance_proof(intent, verified)
    _require_removed(intent, verified)
    intent = {**intent, "phase": "checked"}
    _publish_intent(paths, verified, intent, owner, failure_hook)
    verified = _refresh_local(paths, verified, owner)
    with local.archive_transaction(paths.root, owner) as root:
        current = local.observe_archive(root, verified.local.lineage, owner)
        local.require_same_authority(verified.local, current)
        hook = (
            None
            if failure_hook is None
            else lambda boundary: failure_hook("maintenance-intent.json", boundary)
        )
        root.remove(("audit", "archive", "maintenance-intent.json"), failure_hook=hook)
        current = local.observe_archive(root, verified.local.lineage, owner)
    return VerifiedArchive(verified.identity, verified.snapshots, current, verified.proof)
