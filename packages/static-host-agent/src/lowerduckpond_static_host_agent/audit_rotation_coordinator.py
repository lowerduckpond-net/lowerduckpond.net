"""Repository-serialized one-segment snapshot, proof, index and removal protocol."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent import audit_archive_coordinator as protection
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent import audit_rotation_local as rotation
from lowerduckpond_static_host_agent import audit_rotation_stage as stage
from lowerduckpond_static_host_agent.audit_archive_inventory import verify_protected_inventory
from lowerduckpond_static_host_agent.audit_archive_restic import SNAPSHOT_SOURCE
from lowerduckpond_static_host_agent.audit_rotation_snapshot import create_rotation_snapshot
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import discover_repository, repository_genesis


@dataclass(frozen=True, slots=True)
class RotationPaths(protection.ProtectionPaths):
    source: Path = Path(SNAPSHOT_SOURCE)


def _verify_pending(
    paths: RotationPaths,
    environment: Mapping[str, str],
    owner: int,
    group: int,
    failure_hook: local.ArchiveFailureHook | None,
) -> protection.VerifiedArchive:
    """Prove all protected inventory, allowing only an uncreated prepared attempt.

    The generic verifier/maintenance still refuses that state. This coordinator
    alone may finish it, and it never treats absence as permission to replace
    the descriptor, rotation identity, head or closed source generation.
    """
    identity, snapshots = discover_repository(environment)
    lineage = repository_genesis(identity, snapshots, environment)
    if lineage is None:
        raise BackupIdentityError("audit rotation requires existing permanent lineage evidence")
    with local.archive_transaction(paths.root, owner) as root:
        captured = local.observe_archive(root, lineage, owner)
        local.head_digest(captured.prefix)
        if captured.prefix.maintenance_intent is not None:
            raise BackupIdentityError("audit rotation requires completed maintenance")
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
        intent = current.prefix.rotation_intent
        uncreated = (
            intent is not None
            and intent["phase"] == "prepared"
            and formats.validate_rotation(intent["descriptor"])["segmentNumber"]
            == len(current.prefix.segments)
            and proof.orphan is None
        )
        if uncreated:
            rotation.source_bytes(root, current, owner)
        else:
            local.commit_protected_proof(
                root, current, proof, owner, protection._now(), failure_hook=failure_hook
            )
        current = local.observe_archive(root, lineage, owner)
    return protection.VerifiedArchive(identity, snapshots, current, proof)


def _prepare(
    paths: RotationPaths,
    verified: protection.VerifiedArchive,
    owner: int,
    failure_hook: local.ArchiveFailureHook | None,
) -> local.LocalArchive:
    if verified.local.prefix.rotation_intent is None:
        stage.discard_stage(paths.source, owner, failure_hook=failure_hook)
    with local.archive_transaction(paths.root, owner) as root:
        current = local.observe_archive(root, verified.local.lineage, owner)
        local.require_same_authority(verified.local, current)
        if current.prefix.rotation_intent is None:
            rotation.prepare_rotation(
                root,
                current,
                owner,
                generate_uuid7(
                    clock=lambda: time.time_ns() // 1_000_000, entropy=protection._entropy
                ),
                protection._now(),
                failure_hook=failure_hook,
            )
        return local.observe_archive(root, verified.local.lineage, owner)


def _stage(
    paths: RotationPaths,
    captured: local.LocalArchive,
    owner: int,
    failure_hook: local.ArchiveFailureHook | None,
) -> None:
    with local.archive_transaction(paths.root, owner) as root:
        current = local.observe_archive(root, captured.lineage, owner)
        local.require_same_authority(captured, current)
        raw = rotation.source_bytes(root, current, owner)
        intent = current.prefix.rotation_intent
        if raw is None or intent is None:
            raise BackupIdentityError("uncreated audit attempt lacks its sealed source")
        record = formats.validate_rotation(intent["descriptor"])
    stage.stage_attempt(paths.source, record, raw, owner, failure_hook=failure_hook)


def rotate_archive(
    paths: RotationPaths,
    environment: Mapping[str, str],
    *,
    expected_owner: int,
    expected_group: int,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> bool:
    """Caller holds repository EX and selected-artifact SH until every child exits.

    Network calls never hold tenant-state exclusion. Return true only after one
    indexed segment's source and intent removals have completed durably.
    """
    owner, group = expected_owner, expected_group
    try:
        verified = _verify_pending(paths, environment, owner, group, failure_hook)
        current = _prepare(paths, verified, owner, failure_hook)
        intent = current.prefix.rotation_intent
        if intent is None:
            return False
        if intent["phase"] != "indexed":
            _stage(paths, current, owner, failure_hook)
            # Enumerate again after sealing the prepared attempt, including on
            # the first invocation. A previously committed response-lost copy
            # must be restored and adopted instead of issuing another backup.
            verified = _verify_pending(paths, environment, owner, group, failure_hook)
            intent = verified.local.prefix.rotation_intent
            if intent is None:
                raise BackupIdentityError("prepared audit attempt disappeared")
            if intent["phase"] != "indexed":
                if intent["phase"] != "prepared":
                    raise BackupIdentityError("audit attempt lacks a verifiable snapshot")
                snapshot_id = create_rotation_snapshot(
                    formats.validate_rotation(intent["descriptor"]), environment
                )
                with local.archive_transaction(paths.root, owner) as root:
                    current = local.observe_archive(root, verified.local.lineage, owner)
                    local.require_same_authority(verified.local, current)
                    rotation.record_snapshot(
                        root, current, owner, snapshot_id, failure_hook=failure_hook
                    )
                verified = _verify_pending(paths, environment, owner, group, failure_hook)
        intent = verified.local.prefix.rotation_intent
        if intent is None or intent["phase"] != "indexed":
            raise BackupIdentityError("audit rotation has no durable verified index")
        # Inspect all staging before the irreversible source removal. A failure
        # here leaves both the local source and its indexed attempt intact.
        stage.discard_stage(
            paths.source,
            owner,
            record=formats.validate_rotation(intent["descriptor"]),
            failure_hook=failure_hook,
        )
        with local.archive_transaction(paths.root, owner) as root:
            current = local.observe_archive(root, verified.local.lineage, owner)
            local.require_same_authority(verified.local, current)
            rotation.remove_indexed_source(
                root, current, verified.proof, owner, failure_hook=failure_hook
            )
            current = local.observe_archive(root, verified.local.lineage, owner)
            rotation.complete_rotation(root, current, owner, failure_hook=failure_hook)
        return True
    except Exception as error:
        protection._record_failure(paths, owner, error)
        raise
