"""Capture and restore-verify the unlaunched host under original rollout authority."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_local as audit
from lowerduckpond_static_host_agent.audit_archive_inventory import verify_protected_inventory
from lowerduckpond_static_host_agent.backup_coordinator import CapturePaths, _require_current_root
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_inventory import capture_state_inventory
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    discover_repository,
    inherit_restic_leases,
    repository_genesis,
)
from lowerduckpond_static_host_agent.backup_sources import SOURCE_PATHS
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_gate import require_restore_admission
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore, full_id
from lowerduckpond_static_host_agent.host_restore_materialize import MaterializationPaths
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, LockRequest
from lowerduckpond_static_host_agent.production_backup import BackupAuthority, verify_backup
from lowerduckpond_static_host_agent.production_capture import capture_rollout_backup
from lowerduckpond_static_host_agent.production_database import retain_database, stage_database
from lowerduckpond_static_host_agent.production_namespace import AUTHORIZATION, _names

DEFAULT_CAPTURE_PATHS = CapturePaths()


def _private(path: Path, owner: int) -> None:
    with DurableDirectory.open(
        path.parent, expected_owner=owner, expected_directory_mode=0o700
    ) as parent:
        descriptor = parent.duplicate_descriptor()
        try:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(parent.namespace_allocation_upper_bound(1), 1),
                measure_filesystem_capacity_descriptor(descriptor),
            )
            with suppress(FileExistsError):
                os.mkdir(path.name, mode=0o700, dir_fd=descriptor)
            with parent.open_descendant((path.name,)):
                pass
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _live(
    path: Path, authority: BackupAuthority, lineage: dict[str, object], *, owner: int
) -> audit.LocalArchive:
    with (
        DurableDirectory.open(path, expected_owner=owner, expected_directory_mode=0o700) as root,
        root.open_descendant(("locks",)) as directory,
        LockManager(directory, expected_owner=owner, expected_directory_mode=0o700) as locks,
        locks.acquire_many(tuple(LockRequest(name, LockMode.SHARED) for name in LockName)),
    ):
        _require_current_root(root, path)
        _require_current_root(directory, path / "locks")
        state = capture_state_inventory(
            path, locks=locks, expected_owner=owner, repository_genesis=lineage
        )
        if (
            state.namespace != authority.namespace
            or state.launch is not None
            or authority.launch is not None
            or state.tenants
            or state.intents
            or state.audit.entry_count
        ):
            raise BackupIdentityError("production rollout no longer has its original empty history")
        for name in ("tenants", "intents", "intake", "exports"):
            with root.open_descendant((name,)) as empty:
                _names(empty, frozenset())
        for name in AUTHORIZATION:
            with root.open_descendant(("authorization", name)) as empty:
                _names(empty, frozenset())
        return audit.observe_archive(root, lineage, owner)


def _protect(  # noqa: PLR0913 - original authority, fixed paths and privilege boundaries
    paths: CapturePaths,
    workspace: Path,
    environment: Mapping[str, str],
    authority: BackupAuthority,
    *,
    genesis_snapshot_id: str,
    audit_head_sha256: str,
    owner: int,
) -> None:
    identity, snapshots = discover_repository(environment)
    lineage = repository_genesis(identity, snapshots, environment)
    if (
        identity.binding()["value"] != authority.repository_binding
        or lineage is None
        or hashlib.sha256(canonical_json_bytes(lineage)).hexdigest() != authority.lineage_sha256
        or [item.snapshot_id for item in snapshots if LINEAGE_TAG in item.tags]
        != [genesis_snapshot_id]
    ):
        raise BackupIdentityError("production backup changed its original repository or genesis")
    before = _live(paths.state, authority, lineage, owner=owner)
    if (
        before.prefix.head is None
        or hashlib.sha256(canonical_json_bytes(before.prefix.head)).hexdigest() != audit_head_sha256
        or before.prefix.segments
        or before.prefix.rotation_intent is not None
        or before.prefix.maintenance_intent is not None
    ):
        raise BackupIdentityError("production protected index differs from its original empty head")
    # This verifier performs no authority writes. Refreshing protection status
    # here would change the source of a previously prepared coherent capture.
    proof = verify_protected_inventory(
        identity,
        snapshots,
        lineage,
        before.prefix,
        environment,
        workspace=workspace,
        expected_owner=owner,
        expected_group=owner,
    )
    if proof.orphan is not None:
        raise BackupIdentityError("production rollout has unexpected protected history")
    audit.require_same_authority(before, _live(paths.state, authority, lineage, owner=owner))


def run(  # noqa: PLR0913 - fixed action bindings and privilege boundary
    directory: Path,
    authority: BackupAuthority,
    environment: Mapping[str, str],
    descriptors: tuple[int, int],
    *,
    genesis_snapshot_id: str,
    audit_head_sha256: str,
    owner: int,
    content_group: int,
    paths: CapturePaths = DEFAULT_CAPTURE_PATHS,
) -> dict[str, str]:
    """Caller holds genuine rollout action/repository EX/selection SH leases."""
    require_restore_admission()
    authority.document()
    full_id(genesis_snapshot_id)
    full_id(audit_head_sha256)
    full_id(environment.get("LOWERDUCKPOND_BACKUP_STATUS_SCOPE"))
    _private(directory.parent, owner)
    _private(directory, owner)
    for name in ("database", "capture", "proof", "restored", "scratch", "protection"):
        _private(directory / name, owner)
    with inherit_restic_leases(descriptors):
        _protect(
            paths,
            directory / "protection",
            environment,
            authority,
            genesis_snapshot_id=genesis_snapshot_id,
            audit_head_sha256=audit_head_sha256,
            owner=owner,
        )
        original = retain_database(
            directory / "database", authority, owner=owner, descriptors=descriptors
        )
        _private(paths.staging, owner)
        stage_database(original, paths.staging, owner=owner)
        _private(paths.workspace, owner)
        with RestoreStore.locked(directory / "capture", owner=owner) as store:
            snapshot_id = capture_rollout_backup(
                paths, environment, authority, store, content_group=content_group
            )
        materialization = MaterializationPaths(
            {name: directory / "restored" / name for name in SOURCE_PATHS},
            directory / "restored" / "staging",
            directory / "scratch",
        )
        result = verify_backup(
            snapshot_id,
            environment,
            authority,
            directory / "proof",
            materialization,
            owner=owner,
            content_group=content_group,
        )
        if result["index_sha256"] != audit_head_sha256:
            raise BackupIdentityError("production backup restored a different protected index")
        _protect(
            paths,
            directory / "protection",
            environment,
            authority,
            genesis_snapshot_id=genesis_snapshot_id,
            audit_head_sha256=audit_head_sha256,
            owner=owner,
        )
        require_restore_admission()
        return result
