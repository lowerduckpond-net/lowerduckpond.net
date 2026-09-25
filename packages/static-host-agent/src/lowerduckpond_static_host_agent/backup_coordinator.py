"""Root coherent capture, with repository and selected-artifact leases outside."""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.backup_capture import build_capture_descriptor
from lowerduckpond_static_host_agent.backup_descriptor import (
    MAX_BACKUP_DESCRIPTOR_BYTES,
    decode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_lineage import require_repository_history
from lowerduckpond_static_host_agent.backup_restic import (
    discover_repository,
    inherit_restic_leases,
    repository_genesis,
)
from lowerduckpond_static_host_agent.backup_snapshot import create_coherent_snapshot
from lowerduckpond_static_host_agent.backup_sources import (
    MAX_TREE_BYTES,
    SOURCE_PATHS,
    STAGED_PATHS,
)
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, validate_regular_state_file
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName


@dataclass(frozen=True)
class CapturePaths:
    state: Path = Path(SOURCE_PATHS["state"])
    content: Path = Path(SOURCE_PATHS["content"])
    recovery: Path = Path(SOURCE_PATHS["recovery"])
    staging: Path = Path(STAGED_PATHS["descriptor"]).parent
    workspace: Path = Path("/var/cache/lowerduckpond-backup/workspace")
    caddy: Path = Path("/etc/caddy")


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


def _require_current_root(directory: DurableDirectory, path: Path) -> None:
    descriptor = directory.duplicate_descriptor()
    try:
        opened = os.fstat(descriptor)
        named = path.stat(follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise BackupIdentityError("backup source root changed during capture")
    finally:
        os.close(descriptor)


def _stage_descriptor(path: Path, raw: bytes, owner: int) -> None:
    with DurableDirectory.open(
        path,
        expected_owner=owner,
        expected_directory_mode=0o700,
    ) as staging:
        parent = staging.duplicate_descriptor()
        try:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(
                    MAX_BACKUP_DESCRIPTOR_BYTES + staging.namespace_allocation_upper_bound(1), 1
                ),
                measure_filesystem_capacity_descriptor(parent),
            )
            database = os.open(
                "mariadb.sql.gz",
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            try:
                metadata = validate_regular_state_file(
                    database, expected_owner=owner, expected_mode=0o600
                )
                if not 0 < metadata.st_size <= MAX_TREE_BYTES:
                    raise BackupIdentityError("backup database staging exceeds its bound")
                named = os.stat("mariadb.sql.gz", dir_fd=parent, follow_symlinks=False)
                if (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino):
                    raise BackupIdentityError("backup database staging changed")
            finally:
                os.close(database)
        finally:
            os.close(parent)
        staging.remove_abandoned_publication_temporaries(
            expected_owner=owner,
            expected_mode=0o600,
            maximum_entries=8,
        )
        staging.replace(("static-recovery.json",), raw, mode=0o600)


def capture_backup(  # noqa: PLR0913 - capture leases and optional original rollout authority
    paths: CapturePaths,
    environment: Mapping[str, str],
    *,
    artifact_sha256: str,
    expected_owner: int,
    content_group: int,
    original_descriptor: bytes | None = None,
    capture: Callable[[bytes, Mapping[str, str]], str] | None = None,
) -> str:
    """Caller has validated repository and artifact selection and lends both FDs."""

    identity, snapshots = discover_repository(environment)
    genesis = repository_genesis(identity, snapshots, environment)
    if genesis is None:
        raise BackupIdentityError("coherent backup requires explicit lineage initialization")
    require_repository_history(
        tuple((snapshot.hostname, snapshot.tags) for snapshot in snapshots),
        identity,
        genesis,
    )
    with (
        DurableDirectory.open(
            paths.state, expected_owner=expected_owner, expected_directory_mode=0o700
        ) as state,
        state.open_descendant(("locks",)) as lock_directory,
        LockManager(
            lock_directory, expected_owner=expected_owner, expected_directory_mode=0o700
        ) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED, blocking=True),
        locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED, blocking=True),
    ):
        _require_current_root(state, paths.state)
        _require_current_root(lock_directory, paths.state / "locks")
        descriptors = locks.duplicate_backup_descriptors()
        try:
            with inherit_restic_leases(descriptors):
                milliseconds = time.time_ns() // 1_000_000
                original = (
                    None
                    if original_descriptor is None
                    else decode_backup_descriptor(original_descriptor)
                )
                capture_id = (
                    generate_uuid7(clock=lambda: milliseconds, entropy=_entropy)
                    if original is None
                    else str(original["captureId"])
                )
                captured_at = (
                    datetime.fromtimestamp(milliseconds / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                    if original is None
                    else str(original["capturedAt"])
                )
                raw = build_capture_descriptor(
                    {"state": paths.state, "content": paths.content, "recovery": paths.recovery},
                    paths.workspace,
                    paths.caddy,
                    locks=locks,
                    expected_owner=expected_owner,
                    content_group=content_group,
                    artifact_sha256=artifact_sha256,
                    repository_genesis=genesis,
                    capture_id=capture_id,
                    captured_at=captured_at,
                )
                if original_descriptor is not None and raw != original_descriptor:
                    raise BackupIdentityError("backup original captured authority changed")
                _stage_descriptor(paths.staging, raw, expected_owner)
                snapshot_id = (capture or create_coherent_snapshot)(raw, environment)
                _require_current_root(state, paths.state)
                _require_current_root(lock_directory, paths.state / "locks")
                # Successful Restic completion is inside both shared leases.
                # Revalidate named inodes once more before allowing success.
                current = locks.duplicate_backup_descriptors()
                for descriptor in current:
                    os.close(descriptor)
                return snapshot_id
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
