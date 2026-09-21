"""Archive-free compatibility before the explicit coherent-backup migration."""

from __future__ import annotations

import os
from collections.abc import Mapping

from lowerduckpond_static_host_agent.audit import inspect_audit_readonly
from lowerduckpond_static_host_agent.audit_archive_coordinator import ProtectionPaths
from lowerduckpond_static_host_agent.audit_archive_inventory import is_audit_snapshot
from lowerduckpond_static_host_agent.audit_archive_local import archive_transaction
from lowerduckpond_static_host_agent.audit_archive_restic import (
    check_repository,
    forget_exact_ids,
    ordinary_retention_ids,
    prune_repository,
)
from lowerduckpond_static_host_agent.backup_identity import (
    GENESIS_PATH,
    LINEAGE_PATH,
    BackupIdentityError,
    RepositoryIdentity,
)
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    RepositorySnapshot,
    discover_repository,
)


def _archive_free_inventory(
    paths: ProtectionPaths, environment: Mapping[str, str], owner: int
) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
    identity, snapshots = discover_repository(environment)
    if any(
        is_audit_snapshot(snapshot)
        or LINEAGE_TAG in snapshot.tags
        or any(tag.startswith(("lineage-", "repository-", "capture-")) for tag in snapshot.tags)
        for snapshot in snapshots
    ):
        raise BackupIdentityError("protected history requires coherent maintenance activation")
    with archive_transaction(paths.root, owner) as root:
        for path in (GENESIS_PATH, LINEAGE_PATH, ("audit", "archive")):
            with root.open_descendant(path[:-1]) as parent:
                descriptor = parent.duplicate_descriptor()
                try:
                    # Existence alone, including a dangling final symlink,
                    # closes legacy maintenance. Parent traversal is no-follow.
                    try:
                        os.stat(path[-1], dir_fd=descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                finally:
                    os.close(descriptor)
                raise BackupIdentityError("local lineage requires coherent maintenance activation")
        inspect_audit_readonly(
            root, expected_owner=owner, expected_directory_mode=0o700, expected_record_mode=0o600
        )
    return identity, snapshots


def maintain_archive_free_repository(
    paths: ProtectionPaths, environment: Mapping[str, str], *, expected_owner: int
) -> None:
    """Caller holds repository EX/selection SH. Never a protected-mode fallback.

    A legacy host has no M3.11 lineage/index to journal against. Its old ordinary
    retention remains available only until the first explicit lineage migration.
    Every destructive boundary proves that no protected authority exists. Once
    it does, only the journaled protected coordinator may perform maintenance.
    """
    identity, snapshots = _archive_free_inventory(paths, environment, expected_owner)
    check_repository(environment)
    removals = ordinary_retention_ids(identity, snapshots, frozenset(), environment)
    forget_exact_ids(removals, environment)
    observed, remaining = _archive_free_inventory(paths, environment, expected_owner)
    if observed != identity or set(removals).intersection(item.snapshot_id for item in remaining):
        raise BackupIdentityError("legacy retention did not prove its exact deletion set")
    prune_repository(environment)
    check_repository(environment)
    observed, _ = _archive_free_inventory(paths, environment, expected_owner)
    if observed != identity:
        raise BackupIdentityError("legacy retention repository identity changed")
