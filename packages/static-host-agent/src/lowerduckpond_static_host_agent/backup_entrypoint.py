"""Root-only identity migration for the installed, locked backup configuration."""

from __future__ import annotations

import grp
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from lowerduckpond_static_contracts import ContractError

from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.backup_coordinator import CapturePaths, capture_backup
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_lineage import lineage_for_repository
from lowerduckpond_static_host_agent.backup_restic import (
    discover_repository,
    inherit_restic_leases,
    publish_repository_genesis,
    repository_genesis,
)
from lowerduckpond_static_host_agent.durable import FailureHook, StatePathError


def capture_main(selection_descriptor: int, artifact_sha256: str) -> int:
    if os.geteuid() != 0 or sys.argv[1:]:
        print("backup_static_invalid_invocation", file=sys.stderr)
        return 1
    try:
        with inherit_restic_leases((9, selection_descriptor)):
            snapshot_id = capture_backup(
                CapturePaths(),
                os.environ,
                artifact_sha256=artifact_sha256,
                expected_owner=0,
                content_group=grp.getgrnam("caddy").gr_gid,
            )
    except Exception:
        # No contract, provider response, private source path or credential is
        # interpolated into command diagnostics. The outer unit records failure.
        print("backup_static_unverified", file=sys.stderr)
        return 1
    print(f"backup_static_verified {snapshot_id}")
    return 0


def identity_main(selection_descriptor: int) -> int:
    if os.geteuid() != 0 or sys.argv[1:] not in [["--initialize"], ["--verify"]]:
        print("backup_identity_invalid_invocation", file=sys.stderr)
        return 1
    try:
        with inherit_restic_leases((9, selection_descriptor)):
            ensure_lineage(
                Path("/var/lib/lowerduckpond/static"),
                os.environ,
                initialize=sys.argv[1] == "--initialize",
                expected_owner=0,
            )
    except BackupIdentityError, AuditError, ContractError, StatePathError, OSError:
        # Private repository coordinates, audit entries and credentials never
        # become shareable command diagnostics, even through subprocess errors.
        print("backup_identity_unverified", file=sys.stderr)
        return 1
    print("backup_identity_verified")
    return 0


def ensure_lineage(  # noqa: PLR0913 - explicit privilege and failure boundaries
    root: Path,
    environment: Mapping[str, str],
    *,
    initialize: bool,
    expected_owner: int,
    failure_hook: FailureHook | None = None,
    genesis_failure_hook: FailureHook | None = None,
) -> dict[str, object]:
    """Caller holds repository and selection leases throughout both state phases."""
    identity, snapshots = discover_repository(environment)
    remote = repository_genesis(identity, snapshots, environment)
    if remote is None and initialize:
        candidate = lineage_for_repository(
            root,
            identity,
            snapshot_tags=tuple((snapshot.hostname, snapshot.tags) for snapshot in snapshots),
            initialize=True,
            expected_owner=expected_owner,
            repository_genesis=None,
            commit=False,
            genesis_failure_hook=genesis_failure_hook,
        )
        # No tenant-state lease survives the preparation call. Publication can
        # fail after committing its remote snapshot: rediscovery on the next
        # invocation must verify it rather than create a second genesis.
        remote, snapshots = publish_repository_genesis(identity, candidate, environment)
    return lineage_for_repository(
        root,
        identity,
        snapshot_tags=tuple((snapshot.hostname, snapshot.tags) for snapshot in snapshots),
        initialize=initialize,
        expected_owner=expected_owner,
        repository_genesis=remote,
        failure_hook=failure_hook,
    )
