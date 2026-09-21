"""Root-only identity migration for the installed, locked backup configuration."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from lowerduckpond_static_contracts import ContractError

from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_lineage import lineage_for_repository
from lowerduckpond_static_host_agent.backup_restic import (
    discover_repository,
    publish_repository_genesis,
    repository_genesis,
)
from lowerduckpond_static_host_agent.durable import FailureHook, StatePathError


def identity_main() -> int:
    if os.geteuid() != 0 or sys.argv[1:] not in [["--initialize"], ["--verify"]]:
        print("backup_identity_invalid_invocation", file=sys.stderr)
        return 1
    try:
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
