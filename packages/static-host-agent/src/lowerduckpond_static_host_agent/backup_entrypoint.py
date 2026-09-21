"""Root-only identity migration for the installed, locked backup configuration."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from lowerduckpond_static_contracts import ContractError

from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_lineage import lineage_for_repository
from lowerduckpond_static_host_agent.backup_restic import discover_repository
from lowerduckpond_static_host_agent.durable import StatePathError


def identity_main() -> int:
    if os.geteuid() != 0 or sys.argv[1:] not in [["--initialize"], ["--verify"]]:
        print("backup_identity_invalid_invocation", file=sys.stderr)
        return 1
    try:
        identity, snapshots = discover_repository(os.environ)
        lineage_for_repository(
            Path("/var/lib/lowerduckpond/static"),
            identity,
            snapshot_tags=snapshots,
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
