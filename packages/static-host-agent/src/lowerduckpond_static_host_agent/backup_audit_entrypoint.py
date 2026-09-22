"""Fixed root commands for bounded installed audit protection and maintenance."""

from __future__ import annotations

import os
import sys

from lowerduckpond_static_host_agent.audit_archive_coordinator import (
    ProtectionPaths,
    maintain_archive,
    verify_archive,
)
from lowerduckpond_static_host_agent.audit_rotation_coordinator import RotationPaths, rotate_archive
from lowerduckpond_static_host_agent.backup_legacy_retention import maintain_archive_free_repository
from lowerduckpond_static_host_agent.backup_restic import inherit_restic_leases


def audit_main(selection_descriptor: int) -> int:
    if os.geteuid() != 0 or sys.argv[1:] not in [
        ["--initialize"],
        ["--verify"],
        ["--maintain"],
        ["--rotate"],
    ]:
        print("backup_audit_invalid_invocation", file=sys.stderr)
        return 1
    try:
        with inherit_restic_leases((9, selection_descriptor)):
            if sys.argv[1] == "--rotate":
                if (
                    os.environ.get("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED") != "true"
                    or os.environ.get("LOWERDUCKPOND_AUDIT_ROTATION_ENABLED") != "true"
                ):
                    raise ValueError("audit rotation requires explicit qualified activation")
                rotate_archive(RotationPaths(), os.environ, expected_owner=0, expected_group=0)
            elif sys.argv[1] == "--maintain":
                if tuple(
                    os.environ.get("LOWERDUCKPOND_BACKUP_KEEP_" + name)
                    for name in ("DAILY", "WEEKLY", "MONTHLY")
                ) != ("7", "5", "12"):
                    raise ValueError("unsupported ordinary retention policy")
                mode = os.environ.get("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED")
                if mode == "true":
                    maintain_archive(
                        ProtectionPaths(), os.environ, expected_owner=0, expected_group=0
                    )
                elif mode == "false":
                    maintain_archive_free_repository(
                        ProtectionPaths(), os.environ, expected_owner=0
                    )
                else:
                    raise ValueError("backup migration mode is invalid")
            else:
                verify_archive(
                    ProtectionPaths(),
                    os.environ,
                    expected_owner=0,
                    expected_group=0,
                    initialize=sys.argv[1] == "--initialize",
                )
    except Exception:
        print("backup_audit_unverified", file=sys.stderr)
        return 1
    print("backup_audit_verified")
    return 0
