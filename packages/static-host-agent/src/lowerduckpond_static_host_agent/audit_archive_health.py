"""Bounded credential-free local protection health for the existing textfile collector."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent import audit_archive_store as store
from lowerduckpond_static_host_agent.audit import inspect_audit_readonly
from lowerduckpond_static_host_agent.audit_archive_admission import (
    AuditArchiveCapacityError,
    AuditProtectionError,
    admit_archive_append,
)
from lowerduckpond_static_host_agent.audit_archive_local import archive_transaction
from lowerduckpond_static_host_agent.backup_identity import RepositoryIdentity, canonical_locator
from lowerduckpond_static_host_agent.capacity import CapacityError
from lowerduckpond_static_host_agent.locks import LockMode, StateBusyError

CATEGORIES: Final = (
    "protection",
    "rotation-pending",
    "index-corruption",
    "archive-unavailable",
    "resource-exhaustion",
)


@dataclass(frozen=True, slots=True)
class ProtectionHealth:
    category: str | None
    snapshot_count: int = 0
    protected_bytes: int = 0
    rotation_pending: bool = False

    def metrics(self) -> str:
        lines = [
            f"lowerduckpond_audit_protection_verified {int(self.category is None)}",
            f"lowerduckpond_audit_protected_snapshots {self.snapshot_count}",
            f"lowerduckpond_audit_protected_bytes {self.protected_bytes}",
            f"lowerduckpond_audit_rotation_pending {int(self.rotation_pending)}",
        ]
        lines.extend(
            f'lowerduckpond_audit_failure{{category="{name}"}} {int(self.category == name)}'
            for name in CATEGORIES
        )
        return "\n".join(lines) + "\n"


def inspect_protection_health(  # noqa: PLR0911 - fixed fail-closed categories
    path: Path, environment: Mapping[str, str], *, expected_owner: int
) -> ProtectionHealth:
    """No repository lock or network; contend nonblocking with state mutation."""
    try:
        with archive_transaction(
            path, expected_owner, mode=LockMode.SHARED, blocking=False
        ) as root:
            prefix = store.read_archive_prefix(root, expected_owner=expected_owner)
            if prefix.head is None:
                return ProtectionHealth("protection")
            lineage = store._lineage(root, expected_owner)
            repository = lineage["repository"]
            assert type(repository) is dict  # noqa: S101 - validated lineage
            expected = RepositoryIdentity(
                repository["configId"],
                environment["LOWERDUCKPOND_BACKUP_NODE_NAME"],
                canonical_locator(environment["RESTIC_REPOSITORY"]),
            )
            if expected.binding() != prefix.head["repositoryBinding"]:
                return ProtectionHealth("protection")
            status = prefix.protection_status
            if status is None:
                return ProtectionHealth("protection")
            if status["category"] in CATEGORIES:
                return ProtectionHealth(str(status["category"]))
            audit = inspect_audit_readonly(
                root,
                expected_owner=expected_owner,
                expected_directory_mode=0o700,
                expected_record_mode=0o600,
            )
            with root.open_descendant(("audit",)) as directory:
                admit_archive_append(directory, prefix, 0, entry_count=audit.entry_count)
            count, size = status["protectedSnapshotCount"], status["protectedBytes"]
            assert type(count) is int and type(size) is int  # noqa: S101 - validated status
            return ProtectionHealth(None, count, size, prefix.rotation_intent is not None)
    except StateBusyError:
        return ProtectionHealth("protection")
    except AuditArchiveCapacityError, CapacityError:
        return ProtectionHealth("resource-exhaustion")
    except AuditProtectionError, KeyError:
        return ProtectionHealth("protection")
    except Exception:
        return ProtectionHealth("index-corruption")


def health_main() -> int:
    if os.geteuid() != 0 or sys.argv[1:]:
        print("backup_audit_health_invalid_invocation", file=sys.stderr)
        return 1
    health = inspect_protection_health(
        Path("/var/lib/lowerduckpond/static"), os.environ, expected_owner=0
    )
    print(health.metrics(), end="")
    return int(health.category is not None)
