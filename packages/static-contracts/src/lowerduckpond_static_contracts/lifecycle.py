"""The complete ordinary static-tenant lifecycle table."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final


class LifecycleState(StrEnum):
    """Persisted desired states plus the absence precondition/result."""

    ABSENT = "absent"
    UNDEPLOYED = "undeployed"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class Operation(StrEnum):
    """Ordinary externally requested operations."""

    CREATE = "create"
    DEPLOY = "deploy"
    ROLLBACK = "rollback"
    SUSPEND = "suspend"
    RESUME = "resume"
    RENAME = "rename"
    EXPORT = "export"
    IMPORT = "import"
    ARCHIVE = "archive"
    RESTORE = "restore"
    DELETE = "delete"
    RECONCILE = "reconcile"


_MATRIX = {
    (Operation.CREATE, LifecycleState.ABSENT): LifecycleState.UNDEPLOYED,
    (Operation.DEPLOY, LifecycleState.UNDEPLOYED): LifecycleState.ACTIVE,
    (Operation.DEPLOY, LifecycleState.ACTIVE): LifecycleState.ACTIVE,
    (Operation.DEPLOY, LifecycleState.SUSPENDED): LifecycleState.SUSPENDED,
    (Operation.ROLLBACK, LifecycleState.ACTIVE): LifecycleState.ACTIVE,
    (Operation.ROLLBACK, LifecycleState.SUSPENDED): LifecycleState.SUSPENDED,
    (Operation.SUSPEND, LifecycleState.ACTIVE): LifecycleState.SUSPENDED,
    (Operation.SUSPEND, LifecycleState.SUSPENDED): LifecycleState.SUSPENDED,
    (Operation.RESUME, LifecycleState.SUSPENDED): LifecycleState.ACTIVE,
    (Operation.RESUME, LifecycleState.ACTIVE): LifecycleState.ACTIVE,
    (Operation.RENAME, LifecycleState.UNDEPLOYED): LifecycleState.UNDEPLOYED,
    (Operation.RENAME, LifecycleState.ACTIVE): LifecycleState.ACTIVE,
    (Operation.RENAME, LifecycleState.SUSPENDED): LifecycleState.SUSPENDED,
    (Operation.EXPORT, LifecycleState.ACTIVE): LifecycleState.ACTIVE,
    (Operation.EXPORT, LifecycleState.SUSPENDED): LifecycleState.SUSPENDED,
    (Operation.EXPORT, LifecycleState.ARCHIVED): LifecycleState.ARCHIVED,
    (Operation.IMPORT, LifecycleState.UNDEPLOYED): LifecycleState.ACTIVE,
    (Operation.ARCHIVE, LifecycleState.ACTIVE): LifecycleState.ARCHIVED,
    (Operation.ARCHIVE, LifecycleState.SUSPENDED): LifecycleState.ARCHIVED,
    (Operation.ARCHIVE, LifecycleState.ARCHIVED): LifecycleState.ARCHIVED,
    (Operation.RESTORE, LifecycleState.ARCHIVED): LifecycleState.ACTIVE,
    (Operation.DELETE, LifecycleState.UNDEPLOYED): LifecycleState.ABSENT,
    (Operation.DELETE, LifecycleState.ARCHIVED): LifecycleState.ABSENT,
    (Operation.RECONCILE, LifecycleState.UNDEPLOYED): LifecycleState.UNDEPLOYED,
    (Operation.RECONCILE, LifecycleState.ACTIVE): LifecycleState.ACTIVE,
    (Operation.RECONCILE, LifecycleState.SUSPENDED): LifecycleState.SUSPENDED,
    (Operation.RECONCILE, LifecycleState.ARCHIVED): LifecycleState.ARCHIVED,
}
LIFECYCLE_MATRIX: Final = MappingProxyType(_MATRIX)
