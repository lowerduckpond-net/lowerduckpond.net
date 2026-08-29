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


class TransactionPhase(StrEnum):
    """Durable lifecycle and restart-recovery transaction phases."""

    PREPARED = "prepared"
    RUNTIME_SELECTED = "runtime-selected"
    RESTART_REQUIRED = "restart-required"
    CANDIDATE_STARTING = "candidate-starting"
    ROLLBACK_RESTART_REQUIRED = "rollback-restart-required"
    RECOVERY_STARTING = "recovery-starting"
    STATE_COMMITTED = "state-committed"


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

_TRANSACTION_PHASE_TRANSITIONS = {
    TransactionPhase.PREPARED: frozenset(
        {
            TransactionPhase.RUNTIME_SELECTED,
            TransactionPhase.RESTART_REQUIRED,
            TransactionPhase.STATE_COMMITTED,
        }
    ),
    TransactionPhase.RUNTIME_SELECTED: frozenset({TransactionPhase.STATE_COMMITTED}),
    TransactionPhase.RESTART_REQUIRED: frozenset({TransactionPhase.CANDIDATE_STARTING}),
    TransactionPhase.CANDIDATE_STARTING: frozenset(
        {
            TransactionPhase.CANDIDATE_STARTING,
            TransactionPhase.ROLLBACK_RESTART_REQUIRED,
            TransactionPhase.STATE_COMMITTED,
        }
    ),
    TransactionPhase.ROLLBACK_RESTART_REQUIRED: frozenset({TransactionPhase.RECOVERY_STARTING}),
    TransactionPhase.RECOVERY_STARTING: frozenset(
        {
            TransactionPhase.RECOVERY_STARTING,
            TransactionPhase.STATE_COMMITTED,
        }
    ),
    TransactionPhase.STATE_COMMITTED: frozenset(),
}
TRANSACTION_PHASE_TRANSITIONS: Final = MappingProxyType(_TRANSACTION_PHASE_TRANSITIONS)
