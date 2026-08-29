from __future__ import annotations

import json

from conftest import VECTOR_ROOT
from lowerduckpond_static_contracts.lifecycle import (
    LIFECYCLE_MATRIX,
    TRANSACTION_PHASE_TRANSITIONS,
    LifecycleState,
    Operation,
    TransactionPhase,
)


def test_executable_lifecycle_table_matches_the_reviewed_vector() -> None:
    vector = json.loads((VECTOR_ROOT / "lifecycle-v1.json").read_text(encoding="utf-8"))
    expected = {
        (Operation(operation), LifecycleState(source)): LifecycleState(result)
        for operation, source, result in vector["allowed"]
    }

    assert dict(LIFECYCLE_MATRIX) == expected


def test_every_unlisted_operation_and_source_pair_is_denied() -> None:
    for operation in Operation:
        for source in LifecycleState:
            if (operation, source) in LIFECYCLE_MATRIX:
                continue
            assert (operation, source) not in LIFECYCLE_MATRIX


def test_transaction_phase_transitions_match_the_durable_restart_protocol() -> None:
    assert dict(TRANSACTION_PHASE_TRANSITIONS) == {
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
