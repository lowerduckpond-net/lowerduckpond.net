from __future__ import annotations

import json

from conftest import VECTOR_ROOT
from lowerduckpond_static_contracts.lifecycle import (
    LIFECYCLE_MATRIX,
    LifecycleState,
    Operation,
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
