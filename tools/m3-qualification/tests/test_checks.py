from __future__ import annotations

from lowerduckpond_m3_qualification.checks import (
    EVIDENCE_KEYS_BY_CHECK,
    M3_FRAGMENT_CONTRACTS,
    M3_REQUIRED_CHECK_IDS,
)

M3_CHECK_COUNT = 54


def test_m3_gate_has_one_exact_no_skip_check_set() -> None:
    assert len(M3_REQUIRED_CHECK_IDS) == M3_CHECK_COUNT
    assert all(check_id.startswith("m3.0.") for check_id in M3_REQUIRED_CHECK_IDS)
    assert set(EVIDENCE_KEYS_BY_CHECK) == M3_REQUIRED_CHECK_IDS


def test_fragment_contracts_partition_the_required_check_set() -> None:
    _, assembled_check_ids = M3_FRAGMENT_CONTRACTS["assembled"]
    fragment_check_ids = tuple(
        check_ids for label, (_, check_ids) in M3_FRAGMENT_CONTRACTS.items() if label != "assembled"
    )

    assert assembled_check_ids == M3_REQUIRED_CHECK_IDS
    assert frozenset().union(*fragment_check_ids) == M3_REQUIRED_CHECK_IDS
    assert sum(map(len, fragment_check_ids)) == len(M3_REQUIRED_CHECK_IDS)
