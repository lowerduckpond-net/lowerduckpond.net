from __future__ import annotations

from lowerduckpond_m3_qualification.checks import (
    EVIDENCE_KEYS_BY_CHECK,
    M3_REQUIRED_CHECK_IDS,
)

M3_CHECK_COUNT = 36


def test_m3_gate_has_one_exact_no_skip_check_set() -> None:
    assert len(M3_REQUIRED_CHECK_IDS) == M3_CHECK_COUNT
    assert all(check_id.startswith("m3.0.") for check_id in M3_REQUIRED_CHECK_IDS)
    assert set(EVIDENCE_KEYS_BY_CHECK) == M3_REQUIRED_CHECK_IDS
