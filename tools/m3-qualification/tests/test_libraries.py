from __future__ import annotations

from lowerduckpond_m3_qualification.libraries import run_library_checks

LIBRARY_CHECK_COUNT = 7


def test_every_pinned_library_capability_is_available() -> None:
    checks = run_library_checks()

    assert len(checks) == LIBRARY_CHECK_COUNT
    assert all(check.status == "passed" for check in checks)
    assert {check.check_id for check in checks} == {
        "m3.0.python.botocore",
        "m3.0.python.hypothesis",
        "m3.0.python.jsonschema",
        "m3.0.python.playwright",
        "m3.0.python.rfc8785",
        "m3.0.python.runtime",
        "m3.0.python.safe-yaml",
    }
