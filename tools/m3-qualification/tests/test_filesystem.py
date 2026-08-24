from __future__ import annotations

from pathlib import Path

from lowerduckpond_m3_qualification.filesystem import _filesystem_type, run_filesystem_checks

FILESYSTEM_CHECK_COUNT = 6


def test_filesystem_primitives_pass_on_test_filesystem(tmp_path: Path) -> None:
    filesystem_type = _filesystem_type(tmp_path)

    checks = run_filesystem_checks(work_root=tmp_path / "work", expected_filesystem=filesystem_type)

    assert len(checks) == FILESYSTEM_CHECK_COUNT
    assert all(check.status == "passed" for check in checks)


def test_unexpected_filesystem_is_a_failed_check_not_a_skip(tmp_path: Path) -> None:
    checks = run_filesystem_checks(
        work_root=tmp_path / "work", expected_filesystem="definitely-not-this-filesystem"
    )

    filesystem_check = next(check for check in checks if check.check_id.endswith(".type"))
    assert filesystem_check.status == "failed"
    assert filesystem_check.error_code == "probe_failed"
