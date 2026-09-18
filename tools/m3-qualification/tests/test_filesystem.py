from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from lowerduckpond_m3_qualification import filesystem
from lowerduckpond_m3_qualification.filesystem import _filesystem_type, run_filesystem_checks

FILESYSTEM_CHECK_COUNT = 6
REPORTABLE_LOCAL_FILESYSTEMS = frozenset({"ext4", "overlay", "tmpfs", "xfs"})
SHARED_MEMORY = Path("/dev/shm")  # noqa: S108 - exclusive private TemporaryDirectory below


def test_filesystem_primitives_pass_on_test_filesystem(tmp_path: Path) -> None:
    # Keep the real default filesystem when it is supported by the report
    # contract. Otherwise use the Linux shared-memory mount for this positive
    # primitive probe; production's default requirement remains ext4.
    parent = (
        tmp_path if _filesystem_type(tmp_path) in REPORTABLE_LOCAL_FILESYSTEMS else SHARED_MEMORY
    )
    with tempfile.TemporaryDirectory(prefix="ldp-filesystem-unit-", dir=parent) as name:
        root = Path(name)
        checks = run_filesystem_checks(
            work_root=root / "work", expected_filesystem=_filesystem_type(root)
        )
        assert len(checks) == FILESYSTEM_CHECK_COUNT
        assert all(check.status == "passed" for check in checks)


def test_unexpected_filesystem_is_a_failed_check_not_a_skip(tmp_path: Path) -> None:
    checks = run_filesystem_checks(
        work_root=tmp_path / "work", expected_filesystem="definitely-not-this-filesystem"
    )

    filesystem_check = next(check for check in checks if check.check_id.endswith(".type"))
    assert filesystem_check.status == "failed"
    assert filesystem_check.error_code == "probe_failed"


def test_unreportable_filesystem_is_failed_even_when_it_matches_the_requested_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(filesystem, "_filesystem_type", lambda path: "btrfs")
    checks = run_filesystem_checks(work_root=tmp_path / "work", expected_filesystem="btrfs")
    filesystem_check = next(check for check in checks if check.check_id.endswith(".type"))
    assert filesystem_check.status == "failed"
    assert filesystem_check.error_code == "probe_failed"
