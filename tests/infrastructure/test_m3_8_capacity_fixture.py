from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent import backup_sources, capacity

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "config/ansible/molecule/m3_8"))
import require_capacity  # noqa: E402


def test_capacity_preflight_matches_production_backup_reservation() -> None:
    limits = capacity.DEFAULT_HOST_CAPACITY_LIMITS
    assert require_capacity.INVENTORY_RESERVATION_BYTES == backup_sources.MAX_INVENTORY_BYTES
    assert limits.minimum_available_bytes == require_capacity.MINIMUM_AVAILABLE_BYTES
    assert limits.minimum_available_inodes == require_capacity.MINIMUM_AVAILABLE_INODES
    assert limits.minimum_available_percent == require_capacity.MINIMUM_AVAILABLE_PERCENT


def test_installed_fixture_binds_backup_workspace_to_durable_ext4() -> None:
    playbook = yaml.safe_load(
        (ROOT / "config/ansible/molecule/m3_8/prepare.yml").read_text(encoding="utf-8")
    )
    tasks = playbook[0]["tasks"]
    binding = next(task for task in tasks if task["name"].startswith("Bind the backup cache"))
    assert binding["ansible.posix.mount"] == {
        "path": "/var/cache/lowerduckpond-backup",
        "src": "/var/lib/lowerduckpond/.m3-8-backup-cache",
        "fstype": "none",
        "opts": "bind,nodev,nosuid",
        "state": "mounted",
    }
    capacity = next(task for task in tasks if task["name"].startswith("Require production"))
    assert capacity["ansible.builtin.script"] == {
        "cmd": "{{ playbook_dir }}/require_capacity.py /var/cache/lowerduckpond-backup",
        "executable": "/usr/bin/python3",
    }


def test_capacity_preflight_accepts_a_sized_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        os,
        "statvfs",
        lambda path: os.statvfs_result(
            (4096, 4096, 2_000_000, 2_000_000, 2_000_000, 500_000, 400_000, 400_000, 0, 255)
        ),
    )
    require_capacity.require(tmp_path)


@pytest.mark.parametrize(
    ("files", "available_inodes", "available_blocks"),
    [(0, 0, 2_000_000), (500_000, 100_000, 2_000_000), (500_000, 400_000, 1_000_000)],
)
def test_capacity_preflight_rejects_unusable_fixture_filesystems(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files: int,
    available_inodes: int,
    available_blocks: int,
) -> None:
    monkeypatch.setattr(
        os,
        "statvfs",
        lambda path: os.statvfs_result(
            (
                4096,
                4096,
                2_000_000,
                available_blocks,
                available_blocks,
                files,
                available_inodes,
                available_inodes,
                0,
                255,
            )
        ),
    )
    with pytest.raises(ValueError, match="qualification_capacity_prerequisite_failed"):
        require_capacity.require(tmp_path)
