"""Fail early when the installed fixture cannot exercise production capacity policy."""

from __future__ import annotations

import os
import sys
from pathlib import Path

GIBIBYTE = 1024**3
INVENTORY_RESERVATION_BYTES = GIBIBYTE
MINIMUM_AVAILABLE_BYTES = 5 * GIBIBYTE
MINIMUM_AVAILABLE_INODES = 100_000
MINIMUM_AVAILABLE_PERCENT = 10
PERCENT_DENOMINATOR = 100
ARGUMENT_COUNT = 2


def percentage_floor(total: int) -> int:
    return (total * MINIMUM_AVAILABLE_PERCENT + PERCENT_DENOMINATOR - 1) // PERCENT_DENOMINATOR


def require(path: Path) -> None:
    filesystem = os.statvfs(path)
    fragment_size = filesystem.f_frsize or filesystem.f_bsize
    total_bytes = fragment_size * filesystem.f_blocks
    available_bytes = fragment_size * filesystem.f_bavail
    required_bytes = max(MINIMUM_AVAILABLE_BYTES, percentage_floor(total_bytes))
    required_inodes = max(MINIMUM_AVAILABLE_INODES, percentage_floor(filesystem.f_files))
    if (
        filesystem.f_files <= 0
        or filesystem.f_favail <= required_inodes
        or available_bytes < required_bytes + INVENTORY_RESERVATION_BYTES
    ):
        raise ValueError("qualification_capacity_prerequisite_failed")


def main() -> int:
    try:
        if len(sys.argv) != ARGUMENT_COUNT:
            raise ValueError("qualification_capacity_prerequisite_failed")
        require(Path(sys.argv[1]))
    except OSError, ValueError:
        print("qualification_capacity_prerequisite_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
