from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_static_contracts import Digest
from lowerduckpond_static_host_agent import (
    CapacityError,
    CapacityRejectedError,
    CapacityReservation,
    FilesystemCapacity,
    HostCapacityLimits,
    InodeAllocation,
    ReleaseCapacityUsage,
    ReleaseTreeMeasurement,
    admit_release_capacity,
    aggregate_release_usage,
    measure_filesystem_capacity,
)

_AGGREGATE_INODES = 3
_AGGREGATE_BYTES = 16_384
_GIBIBYTE = 1024 * 1024 * 1024
_EXACT_HOST_BYTES = 10 * _GIBIBYTE
_EXACT_HOST_INODES = 500_000
_EXACT_FREE_BYTES = 5 * _GIBIBYTE
_EXACT_FREE_INODES = 100_000
_PERCENT_FREE_BYTES = 10 * _GIBIBYTE + 1
_PERCENT_FREE_INODES = 100_001


def _measurement(*allocations: InodeAllocation) -> ReleaseTreeMeasurement:
    return ReleaseTreeMeasurement(
        digest=Digest("lowerduckpond-release-tree-v1", "sha256", "0" * 64),
        entry_count=0,
        logical_content_bytes=0,
        allocations=allocations,
    )


def _filesystem(
    *,
    device: int = 1,
    total_bytes: int = 50 * _GIBIBYTE,
    available_bytes: int = 10 * _GIBIBYTE,
    total_inodes: int = 1_000_000,
    available_inodes: int = 200_000,
) -> FilesystemCapacity:
    return FilesystemCapacity(
        device=device,
        fragment_size=1,
        total_blocks=total_bytes,
        available_blocks=available_bytes,
        total_inodes=total_inodes,
        available_inodes=available_inodes,
    )


def test_aggregate_usage_counts_hardlinks_once_across_release_roots() -> None:
    shared = InodeAllocation(1, 10, 4_096)

    usage = aggregate_release_usage(
        [
            _measurement(shared, InodeAllocation(1, 11, 4_096)),
            _measurement(shared, InodeAllocation(1, 12, 8_192)),
        ]
    )

    assert usage.unique_inodes == _AGGREGATE_INODES
    assert usage.allocated_bytes == _AGGREGATE_BYTES


def test_aggregate_usage_rejects_inconsistent_observations_of_one_inode() -> None:
    with pytest.raises(CapacityError, match="inconsistent"):
        aggregate_release_usage(
            [
                _measurement(InodeAllocation(1, 10, 4_096)),
                _measurement(InodeAllocation(1, 10, 8_192)),
            ]
        )


def test_exact_host_and_free_space_boundaries_are_admitted() -> None:
    usage = ReleaseCapacityUsage((InodeAllocation(1, 10, 6 * _GIBIBYTE),))

    projection = admit_release_capacity(
        usage,
        CapacityReservation(allocated_bytes=4 * _GIBIBYTE, unique_inodes=499_999),
        _filesystem(
            available_bytes=9 * _GIBIBYTE,
            available_inodes=599_999,
        ),
    )

    assert projection.projected_allocated_bytes == _EXACT_HOST_BYTES
    assert projection.projected_unique_inodes == _EXACT_HOST_INODES
    assert projection.remaining_available_bytes == _EXACT_FREE_BYTES
    assert projection.remaining_available_inodes == _EXACT_FREE_INODES


@pytest.mark.parametrize(
    ("usage", "reservation", "filesystem", "message"),
    [
        (
            ReleaseCapacityUsage((InodeAllocation(1, 10, 6 * _GIBIBYTE),)),
            CapacityReservation(4 * _GIBIBYTE + 1, 0),
            _filesystem(),
            "byte ceiling",
        ),
        (
            ReleaseCapacityUsage((InodeAllocation(1, 10, 0),)),
            CapacityReservation(0, 500_000),
            _filesystem(available_inodes=600_000),
            "inode ceiling",
        ),
        (
            ReleaseCapacityUsage(()),
            CapacityReservation(5 * _GIBIBYTE + 1, 0),
            _filesystem(),
            "free-block floor",
        ),
        (
            ReleaseCapacityUsage(()),
            CapacityReservation(0, 100_001),
            _filesystem(),
            "free-inode floor",
        ),
    ],
)
def test_one_past_each_capacity_boundary_is_rejected(
    usage: ReleaseCapacityUsage,
    reservation: CapacityReservation,
    filesystem: FilesystemCapacity,
    message: str,
) -> None:
    with pytest.raises(CapacityRejectedError, match=message):
        admit_release_capacity(usage, reservation, filesystem)


def test_percentage_floor_uses_ceiling_and_can_exceed_absolute_floor() -> None:
    filesystem = _filesystem(
        total_bytes=100 * _GIBIBYTE + 1,
        available_bytes=11 * _GIBIBYTE + 1,
        total_inodes=1_000_001,
        available_inodes=200_001,
    )

    projection = admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(_GIBIBYTE, 100_000),
        filesystem,
    )

    assert projection.required_available_bytes == _PERCENT_FREE_BYTES
    assert projection.required_available_inodes == _PERCENT_FREE_INODES
    assert projection.remaining_available_bytes == _PERCENT_FREE_BYTES
    assert projection.remaining_available_inodes == _PERCENT_FREE_INODES


def test_root_reserved_blocks_cannot_substitute_for_ordinary_availability() -> None:
    # The admission API deliberately has no f_bfree input: only f_bavail can reach it.
    filesystem = _filesystem(available_bytes=5 * _GIBIBYTE - 1)

    with pytest.raises(CapacityRejectedError, match="free-block floor"):
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(0, 0),
            filesystem,
        )


def test_usage_from_another_filesystem_is_rejected() -> None:
    usage = ReleaseCapacityUsage((InodeAllocation(2, 10, 1),))

    with pytest.raises(CapacityError, match="different filesystem"):
        admit_release_capacity(
            usage,
            CapacityReservation(0, 0),
            _filesystem(device=1),
        )


def test_callers_cannot_weaken_recorded_host_boundaries() -> None:
    with pytest.raises(ValueError, match="cannot weaken"):
        HostCapacityLimits(maximum_allocated_bytes=10 * _GIBIBYTE + 1)


def test_live_filesystem_measurement_is_descriptor_relative(tmp_path: Path) -> None:
    measured = measure_filesystem_capacity(tmp_path)
    expected = tmp_path.stat().st_dev

    assert measured.device == expected
    assert measured.fragment_size > 0
    assert 0 <= measured.available_blocks <= measured.total_blocks
    assert 0 <= measured.available_inodes <= measured.total_inodes
