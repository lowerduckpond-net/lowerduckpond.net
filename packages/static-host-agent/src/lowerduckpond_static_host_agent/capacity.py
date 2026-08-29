"""Physical host-capacity accounting and fail-closed admission."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.release_tree import (
    InodeAllocation,
    ReleaseTreeMeasurement,
)

GIBIBYTE: Final = 1024 * 1024 * 1024
_PERCENT_DENOMINATOR: Final = 100
_INITIAL_MAXIMUM_ALLOCATED_BYTES: Final = 10 * GIBIBYTE
_INITIAL_MAXIMUM_UNIQUE_INODES: Final = 500_000
_INITIAL_MINIMUM_AVAILABLE_BYTES: Final = 5 * GIBIBYTE
_INITIAL_MINIMUM_AVAILABLE_INODES: Final = 100_000
_INITIAL_MINIMUM_AVAILABLE_PERCENT: Final = 10


class CapacityError(RuntimeError):
    """Capacity inputs could not describe one coherent filesystem."""


class CapacityRejectedError(CapacityError):
    """A worst-case allocation would cross a committed host boundary."""


@dataclass(frozen=True, slots=True)
class HostCapacityLimits:
    """Initial M3 release and free-space ceilings from ADR 0017."""

    maximum_allocated_bytes: int = _INITIAL_MAXIMUM_ALLOCATED_BYTES
    maximum_unique_inodes: int = _INITIAL_MAXIMUM_UNIQUE_INODES
    minimum_available_bytes: int = _INITIAL_MINIMUM_AVAILABLE_BYTES
    minimum_available_inodes: int = _INITIAL_MINIMUM_AVAILABLE_INODES
    minimum_available_percent: int = _INITIAL_MINIMUM_AVAILABLE_PERCENT

    def __post_init__(self) -> None:
        numeric = (
            self.maximum_allocated_bytes,
            self.maximum_unique_inodes,
            self.minimum_available_bytes,
            self.minimum_available_inodes,
        )
        if any(type(value) is not int or value < 0 for value in numeric):
            raise ValueError("capacity limits must be nonnegative integers")
        if (
            type(self.minimum_available_percent) is not int
            or not 0 <= self.minimum_available_percent <= _PERCENT_DENOMINATOR
        ):
            raise ValueError("capacity reserve percentage must be between zero and 100")
        if (
            self.maximum_allocated_bytes > _INITIAL_MAXIMUM_ALLOCATED_BYTES
            or self.maximum_unique_inodes > _INITIAL_MAXIMUM_UNIQUE_INODES
            or self.minimum_available_bytes < _INITIAL_MINIMUM_AVAILABLE_BYTES
            or self.minimum_available_inodes < _INITIAL_MINIMUM_AVAILABLE_INODES
            or self.minimum_available_percent < _INITIAL_MINIMUM_AVAILABLE_PERCENT
        ):
            raise ValueError("capacity limits cannot weaken the committed M3 boundaries")


@dataclass(frozen=True, slots=True)
class CapacityReservation:
    """Worst-case blocks and new inodes reserved before a mutation."""

    allocated_bytes: int
    unique_inodes: int

    def __post_init__(self) -> None:
        if (
            type(self.allocated_bytes) is not int
            or type(self.unique_inodes) is not int
            or self.allocated_bytes < 0
            or self.unique_inodes < 0
        ):
            raise ValueError("capacity reservation must be nonnegative")


@dataclass(frozen=True, slots=True)
class ReleaseCapacityUsage:
    """Deduplicated physical allocation already present on one filesystem."""

    allocations: tuple[InodeAllocation, ...]

    def __post_init__(self) -> None:
        identities = {(item.device, item.inode) for item in self.allocations}
        if len(identities) != len(self.allocations):
            raise CapacityError("release usage contains duplicate inode allocations")

    @property
    def allocated_bytes(self) -> int:
        return sum(allocation.allocated_bytes for allocation in self.allocations)

    @property
    def unique_inodes(self) -> int:
        return len(self.allocations)


@dataclass(frozen=True, slots=True)
class FilesystemCapacity:
    """The ordinarily available block and inode view used for admission."""

    device: int
    fragment_size: int
    total_blocks: int
    available_blocks: int
    total_inodes: int
    available_inodes: int

    def __post_init__(self) -> None:
        values = (
            self.device,
            self.fragment_size,
            self.total_blocks,
            self.available_blocks,
            self.total_inodes,
            self.available_inodes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise CapacityError("filesystem capacity values must be available and nonnegative")
        if self.fragment_size == 0 or self.available_blocks > self.total_blocks:
            raise CapacityError("filesystem block capacity is inconsistent")
        if self.available_inodes > self.total_inodes:
            raise CapacityError("filesystem inode capacity is inconsistent")

    @property
    def total_bytes(self) -> int:
        return self.fragment_size * self.total_blocks

    @property
    def available_bytes(self) -> int:
        return self.fragment_size * self.available_blocks


@dataclass(frozen=True, slots=True)
class CapacityProjection:
    """The admitted aggregate and remaining ordinary filesystem capacity."""

    projected_allocated_bytes: int
    projected_unique_inodes: int
    remaining_available_bytes: int
    remaining_available_inodes: int
    required_available_bytes: int
    required_available_inodes: int


def measure_filesystem_capacity(root: Path) -> FilesystemCapacity:
    """Read statvfs through a no-follow directory descriptor."""

    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_descriptor = os.open(root, flags)
    try:
        filesystem = os.fstatvfs(file_descriptor)
        device = os.fstat(file_descriptor).st_dev
    finally:
        os.close(file_descriptor)
    fragment_size = filesystem.f_frsize or filesystem.f_bsize
    return FilesystemCapacity(
        device=device,
        fragment_size=fragment_size,
        total_blocks=filesystem.f_blocks,
        available_blocks=filesystem.f_bavail,
        total_inodes=filesystem.f_files,
        available_inodes=filesystem.f_favail,
    )


def aggregate_release_usage(
    measurements: Iterable[ReleaseTreeMeasurement],
) -> ReleaseCapacityUsage:
    """Deduplicate hard-linked allocations across every retained release tree."""

    allocations: dict[tuple[int, int], int] = {}
    for measurement in measurements:
        for allocation in measurement.allocations:
            identity = (allocation.device, allocation.inode)
            established = allocations.setdefault(identity, allocation.allocated_bytes)
            if established != allocation.allocated_bytes:
                raise CapacityError("one inode has inconsistent allocated-block accounting")
    return ReleaseCapacityUsage(
        tuple(
            InodeAllocation(device, inode, allocated_bytes)
            for (device, inode), allocated_bytes in sorted(allocations.items())
        )
    )


def _percentage_floor(total: int, percentage: int) -> int:
    return (total * percentage + _PERCENT_DENOMINATOR - 1) // _PERCENT_DENOMINATOR


DEFAULT_HOST_CAPACITY_LIMITS: Final = HostCapacityLimits()


def admit_release_capacity(
    usage: ReleaseCapacityUsage,
    reservation: CapacityReservation,
    filesystem: FilesystemCapacity,
    *,
    limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> CapacityProjection:
    """Admit only if host ceilings and post-allocation free floors all remain satisfied."""

    if any(allocation.device != filesystem.device for allocation in usage.allocations):
        raise CapacityError("release usage spans a different filesystem")

    projected_bytes = usage.allocated_bytes + reservation.allocated_bytes
    projected_inodes = usage.unique_inodes + reservation.unique_inodes
    if projected_bytes > limits.maximum_allocated_bytes:
        raise CapacityRejectedError("release allocation would cross the host byte ceiling")
    if projected_inodes > limits.maximum_unique_inodes:
        raise CapacityRejectedError("release allocation would cross the host inode ceiling")
    if reservation.allocated_bytes > filesystem.available_bytes:
        raise CapacityRejectedError("release reservation exceeds ordinarily available blocks")
    if reservation.unique_inodes > filesystem.available_inodes:
        raise CapacityRejectedError("release reservation exceeds ordinarily available inodes")

    remaining_bytes = filesystem.available_bytes - reservation.allocated_bytes
    remaining_inodes = filesystem.available_inodes - reservation.unique_inodes
    required_bytes = max(
        limits.minimum_available_bytes,
        _percentage_floor(filesystem.total_bytes, limits.minimum_available_percent),
    )
    required_inodes = max(
        limits.minimum_available_inodes,
        _percentage_floor(filesystem.total_inodes, limits.minimum_available_percent),
    )
    if remaining_bytes < required_bytes:
        raise CapacityRejectedError("release reservation would cross the free-block floor")
    if remaining_inodes < required_inodes:
        raise CapacityRejectedError("release reservation would cross the free-inode floor")
    return CapacityProjection(
        projected_allocated_bytes=projected_bytes,
        projected_unique_inodes=projected_inodes,
        remaining_available_bytes=remaining_bytes,
        remaining_available_inodes=remaining_inodes,
        required_available_bytes=required_bytes,
        required_available_inodes=required_inodes,
    )
