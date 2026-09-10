"""One serialized, physically bounded private export construction workspace."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.release_tree import InodeAllocation

MAX_EXPORT_SPOOL_BYTES: Final = 256 * 1024 * 1024
MAX_EXPORT_SPOOL_INODES: Final = 5_120
EXPORT_WORKSPACE_BUNDLE_NAME: Final = "bundle.zip"
_INTERNAL_BUNDLE_LINKS: Final = 2
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_DEPTH: Final = 34
_PRIVATE_DIRECTORY_MODE: Final = 0o700
_PRIVATE_FILE_MODE: Final = 0o600
_BLOCK_BYTES: Final = 512
_DIRECTORY_MODES: Final = frozenset({0o700, 0o555})
_FILE_MODES: Final = frozenset({0o600, 0o400, 0o444})
_BUNDLE_PARTIAL: Final = re.compile(r"\.m3-portable-[0-9a-f]{32}\.partial", flags=re.ASCII)


class ExportSpoolError(RuntimeError):
    """Export construction cannot preserve its bounded private namespace."""


class ExportSpoolOccupiedError(ExportSpoolError):
    """A completed download still occupies the global export slot."""


@dataclass(frozen=True, slots=True)
class ExportSpoolLimits:
    maximum_allocated_bytes: int = MAX_EXPORT_SPOOL_BYTES
    maximum_inodes: int = MAX_EXPORT_SPOOL_INODES

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.maximum_allocated_bytes, MAX_EXPORT_SPOOL_BYTES),
            (self.maximum_inodes, MAX_EXPORT_SPOOL_INODES),
        ):
            if type(value) is not int or not 0 <= value <= ceiling:
                raise ValueError("export limits cannot weaken the committed ceilings")


DEFAULT_EXPORT_SPOOL_LIMITS: Final = ExportSpoolLimits()


class ExportSpool:
    """Retain export exclusion through capture, construction, and terminal cleanup."""

    def __init__(
        self,
        state_root: Path,
        *,
        expected_owner: int,
        limits: ExportSpoolLimits = DEFAULT_EXPORT_SPOOL_LIMITS,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> None:
        with DurableDirectory.open(
            state_root, expected_owner=expected_owner, expected_directory_mode=0o700
        ) as root:
            self._directory = root.open_descendant(("exports",))
            try:
                with root.open_descendant(("locks",)) as locks:
                    self.locks = LockManager(locks, expected_owner=expected_owner)
            except BaseException:
                self._directory.close()
                raise
        self._fd = self._directory.duplicate_descriptor()
        self._owner = expected_owner
        self._limits = limits
        self._capacity_limits = capacity_limits
        self._closed = False

    def __enter__(self) -> ExportSpool:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self.locks.close()
            os.close(self._fd)
            self._directory.close()
            self._closed = True

    @property
    def workspace(self) -> Path:
        """A descriptor-anchored path inside the already verified private root."""

        self._require_locked()
        return Path(f"/proc/self/fd/{self._fd}/.work")

    @contextmanager
    def construction(self, *, blocking: bool = False) -> Iterator[ExportSpool]:
        """Admit one workspace; remove incomplete work on every terminal path."""

        with self.locks.acquire(LockName.EXPORT, mode=LockMode.EXCLUSIVE, blocking=blocking):
            names = self._names()
            self.measure()
            if ".work" in names:
                self.discard_workspace()
                names = self._names()
            if names:
                raise ExportSpoolOccupiedError("a completed export occupies the global slot")
            self.reserve(CapacityReservation(self.fragment_size(), 1))
            os.mkdir(".work", mode=0o700, dir_fd=self._fd)
            os.fsync(self._fd)
            try:
                yield self
            finally:
                self.discard_workspace()

    def reconcile_incomplete(self, *, blocking: bool = False) -> bool:
        """Remove only abandoned construction; retain the completed download."""

        with self.locks.acquire(LockName.EXPORT, mode=LockMode.EXCLUSIVE, blocking=blocking):
            names = self._names()
            self.measure()
            if ".work" not in names:
                return False
            self.discard_workspace()
            return True

    def fragment_size(self) -> int:
        self._require_locked()
        return measure_filesystem_capacity_descriptor(self._fd).fragment_size

    def measure(self) -> ReleaseCapacityUsage:
        """Count actual blocks and inodes, including every namespace directory."""

        self._require_locked()
        self._names()
        allocations: list[InodeAllocation] = []
        _walk(self._fd, self._owner, allocations, depth=0)
        return ReleaseCapacityUsage(tuple(allocations))

    def reserve(self, reservation: CapacityReservation) -> None:
        """Require physical spool limits and the host's ordinary free-space reserve."""

        usage = self.measure()
        self._admit(usage.allocated_bytes, usage.unique_inodes, reservation)

    @contextmanager
    def accounting(self) -> Iterator[ExportSpoolAccounting]:
        """Track owned mutations from one complete walk under export exclusion."""

        account = ExportSpoolAccounting(self, self.measure())
        try:
            yield account
        finally:
            account.close()

    def _admit(self, allocated_bytes: int, inodes: int, reservation: CapacityReservation) -> None:
        self._require_locked()
        if (
            allocated_bytes + reservation.allocated_bytes > self._limits.maximum_allocated_bytes
            or inodes + reservation.unique_inodes > self._limits.maximum_inodes
        ):
            raise ExportSpoolError("export spool allocation exceeds its byte or inode limit")
        # Existing spool allocations are already reflected in statvfs. The
        # spool's stricter aggregate ceilings above precede host headroom checks.
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            reservation,
            measure_filesystem_capacity_descriptor(self._fd),
            limits=self._capacity_limits,
        )

    def discard_workspace(self) -> None:
        """Durably resume bounded cleanup even after a partially sealed snapshot."""

        self._require_locked()
        self.measure()
        try:
            descriptor = os.open(".work", _DIRECTORY_FLAGS, dir_fd=self._fd)
        except FileNotFoundError:
            os.fsync(self._fd)
            return
        try:
            _remove_contents(descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(".work", dir_fd=self._fd)
        os.fsync(self._fd)

    def _names(self) -> tuple[str, ...]:
        self._require_locked()
        names = _names(self._fd, maximum=2)
        completed = [name for name in names if name != ".work"]
        if len(completed) > 1:
            raise ExportSpoolError("export spool contains more than one completed result")
        for name in completed:
            if not name.endswith(".zip"):
                raise ExportSpoolError("export spool contains an unknown entry")
            validate_uuid7(name.removesuffix(".zip"))
            metadata = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            ):
                raise ExportSpoolError("completed export is not a private regular file")
        if ".work" in names:
            metadata = os.stat(".work", dir_fd=self._fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
            ):
                raise ExportSpoolError("export workspace is not a private directory")
        return names

    def _require_locked(self) -> None:
        if self._closed:
            raise RuntimeError("export spool is closed")
        self.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)


class ExportSpoolAccounting:
    """Physical allocations updated through descriptors for one owned copy."""

    def __init__(self, spool: ExportSpool, usage: ReleaseCapacityUsage) -> None:
        self._spool = spool
        self._allocations = {
            (item.device, item.inode): item.allocated_bytes for item in usage.allocations
        }
        self._allocated_bytes = usage.allocated_bytes
        self._device = os.fstat(spool._fd).st_dev
        self._active = True

    def close(self) -> None:
        self._active = False

    def record(self, descriptor: int) -> None:
        """Charge a created inode or its changed blocks, including its parent."""

        self._require_active()
        metadata = os.fstat(descriptor)
        checked: list[InodeAllocation] = []
        _record(metadata, self._spool._owner, checked)
        allocation = checked[0]
        if allocation.device != self._device:
            raise ExportSpoolError("export copy crosses a filesystem boundary")
        identity = (allocation.device, allocation.inode)
        previous = self._allocations.get(identity, 0)
        self._allocated_bytes += allocation.allocated_bytes - previous
        self._allocations[identity] = allocation.allocated_bytes
        self.reserve(CapacityReservation(0, 0))

    def reserve(self, reservation: CapacityReservation) -> None:
        self._require_active()
        self._spool._admit(self._allocated_bytes, len(self._allocations), reservation)

    def _require_active(self) -> None:
        if not self._active:
            raise RuntimeError("export copy accounting is closed")
        self._spool._require_locked()


def _names(descriptor: int, *, maximum: int) -> tuple[str, ...]:
    scan = os.open(".", _DIRECTORY_FLAGS, dir_fd=descriptor)
    try:
        names: list[str] = []
        with os.scandir(scan) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    raise ExportSpoolError("export namespace exceeds its entry bound")
        return tuple(sorted(names))
    finally:
        os.close(scan)


def _walk(
    descriptor: int,
    owner: int,
    allocations: list[InodeAllocation],
    *,
    depth: int,
    linked_inodes: set[tuple[int, int]] | None = None,
) -> None:
    if linked_inodes is None:
        linked_inodes = set()
    metadata = os.fstat(descriptor)
    if depth > _MAX_DEPTH:
        raise ExportSpoolError("export namespace exceeds its depth bound")
    _record(metadata, owner, allocations)
    for name in _names(descriptor, maximum=MAX_EXPORT_SPOOL_INODES):
        child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if child.st_dev != metadata.st_dev:
            raise ExportSpoolError("export namespace crosses a filesystem boundary")
        if stat.S_ISDIR(child.st_mode):
            child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (child.st_dev, child.st_ino):
                    raise ExportSpoolError("export namespace changed while opening")
                _walk(child_fd, owner, allocations, depth=depth + 1, linked_inodes=linked_inodes)
            finally:
                os.close(child_fd)
        else:
            internal_link = (
                depth == 1
                and child.st_nlink == _INTERNAL_BUNDLE_LINKS
                and _internal_bundle_link(descriptor, name, child)
            )
            identity = (child.st_dev, child.st_ino)
            if internal_link and identity in linked_inodes:
                continue
            _record(child, owner, allocations, internal_link=internal_link)
            if internal_link:
                linked_inodes.add(identity)


def _internal_bundle_link(descriptor: int, name: str, metadata: os.stat_result) -> bool:
    """Recognize only the builder's two names wholly inside the private workspace."""

    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE:
        return False
    if name == EXPORT_WORKSPACE_BUNDLE_NAME:
        candidates = tuple(
            candidate
            for candidate in _names(descriptor, maximum=MAX_EXPORT_SPOOL_INODES)
            if _BUNDLE_PARTIAL.fullmatch(candidate)
        )
    elif _BUNDLE_PARTIAL.fullmatch(name):
        candidates = (EXPORT_WORKSPACE_BUNDLE_NAME,)
    else:
        return False
    for candidate in candidates:
        try:
            other = os.stat(candidate, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (other.st_dev, other.st_ino, other.st_nlink) == (
            metadata.st_dev,
            metadata.st_ino,
            _INTERNAL_BUNDLE_LINKS,
        ):
            return True
    return False


def _record(
    metadata: os.stat_result,
    owner: int,
    allocations: list[InodeAllocation],
    *,
    internal_link: bool = False,
) -> None:
    directory = stat.S_ISDIR(metadata.st_mode)
    if (
        metadata.st_uid != owner
        or stat.S_IMODE(metadata.st_mode) not in (_DIRECTORY_MODES if directory else _FILE_MODES)
        or (
            not directory
            and (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != (_INTERNAL_BUNDLE_LINKS if internal_link else 1)
            )
        )
    ):
        raise ExportSpoolError("export namespace contains an unsafe inode")
    allocations.append(
        InodeAllocation(metadata.st_dev, metadata.st_ino, metadata.st_blocks * _BLOCK_BYTES)
    )
    if len(allocations) > MAX_EXPORT_SPOOL_INODES:
        raise ExportSpoolError("export namespace exceeds its inode traversal bound")


def _remove_contents(descriptor: int) -> None:
    # The complete bounded no-follow walk precedes any removal. Export exclusion
    # and the root-only parent prevent a tenant or another worker changing it.
    os.fchmod(descriptor, 0o700)
    for name in _names(descriptor, maximum=MAX_EXPORT_SPOOL_INODES):
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                _remove_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)
    os.fsync(descriptor)
