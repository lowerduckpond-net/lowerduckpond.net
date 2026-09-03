"""Canonical release-tree measurement over a hostile filesystem namespace."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_contracts import Digest

from lowerduckpond_static_host_agent.locks import LockMode, LockName

RELEASE_TREE_FORMAT: Final = "lowerduckpond-release-tree-v1"
MAX_RELEASE_ENTRIES: Final = 5_000
MAX_RELEASE_CONTENT_BYTES: Final = 100 * 1024 * 1024
MAX_RELEASE_FILE_BYTES: Final = 25 * 1024 * 1024
MAX_RELEASE_PATH_BYTES: Final = 1_024
MAX_RELEASE_COMPONENT_BYTES: Final = 255
MAX_RELEASE_DEPTH: Final = 32

_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_SIZE: Final = 64 * 1024
_BLOCK_UNIT_BYTES: Final = 512


class ReleaseTreeError(RuntimeError):
    """A release tree violated its normalized or stable filesystem contract."""


class ReleaseTreeBoundary(StrEnum):
    """Observable boundaries used to prove mutation detection."""

    AFTER_SCAN = "after-scan"
    FILE_CHUNK = "file-chunk"
    BEFORE_FINAL_VALIDATION = "before-final-validation"
    FINAL_ENTRY = "final-entry"


MeasurementHook = Callable[[ReleaseTreeBoundary, bytes | None], None]


class _DigestWriter(Protocol):
    def update(self, value: bytes, /) -> None: ...


class _PublicationLockProof(Protocol):
    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ReleaseTreeLimits:
    """Version-one normalized tree limits."""

    maximum_entries: int = MAX_RELEASE_ENTRIES
    maximum_content_bytes: int = MAX_RELEASE_CONTENT_BYTES
    maximum_file_bytes: int = MAX_RELEASE_FILE_BYTES
    maximum_path_bytes: int = MAX_RELEASE_PATH_BYTES
    maximum_component_bytes: int = MAX_RELEASE_COMPONENT_BYTES
    maximum_depth: int = MAX_RELEASE_DEPTH

    def __post_init__(self) -> None:
        values = (
            self.maximum_entries,
            self.maximum_content_bytes,
            self.maximum_file_bytes,
            self.maximum_path_bytes,
            self.maximum_component_bytes,
            self.maximum_depth,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("release-tree limits must be nonnegative integers")
        if self.maximum_entries > (1 << 32) - 1:
            raise ValueError("release-tree entry limit is not encodable")
        if self.maximum_file_bytes > self.maximum_content_bytes:
            raise ValueError("per-file limit cannot exceed the content limit")
        committed = (
            MAX_RELEASE_ENTRIES,
            MAX_RELEASE_CONTENT_BYTES,
            MAX_RELEASE_FILE_BYTES,
            MAX_RELEASE_PATH_BYTES,
            MAX_RELEASE_COMPONENT_BYTES,
            MAX_RELEASE_DEPTH,
        )
        if any(value > ceiling for value, ceiling in zip(values, committed, strict=True)):
            raise ValueError("release-tree limits cannot weaken the committed v1 ceilings")


@dataclass(frozen=True, slots=True, order=True)
class InodeAllocation:
    """One unique filesystem allocation charged by host admission."""

    device: int
    inode: int
    allocated_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.device) is not int
            or type(self.inode) is not int
            or type(self.allocated_bytes) is not int
            or self.device < 0
            or self.inode <= 0
            or self.allocated_bytes < 0
        ):
            raise ValueError("inode allocation values must be nonnegative and concrete")


@dataclass(frozen=True, slots=True)
class ReleaseTreeMeasurement:
    """The protocol digest and physical usage proven by one stable tree walk."""

    digest: Digest
    entry_count: int
    logical_content_bytes: int
    allocations: tuple[InodeAllocation, ...]

    def __post_init__(self) -> None:
        if self.digest.format != RELEASE_TREE_FORMAT or self.digest.algorithm != "sha256":
            raise ValueError("release-tree measurement has the wrong digest format")
        if (
            type(self.entry_count) is not int
            or type(self.logical_content_bytes) is not int
            or self.entry_count < 0
            or self.logical_content_bytes < 0
        ):
            raise ValueError("release-tree measurement counts must be nonnegative")
        identities = {(item.device, item.inode) for item in self.allocations}
        if len(identities) != len(self.allocations):
            raise ValueError("release-tree measurement contains duplicate inode allocations")

    @property
    def unique_inode_count(self) -> int:
        return len(self.allocations)

    @property
    def allocated_bytes(self) -> int:
        return sum(allocation.allocated_bytes for allocation in self.allocations)


@dataclass(frozen=True, slots=True)
class _Snapshot:
    device: int
    inode: int
    mode: int
    owner: int
    group: int
    links: int
    size: int
    blocks: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def capture(cls, value: os.stat_result) -> _Snapshot:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            owner=value.st_uid,
            group=value.st_gid,
            links=value.st_nlink,
            size=value.st_size,
            blocks=value.st_blocks,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class _Entry:
    components: tuple[str, ...]
    path_bytes: bytes
    is_directory: bool
    snapshot: _Snapshot


@dataclass(slots=True)
class _ScanState:
    entries: list[_Entry]
    allocations: dict[tuple[int, int], int]
    directory_identities: set[tuple[int, int]]
    casefolded_paths: set[str]
    logical_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _ScanContext:
    expected_owner: int
    expected_device: int
    limits: ReleaseTreeLimits
    state: _ScanState


def _notify(
    hook: MeasurementHook | None,
    boundary: ReleaseTreeBoundary,
    path: bytes | None = None,
) -> None:
    if hook is not None:
        hook(boundary, path)


def _validate_snapshot(
    snapshot: _Snapshot,
    *,
    expected_owner: int,
    expected_mode: int,
    is_directory: bool,
) -> None:
    expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
    if not expected_type(snapshot.mode):
        raise ReleaseTreeError("release tree contains a disallowed inode type")
    if snapshot.owner != expected_owner:
        raise ReleaseTreeError("release tree contains an inode with the wrong owner")
    if stat.S_IMODE(snapshot.mode) != expected_mode:
        raise ReleaseTreeError("release tree contains an inode with the wrong mode")
    if snapshot.blocks < 0:
        raise ReleaseTreeError("release tree inode has invalid allocated-block accounting")


def _validate_component(component: str, limits: ReleaseTreeLimits) -> bytes:
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        or "\x00" in component
    ):
        raise ReleaseTreeError("release tree contains an invalid path component")
    try:
        encoded = component.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ReleaseTreeError("release tree name is not valid UTF-8") from error
    if unicodedata.normalize("NFC", component) != component:
        raise ReleaseTreeError("release tree name is not NFC normalized")
    if any(unicodedata.category(character) == "Cc" for character in component):
        raise ReleaseTreeError("release tree name contains a control character")
    if len(encoded) > limits.maximum_component_bytes:
        raise ReleaseTreeError("release tree component exceeds its byte limit")
    return encoded


def _validate_path(
    components: tuple[str, ...],
    component_bytes: tuple[bytes, ...],
    limits: ReleaseTreeLimits,
) -> bytes:
    if len(components) > limits.maximum_depth:
        raise ReleaseTreeError("release tree path exceeds its depth limit")
    path = b"/".join(component_bytes)
    if len(path) > limits.maximum_path_bytes:
        raise ReleaseTreeError("release tree path exceeds its byte limit")
    if components[0].lower() == "cdn-cgi":
        raise ReleaseTreeError("release tree uses Cloudflare's reserved first component")
    return path


def _same_generation(first: _Snapshot, second: _Snapshot) -> bool:
    return first == second


def _open_directory_at(root_fd: int, components: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for component in components:
            descendant = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = descendant
    except BaseException:
        os.close(current)
        raise
    return current


def _open_file_at(root_fd: int, components: tuple[str, ...]) -> tuple[int, int, str]:
    parent_fd = _open_directory_at(root_fd, components[:-1])
    try:
        file_fd = os.open(components[-1], _FILE_FLAGS, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd, file_fd, components[-1]


def _stat_entry(parent_fd: int, name: str, *, error_message: str) -> _Snapshot:
    try:
        return _Snapshot.capture(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    except OSError as error:
        raise ReleaseTreeError(error_message) from error


def _record_allocation(
    allocations: dict[tuple[int, int], int],
    snapshot: _Snapshot,
) -> None:
    identity = (snapshot.device, snapshot.inode)
    allocated_bytes = snapshot.blocks * _BLOCK_UNIT_BYTES
    established = allocations.setdefault(identity, allocated_bytes)
    if established != allocated_bytes:
        raise ReleaseTreeError("hard-linked inode allocation changed during measurement")


def _scan_directory(
    directory_fd: int,
    components: tuple[str, ...],
    encoded: tuple[bytes, ...],
    context: _ScanContext,
) -> None:
    try:
        with os.scandir(directory_fd) as iterator:
            for directory_entry in iterator:
                _scan_entry(
                    directory_fd,
                    directory_entry.name,
                    components,
                    encoded,
                    context,
                )
    except ReleaseTreeError:
        raise
    except OSError as error:
        raise ReleaseTreeError("release directory could not be enumerated") from error


def _scan_entry(
    directory_fd: int,
    name: str,
    components: tuple[str, ...],
    encoded: tuple[bytes, ...],
    context: _ScanContext,
) -> None:
    name_bytes = _validate_component(name, context.limits)
    child_components = (*components, name)
    child_encoded = (*encoded, name_bytes)
    path_bytes = _validate_path(child_components, child_encoded, context.limits)
    try:
        snapshot = _Snapshot.capture(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except OSError as error:
        raise ReleaseTreeError("release entry changed while it was enumerated") from error
    is_directory = stat.S_ISDIR(snapshot.mode)
    _validate_snapshot(
        snapshot,
        expected_owner=context.expected_owner,
        expected_mode=0o755 if is_directory else 0o644,
        is_directory=is_directory,
    )
    if snapshot.device != context.expected_device:
        raise ReleaseTreeError("release tree crosses a filesystem boundary")
    folded = unicodedata.normalize("NFC", "/".join(child_components).casefold())
    if folded in context.state.casefolded_paths:
        raise ReleaseTreeError("release tree contains a case-folding collision")
    context.state.casefolded_paths.add(folded)
    entry = _Entry(child_components, path_bytes, is_directory, snapshot)
    context.state.entries.append(entry)
    if len(context.state.entries) > context.limits.maximum_entries:
        raise ReleaseTreeError("release tree exceeds its entry limit")
    _record_allocation(context.state.allocations, snapshot)
    if is_directory:
        _scan_child_directory(
            directory_fd,
            name,
            entry,
            child_encoded,
            context,
        )
    else:
        if snapshot.size < 0 or snapshot.size > context.limits.maximum_file_bytes:
            raise ReleaseTreeError("release file exceeds its byte limit")
        context.state.logical_bytes += snapshot.size
        if context.state.logical_bytes > context.limits.maximum_content_bytes:
            raise ReleaseTreeError("release tree exceeds its content limit")


def _scan_child_directory(
    parent_fd: int,
    name: str,
    entry: _Entry,
    encoded: tuple[bytes, ...],
    context: _ScanContext,
) -> None:
    identity = (entry.snapshot.device, entry.snapshot.inode)
    if identity in context.state.directory_identities:
        raise ReleaseTreeError("release tree contains an aliased directory")
    context.state.directory_identities.add(identity)
    try:
        child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise ReleaseTreeError("release directory changed while it was opened") from error
    try:
        opened = _Snapshot.capture(os.fstat(child_fd))
        if not _same_generation(entry.snapshot, opened):
            raise ReleaseTreeError("release directory changed while it was opened")
        _scan_directory(
            child_fd,
            entry.components,
            encoded,
            context,
        )
    finally:
        os.close(child_fd)


def _hash_file(
    digest: _DigestWriter,
    root_fd: int,
    entry: _Entry,
    hook: MeasurementHook | None,
) -> None:
    try:
        parent_fd, file_fd, name = _open_file_at(root_fd, entry.components)
    except OSError as error:
        raise ReleaseTreeError("release file changed before it could be read") from error
    try:
        opened = _Snapshot.capture(os.fstat(file_fd))
        current = _stat_entry(
            parent_fd,
            name,
            error_message="release file changed before it was read",
        )
        if not _same_generation(entry.snapshot, opened) or not _same_generation(opened, current):
            raise ReleaseTreeError("release file changed before it was read")
        remaining = entry.snapshot.size
        while remaining:
            try:
                chunk = os.read(file_fd, min(remaining, _READ_SIZE))
            except OSError as error:
                raise ReleaseTreeError("release file could not be read") from error
            if not chunk:
                raise ReleaseTreeError("release file became shorter while it was read")
            digest.update(chunk)
            remaining -= len(chunk)
            _notify(hook, ReleaseTreeBoundary.FILE_CHUNK, entry.path_bytes)
        try:
            trailing = os.read(file_fd, 1)
        except OSError as error:
            raise ReleaseTreeError("release file could not be read") from error
        if trailing:
            raise ReleaseTreeError("release file became longer while it was read")
        final = _Snapshot.capture(os.fstat(file_fd))
        final_path = _stat_entry(
            parent_fd,
            name,
            error_message="release file changed while it was read",
        )
        if not _same_generation(entry.snapshot, final) or not _same_generation(final, final_path):
            raise ReleaseTreeError("release file changed while it was read")
    finally:
        os.close(file_fd)
        os.close(parent_fd)


def _validate_tree(
    root_fd: int,
    root_path: Path,
    root_snapshot: _Snapshot,
    entries: list[_Entry],
    hook: MeasurementHook | None,
) -> None:
    final_order = sorted(entries, key=lambda entry: (-len(entry.components), entry.path_bytes))
    for entry in final_order:
        if entry.is_directory:
            try:
                entry_fd = _open_directory_at(root_fd, entry.components)
            except OSError as error:
                raise ReleaseTreeError("release directory changed during measurement") from error
            parent_fd = None
        else:
            try:
                parent_fd, entry_fd, name = _open_file_at(root_fd, entry.components)
            except OSError as error:
                raise ReleaseTreeError("release file changed during measurement") from error
        try:
            final = _Snapshot.capture(os.fstat(entry_fd))
            if not _same_generation(entry.snapshot, final):
                raise ReleaseTreeError("release entry changed during final validation")
            if parent_fd is not None:
                final_path = _stat_entry(
                    parent_fd,
                    name,
                    error_message="release file changed during final validation",
                )
                if not _same_generation(final, final_path):
                    raise ReleaseTreeError("release file changed during final validation")
        finally:
            os.close(entry_fd)
            if parent_fd is not None:
                os.close(parent_fd)
        _notify(hook, ReleaseTreeBoundary.FINAL_ENTRY, entry.path_bytes)
    current_root = _Snapshot.capture(os.fstat(root_fd))
    try:
        named_root = _Snapshot.capture(root_path.stat(follow_symlinks=False))
    except OSError as error:
        raise ReleaseTreeError("release root changed during measurement") from error
    if not _same_generation(root_snapshot, current_root) or not _same_generation(
        current_root, named_root
    ):
        raise ReleaseTreeError("release root changed during measurement")


DEFAULT_RELEASE_TREE_LIMITS: Final = ReleaseTreeLimits()


def _measure_release_tree(
    root: Path,
    *,
    expected_owner: int,
    limits: ReleaseTreeLimits = DEFAULT_RELEASE_TREE_LIMITS,
    measurement_hook: MeasurementHook | None = None,
) -> ReleaseTreeMeasurement:
    """Measure one normalized, stable release without following namespace links."""

    try:
        root_fd = os.open(root, _DIRECTORY_FLAGS)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReleaseTreeError("release root is not a no-follow directory") from error
        raise ReleaseTreeError("release root could not be opened") from error
    try:
        root_snapshot = _Snapshot.capture(os.fstat(root_fd))
        _validate_snapshot(
            root_snapshot,
            expected_owner=expected_owner,
            expected_mode=0o755,
            is_directory=True,
        )
        try:
            named_root = _Snapshot.capture(root.stat(follow_symlinks=False))
        except OSError as error:
            raise ReleaseTreeError("release root changed while it was opened") from error
        if not _same_generation(root_snapshot, named_root):
            raise ReleaseTreeError("release root changed while it was opened")

        state = _ScanState(
            entries=[],
            allocations={},
            directory_identities={(root_snapshot.device, root_snapshot.inode)},
            casefolded_paths=set(),
        )
        _record_allocation(state.allocations, root_snapshot)
        _scan_directory(
            root_fd,
            (),
            (),
            _ScanContext(expected_owner, root_snapshot.device, limits, state),
        )
        state.entries.sort(key=lambda entry: entry.path_bytes)
        _notify(measurement_hook, ReleaseTreeBoundary.AFTER_SCAN)

        digest = hashlib.sha256()
        digest.update(RELEASE_TREE_FORMAT.encode("ascii") + b"\0")
        digest.update(len(state.entries).to_bytes(4, "big"))
        for entry in state.entries:
            digest.update(b"D" if entry.is_directory else b"F")
            digest.update(len(entry.path_bytes).to_bytes(4, "big"))
            digest.update(entry.path_bytes)
            if not entry.is_directory:
                digest.update(entry.snapshot.size.to_bytes(8, "big"))
                _hash_file(digest, root_fd, entry, measurement_hook)

        _notify(measurement_hook, ReleaseTreeBoundary.BEFORE_FINAL_VALIDATION)
        _validate_tree(root_fd, root, root_snapshot, state.entries, measurement_hook)
        ordered_allocations = tuple(
            InodeAllocation(device, inode, allocated_bytes)
            for (device, inode), allocated_bytes in sorted(state.allocations.items())
        )
        return ReleaseTreeMeasurement(
            digest=Digest(RELEASE_TREE_FORMAT, "sha256", digest.hexdigest()),
            entry_count=len(state.entries),
            logical_content_bytes=state.logical_bytes,
            allocations=ordered_allocations,
        )
    finally:
        os.close(root_fd)


def measure_release_tree(
    root: Path,
    *,
    lock_manager: _PublicationLockProof,
    expected_owner: int,
    limits: ReleaseTreeLimits = DEFAULT_RELEASE_TREE_LIMITS,
    measurement_hook: MeasurementHook | None = None,
) -> ReleaseTreeMeasurement:
    """Measure an authoritative release while publication remains excluded."""

    lock_manager.require_held(LockName.PUBLICATION)
    return _measure_release_tree(
        root,
        expected_owner=expected_owner,
        limits=limits,
        measurement_hook=measurement_hook,
    )


def measure_release_tree_snapshot(
    root: Path,
    *,
    lock_manager: _PublicationLockProof,
    expected_owner: int,
    limits: ReleaseTreeLimits = DEFAULT_RELEASE_TREE_LIMITS,
    measurement_hook: MeasurementHook | None = None,
) -> ReleaseTreeMeasurement:
    """Measure a private export snapshot while its exclusive spool lock is held."""

    lock_manager.require_held(LockName.EXPORT)
    return _measure_release_tree(
        root,
        expected_owner=expected_owner,
        limits=limits,
        measurement_hook=measurement_hook,
    )
