"""Descriptor-relative durable file operations for root-owned state."""

from __future__ import annotations

import ctypes
import errno
import os
import re
import secrets
import stat
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Final, Self

_DIRECTORY_OPEN_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_READ_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_RENAME_NOREPLACE: Final = 1
_STAT_BLOCK_BYTES: Final = 512
_TEMP_NAME_PREFIX: Final = ".ldp-state-"
_TEMP_NAME_PATTERN: Final = re.compile(r"\.ldp-state-[0-9a-f]{32}", flags=re.ASCII)


class StatePathError(RuntimeError):
    """A state path escaped, traversed a link, or had an unsafe shape."""


class StateAlreadyExistsError(RuntimeError):
    """An immutable record already exists at the requested fixed path."""


class DurabilityBoundary(StrEnum):
    """Observable barriers used by failure-injection tests."""

    WRITE = "write"
    FILE_SYNC = "file-sync"
    RENAME = "rename"
    DIRECTORY_SYNC = "directory-sync"
    REMOVE = "remove"


FailureHook = Callable[[DurabilityBoundary], None]
TemporaryNameSource = Callable[[], str]


def _default_temporary_name() -> str:
    return f"{_TEMP_NAME_PREFIX}{secrets.token_hex(16)}"


def _validate_components(components: tuple[str, ...]) -> None:
    if not components:
        raise StatePathError("a state path must contain at least one component")
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or "/" in component
            or "\x00" in component
            or Path(component).is_absolute()
        ):
            raise StatePathError("state paths must contain fixed relative components")


def _validate_temporary_name(temporary_name: str, destination: str) -> None:
    _validate_components((temporary_name,))
    if not temporary_name.startswith(_TEMP_NAME_PREFIX) or temporary_name == destination:
        raise StatePathError("temporary state names must use the reserved internal prefix")


def _notify(hook: FailureHook | None, boundary: DurabilityBoundary) -> None:
    if hook is not None:
        hook(boundary)


def _write_all(file_descriptor: int, data: bytes, hook: FailureHook | None) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(file_descriptor, remaining)
        if written <= 0:
            raise OSError(errno.EIO, "state write made no progress")
        remaining = remaining[written:]
        _notify(hook, DurabilityBoundary.WRITE)


def _read_bounded(file_descriptor: int, *, maximum_bytes: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining:
        chunk = os.read(file_descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > maximum_bytes:
        raise StatePathError("state object exceeds its read limit")
    if len(data) != expected_size:
        raise StatePathError("state object size changed while it was read")
    return data


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:  # pragma: no cover - the host contract is Linux/glibc
        raise RuntimeError("renameat2 is required for immutable state publication") from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


class DurableDirectory:
    """An opened trusted root for fixed, descriptor-relative state paths."""

    def __init__(
        self,
        directory_fd: int,
        *,
        expected_owner: int | None,
        expected_directory_mode: int | None,
    ) -> None:
        self._directory_fd = directory_fd
        self._expected_owner = expected_owner
        self._expected_directory_mode = expected_directory_mode
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_owner: int | None = None,
        expected_directory_mode: int | None = None,
    ) -> Self:
        """Open the fixed state root without following its final component."""

        if (expected_owner is None) != (expected_directory_mode is None):
            raise ValueError("directory owner and mode validation must be configured together")

        try:
            directory_fd = os.open(path, _DIRECTORY_OPEN_FLAGS)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise StatePathError("state root is not a no-follow directory") from error
            raise
        try:
            if expected_owner is not None and expected_directory_mode is not None:
                opened = validate_state_directory(
                    directory_fd,
                    expected_owner=expected_owner,
                    expected_mode=expected_directory_mode,
                )
                current = path.stat(follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                    raise StatePathError("state root changed while it was opened")
        except BaseException:
            os.close(directory_fd)
            raise
        return cls(
            directory_fd,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
        )

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            os.close(self._directory_fd)
            self._closed = True

    def duplicate_descriptor(self) -> int:
        """Return a caller-owned, independently positioned directory descriptor."""

        self._require_open()
        descriptor = os.open(".", _DIRECTORY_OPEN_FLAGS, dir_fd=self._directory_fd)
        if (
            os.fstat(descriptor).st_dev,
            os.fstat(descriptor).st_ino,
        ) != (
            os.fstat(self._directory_fd).st_dev,
            os.fstat(self._directory_fd).st_ino,
        ):
            os.close(descriptor)
            raise StatePathError("state directory changed while reopening its descriptor")
        return descriptor

    def remove_abandoned_publication_temporaries(
        self,
        *,
        expected_owner: int,
        expected_mode: int,
        maximum_entries: int,
    ) -> int:
        """Remove only safely shaped temporaries left by an interrupted writer."""

        self._require_open()
        if type(maximum_entries) is not int or maximum_entries < 0:
            raise ValueError("temporary scan bound must be a nonnegative integer")
        descriptor = self.duplicate_descriptor()
        removed = 0
        try:
            names: list[str] = []
            with os.scandir(descriptor) as iterator:
                for entry_count, entry in enumerate(iterator, start=1):
                    if entry_count > maximum_entries:
                        raise StatePathError(
                            "state directory exceeds its temporary recovery ceiling"
                        )
                    if entry.name.startswith(_TEMP_NAME_PREFIX):
                        names.append(entry.name)
            names.sort()
            for name in names:
                if _TEMP_NAME_PATTERN.fullmatch(name) is None:
                    raise StatePathError("reserved temporary name has an invalid shape")
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != expected_owner
                    or stat.S_IMODE(metadata.st_mode) != expected_mode
                    or metadata.st_nlink != 1
                ):
                    raise StatePathError("reserved temporary has an unsafe inode shape")
            for name in names:
                os.unlink(name, dir_fd=descriptor)
                removed += 1
            if removed:
                os.fsync(descriptor)
            return removed
        finally:
            os.close(descriptor)

    def allocation_upper_bound(self, byte_count: int) -> int:
        """Round one complete write up to this filesystem's allocation fragment."""

        self._require_open()
        if type(byte_count) is not int or byte_count < 0:
            raise ValueError("allocation byte count must be a nonnegative integer")
        filesystem = os.fstatvfs(self._directory_fd)
        fragment_size = filesystem.f_frsize or filesystem.f_bsize
        if fragment_size <= 0:
            raise StatePathError("state filesystem has no valid allocation fragment")
        return ((byte_count + fragment_size - 1) // fragment_size) * fragment_size

    def regular_allocation(
        self,
        components: tuple[str, ...],
        *,
        expected_owner: int,
        expected_mode: int,
    ) -> int:
        """Measure one verified regular file's currently allocated blocks."""

        parent_fd, filename = self._open_parent(components)
        file_fd: int | None = None
        try:
            file_fd = os.open(filename, _FILE_READ_FLAGS, dir_fd=parent_fd)
            opened = validate_regular_state_file(
                file_fd,
                expected_owner=expected_owner,
                expected_mode=expected_mode,
            )
            current = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise StatePathError("state inode changed while measuring allocation")
            return opened.st_blocks * _STAT_BLOCK_BYTES
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(parent_fd)

    def namespace_allocation_upper_bound(self, entry_count: int) -> int:
        """Reserve ext4 directory growth for temporary creation and rename."""

        self._require_open()
        if type(entry_count) is not int or entry_count < 0:
            raise ValueError("namespace entry count must be a nonnegative integer")
        filesystem = os.fstatvfs(self._directory_fd)
        block_size = max(filesystem.f_frsize, filesystem.f_bsize)
        if block_size <= 0:
            raise StatePathError("state filesystem has no valid directory block size")
        # Immutable publication first creates a temporary directory entry and
        # then renames it without replacement. At a directory-block boundary,
        # each namespace mutation can require a block before the old temporary
        # entry is reclaimed. Production M3 state is committed to ext4.
        return entry_count * 2 * block_size

    def open_descendant(self, components: tuple[str, ...]) -> DurableDirectory:
        """Open a verified descendant directory without resolving the root path again."""

        if not components:
            raise StatePathError("a descendant directory path must not be empty")
        directory_fd = self._open_directory(components)
        return DurableDirectory(
            directory_fd,
            expected_owner=self._expected_owner,
            expected_directory_mode=self._expected_directory_mode,
        )

    def create_immutable(
        self,
        components: tuple[str, ...],
        data: bytes,
        *,
        mode: int = 0o600,
        failure_hook: FailureHook | None = None,
        temporary_name_source: TemporaryNameSource = _default_temporary_name,
    ) -> None:
        """Publish a complete immutable record without replacing an existing one."""

        _validate_components(components)
        destination = components[-1]
        temporary_name = temporary_name_source()
        _validate_temporary_name(temporary_name, destination)
        parent_fd, destination = self._open_parent(components)
        temporary_fd: int | None = None
        temporary_created = False
        published = False
        try:
            temporary_fd = os.open(
                temporary_name,
                _FILE_CREATE_FLAGS,
                mode,
                dir_fd=parent_fd,
            )
            temporary_created = True
            os.fchmod(temporary_fd, mode)
            _write_all(temporary_fd, data, failure_hook)
            os.fsync(temporary_fd)
            _notify(failure_hook, DurabilityBoundary.FILE_SYNC)
            os.close(temporary_fd)
            temporary_fd = None
            try:
                _rename_noreplace(parent_fd, temporary_name, destination)
            except FileExistsError as error:
                raise StateAlreadyExistsError("immutable state record already exists") from error
            published = True
            _notify(failure_hook, DurabilityBoundary.RENAME)
            os.fsync(parent_fd)
            _notify(failure_hook, DurabilityBoundary.DIRECTORY_SYNC)
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if temporary_created and not published:
                self._remove_temporary(parent_fd, temporary_name)
            os.close(parent_fd)

    def replace(
        self,
        components: tuple[str, ...],
        data: bytes,
        *,
        mode: int = 0o600,
        failure_hook: FailureHook | None = None,
        temporary_name_source: TemporaryNameSource = _default_temporary_name,
    ) -> None:
        """Atomically replace one fixed state record and sync its parent."""

        _validate_components(components)
        destination = components[-1]
        temporary_name = temporary_name_source()
        _validate_temporary_name(temporary_name, destination)
        parent_fd, destination = self._open_parent(components)
        temporary_fd: int | None = None
        temporary_created = False
        published = False
        try:
            temporary_fd = os.open(
                temporary_name,
                _FILE_CREATE_FLAGS,
                mode,
                dir_fd=parent_fd,
            )
            temporary_created = True
            os.fchmod(temporary_fd, mode)
            _write_all(temporary_fd, data, failure_hook)
            os.fsync(temporary_fd)
            _notify(failure_hook, DurabilityBoundary.FILE_SYNC)
            os.close(temporary_fd)
            temporary_fd = None
            os.replace(
                temporary_name,
                destination,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            published = True
            _notify(failure_hook, DurabilityBoundary.RENAME)
            os.fsync(parent_fd)
            _notify(failure_hook, DurabilityBoundary.DIRECTORY_SYNC)
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if temporary_created and not published:
                self._remove_temporary(parent_fd, temporary_name)
            os.close(parent_fd)

    def remove(
        self,
        components: tuple[str, ...],
        *,
        missing_ok: bool = False,
        failure_hook: FailureHook | None = None,
    ) -> None:
        """Remove one fixed state record and sync its parent directory."""

        parent_fd, destination = self._open_parent(components)
        try:
            try:
                os.unlink(destination, dir_fd=parent_fd)
            except FileNotFoundError:
                if missing_ok:
                    return
                raise
            _notify(failure_hook, DurabilityBoundary.REMOVE)
            os.fsync(parent_fd)
            _notify(failure_hook, DurabilityBoundary.DIRECTORY_SYNC)
        finally:
            os.close(parent_fd)

    def read_regular(
        self,
        components: tuple[str, ...],
        *,
        expected_owner: int,
        expected_mode: int,
        maximum_bytes: int,
    ) -> bytes:
        """Read one bounded, stable, no-follow regular file from the trusted root."""

        if maximum_bytes < 0:
            raise ValueError("maximum_bytes must not be negative")
        parent_fd, filename = self._open_parent(components)
        file_fd: int | None = None
        try:
            try:
                file_fd = os.open(filename, _FILE_READ_FLAGS, dir_fd=parent_fd)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise StatePathError(
                        "state path does not end in a no-follow regular file"
                    ) from error
                raise
            before = validate_regular_state_file(
                file_fd,
                expected_owner=expected_owner,
                expected_mode=expected_mode,
            )
            current = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise StatePathError("state inode changed while it was opened")
            if before.st_size > maximum_bytes:
                raise StatePathError("state object exceeds its read limit")

            data = _read_bounded(
                file_fd,
                maximum_bytes=maximum_bytes,
                expected_size=before.st_size,
            )

            after = validate_regular_state_file(
                file_fd,
                expected_owner=expected_owner,
                expected_mode=expected_mode,
            )
            if _state_file_generation(before) != _state_file_generation(after):
                raise StatePathError("state object changed while it was read")
            current = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
                raise StatePathError("state inode changed while it was read")
            return data
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(parent_fd)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("durable directory is closed")

    def _open_parent(self, components: tuple[str, ...]) -> tuple[int, str]:
        self._require_open()
        _validate_components(components)
        return self._open_directory(components[:-1]), components[-1]

    def _open_directory(self, components: tuple[str, ...]) -> int:
        self._require_open()
        if components:
            _validate_components(components)
        current_fd = os.dup(self._directory_fd)
        try:
            if self._expected_owner is not None and self._expected_directory_mode is not None:
                validate_state_directory(
                    current_fd,
                    expected_owner=self._expected_owner,
                    expected_mode=self._expected_directory_mode,
                )
            for component in components:
                next_fd = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
                try:
                    if (
                        self._expected_owner is not None
                        and self._expected_directory_mode is not None
                    ):
                        opened = validate_state_directory(
                            next_fd,
                            expected_owner=self._expected_owner,
                            expected_mode=self._expected_directory_mode,
                        )
                        current = os.stat(
                            component,
                            dir_fd=current_fd,
                            follow_symlinks=False,
                        )
                        if (opened.st_dev, opened.st_ino) != (
                            current.st_dev,
                            current.st_ino,
                        ):
                            raise StatePathError("state directory changed while it was opened")
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current_fd)
                current_fd = next_fd
        except BaseException as error:
            os.close(current_fd)
            if isinstance(error, OSError) and error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise StatePathError("state path traverses a non-directory or link") from error
            raise
        return current_fd

    @staticmethod
    def _remove_temporary(parent_fd: int, temporary_name: str) -> None:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            return
        os.fsync(parent_fd)


def validate_regular_state_file(
    file_descriptor: int,
    *,
    expected_owner: int,
    expected_mode: int,
) -> os.stat_result:
    """Validate metadata common to every trusted root-owned state reader."""

    metadata = os.fstat(file_descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise StatePathError("state object is not a regular file")
    if metadata.st_uid != expected_owner:
        raise StatePathError("state object has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise StatePathError("state object has an unexpected mode")
    if metadata.st_nlink != 1:
        raise StatePathError("state object must have exactly one link")
    return metadata


def validate_state_directory(
    file_descriptor: int,
    *,
    expected_owner: int,
    expected_mode: int,
) -> os.stat_result:
    """Validate one directory in the authoritative root-owned state tree."""

    metadata = os.fstat(file_descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise StatePathError("state path component is not a directory")
    if metadata.st_uid != expected_owner:
        raise StatePathError("state directory has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise StatePathError("state directory has an unexpected mode")
    return metadata


def _state_file_generation(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
