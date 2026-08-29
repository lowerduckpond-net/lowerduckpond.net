"""Descriptor-relative durable file operations for root-owned state."""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Final, Self

_DIRECTORY_OPEN_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_RENAME_NOREPLACE: Final = 1
_TEMP_NAME_PREFIX: Final = ".ldp-state-"


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

    def __init__(self, directory_fd: int) -> None:
        self._directory_fd = directory_fd
        self._closed = False

    @classmethod
    def open(cls, path: Path) -> Self:
        """Open the fixed state root without following its final component."""

        try:
            directory_fd = os.open(path, _DIRECTORY_OPEN_FLAGS)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise StatePathError("state root is not a no-follow directory") from error
            raise
        return cls(directory_fd)

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

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("durable directory is closed")

    def _open_parent(self, components: tuple[str, ...]) -> tuple[int, str]:
        self._require_open()
        _validate_components(components)
        current_fd = os.dup(self._directory_fd)
        try:
            for component in components[:-1]:
                next_fd = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
        except OSError as error:
            os.close(current_fd)
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise StatePathError("state path traverses a non-directory or link") from error
            raise
        return current_fd, components[-1]

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
