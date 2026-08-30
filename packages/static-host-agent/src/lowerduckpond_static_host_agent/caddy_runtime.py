"""Atomic Caddy-generation selection and descriptor-pinned process launch."""

from __future__ import annotations

import errno
import fcntl
import os
import re
import secrets
import stat
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from lowerduckpond_static_contracts import ContractError, validate_uuid7

from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_GENERATION_ROOT_MODE,
    MAX_CADDY_ENVIRONMENT_BYTES,
    CaddyGenerationManifest,
    CaddyGenerationStore,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

CADDY_ACTIVE_REFERENCE_NAME: Final = "active"
CADDY_GENERATIONS_DIRECTORY_NAME: Final = "generations"
CADDY_ACTIVE_REFERENCE_MODE: Final = 0o640
CADDY_RUNTIME_ROOT_MODE: Final = 0o750
CADDY_PUBLICATION_LOCK_MODE: Final = 0o600

_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_REFERENCE_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_REFERENCE_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCK_FLAGS: Final = os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_REFERENCE_BYTES: Final = 37
_REFERENCE_TEMPORARY_CREATION_MODE: Final = 0o600
_REFERENCE_TEMPORARY_PREFIX: Final = ".ldp-active-"
_REFERENCE_TEMPORARY_PATTERN: Final = re.compile(r"\.ldp-active-[0-9a-f]{32}")
_ENVIRONMENT_NAME_PATTERN: Final = re.compile(r"[A-Z_][A-Z0-9_]*", flags=re.ASCII)
_INHERITED_SYSTEMD_ENVIRONMENT: Final = frozenset(
    {
        "INVOCATION_ID",
        "NOTIFY_SOCKET",
        "WATCHDOG_PID",
        "WATCHDOG_USEC",
    }
)


class CaddyRuntimeError(RuntimeError):
    """The selected Caddy runtime or launcher boundary is unsafe."""


class CaddySelectionBoundary(StrEnum):
    """Observable durability barriers for active-reference failure injection."""

    REFERENCE_SYNC = "reference-sync"
    RENAME = "rename"
    PARENT_SYNC = "parent-sync"


SelectionFailureHook = Callable[[CaddySelectionBoundary], None]
Execve = Callable[[int, list[str], dict[str, str]], object]


@dataclass(frozen=True, slots=True)
class SelectedCaddyGeneration:
    """One active-reference read paired with its verified pinned generation."""

    generation_id: str
    generation: PinnedCaddyGeneration


class CaddyRuntime:
    """One pinned runtime root and its exact shared publication lock."""

    def __init__(
        self,
        root_fd: int,
        lock_fd: int,
        *,
        owner: int,
        group: int,
        creation_group: int,
    ) -> None:
        self._root_fd = root_fd
        self._lock_fd = lock_fd
        self._owner = owner
        self._group = group
        self._creation_group = creation_group
        self._context_mutex = threading.RLock()
        self._locked = False
        self._closed = False

    @classmethod
    def open(  # noqa: PLR0913
        cls,
        root: Path,
        publication_lock: Path,
        *,
        expected_owner: int,
        expected_group: int,
        expected_lock_owner: int | None = None,
        expected_lock_group: int | None = None,
        root_mode: int = CADDY_RUNTIME_ROOT_MODE,
        lock_mode: int = CADDY_PUBLICATION_LOCK_MODE,
    ) -> Self:
        """Pin the trusted runtime root and publication-lock inode."""

        root_fd = _open_runtime_root(
            root,
            owner=expected_owner,
            group=expected_group,
            mode=root_mode,
        )
        lock_fd: int | None = None
        try:
            lock_fd = _open_lock(publication_lock)
            _validate_lock(
                os.fstat(lock_fd),
                owner=(expected_owner if expected_lock_owner is None else expected_lock_owner),
                group=(expected_owner if expected_lock_group is None else expected_lock_group),
                mode=lock_mode,
            )
            _require_path_identity(publication_lock, lock_fd, label="publication lock")
        except BaseException:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(root_fd)
            raise
        return cls(
            root_fd,
            lock_fd,
            owner=expected_owner,
            group=expected_group,
            creation_group=os.getegid(),
        )

    @classmethod
    def from_lock_descriptor(  # noqa: PLR0913
        cls,
        root: Path,
        publication_lock_fd: int,
        *,
        expected_owner: int,
        expected_group: int,
        expected_lock_owner: int,
        expected_lock_group: int,
        root_mode: int = CADDY_RUNTIME_ROOT_MODE,
        lock_mode: int = CADDY_PUBLICATION_LOCK_MODE,
    ) -> Self:
        """Pin a systemd-opened global publication lock without path traversal."""

        root_fd = _open_runtime_root(
            root,
            owner=expected_owner,
            group=expected_group,
            mode=root_mode,
        )
        lock_fd: int | None = None
        try:
            lock_fd = fcntl.fcntl(publication_lock_fd, fcntl.F_DUPFD_CLOEXEC, 0)
            os.set_inheritable(publication_lock_fd, False)
            _validate_lock(
                os.fstat(lock_fd),
                owner=expected_lock_owner,
                group=expected_lock_group,
                mode=lock_mode,
            )
        except BaseException:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(root_fd)
            raise
        return cls(
            root_fd,
            lock_fd,
            owner=expected_owner,
            group=expected_group,
            creation_group=os.getegid(),
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

    @contextmanager
    def locked(self) -> Iterator[object]:
        """Hold the exact publication lock for one bounded runtime transition."""

        with self._context_mutex:
            self._require_open()
            if self._locked:
                raise CaddyRuntimeError("publication lock is not reentrant")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            self._locked = True
            try:
                yield self
            finally:
                self._locked = False
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    @contextmanager
    def using_held_publication_lock(self, lock_manager: LockManager) -> Iterator[object]:
        """Use this exact inode through a caller's already-held ordered lock."""

        if not self._context_mutex.acquire(blocking=False):
            raise CaddyRuntimeError("Caddy runtime is busy in this process")
        try:
            self._require_open()
            if self._locked:
                raise CaddyRuntimeError("publication lock is not reentrant")
            lock_manager.require_held(
                LockName.PUBLICATION,
                mode=LockMode.EXCLUSIVE,
                descriptor=self._lock_fd,
            )
            self._locked = True
            try:
                yield self
            finally:
                self._locked = False
        finally:
            self._context_mutex.release()

    def read_active(self) -> str:
        """Read the active reference exactly once while holding publication."""

        self._require_locked()
        reference_fd = _open_relative_reference(self._root_fd)
        try:
            _validate_reference(
                os.fstat(reference_fd),
                owner=self._owner,
                group=self._group,
            )
            data = os.pread(reference_fd, _REFERENCE_BYTES + 1, 0)
        finally:
            os.close(reference_fd)
        return _decode_reference(data)

    def open_active_verified(self) -> SelectedCaddyGeneration:
        """Read active once, then pin and manifest-verify that exact generation."""

        self._require_locked()
        generation_id = self.read_active()
        store = self._open_generation_store()
        try:
            generation = store.open_verified(generation_id)
        finally:
            store.close()
        return SelectedCaddyGeneration(generation_id, generation)

    def select_active(
        self,
        generation_id: str,
        *,
        failure_hook: SelectionFailureHook | None = None,
    ) -> None:
        """Verify and durably select one complete immutable generation."""

        self._require_locked()
        self.remove_abandoned_reference_temporaries()
        canonical_id = _canonical_generation_id(generation_id)
        store = self._open_generation_store()
        try:
            with store.open_verified(canonical_id):
                pass
        finally:
            store.close()
        _validate_existing_reference_if_present(
            self._root_fd,
            owner=self._owner,
            group=self._group,
        )
        temporary_name = f"{_REFERENCE_TEMPORARY_PREFIX}{secrets.token_hex(16)}"
        temporary_fd: int | None = None
        created = False
        renamed = False
        try:
            temporary_fd = os.open(
                temporary_name,
                _REFERENCE_CREATE_FLAGS,
                mode=_REFERENCE_TEMPORARY_CREATION_MODE,
                dir_fd=self._root_fd,
            )
            created = True
            os.fchown(temporary_fd, self._owner, self._group)
            os.fchmod(temporary_fd, CADDY_ACTIVE_REFERENCE_MODE)
            _write_all(temporary_fd, f"{canonical_id}\n".encode("ascii"))
            os.fsync(temporary_fd)
            _notify(failure_hook, CaddySelectionBoundary.REFERENCE_SYNC)
            os.close(temporary_fd)
            temporary_fd = None
            os.replace(
                temporary_name,
                CADDY_ACTIVE_REFERENCE_NAME,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
            renamed = True
            _notify(failure_hook, CaddySelectionBoundary.RENAME)
            os.fsync(self._root_fd)
            _notify(failure_hook, CaddySelectionBoundary.PARENT_SYNC)
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if created and not renamed:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=self._root_fd)
                    os.fsync(self._root_fd)

    def remove_abandoned_reference_temporaries(
        self,
        *,
        maximum_entries: int = 4_096,
    ) -> int:
        """Bound, validate, remove, and sync crash-left active-reference staging."""

        self._require_locked()
        if type(maximum_entries) is not int or maximum_entries < 0:
            raise ValueError("active-reference recovery bound must be nonnegative")
        scan_fd = os.open(".", _DIRECTORY_FLAGS, dir_fd=self._root_fd)
        names: list[str] = []
        try:
            with os.scandir(scan_fd) as iterator:
                for entry_count, entry in enumerate(iterator, start=1):
                    if entry_count > maximum_entries:
                        raise CaddyRuntimeError(
                            "Caddy runtime root exceeds its recovery scan bound"
                        )
                    if entry.name.startswith(_REFERENCE_TEMPORARY_PREFIX):
                        if _REFERENCE_TEMPORARY_PATTERN.fullmatch(entry.name) is None:
                            raise CaddyRuntimeError(
                                "reserved active-reference temporary name is malformed"
                            )
                        names.append(entry.name)
            for name in sorted(names):
                metadata = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
                if not _safe_temporary_reference(
                    metadata,
                    owner=self._owner,
                    group=self._group,
                    creation_group=self._creation_group,
                ):
                    raise CaddyRuntimeError(
                        "reserved active-reference temporary metadata is unsafe"
                    )
            for name in sorted(names):
                os.unlink(name, dir_fd=self._root_fd)
            if names:
                os.fsync(self._root_fd)
            return len(names)
        finally:
            os.close(scan_fd)

    def close(self) -> None:
        """Close the pinned runtime descriptors when no transition is active."""

        with self._context_mutex:
            if not self._closed:
                if self._locked:
                    raise CaddyRuntimeError("cannot close a locked Caddy runtime")
                os.close(self._lock_fd)
                os.close(self._root_fd)
                self._closed = True

    def _open_generation_store(self) -> CaddyGenerationStore:
        generation_fd = os.open(
            CADDY_GENERATIONS_DIRECTORY_NAME,
            _DIRECTORY_FLAGS,
            dir_fd=self._root_fd,
        )
        try:
            _validate_directory(
                os.fstat(generation_fd),
                owner=self._owner,
                group=self._group,
                mode=CADDY_GENERATION_ROOT_MODE,
                label="Caddy generation root",
            )
        except BaseException:
            os.close(generation_fd)
            raise
        return CaddyGenerationStore(
            generation_fd,
            owner=self._owner,
            group=self._group,
        )

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("Caddy runtime is closed")

    def _require_locked(self) -> None:
        self._require_open()
        if not self._locked:
            raise CaddyRuntimeError("publication lock is required")


class PreparedCaddyExecution:
    """Already-open executable and configuration for one selected generation."""

    def __init__(
        self,
        *,
        generation_id: str,
        manifest: CaddyGenerationManifest,
        binary_fd: int,
        configuration_fd: int,
        environment: Mapping[str, str],
    ) -> None:
        self.generation_id = generation_id
        self.manifest = manifest
        self._binary_fd = binary_fd
        self._configuration_fd = configuration_fd
        self._environment = dict(environment)
        self._closed = False

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

    def execute(
        self,
        *,
        inherited_environment: Mapping[str, str],
        execve: Execve = os.execve,
    ) -> None:
        """Execute the already-open binary with only bound and systemd environment."""

        self._require_open()
        environment = dict(self._environment)
        for name in _INHERITED_SYSTEMD_ENVIRONMENT:
            if name in inherited_environment:
                environment[name] = inherited_environment[name]
        os.set_inheritable(self._configuration_fd, True)
        arguments = [
            "caddy",
            "run",
            "--config",
            f"/proc/self/fd/{self._configuration_fd}",
        ]
        result = execve(self._binary_fd, arguments, environment)
        raise CaddyRuntimeError(f"Caddy exec unexpectedly returned: {result!r}")

    def duplicate_binary_descriptor(self) -> int:
        """Return a caller-owned descriptor for diagnostic identity checks."""

        self._require_open()
        return os.dup(self._binary_fd)

    def duplicate_configuration_descriptor(self) -> int:
        """Return a caller-owned descriptor for the exact adapted configuration."""

        self._require_open()
        return os.dup(self._configuration_fd)

    def close(self) -> None:
        """Close prepared descriptors when execution is abandoned."""

        if not self._closed:
            os.close(self._configuration_fd)
            os.close(self._binary_fd)
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("prepared Caddy execution is closed")


def prepare_active_caddy_execution(runtime: CaddyRuntime) -> PreparedCaddyExecution:
    """Pin every selected runtime input before releasing publication."""

    with runtime.locked():
        selected = runtime.open_active_verified()
        with selected.generation as generation:
            binary_fd = generation.duplicate_payload_descriptor(CADDY_BINARY_NAME)
            configuration_fd: int | None = None
            environment_fd: int | None = None
            try:
                configuration_fd = generation.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
                environment_fd = generation.duplicate_payload_descriptor(CADDY_ENVIRONMENT_NAME)
                environment_bytes = os.pread(
                    environment_fd,
                    MAX_CADDY_ENVIRONMENT_BYTES + 1,
                    0,
                )
                environment = _parse_environment(environment_bytes)
            except BaseException:
                if environment_fd is not None:
                    os.close(environment_fd)
                if configuration_fd is not None:
                    os.close(configuration_fd)
                os.close(binary_fd)
                raise
            os.close(environment_fd)
            return PreparedCaddyExecution(
                generation_id=selected.generation_id,
                manifest=generation.manifest,
                binary_fd=binary_fd,
                configuration_fd=configuration_fd,
                environment=environment,
            )


def _open_directory(path: Path, *, label: str) -> int:
    try:
        return os.open(path, _DIRECTORY_FLAGS)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise CaddyRuntimeError(f"{label} is not a no-follow directory") from error
        raise


def _open_runtime_root(path: Path, *, owner: int, group: int, mode: int) -> int:
    descriptor = _open_directory(path, label="Caddy runtime root")
    try:
        _validate_directory(
            os.fstat(descriptor),
            owner=owner,
            group=group,
            mode=mode,
            label="Caddy runtime root",
        )
        _require_path_identity(path, descriptor, label="Caddy runtime root")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_lock(path: Path) -> int:
    try:
        return os.open(path, _LOCK_FLAGS)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENXIO}:
            raise CaddyRuntimeError("publication lock is not a no-follow regular file") from error
        raise


def _open_relative_reference(root_fd: int) -> int:
    try:
        return os.open(CADDY_ACTIVE_REFERENCE_NAME, _REFERENCE_FLAGS, dir_fd=root_fd)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENXIO}:
            raise CaddyRuntimeError("active reference is not a no-follow regular file") from error
        raise


def _validate_directory(
    metadata: os.stat_result,
    *,
    owner: int,
    group: int,
    mode: int,
    label: str,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_gid != group
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise CaddyRuntimeError(f"{label} metadata is unsafe")


def _validate_lock(
    metadata: os.stat_result,
    *,
    owner: int,
    group: int,
    mode: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_gid != group
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise CaddyRuntimeError("publication lock metadata is unsafe")


def _validate_reference(
    metadata: os.stat_result,
    *,
    owner: int,
    group: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_gid != group
        or stat.S_IMODE(metadata.st_mode) != CADDY_ACTIVE_REFERENCE_MODE
        or metadata.st_nlink != 1
        or metadata.st_size != _REFERENCE_BYTES
    ):
        raise CaddyRuntimeError("active reference metadata is unsafe")


def _safe_temporary_reference(
    metadata: os.stat_result,
    *,
    owner: int,
    group: int,
    creation_group: int,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == owner
        and metadata.st_nlink == 1
        and 0 <= metadata.st_size <= _REFERENCE_BYTES
        and (
            (
                metadata.st_gid in {creation_group, group}
                and stat.S_IMODE(metadata.st_mode) == _REFERENCE_TEMPORARY_CREATION_MODE
            )
            or (
                metadata.st_gid == group
                and stat.S_IMODE(metadata.st_mode) == CADDY_ACTIVE_REFERENCE_MODE
            )
        )
    )


def _validate_existing_reference_if_present(
    root_fd: int,
    *,
    owner: int,
    group: int,
) -> None:
    try:
        descriptor = _open_relative_reference(root_fd)
    except FileNotFoundError:
        return
    try:
        _validate_reference(os.fstat(descriptor), owner=owner, group=group)
        _decode_reference(os.pread(descriptor, _REFERENCE_BYTES + 1, 0))
    finally:
        os.close(descriptor)


def _decode_reference(data: bytes) -> str:
    if len(data) != _REFERENCE_BYTES or not data.endswith(b"\n"):
        raise CaddyRuntimeError("active reference content is malformed")
    try:
        value = data[:-1].decode("ascii", errors="strict")
    except UnicodeError as error:
        raise CaddyRuntimeError("active reference content is malformed") from error
    return _canonical_generation_id(value)


def _canonical_generation_id(value: str) -> str:
    try:
        return validate_uuid7(value)
    except ContractError as error:
        raise CaddyRuntimeError("active reference does not name a UUIDv7 generation") from error


def _parse_environment(data: bytes) -> dict[str, str]:
    if (
        not data
        or len(data) > MAX_CADDY_ENVIRONMENT_BYTES
        or not data.endswith(b"\n")
        or b"\r" in data
        or b"\0" in data
    ):
        raise CaddyRuntimeError("selected Caddy environment is malformed")
    result: dict[str, str] = {}
    for line in data[:-1].split(b"\n"):
        if not line or b"=" not in line:
            raise CaddyRuntimeError("selected Caddy environment is malformed")
        raw_name, raw_value = line.split(b"=", 1)
        try:
            name = raw_name.decode("ascii", errors="strict")
            value = raw_value.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise CaddyRuntimeError("selected Caddy environment is malformed") from error
        if (
            _ENVIRONMENT_NAME_PATTERN.fullmatch(name) is None
            or name in result
            or name in _INHERITED_SYSTEMD_ENVIRONMENT
        ):
            raise CaddyRuntimeError("selected Caddy environment contains a forbidden name")
        result[name] = value
    return result


def _require_path_identity(path: Path, descriptor: int, *, label: str) -> None:
    current = path.stat(follow_symlinks=False)
    opened = os.fstat(descriptor)
    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise CaddyRuntimeError(f"{label} changed while opening")


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written == 0:
            raise CaddyRuntimeError("active reference write made no progress")
        offset += written


def _notify(hook: SelectionFailureHook | None, boundary: CaddySelectionBoundary) -> None:
    if hook is not None:
        hook(boundary)
