"""Kernel-backed locks with executable global ordering assertions."""

from __future__ import annotations

import errno
import fcntl
import os
import threading
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    StateAlreadyExistsError,
    StatePathError,
    validate_regular_state_file,
    validate_state_directory,
)

_LOCK_OPEN_FLAGS: Final = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCK_CONTEXT = threading.local()


class StateBusyError(RuntimeError):
    """A requested state transaction cannot begin without waiting."""


class LockOrderError(RuntimeError):
    """A caller attempted to violate the global host lock order."""


class LockName(IntEnum):
    """The one permitted outer-to-inner lock order."""

    INTAKE = 0
    EXPORT = 10
    PUBLICATION = 20
    TENANT_STATE = 30

    @property
    def filename(self) -> str:
        return {
            LockName.INTAKE: "intake.lock",
            LockName.EXPORT: "export.lock",
            LockName.PUBLICATION: "publication.lock",
            LockName.TENANT_STATE: "tenant-state.lock",
        }[self]


class LockMode(StrEnum):
    SHARED = "shared"
    EXCLUSIVE = "exclusive"


@dataclass(frozen=True, slots=True)
class LockRequest:
    name: LockName
    mode: LockMode = LockMode.EXCLUSIVE


@dataclass(frozen=True, slots=True)
class _HeldLock:
    manager_token: object
    name: LockName


class LockManager:
    """Acquire verified lock inodes without allowing order inversions."""

    def __init__(
        self,
        directory: Path | DurableDirectory,
        *,
        expected_owner: int,
        expected_directory_mode: int | None = None,
    ) -> None:
        if isinstance(directory, DurableDirectory):
            self._directory_fd = directory.duplicate_descriptor()
        else:
            try:
                self._directory_fd = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise StatePathError("lock root is not a no-follow directory") from error
                raise
        self._expected_owner = expected_owner
        self._expected_directory_mode = expected_directory_mode
        self._token = object()
        self._active_count = 0
        self._state_guard = threading.Lock()
        if expected_directory_mode is not None:
            try:
                validate_state_directory(
                    self._directory_fd,
                    expected_owner=expected_owner,
                    expected_mode=expected_directory_mode,
                )
            except BaseException:
                os.close(self._directory_fd)
                self._directory_fd = -1
                raise

    @classmethod
    def initialize(cls, directory: Path, *, expected_owner: int) -> LockManager:
        """Durably create the fixed lock inodes, tolerating exact prior creation."""

        with DurableDirectory.open(directory) as durable_directory:
            for lock_name in LockName:
                with suppress(StateAlreadyExistsError):
                    durable_directory.create_immutable(
                        (lock_name.filename,),
                        b"",
                        mode=0o600,
                    )
        manager = cls(directory, expected_owner=expected_owner)
        try:
            for lock_name in LockName:
                os.close(manager._open_verified_lock(lock_name))
        except BaseException:
            manager.close()
            raise
        return manager

    def close(self) -> None:
        with self._state_guard:
            if self._directory_fd >= 0:
                if self._active_count:
                    raise RuntimeError("cannot close a lock manager while locks are held")
                os.close(self._directory_fd)
                self._directory_fd = -1

    def _reserve_acquisition(self) -> None:
        with self._state_guard:
            if self._directory_fd < 0:
                raise RuntimeError("lock manager is closed")
            self._active_count += 1

    def _release_acquisition(self) -> None:
        with self._state_guard:
            self._active_count -= 1
            if self._active_count < 0:
                raise RuntimeError("lock-manager acquisition count was corrupted")

    def _directory_descriptor(self) -> int:
        with self._state_guard:
            if self._directory_fd < 0:
                raise RuntimeError("lock manager is closed")
            if self._expected_directory_mode is not None:
                validate_state_directory(
                    self._directory_fd,
                    expected_owner=self._expected_owner,
                    expected_mode=self._expected_directory_mode,
                )
            return self._directory_fd

    def __enter__(self) -> LockManager:
        if self._directory_fd < 0:
            raise RuntimeError("lock manager is closed")
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    @contextmanager
    def acquire(
        self,
        name: LockName,
        *,
        mode: LockMode = LockMode.EXCLUSIVE,
        blocking: bool = False,
    ) -> Iterator[None]:
        """Acquire one lock after proving it follows every currently held lock."""

        self._assert_next(name)
        self._reserve_acquisition()
        try:
            lock_fd = self._open_verified_lock(name)
        except BaseException:
            self._release_acquisition()
            raise
        operation = fcntl.LOCK_SH if mode is LockMode.SHARED else fcntl.LOCK_EX
        if not blocking:
            operation |= fcntl.LOCK_NB
        try:
            try:
                fcntl.flock(lock_fd, operation)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise StateBusyError(f"{name.filename} is busy") from error
                raise
            held = self._held()
            held_lock = _HeldLock(self._token, name)
            held.append(held_lock)
            try:
                yield
            finally:
                removed = held.pop()
                if removed != held_lock:
                    raise RuntimeError("lock stack was corrupted")
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            try:
                os.close(lock_fd)
            finally:
                self._release_acquisition()

    @contextmanager
    def acquire_many(
        self,
        requests: Sequence[LockRequest],
        *,
        blocking: bool = False,
    ) -> Iterator[None]:
        """Acquire a complete ordered lock set or release it without allocation."""

        self._assert_sequence(requests)
        with ExitStack() as stack:
            for request in requests:
                stack.enter_context(
                    self.acquire(
                        request.name,
                        mode=request.mode,
                        blocking=blocking,
                    )
                )
            yield

    @staticmethod
    def _held() -> list[_HeldLock]:
        held = cast(list[_HeldLock] | None, getattr(_LOCK_CONTEXT, "held", None))
        if held is None:
            held = []
            _LOCK_CONTEXT.held = held
        return held

    def _assert_next(self, name: LockName) -> None:
        held = self._held()
        if any(lock.name is name for lock in held):
            raise LockOrderError("a host lock cannot be acquired recursively")
        if held and name <= held[-1].name:
            raise LockOrderError("host locks must follow intake, export, publication, tenant-state")

    def _assert_sequence(self, requests: Sequence[LockRequest]) -> None:
        previous = self._held()[-1].name if self._held() else None
        seen: set[LockName] = set()
        for request in requests:
            if request.name in seen or (previous is not None and request.name <= previous):
                raise LockOrderError(
                    "host locks must follow intake, export, publication, tenant-state"
                )
            seen.add(request.name)
            previous = request.name

    def _open_verified_lock(self, name: LockName) -> int:
        directory_fd = self._directory_descriptor()
        try:
            lock_fd = os.open(name.filename, _LOCK_OPEN_FLAGS, dir_fd=directory_fd)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise StatePathError("lock path is not a no-follow regular file") from error
            raise
        try:
            opened = validate_regular_state_file(
                lock_fd,
                expected_owner=self._expected_owner,
                expected_mode=0o600,
            )
            current = os.stat(name.filename, dir_fd=directory_fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise StatePathError("lock inode changed while it was opened")
        except BaseException:
            os.close(lock_fd)
            raise
        return lock_fd
