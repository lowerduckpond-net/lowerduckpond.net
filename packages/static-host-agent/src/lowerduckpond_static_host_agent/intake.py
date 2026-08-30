"""Serialized, durable, one-slot artifact intake."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import (
    MAX_DEPLOY_ARTIFACT_BYTES,
    MAX_IMPORT_ARTIFACT_BYTES,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import validate_state_directory
from lowerduckpond_static_host_agent.issuance import VerifiedArtifact
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_TEMPORARY: Final = re.compile(r"\.ldp-intake-[0-9a-f]{32}", flags=re.ASCII)
_ADMITTED: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.artifact",
    flags=re.ASCII,
)
_SHA256: Final = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
_CHUNK_BYTES: Final = 64 * 1024
_RENAME_NOREPLACE: Final = 1
_ARTIFACT_MODE: Final = 0o600


class IntakeError(RuntimeError):
    """Artifact intake could not preserve its single-slot durable boundary."""


class IntakeOccupiedError(IntakeError):
    """One admitted artifact already owns the bounded intake slot."""


@dataclass(frozen=True, slots=True)
class AdmittedArtifact:
    """One synced artifact published beneath the fixed intake root."""

    filename: str
    verified: VerifiedArtifact


class ArtifactLease:
    """Hold the intake lock until job commit or terminal cleanup."""

    def __init__(self, artifact: AdmittedArtifact) -> None:
        self.artifact = artifact
        self._committed = False

    def commit(self) -> None:
        """Retain the admitted artifact after its immutable job is durable."""

        self._committed = True

    @property
    def committed(self) -> bool:
        return self._committed


class ArtifactIntake:
    """Stream a caller artifact into one root-owned durable admission slot."""

    def __init__(
        self,
        state_root: Path,
        *,
        expected_owner: int,
        limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> None:
        self._intake_path = state_root / "intake"
        self._directory_fd = os.open(self._intake_path, _DIRECTORY_FLAGS)
        try:
            validate_state_directory(
                self._directory_fd,
                expected_owner=expected_owner,
                expected_mode=0o700,
            )
            self._locks = LockManager(
                state_root / "locks",
                expected_owner=expected_owner,
                expected_directory_mode=0o700,
            )
        except BaseException:
            os.close(self._directory_fd)
            raise
        self._expected_owner = expected_owner
        self._limits = limits
        self._closed = False

    def __enter__(self) -> ArtifactIntake:
        self._require_open()
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._locks.close()
            os.close(self._directory_fd)
            self._closed = True

    @contextmanager
    def admit(
        self,
        *,
        operation: str,
        correlation_id: object,
        declared: VerifiedArtifact,
        read: Callable[[int], bytes],
        blocking: bool = False,
    ) -> Iterator[ArtifactLease]:
        """Publish exact bytes and retain the lock through immutable job commit."""

        self._require_open()
        canonical_id = validate_uuid7(correlation_id)
        _validate_declared(operation, declared)
        with self._locks.acquire(LockName.INTAKE, mode=LockMode.EXCLUSIVE, blocking=blocking):
            self._reconcile_before_admission()
            filename = f"{canonical_id}.artifact"
            temporary = f".ldp-intake-{secrets.token_hex(16)}"
            published = False
            lease: ArtifactLease | None = None
            try:
                verified = self._stream_temporary(temporary, declared=declared, read=read)
                _rename_no_replace(self._directory_fd, temporary, filename)
                published = True
                os.fsync(self._directory_fd)
                lease = ArtifactLease(AdmittedArtifact(filename, verified))
                yield lease
            finally:
                retain = published and lease is not None and lease.committed
                if not retain:
                    self._remove(temporary if not published else filename)

    def _reconcile_before_admission(self) -> None:
        names: list[str] = []
        descriptor = os.dup(self._directory_fd)
        try:
            with os.scandir(descriptor) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > 1:
                        raise IntakeError("intake contains more than its single slot")
                    names.append(entry.name)
        finally:
            os.close(descriptor)
        if not names:
            return
        name = names[0]
        self._validate_entry(name)
        if _TEMPORARY.fullmatch(name) is not None:
            self._remove(name)
            return
        if _ADMITTED.fullmatch(name) is not None:
            raise IntakeOccupiedError("intake slot contains an admitted artifact")
        raise IntakeError("intake contains an unrecognized object")

    def _validate_entry(self, name: str) -> os.stat_result:
        metadata = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self._expected_owner
            or stat.S_IMODE(metadata.st_mode) != _ARTIFACT_MODE
            or metadata.st_nlink != 1
        ):
            raise IntakeError("intake object has unsafe metadata")
        return metadata

    def _stream_temporary(
        self,
        temporary: str,
        *,
        declared: VerifiedArtifact,
        read: Callable[[int], bytes],
    ) -> VerifiedArtifact:
        self._admit_capacity(declared.size)
        file_descriptor = os.open(
            temporary,
            _CREATE_FLAGS,
            _ARTIFACT_MODE,
            dir_fd=self._directory_fd,
        )
        digest = hashlib.sha256()
        remaining = declared.size
        try:
            os.fchmod(file_descriptor, _ARTIFACT_MODE)
            while remaining:
                chunk = read(min(remaining, _CHUNK_BYTES))
                if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
                    raise IntakeError("artifact stream ended outside its declared length")
                _write_all(file_descriptor, chunk)
                digest.update(chunk)
                remaining -= len(chunk)
                self._admit_capacity(remaining)
            metadata = os.fstat(file_descriptor)
            if metadata.st_size != declared.size:
                raise IntakeError("artifact size changed during intake")
            if digest.hexdigest() != declared.sha256:
                raise IntakeError("artifact digest does not match its request binding")
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        self._validate_entry(temporary)
        return VerifiedArtifact(size=declared.size, sha256=digest.hexdigest())

    def _admit_capacity(self, byte_count: int) -> None:
        filesystem = measure_filesystem_capacity_descriptor(self._directory_fd)
        fragment = filesystem.fragment_size
        rounded = ((byte_count + fragment - 1) // fragment) * fragment
        namespace = 2 * max(filesystem.fragment_size, fragment)
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(allocated_bytes=rounded + namespace, unique_inodes=1),
            filesystem,
            limits=self._limits,
        )

    def _remove(self, name: str) -> None:
        try:
            os.unlink(name, dir_fd=self._directory_fd)
        except FileNotFoundError:
            return
        os.fsync(self._directory_fd)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("artifact intake is closed")


def _validate_declared(operation: str, artifact: VerifiedArtifact) -> None:
    maximum = {
        "deploy": MAX_DEPLOY_ARTIFACT_BYTES,
        "import": MAX_IMPORT_ARTIFACT_BYTES,
    }.get(operation)
    if maximum is None:
        raise IntakeError("operation does not accept an uploaded artifact")
    if (
        type(artifact.size) is not int
        or artifact.size <= 0
        or artifact.size > maximum
        or type(artifact.sha256) is not str
        or _SHA256.fullmatch(artifact.sha256) is None
    ):
        raise IntakeError("declared artifact binding is invalid")


def _write_all(file_descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(file_descriptor, remaining)
        if written <= 0:
            raise OSError(errno.EIO, "artifact write made no progress")
        remaining = remaining[written:]


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            directory_fd,
            os.fsencode(source),
            directory_fd,
            os.fsencode(destination),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise IntakeOccupiedError("intake destination already exists")
        raise OSError(error_number, os.strerror(error_number), destination)
