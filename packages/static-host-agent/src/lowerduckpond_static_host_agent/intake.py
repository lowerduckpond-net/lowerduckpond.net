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
    Digest,
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
from lowerduckpond_static_host_agent.portable_bundle import (
    PortableBundleError,
    inspect_portable_bundle,
)
from lowerduckpond_static_host_agent.zip_structure import (
    ZipExtraction,
    ZipStructureError,
    deployment_zip_release_tree_digest,
    extract_deployment_zip,
)

_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
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


class IntakeArtifactUnavailableError(IntakeError):
    """A committed job's exact admitted artifact is unavailable."""


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
        self._discarded = False

    def commit(self) -> None:
        """Retain the admitted artifact after its immutable job is durable."""

        if self._discarded:
            raise RuntimeError("discarded artifact lease cannot be committed")
        self._committed = True

    def discard(self) -> None:
        """Remove an existing or newly admitted retry artifact on context exit."""

        if self._committed:
            raise RuntimeError("committed artifact lease cannot be discarded")
        self._discarded = True

    @property
    def committed(self) -> bool:
        return self._committed

    @property
    def discarded(self) -> bool:
        return self._discarded


class ArtifactClaim:
    """Hold the intake lock while one executor owns an admitted artifact."""

    def __init__(self, artifact: AdmittedArtifact) -> None:
        self.artifact = artifact
        self._consumed = False

    def consume(self) -> None:
        """Remove the artifact after its terminal result is durable."""

        self._consumed = True

    @property
    def consumed(self) -> bool:
        return self._consumed


@dataclass(frozen=True, slots=True)
class IntakeReconciliation:
    """One bounded startup reconciliation outcome."""

    retained_filename: str | None
    removed_entries: int


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
    def admit(  # noqa: PLR0913 - each argument is an explicit intake boundary
        self,
        *,
        operation: str,
        correlation_id: object,
        declared: VerifiedArtifact,
        read: Callable[[int], bytes],
        blocking: bool = False,
        allow_existing: bool = False,
    ) -> Iterator[ArtifactLease]:
        """Publish exact bytes and retain the lock through immutable job commit."""

        self._require_open()
        canonical_id = validate_uuid7(correlation_id)
        _validate_declared(operation, declared)
        with self._locks.acquire(LockName.INTAKE, mode=LockMode.EXCLUSIVE, blocking=blocking):
            filename = f"{canonical_id}.artifact"
            existing = self._reconcile_before_admission(
                filename=filename,
                declared=declared,
                allow_existing=allow_existing,
            )
            if existing is not None:
                self._verify_discarded_stream(declared=declared, read=read)
                existing_lease = ArtifactLease(existing)
                try:
                    yield existing_lease
                finally:
                    if existing_lease.discarded:
                        self._remove(filename)
                return
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
                retain = published and lease is not None and lease.committed and not lease.discarded
                if not retain:
                    self._remove(temporary if not published else filename)

    def discard_retry(
        self,
        *,
        declared: VerifiedArtifact,
        read: Callable[[int], bytes],
    ) -> None:
        """Consume and verify retry bytes without allocating another slot."""

        self._require_open()
        self._verify_discarded_stream(declared=declared, read=read)

    @contextmanager
    def claim(
        self,
        *,
        correlation_id: object,
        declared: VerifiedArtifact,
        blocking: bool = False,
    ) -> Iterator[ArtifactClaim]:
        """Validate and exclusively retain one admitted artifact for execution."""

        self._require_open()
        filename = f"{validate_uuid7(correlation_id)}.artifact"
        with self._locks.acquire(LockName.INTAKE, mode=LockMode.EXCLUSIVE, blocking=blocking):
            names = self._scan_slot()
            if names != [filename]:
                raise IntakeArtifactUnavailableError(
                    "authorized artifact is absent from the intake slot"
                )
            self._validate_entry(filename)
            self._verify_existing(filename, declared=declared)
            claim = ArtifactClaim(AdmittedArtifact(filename, declared))
            try:
                yield claim
            finally:
                if claim.consumed:
                    self._remove(filename)

    def deployment_release_tree_digest(self, artifact: AdmittedArtifact) -> Digest:
        """Derive exact normalized release content while the intake claim is held."""

        self._require_open()
        self._locks.require_held(LockName.INTAKE, mode=LockMode.EXCLUSIVE)
        if not _ADMITTED.fullmatch(artifact.filename):
            raise IntakeError("claimed artifact filename is not canonical")
        self._validate_entry(artifact.filename)
        self._verify_existing(artifact.filename, declared=artifact.verified)
        try:
            return deployment_zip_release_tree_digest(
                self._intake_path / artifact.filename,
                expected_owner=self._expected_owner,
            )
        except (OSError, ValueError, ZipStructureError) as error:
            raise IntakeError("claimed deployment artifact cannot be derived safely") from error

    def extract_deployment_release(
        self,
        artifact: AdmittedArtifact,
        *,
        staging_parent: Path,
        staging_name: str,
        retained_usage: ReleaseCapacityUsage,
        limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> ZipExtraction:
        """Repeat validation and extract one claimed deploy into private staging."""

        self._require_open()
        self._locks.require_held(LockName.INTAKE, mode=LockMode.EXCLUSIVE)
        if not _ADMITTED.fullmatch(artifact.filename):
            raise IntakeError("claimed artifact filename is not canonical")
        self._validate_entry(artifact.filename)
        self._verify_existing(artifact.filename, declared=artifact.verified)
        try:
            return extract_deployment_zip(
                self._intake_path / artifact.filename,
                staging_parent=staging_parent,
                staging_name=staging_name,
                expected_owner=self._expected_owner,
                retained_usage=retained_usage,
                lock_manager=self._locks,
                capacity_limits=limits,
            )
        except (OSError, ValueError, ZipStructureError) as error:
            raise IntakeError("claimed deployment artifact cannot be extracted safely") from error

    def import_release_tree_digest(self, artifact: AdmittedArtifact) -> Digest:
        """Derive exact normalized content from one claimed portable bundle."""

        self._require_open()
        self._locks.require_held(LockName.INTAKE, mode=LockMode.EXCLUSIVE)
        if not _ADMITTED.fullmatch(artifact.filename):
            raise IntakeError("claimed artifact filename is not canonical")
        self._validate_entry(artifact.filename)
        self._verify_existing(artifact.filename, declared=artifact.verified)
        try:
            return inspect_portable_bundle(
                self._intake_path / artifact.filename,
                expected_owner=self._expected_owner,
            ).release_tree_digest
        except (OSError, ValueError, PortableBundleError) as error:
            raise IntakeError("claimed import artifact cannot be derived safely") from error

    def reconcile(
        self,
        *,
        authority: Callable[[], tuple[dict[str, VerifiedArtifact], set[str]]],
        blocking: bool = False,
    ) -> IntakeReconciliation:
        """Snapshot authority while holding intake, then reconcile its one slot."""

        self._require_open()
        with self._locks.acquire(LockName.INTAKE, mode=LockMode.EXCLUSIVE, blocking=blocking):
            authorized, terminal = authority()
            names = self._scan_slot()
            if not names:
                return IntakeReconciliation(None, 0)
            name = names[0]
            self._validate_entry(name)
            if _TEMPORARY.fullmatch(name) is not None:
                self._remove(name)
                return IntakeReconciliation(None, 1)
            if _ADMITTED.fullmatch(name) is None:
                raise IntakeError("intake contains an unrecognized object")
            declared = authorized.get(name)
            if name in terminal or declared is None:
                self._remove(name)
                return IntakeReconciliation(None, 1)
            self._verify_existing(name, declared=declared)
            return IntakeReconciliation(name, 0)

    def _reconcile_before_admission(
        self,
        *,
        filename: str,
        declared: VerifiedArtifact,
        allow_existing: bool,
    ) -> AdmittedArtifact | None:
        names = self._scan_slot()
        if not names:
            return None
        name = names[0]
        self._validate_entry(name)
        if _TEMPORARY.fullmatch(name) is not None:
            self._remove(name)
            return None
        if _ADMITTED.fullmatch(name) is not None:
            if allow_existing and name == filename:
                self._verify_existing(name, declared=declared)
                return AdmittedArtifact(name, declared)
            raise IntakeOccupiedError("intake slot contains an admitted artifact")
        raise IntakeError("intake contains an unrecognized object")

    def _scan_slot(self) -> list[str]:
        names: list[str] = []
        # A duplicated directory descriptor shares its enumeration offset with
        # the original. Open a fresh descriptor so every admission rescans the
        # complete fixed directory rather than inheriting an earlier EOF.
        descriptor = os.open(".", _DIRECTORY_FLAGS, dir_fd=self._directory_fd)
        try:
            with os.scandir(descriptor) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > 1:
                        raise IntakeError("intake contains more than its single slot")
                    names.append(entry.name)
        finally:
            os.close(descriptor)
        return names

    def _verify_existing(self, name: str, *, declared: VerifiedArtifact) -> None:
        file_descriptor = os.open(name, _READ_FLAGS, dir_fd=self._directory_fd)
        try:
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != self._expected_owner
                or stat.S_IMODE(before.st_mode) != _ARTIFACT_MODE
                or before.st_nlink != 1
                or before.st_size != declared.size
            ):
                raise IntakeError("admitted retry artifact has unsafe metadata")
            digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, _CHUNK_BYTES):
                digest.update(chunk)
            after = os.fstat(file_descriptor)
            if _generation(before) != _generation(after) or digest.hexdigest() != declared.sha256:
                raise IntakeError("admitted retry artifact does not match its binding")
        finally:
            os.close(file_descriptor)

    def _verify_discarded_stream(
        self,
        *,
        declared: VerifiedArtifact,
        read: Callable[[int], bytes],
    ) -> None:
        digest = hashlib.sha256()
        remaining = declared.size
        while remaining:
            chunk = read(min(remaining, _CHUNK_BYTES))
            if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
                raise IntakeError("artifact retry ended outside its declared length")
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.hexdigest() != declared.sha256:
            raise IntakeError("artifact retry does not match its request binding")

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


def _generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


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
