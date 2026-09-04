"""Atomic Caddy-generation selection and descriptor-pinned process launch."""

from __future__ import annotations

import errno
import fcntl
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Collection, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import Final, Protocol, Self, cast

from lowerduckpond_static_contracts import (
    ContractError,
    decode_json_object,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_GENERATION_ROOT_MODE,
    CADDY_ROUTE_METADATA_NAME,
    MAX_CADDY_CONFIGURATION_BYTES,
    MAX_CADDY_ENVIRONMENT_BYTES,
    MAX_CADDY_ROUTE_METADATA_BYTES,
    CaddyGenerationManifest,
    CaddyGenerationStore,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.caddy_routes import (
    CaddyRouteError,
    PlatformOnlyCaddyRoutes,
    TenantCaddyRoutes,
    TenantRouteInput,
    build_platform_only_caddy_routes,
    build_tenant_caddy_routes,
    configured_origin_pull_policy,
)
from lowerduckpond_static_host_agent.issuance import PublicationGate
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteSnapshotTransaction,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.tenant_generation import (
    derive_tenant_generation_payload,
)

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
_CADDY_VALIDATION_OUTPUT_BYTES: Final = 262_144
_CADDY_VALIDATION_TIMEOUT_SECONDS: Final = 30
_CADDY_VALIDATION_API_TOKEN: Final = "0" * 40
_CADDY_VALIDATION_DATA_MODE: Final = 0o770
_BASH: Final = "/usr/bin/bash"
_PRLIMIT: Final = "/usr/bin/prlimit"
_SETPRIV: Final = "/usr/bin/setpriv"
_SYSTEMCTL: Final = "/usr/bin/systemctl"
_SYSTEMD_RUN: Final = "/usr/bin/systemd-run"
_EXEC_PINNED_CADDY: Final = 'exec -a caddy "/proc/self/fd/$1" "${@:2}"'
_CADDY_VALIDATION_SCOPE_PROPERTIES: Final = (
    "MemoryMax=256M",
    "MemorySwapMax=0",
    "TasksMax=32",
    "CPUQuota=100%",
    "RuntimeMaxSec=30s",
    "OOMPolicy=kill",
    "KillMode=control-group",
)
_CADDY_VALIDATION_RESOURCE_LIMITS: Final = (
    "--core=0",
    "--cpu=15",
    "--fsize=16777216",
    "--memlock=0",
    "--nofile=64",
    "--stack=16777216",
)
_INHERITED_SYSTEMD_ENVIRONMENT: Final = frozenset(
    {
        "INVOCATION_ID",
        "NOTIFY_SOCKET",
        "WATCHDOG_PID",
        "WATCHDOG_USEC",
    }
)
_ALLOWED_GENERATION_ENVIRONMENT: Final = frozenset(
    {
        "CLOUDFLARE_API_TOKEN",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    }
)
_FORBIDDEN_GENERATION_ENVIRONMENT: Final = _INHERITED_SYSTEMD_ENVIRONMENT | {
    "LISTEN_FDNAMES",
    "LISTEN_FDS",
    "LISTEN_PID",
}


class CaddyRuntimeError(RuntimeError):
    """The selected Caddy runtime or launcher boundary is unsafe."""


class CaddySelectionBoundary(StrEnum):
    """Observable durability barriers for active-reference failure injection."""

    REFERENCE_SYNC = "reference-sync"
    RENAME = "rename"
    PARENT_SYNC = "parent-sync"


SelectionFailureHook = Callable[[CaddySelectionBoundary], None]
Execve = Callable[[int, list[str], dict[str, str]], object]
CandidateValidator = Callable[[PinnedCaddyGeneration, Mapping[str, str]], None]


class _HeldLockVerifier(Protocol):
    """Prove that the current thread owns one exact ordered host lock."""

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class SelectedCaddyGeneration:
    """One active-reference read paired with its verified pinned generation."""

    generation_id: str
    generation: PinnedCaddyGeneration


@dataclass(frozen=True, slots=True)
class _ValidationResult:
    returncode: int
    stdout: bytes


@dataclass(frozen=True, slots=True)
class _ValidationInvocation:
    command: tuple[str, ...]
    scope_unit: str | None


class CaddyRuntime:
    """One pinned runtime root and its exact shared publication lock."""

    def __init__(  # noqa: PLR0913
        self,
        root_fd: int,
        lock_fd: int,
        *,
        owner: int,
        group: int,
        creation_group: int,
        expected_binary_sha256: str | None,
        candidate_validator: CandidateValidator,
    ) -> None:
        self._root_fd = root_fd
        self._lock_fd = lock_fd
        self._owner = owner
        self._group = group
        self._creation_group = creation_group
        self._expected_binary_sha256 = (
            None
            if expected_binary_sha256 is None
            else _validate_expected_binary_sha256(expected_binary_sha256)
        )
        self._candidate_validator = candidate_validator
        self._context_mutex = threading.RLock()
        self._locked = False
        self._lock_owner_thread: int | None = None
        self._closed = False

    @classmethod
    def open(  # noqa: PLR0913
        cls,
        root: Path,
        publication_lock: Path,
        *,
        expected_owner: int,
        expected_group: int,
        validation_uid: int,
        validation_gid: int,
        expected_binary_sha256: str | None,
        expected_lock_owner: int | None = None,
        expected_lock_group: int | None = None,
        root_mode: int = CADDY_RUNTIME_ROOT_MODE,
        lock_mode: int = CADDY_PUBLICATION_LOCK_MODE,
        candidate_validator: CandidateValidator | None = None,
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
            expected_binary_sha256=expected_binary_sha256,
            candidate_validator=(
                partial(
                    _validate_generation_candidate,
                    validation_uid=validation_uid,
                    validation_gid=validation_gid,
                )
                if candidate_validator is None
                else candidate_validator
            ),
        )

    @classmethod
    def from_lock_descriptor(  # noqa: PLR0913
        cls,
        root: Path,
        publication_lock_fd: int,
        *,
        expected_owner: int,
        expected_group: int,
        validation_uid: int,
        validation_gid: int,
        expected_binary_sha256: str | None,
        expected_lock_owner: int,
        expected_lock_group: int,
        root_mode: int = CADDY_RUNTIME_ROOT_MODE,
        lock_mode: int = CADDY_PUBLICATION_LOCK_MODE,
        candidate_validator: CandidateValidator | None = None,
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
            expected_binary_sha256=expected_binary_sha256,
            candidate_validator=(
                partial(
                    _validate_generation_candidate,
                    validation_uid=validation_uid,
                    validation_gid=validation_gid,
                )
                if candidate_validator is None
                else candidate_validator
            ),
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
            self._lock_owner_thread = threading.get_ident()
            try:
                yield self
            finally:
                self._lock_owner_thread = None
                self._locked = False
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    @contextmanager
    def using_held_publication_lock(self, lock_manager: _HeldLockVerifier) -> Iterator[object]:
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
            self._lock_owner_thread = threading.get_ident()
            try:
                yield self
            finally:
                self._lock_owner_thread = None
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
        return SelectedCaddyGeneration(
            generation_id,
            self.open_verified_generation(generation_id),
        )

    def open_verified_generation(self, generation_id: str) -> PinnedCaddyGeneration:
        """Pin and verify one explicit complete generation under publication."""

        self._require_locked()
        canonical_id = _canonical_generation_id(generation_id)
        store = self._open_generation_store()
        try:
            generation = store.open_verified(canonical_id)
            try:
                if self._expected_binary_sha256 is not None:
                    _validate_trusted_binary(generation, self._expected_binary_sha256)
                _validate_route_binding(generation)
            except BaseException:
                generation.close()
                raise
        finally:
            store.close()
        return generation

    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        """Return exact tenant inputs from one verified tenant-capable generation."""

        self._require_locked()
        with self.open_verified_generation(generation_id) as generation:
            descriptor = generation.duplicate_payload_descriptor(CADDY_ROUTE_METADATA_NAME)
            try:
                route_metadata = decode_json_object(
                    os.pread(descriptor, MAX_CADDY_ROUTE_METADATA_BYTES + 1, 0),
                    maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES,
                )
            finally:
                os.close(descriptor)
        route_state = route_metadata.get("routeState")
        if type(route_state) is not dict or route_state.get("generationClass") != "tenant-capable":
            raise CaddyRuntimeError("generation has no tenant route snapshot")
        namespace, tenants = _tenant_route_inputs(route_state, generation_id=generation_id)
        return TenantRouteSnapshot(namespace, tenants)

    def publish_candidate(
        self,
        generation_id: str,
        *,
        transaction: RouteSnapshotTransaction,
        overlay: TenantRouteOverlay,
        gate: PublicationGate,
    ) -> CaddyGenerationManifest:
        """Derive, admit, and validate one unselected tenant generation."""

        self._require_locked()
        gate.require_enabled()
        candidate_id = _canonical_generation_id(generation_id)
        active = self.open_active_verified()
        try:
            if candidate_id == active.generation_id:
                raise CaddyRuntimeError("candidate Caddy generation is already active")
            payload = derive_tenant_generation_payload(
                active.generation,
                snapshot_tenant_routes(transaction, overlay=overlay),
                candidate_generation_id=candidate_id,
            )

            store = self._open_generation_store()
            try:
                retained = store.list_verified()
                if active.generation_id not in retained:
                    raise CaddyRuntimeError("active Caddy generation is absent from storage")
                store.admit_candidate(payload, retained)
                manifest = store.publish(candidate_id, payload)
                try:
                    with store.open_verified(candidate_id) as candidate:
                        if self._expected_binary_sha256 is not None:
                            _validate_trusted_binary(candidate, self._expected_binary_sha256)
                        _validate_route_binding(candidate)
                        environment = _read_generation_environment(candidate)
                        self._candidate_validator(candidate, environment)
                except BaseException:
                    store.discard_published(candidate_id, manifest)
                    raise
                return manifest
            finally:
                store.close()
        finally:
            active.generation.close()

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
            with store.open_verified(canonical_id) as generation:
                if self._expected_binary_sha256 is not None:
                    _validate_trusted_binary(generation, self._expected_binary_sha256)
                _validate_route_binding(generation)
                environment = _read_generation_environment(generation)
                self._candidate_validator(generation, environment)
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

    def prune_unreferenced_generations(
        self,
        protected_generation_ids: Collection[str],
        *,
        keep_newest_unprotected: int = 0,
    ) -> tuple[str, ...]:
        """Retain active, explicit recovery targets, and optional predecessor."""

        self._require_locked()
        protected = {
            _canonical_generation_id(generation_id) for generation_id in protected_generation_ids
        }
        protected.add(self.read_active())
        store = self._open_generation_store()
        try:
            return store.prune_unreferenced(
                protected,
                keep_newest_unprotected=keep_newest_unprotected,
            )
        finally:
            store.close()

    def discard_unselected_candidate(
        self,
        generation_id: str,
        manifest: CaddyGenerationManifest,
    ) -> None:
        """Remove only one exact candidate that never became active."""

        self._require_locked()
        candidate_id = _canonical_generation_id(generation_id)
        if manifest.generation_id != candidate_id:
            raise CaddyRuntimeError("candidate manifest identity disagrees")
        if self.read_active() == candidate_id:
            raise CaddyRuntimeError("cannot discard the active Caddy generation")
        store = self._open_generation_store()
        try:
            store.discard_published(candidate_id, manifest)
        finally:
            store.close()

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
        if not self._locked or self._lock_owner_thread != threading.get_ident():
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
        inherited_before = os.get_inheritable(self._configuration_fd)
        os.set_inheritable(self._configuration_fd, True)
        arguments = [
            "caddy",
            "run",
            "--config",
            f"/proc/self/fd/{self._configuration_fd}",
        ]
        try:
            result = execve(self._binary_fd, arguments, environment)
        finally:
            os.set_inheritable(self._configuration_fd, inherited_before)
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
                environment = _parse_environment(
                    os.pread(environment_fd, MAX_CADDY_ENVIRONMENT_BYTES + 1, 0)
                )
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


def _validate_expected_binary_sha256(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value, flags=re.ASCII) is None:
        raise ValueError("trusted Caddy binary SHA-256 must be lowercase hexadecimal")
    return value


def _validate_trusted_binary(
    generation: PinnedCaddyGeneration,
    expected_binary_sha256: str,
) -> None:
    binary = next(item for item in generation.manifest.files if item.name == CADDY_BINARY_NAME)
    if not secrets.compare_digest(binary.sha256, expected_binary_sha256):
        raise CaddyRuntimeError("selected Caddy binary does not match the trusted digest")


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
            or name not in _ALLOWED_GENERATION_ENVIRONMENT
            or name in _FORBIDDEN_GENERATION_ENVIRONMENT
        ):
            raise CaddyRuntimeError("selected Caddy environment contains a forbidden name")
        result[name] = value
    if not result.get("CLOUDFLARE_API_TOKEN"):
        raise CaddyRuntimeError("selected Caddy environment has no DNS credential")
    return result


def _validate_route_binding(generation: PinnedCaddyGeneration) -> None:
    configuration_fd = generation.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
    route_metadata_fd: int | None = None
    try:
        route_metadata_fd = generation.duplicate_payload_descriptor(CADDY_ROUTE_METADATA_NAME)
        configuration = decode_json_object(
            os.pread(configuration_fd, MAX_CADDY_CONFIGURATION_BYTES + 1, 0),
            maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES,
        )
        route_metadata = decode_json_object(
            os.pread(
                route_metadata_fd,
                MAX_CADDY_ROUTE_METADATA_BYTES + 1,
                0,
            ),
            maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES,
        )
    finally:
        if route_metadata_fd is not None:
            os.close(route_metadata_fd)
        os.close(configuration_fd)

    route_state = route_metadata.get("routeState")
    if type(route_state) is not dict:
        raise CaddyRuntimeError("selected Caddy route state is malformed")
    generation_class = route_state.get("generationClass")
    try:
        origin_pull_ca_der, origin_pull_required = configured_origin_pull_policy(configuration)
        expected: PlatformOnlyCaddyRoutes | TenantCaddyRoutes
        if generation_class == "platform-only":
            expected = build_platform_only_caddy_routes(
                origin_pull_ca_der=origin_pull_ca_der,
                origin_pull_required=origin_pull_required,
            )
        elif generation_class == "tenant-capable":
            namespace, tenants = _tenant_route_inputs(
                route_state,
                generation_id=generation.manifest.generation_id,
            )
            expected = build_tenant_caddy_routes(
                platform_namespace=namespace,
                tenants=tenants,
                runtime_generation_id=generation.manifest.generation_id,
                origin_pull_ca_der=origin_pull_ca_der,
                origin_pull_required=origin_pull_required,
            )
        else:
            raise CaddyRuntimeError("selected Caddy generation class is not recognized")
    except (ContractError, CaddyRouteError, KeyError, TypeError, ValueError) as error:
        raise CaddyRuntimeError("selected Caddy route state is malformed") from error
    if configuration != expected.configuration or route_metadata != expected.route_metadata:
        raise CaddyRuntimeError("selected Caddy configuration and declared route state disagree")


def _tenant_route_inputs(
    route_state: dict[str, object],
    *,
    generation_id: str,
) -> tuple[dict[str, object], tuple[TenantRouteInput, ...]]:
    if route_state.get("runtimeGenerationId") != generation_id:
        raise CaddyRuntimeError("selected Caddy route generation identity disagrees")
    namespace = route_state.get("platformNamespace")
    raw_tenants = route_state.get("tenantStates")
    if type(namespace) is not dict or type(raw_tenants) is not list:
        raise CaddyRuntimeError("selected Caddy tenant route inputs are malformed")
    tenants: list[TenantRouteInput] = []
    for raw_tenant in raw_tenants:
        if type(raw_tenant) is not dict or set(raw_tenant) != {
            "activeDeployment",
            "desiredManifest",
            "observedState",
            "routeSet",
        }:
            raise CaddyRuntimeError("selected Caddy tenant route inputs are malformed")
        manifest = raw_tenant["desiredManifest"]
        observed = raw_tenant["observedState"]
        deployment = raw_tenant["activeDeployment"]
        if (
            type(manifest) is not dict
            or type(observed) is not dict
            or (deployment is not None and type(deployment) is not dict)
        ):
            raise CaddyRuntimeError("selected Caddy tenant route inputs are malformed")
        tenants.append(
            TenantRouteInput(
                manifest=cast(dict[str, object], manifest),
                observed_state=cast(dict[str, object], observed),
                deployment=cast(dict[str, object] | None, deployment),
            )
        )
    return cast(dict[str, object], namespace), tuple(tenants)


def _validate_generation_candidate(
    generation: PinnedCaddyGeneration,
    environment: Mapping[str, str],
    *,
    validation_uid: int,
    validation_gid: int,
) -> None:
    binary_fd = generation.duplicate_payload_descriptor(CADDY_BINARY_NAME)
    configuration_fd: int | None = None
    validation_root: Path | None = None
    try:
        configuration_fd = generation.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
        validation_root, isolated_environment = _create_validation_environment(
            environment,
            validation_uid=validation_uid,
            validation_gid=validation_gid,
        )
        module_environment = dict(isolated_environment)
        module_environment.pop("CLOUDFLARE_API_TOKEN", None)
        modules = _run_validation_command(
            binary_fd,
            ["list-modules"],
            environment=module_environment,
            inherited_descriptors=(),
            validation_uid=validation_uid,
            validation_gid=validation_gid,
        )
        if modules.returncode != 0 or b"dns.providers.cloudflare" not in {
            line.strip() for line in modules.stdout.splitlines()
        }:
            raise CaddyRuntimeError("selected Caddy binary does not provide the required module")
        validation_environment = dict(module_environment)
        validation_environment["CLOUDFLARE_API_TOKEN"] = _CADDY_VALIDATION_API_TOKEN
        validated = _run_validation_command(
            binary_fd,
            ["validate", "--config", f"/proc/self/fd/{configuration_fd}"],
            environment=validation_environment,
            inherited_descriptors=(configuration_fd,),
            validation_uid=validation_uid,
            validation_gid=validation_gid,
        )
        if validated.returncode != 0:
            raise CaddyRuntimeError("selected Caddy configuration is invalid")
    finally:
        if validation_root is not None:
            shutil.rmtree(validation_root)
        if configuration_fd is not None:
            os.close(configuration_fd)
        os.close(binary_fd)


def _create_validation_environment(
    environment: Mapping[str, str],
    *,
    validation_uid: int,
    validation_gid: int,
) -> tuple[Path, dict[str, str]]:
    if min(validation_uid, validation_gid) < 0:
        raise ValueError("validation identity must use nonnegative numeric IDs")
    if os.geteuid() not in {0, validation_uid} or (
        os.geteuid() != 0 and os.getegid() != validation_gid
    ):
        raise CaddyRuntimeError("cannot enter the Caddy validation identity")
    root = Path(
        tempfile.mkdtemp(
            prefix="lowerduckpond-caddy-validation-",
            dir="/dev/shm",
        )
    )
    try:
        data = root / "data"
        data.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(root, 0, validation_gid)
            os.chown(data, 0, validation_gid)
        root.chmod(0o750)
        data.chmod(_CADDY_VALIDATION_DATA_MODE)
    except BaseException:
        shutil.rmtree(root)
        raise
    isolated = dict(environment)
    for name in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        isolated[name] = str(data)
    return root, isolated


def _validation_invocation(  # noqa: PLR0913
    binary_fd: int,
    arguments: list[str],
    *,
    validation_uid: int,
    validation_gid: int,
    root_execution: bool,
    scope_suffix: str,
) -> _ValidationInvocation:
    identity_arguments: list[str] = []
    capability_arguments = ["--inh-caps=-all", "--ambient-caps=-all"]
    if root_execution:
        identity_arguments = [
            f"--reuid={validation_uid}",
            f"--regid={validation_gid}",
            "--clear-groups",
        ]
        capability_arguments.append("--bounding-set=-all")
    sandboxed_command = [
        _SETPRIV,
        *identity_arguments,
        *capability_arguments,
        "--no-new-privs",
        "--",
        _PRLIMIT,
        *_CADDY_VALIDATION_RESOURCE_LIMITS,
        "--",
        _BASH,
        "-c",
        _EXEC_PINNED_CADDY,
        "lowerduckpond-caddy-validation",
        str(binary_fd),
        *arguments,
    ]
    if not root_execution:
        return _ValidationInvocation(tuple(sandboxed_command), None)
    if re.fullmatch(r"[0-9a-f]{16}", scope_suffix, flags=re.ASCII) is None:
        raise ValueError("validation scope suffix must be 16 lowercase hexadecimal digits")
    scope_stem = f"lowerduckpond-caddy-validation-{scope_suffix}"
    command = [
        _SYSTEMD_RUN,
        "--quiet",
        "--scope",
        "--collect",
        "--expand-environment=no",
        f"--unit={scope_stem}",
    ]
    for item in _CADDY_VALIDATION_SCOPE_PROPERTIES:
        command.extend(("--property", item))
    command.extend(("--", *sandboxed_command))
    return _ValidationInvocation(tuple(command), f"{scope_stem}.scope")


def _run_validation_command(  # noqa: PLR0913
    binary_fd: int,
    arguments: list[str],
    *,
    environment: Mapping[str, str],
    inherited_descriptors: tuple[int, ...],
    validation_uid: int,
    validation_gid: int,
) -> _ValidationResult:
    invocation = _validation_invocation(
        binary_fd,
        arguments,
        validation_uid=validation_uid,
        validation_gid=validation_gid,
        root_execution=os.geteuid() == 0,
        scope_suffix=secrets.token_hex(8),
    )
    descriptors = (binary_fd, *inherited_descriptors)
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed setpriv and pinned input
            invocation.command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            pass_fds=descriptors,
            start_new_session=True,
        )
    except OSError as error:
        raise CaddyRuntimeError("selected Caddy validation could not run") from error
    if process.stdout is None:
        _kill_validation_process(process, scope_unit=invocation.scope_unit)
        raise CaddyRuntimeError("selected Caddy validation has no output boundary")
    output = bytearray()
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + _CADDY_VALIDATION_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaddyRuntimeError("selected Caddy validation exceeded its deadline")
            if not selector.select(remaining):
                raise CaddyRuntimeError("selected Caddy validation exceeded its deadline")
            try:
                chunk = os.read(
                    descriptor,
                    min(65_536, _CADDY_VALIDATION_OUTPUT_BYTES + 1 - len(output)),
                )
            except BlockingIOError:
                continue
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > _CADDY_VALIDATION_OUTPUT_BYTES:
                raise CaddyRuntimeError("selected Caddy validation output exceeded its limit")
        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise CaddyRuntimeError("selected Caddy validation exceeded its deadline") from error
        return _ValidationResult(returncode, bytes(output))
    finally:
        selector.close()
        process.stdout.close()
        _kill_validation_process(process, scope_unit=invocation.scope_unit)


def _kill_validation_process(
    process: subprocess.Popen[bytes],
    *,
    scope_unit: str | None,
) -> None:
    scope_error: BaseException | None = None
    process_is_unreaped = process.returncode is None
    if scope_unit is not None:
        try:
            for arguments in (
                (
                    "kill",
                    "--kill-whom=all",
                    "--signal=KILL",
                    scope_unit,
                ),
                ("stop", scope_unit),
            ):
                subprocess.run(  # noqa: S603 - fixed systemd scope operation
                    [_SYSTEMCTL, *arguments],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin"},
                    check=False,
                    timeout=5,
                )
            status = subprocess.run(  # noqa: S603 - fixed systemd scope operation
                [
                    _SYSTEMCTL,
                    "show",
                    "--property=LoadState",
                    "--property=ActiveState",
                    scope_unit,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin"},
                check=False,
                timeout=5,
            )
            properties = {
                name: value
                for line in status.stdout.decode("ascii", errors="replace").splitlines()
                if "=" in line
                for name, value in (line.split("=", 1),)
            }
            if status.returncode != 0 or not (
                properties.get("LoadState") == "not-found"
                or properties.get("ActiveState") in {"failed", "inactive"}
            ):
                scope_error = CaddyRuntimeError(
                    "selected Caddy validation scope could not be torn down"
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            scope_error = CaddyRuntimeError(
                "selected Caddy validation scope could not be torn down"
            )
            scope_error.__cause__ = error
    try:
        if process_is_unreaped:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            with suppress(ProcessLookupError):
                process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            if scope_error is None:
                scope_error = CaddyRuntimeError(
                    "selected Caddy validation process could not be reaped"
                )
                scope_error.__cause__ = error
    finally:
        if scope_error is not None:
            raise scope_error


def _read_generation_environment(generation: PinnedCaddyGeneration) -> dict[str, str]:
    descriptor = generation.duplicate_payload_descriptor(CADDY_ENVIRONMENT_NAME)
    try:
        return _parse_environment(os.pread(descriptor, MAX_CADDY_ENVIRONMENT_BYTES + 1, 0))
    finally:
        os.close(descriptor)


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
