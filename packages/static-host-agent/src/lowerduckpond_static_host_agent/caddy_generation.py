"""Complete immutable Caddy runtime-generation publication and verification."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from lowerduckpond_static_contracts import (
    ContractError,
    Digest,
    canonical_json_bytes,
    decode_json_object,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.release_tree import InodeAllocation

CADDY_GENERATION_SCHEMA: Final = "lowerduckpond.caddy-generation/v1"
CADDY_ROUTE_METADATA_SCHEMA: Final = "lowerduckpond.caddy-route-metadata/v1"
CADDY_ROUTE_STATE_DIGEST_FORMAT: Final = "lowerduckpond-caddy-route-state-v1"

CADDY_BINARY_NAME: Final = "caddy"
CADDY_ENVIRONMENT_NAME: Final = "environment"
CADDY_CONFIGURATION_NAME: Final = "caddy.json"
CADDY_ROUTE_METADATA_NAME: Final = "routes.json"
CADDY_MANIFEST_NAME: Final = "manifest.json"

CADDY_BINARY_MODE: Final = 0o550
CADDY_PRIVATE_FILE_MODE: Final = 0o440
CADDY_GENERATION_MODE: Final = 0o550
CADDY_GENERATION_ROOT_MODE: Final = 0o750

MAX_CADDY_BINARY_BYTES: Final = 128 * 1024 * 1024
MAX_CADDY_ENVIRONMENT_BYTES: Final = 64 * 1024
MAX_CADDY_CONFIGURATION_BYTES: Final = 2 * 1024 * 1024
MAX_CADDY_ROUTE_METADATA_BYTES: Final = 2 * 1024 * 1024
MAX_CADDY_MANIFEST_BYTES: Final = 32 * 1024
MAX_CADDY_GENERATION_ALLOCATED_BYTES: Final = 256 * 1024 * 1024
MAX_CADDY_GENERATION_UNIQUE_INODES: Final = 4_096
MAX_CADDY_GENERATIONS: Final = 3
MAX_CADDY_BOOTSTRAP_RETAINED_GENERATIONS: Final = 2
MAX_CADDY_GENERATION_SCAN_ENTRIES: Final = 4_096

_DIRECTORY_OPEN_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_READ_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_RENAME_NOREPLACE: Final = 1
_COPY_CHUNK_BYTES: Final = 64 * 1024
_TEMPORARY_PREFIX: Final = ".ldp-generation-"
_TEMPORARY_PATTERN: Final = re.compile(r"\.ldp-generation-[0-9a-f]{32}", flags=re.ASCII)
_RETIRED_PREFIX: Final = ".ldp-retired-"
_RETIRED_PATTERN: Final = re.compile(
    r"\.ldp-retired-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    flags=re.ASCII,
)
_ENVIRONMENT_NAME_PATTERN: Final = re.compile(r"[A-Z_][A-Z0-9_]*", flags=re.ASCII)
_MAXIMUM_PERMISSION_MODE: Final = 0o777
_PAYLOAD_NAMES: Final = (
    CADDY_BINARY_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ROUTE_METADATA_NAME,
)
_INVENTORY_NAMES: Final = frozenset((*_PAYLOAD_NAMES, CADDY_MANIFEST_NAME))


class CaddyGenerationError(RuntimeError):
    """A Caddy generation violated its immutable runtime contract."""


class CaddyGenerationAlreadyExistsError(CaddyGenerationError):
    """The requested immutable generation ID is already present."""


class CaddyGenerationBoundary(StrEnum):
    """Observable durability barriers for generation failure injection."""

    BINARY_SYNC = "binary-sync"
    ENVIRONMENT_SYNC = "environment-sync"
    CONFIGURATION_SYNC = "configuration-sync"
    ROUTE_METADATA_SYNC = "route-metadata-sync"
    MANIFEST_SYNC = "manifest-sync"
    DIRECTORY_SYNC = "directory-sync"
    RENAME = "rename"
    PARENT_SYNC = "parent-sync"


GenerationFailureHook = Callable[[CaddyGenerationBoundary], None]
TemporaryNameSource = Callable[[], str]


@dataclass(frozen=True, slots=True)
class CaddyBinarySource:
    """One staged, root-owned Caddy binary input."""

    path: Path
    owner: int
    group: int
    mode: int = 0o755

    def __post_init__(self) -> None:
        if type(self.owner) is not int or self.owner < 0:
            raise ValueError("Caddy binary owner must be a nonnegative integer")
        if type(self.group) is not int or self.group < 0:
            raise ValueError("Caddy binary group must be a nonnegative integer")
        if type(self.mode) is not int or not 0 <= self.mode <= _MAXIMUM_PERMISSION_MODE:
            raise ValueError("Caddy binary mode must be a concrete permission mode")


@dataclass(frozen=True, slots=True)
class CaddyGenerationPayload:
    """Trusted host inputs already adapted for one complete runtime generation."""

    binary: CaddyBinarySource
    environment: bytes
    configuration: Mapping[str, object]
    route_metadata: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.environment) is not bytes:
            raise TypeError("Caddy environment must be exact bytes")
        _validate_environment(self.environment)
        _canonical_object(self.configuration, maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES)
        route_bytes = _canonical_object(
            self.route_metadata,
            maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES,
        )
        _validate_route_metadata(decode_json_object(route_bytes, maximum_bytes=len(route_bytes)))


@dataclass(frozen=True, slots=True)
class CaddyGenerationFile:
    """One exact file bound by a complete-generation manifest."""

    name: str
    mode: int
    size: int
    sha256: str

    def __post_init__(self) -> None:
        if self.name not in _PAYLOAD_NAMES:
            raise CaddyGenerationError("generation manifest names a disallowed payload")
        if type(self.mode) is not int or self.mode not in {
            CADDY_BINARY_MODE,
            CADDY_PRIVATE_FILE_MODE,
        }:
            raise CaddyGenerationError("generation manifest contains an invalid file mode")
        if type(self.size) is not int or self.size < 0:
            raise CaddyGenerationError("generation manifest contains an invalid file size")
        if (
            type(self.sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256, flags=re.ASCII) is None
        ):
            raise CaddyGenerationError("generation manifest contains an invalid SHA-256")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical manifest representation."""

        return {
            "mode": f"{self.mode:04o}",
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class CaddyGenerationManifest:
    """The exact immutable payload inventory for one generation."""

    generation_id: str
    route_state_digest: Digest
    files: tuple[CaddyGenerationFile, ...]

    def __post_init__(self) -> None:
        try:
            validate_uuid7(self.generation_id)
        except ContractError as error:
            raise CaddyGenerationError("generation manifest ID is not UUIDv7") from error
        if self.route_state_digest.format != CADDY_ROUTE_STATE_DIGEST_FORMAT:
            raise CaddyGenerationError("generation manifest route digest has the wrong format")
        if tuple(sorted(item.name for item in self.files)) != tuple(sorted(_PAYLOAD_NAMES)):
            raise CaddyGenerationError("generation manifest does not bind the exact payload")
        expected_modes = {
            CADDY_BINARY_NAME: CADDY_BINARY_MODE,
            CADDY_ENVIRONMENT_NAME: CADDY_PRIVATE_FILE_MODE,
            CADDY_CONFIGURATION_NAME: CADDY_PRIVATE_FILE_MODE,
            CADDY_ROUTE_METADATA_NAME: CADDY_PRIVATE_FILE_MODE,
        }
        if any(item.mode != expected_modes[item.name] for item in self.files):
            raise CaddyGenerationError("generation manifest payload mode is not allowlisted")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical manifest document."""

        return {
            "files": [item.to_dict() for item in sorted(self.files, key=lambda item: item.name)],
            "generationId": self.generation_id,
            "routeStateDigest": self.route_state_digest.to_dict(),
            "schema": CADDY_GENERATION_SCHEMA,
        }

    def to_bytes(self) -> bytes:
        """Serialize the manifest canonically within its committed limit."""

        return canonical_json_bytes(self.to_dict(), maximum_bytes=MAX_CADDY_MANIFEST_BYTES)


class PinnedCaddyGeneration:
    """One manifest-verified generation whose directory and payloads stay pinned."""

    def __init__(
        self,
        directory_fd: int,
        payload_fds: dict[str, int],
        manifest: CaddyGenerationManifest,
    ) -> None:
        self._directory_fd = directory_fd
        self._payload_fds = payload_fds
        self._manifest = manifest
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

    @property
    def manifest(self) -> CaddyGenerationManifest:
        """Return the verified manifest."""

        self._require_open()
        return self._manifest

    def duplicate_directory_descriptor(self) -> int:
        """Return a caller-owned descriptor for the verified generation directory."""

        self._require_open()
        return _reopen_directory(self._directory_fd)

    def duplicate_payload_descriptor(self, name: str) -> int:
        """Return a caller-owned descriptor for one verified payload."""

        self._require_open()
        if name not in _PAYLOAD_NAMES:
            raise ValueError("payload name is not part of a complete Caddy generation")
        try:
            reopened = os.open(name, _FILE_READ_FLAGS, dir_fd=self._directory_fd)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENXIO}:
                raise CaddyGenerationError(
                    "verified generation payload is no longer a regular file"
                ) from error
            raise
        if _snapshot(os.fstat(reopened)) != _snapshot(os.fstat(self._payload_fds[name])):
            os.close(reopened)
            raise CaddyGenerationError("verified generation payload changed before reopening")
        return reopened

    def close(self) -> None:
        """Close all pinned generation descriptors."""

        if not self._closed:
            for descriptor in self._payload_fds.values():
                os.close(descriptor)
            os.close(self._directory_fd)
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("pinned Caddy generation is closed")


class CaddyGenerationStore:
    """Descriptor-relative publisher and verifier for complete Caddy generations."""

    def __init__(self, root_fd: int, *, owner: int, group: int) -> None:
        self._root_fd = root_fd
        self._owner = owner
        self._group = group
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_owner: int,
        expected_group: int,
        expected_mode: int = CADDY_GENERATION_ROOT_MODE,
    ) -> Self:
        """Open and pin the trusted generation root without following links."""

        root_fd = _open_directory_path(path, label="Caddy generation root")
        try:
            metadata = os.fstat(root_fd)
            _validate_directory_metadata(
                metadata,
                owner=expected_owner,
                group=expected_group,
                mode=expected_mode,
                label="Caddy generation root",
            )
            current = path.stat(follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
                raise CaddyGenerationError("Caddy generation root changed while opening")
        except BaseException:
            os.close(root_fd)
            raise
        return cls(root_fd, owner=expected_owner, group=expected_group)

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
            os.close(self._root_fd)
            self._closed = True

    def remove_abandoned_temporaries(
        self,
        *,
        maximum_entries: int = MAX_CADDY_GENERATION_SCAN_ENTRIES,
    ) -> int:
        """Remove safely shaped builder and retired-generation crash remnants."""

        self._require_open()
        if type(maximum_entries) is not int or maximum_entries < 0:
            raise ValueError("generation recovery bound must be a nonnegative integer")
        names: list[str] = []
        scan_fd = _reopen_directory(self._root_fd)
        try:
            iterator = os.scandir(scan_fd)
            with iterator:
                for entry_count, entry in enumerate(iterator, start=1):
                    if entry_count > maximum_entries:
                        raise CaddyGenerationError(
                            "generation root exceeds its recovery scan bound"
                        )
                    if entry.name.startswith((_TEMPORARY_PREFIX, _RETIRED_PREFIX)):
                        if not _is_reserved_generation_temporary(entry.name):
                            raise CaddyGenerationError(
                                "reserved generation temporary name is malformed"
                            )
                        names.append(entry.name)
        finally:
            os.close(scan_fd)
        for name in sorted(names):
            _remove_generation_temporary(
                self._root_fd,
                name,
                owner=self._owner,
                group=self._group,
                creation_group=os.getegid(),
            )
        return len(names)

    def list_verified(
        self,
        *,
        maximum_entries: int = MAX_CADDY_GENERATION_SCAN_ENTRIES,
    ) -> tuple[str, ...]:
        """Return the sorted complete generation IDs in one bounded exact scan."""

        self._require_open()
        if type(maximum_entries) is not int or maximum_entries < 0:
            raise ValueError("generation scan bound must be a nonnegative integer")
        identifiers: list[str] = []
        scan_fd = _reopen_directory(self._root_fd)
        try:
            with os.scandir(scan_fd) as iterator:
                for entry_count, entry in enumerate(iterator, start=1):
                    if entry_count > maximum_entries:
                        raise CaddyGenerationError("generation root exceeds its scan bound")
                    if entry.name.startswith((_TEMPORARY_PREFIX, _RETIRED_PREFIX)):
                        raise CaddyGenerationError(
                            "generation recovery must remove reserved temporaries first"
                        )
                    try:
                        identifier = validate_uuid7(entry.name)
                    except ContractError as error:
                        raise CaddyGenerationError(
                            "generation root contains an unrecognized entry"
                        ) from error
                    identifiers.append(identifier)
        finally:
            os.close(scan_fd)
        identifiers.sort()
        for identifier in identifiers:
            with self.open_verified(identifier):
                pass
        return tuple(identifiers)

    def bootstrap_retention_matches(self, active_generation_id: str) -> bool:
        """Report whether bootstrap storage is active plus at most one predecessor."""

        self._require_open()
        active = validate_uuid7(active_generation_id)
        scan_fd = _reopen_directory(self._root_fd)
        identifiers: list[str] = []
        cleanup_required = False
        try:
            with os.scandir(scan_fd) as iterator:
                for entry_count, entry in enumerate(iterator, start=1):
                    if entry_count > MAX_CADDY_GENERATION_SCAN_ENTRIES:
                        raise CaddyGenerationError("generation root exceeds its scan bound")
                    if entry.name.startswith((_TEMPORARY_PREFIX, _RETIRED_PREFIX)):
                        if not _is_reserved_generation_temporary(entry.name):
                            raise CaddyGenerationError(
                                "reserved generation temporary name is malformed"
                            )
                        cleanup_required = True
                        continue
                    try:
                        identifiers.append(validate_uuid7(entry.name))
                    except ContractError as error:
                        raise CaddyGenerationError(
                            "generation root contains an unrecognized entry"
                        ) from error
        finally:
            os.close(scan_fd)
        identifiers.sort()
        for identifier in identifiers:
            with self.open_verified(identifier):
                pass
        return (
            not cleanup_required
            and active in identifiers
            and len(identifiers) <= MAX_CADDY_BOOTSTRAP_RETAINED_GENERATIONS
        )

    def prune_unreferenced(
        self,
        protected_generation_ids: Collection[str],
        *,
        keep_newest_unprotected: int = 0,
    ) -> tuple[str, ...]:
        """Durably remove complete generations outside the bounded protected set."""

        self._require_open()
        if type(keep_newest_unprotected) is not int or keep_newest_unprotected < 0:
            raise ValueError("retained unprotected count must be a nonnegative integer")
        protected = {validate_uuid7(value) for value in protected_generation_ids}
        if len(protected) + keep_newest_unprotected > MAX_CADDY_GENERATIONS:
            raise CaddyGenerationError("generation retention set exceeds its maximum")
        self.remove_abandoned_temporaries()
        identifiers = self.list_verified()
        missing = protected.difference(identifiers)
        if missing:
            raise CaddyGenerationError("a protected Caddy generation is absent")
        unprotected = [value for value in identifiers if value not in protected]
        retained = (
            protected.union(unprotected[-keep_newest_unprotected:])
            if keep_newest_unprotected
            else protected
        )
        removed: list[str] = []
        for identifier in identifiers:
            if identifier not in retained:
                self.remove_verified(identifier)
                removed.append(identifier)
        self._require_generation_bounds(tuple(sorted(retained)))
        return tuple(removed)

    def admit_candidate(
        self,
        payload: CaddyGenerationPayload,
        retained_generation_ids: Collection[str],
    ) -> None:
        """Admit one worst-case complete candidate before any generation write."""

        self._require_open()
        retained = tuple(sorted({validate_uuid7(value) for value in retained_generation_ids}))
        if len(retained) >= MAX_CADDY_GENERATIONS:
            raise CaddyGenerationError("no Caddy generation slot remains for a candidate")
        allocations = self._measure_allocations(retained)
        filesystem = measure_filesystem_capacity_descriptor(self._root_fd)
        reservation = _candidate_reservation(payload, filesystem.fragment_size)
        admit_release_capacity(
            ReleaseCapacityUsage(allocations),
            reservation,
            filesystem,
            limits=HostCapacityLimits(
                maximum_allocated_bytes=MAX_CADDY_GENERATION_ALLOCATED_BYTES,
                maximum_unique_inodes=MAX_CADDY_GENERATION_UNIQUE_INODES,
            ),
        )

    def remove_verified(self, generation_id: str) -> None:
        """Rename one verified final generation aside, sync, and remove it safely."""

        self._require_open()
        canonical_id = validate_uuid7(generation_id)
        retired_name = f"{_RETIRED_PREFIX}{canonical_id}"
        try:
            os.stat(retired_name, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CaddyGenerationError("retired generation staging already exists")
        with self.open_verified(canonical_id) as generation:
            descriptor = generation.duplicate_directory_descriptor()
            try:
                pinned = os.fstat(descriptor)
                current = os.stat(canonical_id, dir_fd=self._root_fd, follow_symlinks=False)
                if _snapshot(pinned) != _snapshot(current):
                    raise CaddyGenerationError("generation changed before retirement")
                os.rename(
                    canonical_id,
                    retired_name,
                    src_dir_fd=self._root_fd,
                    dst_dir_fd=self._root_fd,
                )
                renamed = os.stat(retired_name, dir_fd=self._root_fd, follow_symlinks=False)
                if (pinned.st_dev, pinned.st_ino) != (renamed.st_dev, renamed.st_ino):
                    raise CaddyGenerationError("retired generation inode changed during rename")
                os.fsync(self._root_fd)
            finally:
                os.close(descriptor)
        _remove_generation_temporary(
            self._root_fd,
            retired_name,
            owner=self._owner,
            group=self._group,
            creation_group=os.getegid(),
        )

    def _measure_allocations(
        self,
        generation_ids: Collection[str],
    ) -> tuple[InodeAllocation, ...]:
        allocations: dict[tuple[int, int], int] = {}
        for generation_id in generation_ids:
            with self.open_verified(generation_id) as generation:
                descriptor = generation.duplicate_directory_descriptor()
                try:
                    metadata = [os.fstat(descriptor)]
                    with os.scandir(os.dup(descriptor)) as iterator:
                        names = sorted(entry.name for entry in iterator)
                    metadata.extend(
                        os.stat(name, dir_fd=descriptor, follow_symlinks=False) for name in names
                    )
                finally:
                    os.close(descriptor)
            for item in metadata:
                identity = (item.st_dev, item.st_ino)
                allocated_bytes = item.st_blocks * 512
                established = allocations.setdefault(identity, allocated_bytes)
                if established != allocated_bytes:
                    raise CaddyGenerationError(
                        "one generation inode has inconsistent allocation accounting"
                    )
        return tuple(
            InodeAllocation(device, inode, allocated_bytes)
            for (device, inode), allocated_bytes in sorted(allocations.items())
        )

    def _require_generation_bounds(self, generation_ids: Collection[str]) -> None:
        if len(generation_ids) > MAX_CADDY_GENERATIONS:
            raise CaddyGenerationError("generation count exceeds its maximum")
        allocations = self._measure_allocations(generation_ids)
        if sum(item.allocated_bytes for item in allocations) > MAX_CADDY_GENERATION_ALLOCATED_BYTES:
            raise CaddyGenerationError("generation allocation exceeds its byte ceiling")
        if len(allocations) > MAX_CADDY_GENERATION_UNIQUE_INODES:
            raise CaddyGenerationError("generation allocation exceeds its inode ceiling")

    def publish(  # noqa: PLR0915
        self,
        generation_id: str,
        payload: CaddyGenerationPayload,
        *,
        failure_hook: GenerationFailureHook | None = None,
        temporary_name_source: TemporaryNameSource | None = None,
    ) -> CaddyGenerationManifest:
        """Build, sync, and publish one complete generation without replacement."""

        self._require_open()
        try:
            canonical_id = validate_uuid7(generation_id)
        except ContractError as error:
            raise CaddyGenerationError("Caddy generation ID is not UUIDv7") from error
        temporary_name = (
            temporary_name_source() if temporary_name_source is not None else _temporary_name()
        )
        _validate_temporary_name(temporary_name, canonical_id)
        temporary_fd: int | None = None
        created = False
        published = False
        try:
            os.mkdir(temporary_name, mode=0o700, dir_fd=self._root_fd)
            created = True
            temporary_fd = os.open(temporary_name, _DIRECTORY_OPEN_FLAGS, dir_fd=self._root_fd)
            os.fchmod(temporary_fd, 0o700)
            os.fchown(temporary_fd, self._owner, self._group)

            files = [
                _copy_binary(
                    temporary_fd,
                    payload.binary,
                    owner=self._owner,
                    group=self._group,
                )
            ]
            _notify(failure_hook, CaddyGenerationBoundary.BINARY_SYNC)
            files.append(
                _write_payload(
                    temporary_fd,
                    CADDY_ENVIRONMENT_NAME,
                    payload.environment,
                    mode=CADDY_PRIVATE_FILE_MODE,
                    owner=self._owner,
                    group=self._group,
                )
            )
            _notify(failure_hook, CaddyGenerationBoundary.ENVIRONMENT_SYNC)
            configuration = _canonical_object(
                payload.configuration,
                maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES,
            )
            route_metadata = _canonical_object(
                payload.route_metadata,
                maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES,
            )
            files.append(
                _write_payload(
                    temporary_fd,
                    CADDY_CONFIGURATION_NAME,
                    configuration,
                    mode=CADDY_PRIVATE_FILE_MODE,
                    owner=self._owner,
                    group=self._group,
                )
            )
            _notify(failure_hook, CaddyGenerationBoundary.CONFIGURATION_SYNC)
            files.append(
                _write_payload(
                    temporary_fd,
                    CADDY_ROUTE_METADATA_NAME,
                    route_metadata,
                    mode=CADDY_PRIVATE_FILE_MODE,
                    owner=self._owner,
                    group=self._group,
                )
            )
            _notify(failure_hook, CaddyGenerationBoundary.ROUTE_METADATA_SYNC)

            routes_document = decode_json_object(
                route_metadata,
                maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES,
            )
            route_digest = _validate_route_metadata(routes_document)
            manifest = CaddyGenerationManifest(
                canonical_id,
                route_digest,
                tuple(sorted(files, key=lambda item: item.name)),
            )
            _write_manifest(
                temporary_fd,
                manifest.to_bytes(),
                owner=self._owner,
                group=self._group,
            )
            _notify(failure_hook, CaddyGenerationBoundary.MANIFEST_SYNC)

            os.fchmod(temporary_fd, CADDY_GENERATION_MODE)
            os.fsync(temporary_fd)
            _notify(failure_hook, CaddyGenerationBoundary.DIRECTORY_SYNC)
            os.close(temporary_fd)
            temporary_fd = None
            try:
                _rename_noreplace(self._root_fd, temporary_name, canonical_id)
            except FileExistsError as error:
                raise CaddyGenerationAlreadyExistsError(
                    "immutable Caddy generation already exists"
                ) from error
            published = True
            _notify(failure_hook, CaddyGenerationBoundary.RENAME)
            os.fsync(self._root_fd)
            _notify(failure_hook, CaddyGenerationBoundary.PARENT_SYNC)
            return manifest
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if created and not published:
                _remove_generation_temporary(
                    self._root_fd,
                    temporary_name,
                    owner=self._owner,
                    group=self._group,
                    creation_group=os.getegid(),
                )

    def open_verified(self, generation_id: str) -> PinnedCaddyGeneration:
        """Pin, manifest-verify, and return one complete immutable generation."""

        self._require_open()
        try:
            canonical_id = validate_uuid7(generation_id)
        except ContractError as error:
            raise CaddyGenerationError("Caddy generation ID is not UUIDv7") from error
        try:
            generation_fd = os.open(canonical_id, _DIRECTORY_OPEN_FLAGS, dir_fd=self._root_fd)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise CaddyGenerationError(
                    "Caddy generation is not a no-follow directory"
                ) from error
            raise
        payload_fds: dict[str, int] = {}
        try:
            _validate_directory_metadata(
                os.fstat(generation_fd),
                owner=self._owner,
                group=self._group,
                mode=CADDY_GENERATION_MODE,
                label="Caddy generation",
            )
            _validate_exact_inventory(generation_fd)
            manifest_bytes = _read_named_file(
                generation_fd,
                CADDY_MANIFEST_NAME,
                owner=self._owner,
                group=self._group,
                mode=CADDY_PRIVATE_FILE_MODE,
                maximum_bytes=MAX_CADDY_MANIFEST_BYTES,
            )
            manifest_document = decode_json_object(
                manifest_bytes,
                maximum_bytes=MAX_CADDY_MANIFEST_BYTES,
            )
            if (
                canonical_json_bytes(
                    manifest_document,
                    maximum_bytes=MAX_CADDY_MANIFEST_BYTES,
                )
                != manifest_bytes
            ):
                raise CaddyGenerationError("Caddy generation manifest is not canonical")
            manifest = _parse_manifest(manifest_document, expected_generation_id=canonical_id)

            limits = {
                CADDY_BINARY_NAME: MAX_CADDY_BINARY_BYTES,
                CADDY_ENVIRONMENT_NAME: MAX_CADDY_ENVIRONMENT_BYTES,
                CADDY_CONFIGURATION_NAME: MAX_CADDY_CONFIGURATION_BYTES,
                CADDY_ROUTE_METADATA_NAME: MAX_CADDY_ROUTE_METADATA_BYTES,
            }
            for item in manifest.files:
                descriptor, digest = _open_and_hash_payload(
                    generation_fd,
                    item.name,
                    owner=self._owner,
                    group=self._group,
                    mode=item.mode,
                    maximum_bytes=limits[item.name],
                    expected_size=item.size,
                )
                if digest != item.sha256:
                    os.close(descriptor)
                    raise CaddyGenerationError("Caddy generation payload digest does not match")
                payload_fds[item.name] = descriptor

            environment = _read_pinned(
                payload_fds[CADDY_ENVIRONMENT_NAME],
                MAX_CADDY_ENVIRONMENT_BYTES,
            )
            _validate_environment(environment)
            configuration = _read_pinned(
                payload_fds[CADDY_CONFIGURATION_NAME],
                MAX_CADDY_CONFIGURATION_BYTES,
            )
            _require_canonical_object(configuration, MAX_CADDY_CONFIGURATION_BYTES, "configuration")
            route_metadata = _read_pinned(
                payload_fds[CADDY_ROUTE_METADATA_NAME],
                MAX_CADDY_ROUTE_METADATA_BYTES,
            )
            routes_document = _require_canonical_object(
                route_metadata,
                MAX_CADDY_ROUTE_METADATA_BYTES,
                "route metadata",
            )
            if _validate_route_metadata(routes_document) != manifest.route_state_digest:
                raise CaddyGenerationError("route metadata and manifest state digests disagree")
            return PinnedCaddyGeneration(generation_fd, payload_fds, manifest)
        except BaseException:
            for descriptor in payload_fds.values():
                os.close(descriptor)
            os.close(generation_fd)
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("Caddy generation store is closed")


def caddy_route_state_digest(document: Mapping[str, object]) -> Digest:
    """Bind exact canonical typed route state to one generation."""

    canonical = _canonical_object(document, maximum_bytes=MAX_CADDY_ROUTE_METADATA_BYTES)
    framed = (
        CADDY_ROUTE_STATE_DIGEST_FORMAT.encode("ascii")
        + b"\0"
        + len(canonical).to_bytes(4, "big")
        + canonical
    )
    return Digest(CADDY_ROUTE_STATE_DIGEST_FORMAT, "sha256", hashlib.sha256(framed).hexdigest())


def _notify(
    hook: GenerationFailureHook | None,
    boundary: CaddyGenerationBoundary,
) -> None:
    if hook is not None:
        hook(boundary)


def _canonical_object(value: Mapping[str, object], *, maximum_bytes: int) -> bytes:
    if not isinstance(value, Mapping):
        raise TypeError("Caddy generation JSON inputs must be mappings")
    return canonical_json_bytes(dict(value), maximum_bytes=maximum_bytes)


def _validate_route_metadata(document: dict[str, object]) -> Digest:
    if set(document) != {"routeState", "routeStateDigest", "schema"}:
        raise CaddyGenerationError("route metadata has unexpected members")
    if document["schema"] != CADDY_ROUTE_METADATA_SCHEMA:
        raise CaddyGenerationError("route metadata schema is not recognized")
    route_state = document["routeState"]
    if type(route_state) is not dict:
        raise CaddyGenerationError("route metadata state must be an object")
    expected = caddy_route_state_digest(route_state)
    actual = _parse_digest(document["routeStateDigest"])
    if actual != expected:
        raise CaddyGenerationError("route metadata state digest does not match")
    return actual


def _parse_digest(value: object) -> Digest:
    if type(value) is not dict or set(value) != {"algorithm", "format", "value"}:
        raise CaddyGenerationError("digest representation is invalid")
    try:
        return Digest(value["format"], value["algorithm"], value["value"])
    except (ContractError, TypeError) as error:
        raise CaddyGenerationError("digest representation is invalid") from error


def _validate_environment(data: bytes) -> None:
    if len(data) > MAX_CADDY_ENVIRONMENT_BYTES:
        raise CaddyGenerationError("Caddy environment exceeds its byte limit")
    if not data or not data.endswith(b"\n") or b"\r" in data or b"\0" in data:
        raise CaddyGenerationError("Caddy environment is not normalized LF-delimited data")
    names: set[str] = set()
    for line in data.removesuffix(b"\n").split(b"\n"):
        if not line or b"=" not in line:
            raise CaddyGenerationError("Caddy environment contains a malformed assignment")
        raw_name, value = line.split(b"=", 1)
        try:
            name = raw_name.decode("ascii", errors="strict")
            value.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise CaddyGenerationError("Caddy environment contains invalid text") from error
        if _ENVIRONMENT_NAME_PATTERN.fullmatch(name) is None or name in names:
            raise CaddyGenerationError("Caddy environment contains an invalid or duplicate name")
        names.add(name)


def _temporary_name() -> str:
    return f"{_TEMPORARY_PREFIX}{secrets.token_hex(16)}"


def _validate_temporary_name(name: str, generation_id: str) -> None:
    if _TEMPORARY_PATTERN.fullmatch(name) is None or name == generation_id:
        raise CaddyGenerationError("generation temporary name has an unsafe shape")


def _open_directory_path(path: Path, *, label: str) -> int:
    try:
        return os.open(path, _DIRECTORY_OPEN_FLAGS)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise CaddyGenerationError(f"{label} is not a no-follow directory") from error
        raise


def _reopen_directory(directory_fd: int) -> int:
    reopened = os.open(".", _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
    if (
        os.fstat(reopened).st_dev,
        os.fstat(reopened).st_ino,
    ) != (
        os.fstat(directory_fd).st_dev,
        os.fstat(directory_fd).st_ino,
    ):
        os.close(reopened)
        raise CaddyGenerationError("directory changed while reopening its descriptor")
    return reopened


def _validate_directory_metadata(
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
        raise CaddyGenerationError(f"{label} metadata is unsafe")


def _copy_binary(
    directory_fd: int,
    source: CaddyBinarySource,
    *,
    owner: int,
    group: int,
) -> CaddyGenerationFile:
    try:
        source_fd = os.open(source.path, _FILE_READ_FLAGS)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENXIO}:
            raise CaddyGenerationError(
                "staged Caddy binary is not a no-follow regular file"
            ) from error
        raise
    destination_fd: int | None = None
    try:
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != source.owner
            or before.st_gid != source.group
            or stat.S_IMODE(before.st_mode) != source.mode
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_CADDY_BINARY_BYTES
        ):
            raise CaddyGenerationError("staged Caddy binary metadata is unsafe")
        destination_fd = _create_payload_file(
            directory_fd,
            CADDY_BINARY_NAME,
            mode=CADDY_BINARY_MODE,
            owner=owner,
            group=group,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_fd, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_CADDY_BINARY_BYTES:
                raise CaddyGenerationError("staged Caddy binary exceeds its byte limit")
            _write_all(destination_fd, chunk)
            digest.update(chunk)
        after = os.fstat(source_fd)
        if _snapshot(before) != _snapshot(after) or copied != before.st_size:
            raise CaddyGenerationError("staged Caddy binary changed while copying")
        os.fsync(destination_fd)
        return CaddyGenerationFile(
            CADDY_BINARY_NAME,
            CADDY_BINARY_MODE,
            copied,
            digest.hexdigest(),
        )
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def _write_payload(  # noqa: PLR0913
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    mode: int,
    owner: int,
    group: int,
) -> CaddyGenerationFile:
    descriptor = _create_payload_file(
        directory_fd,
        name,
        mode=mode,
        owner=owner,
        group=group,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return CaddyGenerationFile(name, mode, len(data), hashlib.sha256(data).hexdigest())


def _write_manifest(
    directory_fd: int,
    data: bytes,
    *,
    owner: int,
    group: int,
) -> None:
    descriptor = _create_payload_file(
        directory_fd,
        CADDY_MANIFEST_NAME,
        mode=CADDY_PRIVATE_FILE_MODE,
        owner=owner,
        group=group,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_payload_file(
    directory_fd: int,
    name: str,
    *,
    mode: int,
    owner: int,
    group: int,
) -> int:
    descriptor = os.open(name, _FILE_CREATE_FLAGS, mode, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, owner, group)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError(errno.EIO, "Caddy generation write made no progress")
        remaining = remaining[written:]


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:  # pragma: no cover - production is Linux/glibc
        raise RuntimeError("renameat2 is required for generation publication") from error
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
        raise OSError(error_number, os.strerror(error_number), destination)


def _is_reserved_generation_temporary(name: str) -> bool:
    return (
        _TEMPORARY_PATTERN.fullmatch(name) is not None
        or _RETIRED_PATTERN.fullmatch(name) is not None
    )


def _remove_generation_temporary(
    root_fd: int,
    name: str,
    *,
    owner: int,
    group: int,
    creation_group: int,
) -> None:
    if not _is_reserved_generation_temporary(name):
        raise CaddyGenerationError("refusing to remove an unrecognized generation temporary")
    try:
        directory_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        return
    try:
        directory_metadata = os.fstat(directory_fd)
        directory_mode = stat.S_IMODE(directory_metadata.st_mode)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != owner
            or directory_metadata.st_gid not in {group, creation_group}
            or (directory_mode != CADDY_GENERATION_MODE and directory_mode & ~0o700)
        ):
            raise CaddyGenerationError("generation temporary directory metadata is unsafe")
        with os.scandir(os.dup(directory_fd)) as iterator:
            names = [entry.name for entry in iterator]
        if not set(names).issubset(_INVENTORY_NAMES):
            raise CaddyGenerationError("generation temporary contains an unexpected entry")
        for entry_name in names:
            metadata = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
            expected_mode = (
                CADDY_BINARY_MODE if entry_name == CADDY_BINARY_NAME else CADDY_PRIVATE_FILE_MODE
            )
            actual_mode = stat.S_IMODE(metadata.st_mode)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != owner
                or metadata.st_gid not in {group, creation_group}
                or actual_mode & ~expected_mode
                or metadata.st_nlink != 1
            ):
                raise CaddyGenerationError("generation temporary contains an unsafe entry")
        os.fchmod(directory_fd, 0o700)
        for entry_name in names:
            os.unlink(entry_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=root_fd)
    os.fsync(root_fd)


def _candidate_reservation(
    payload: CaddyGenerationPayload,
    fragment_size: int,
) -> CapacityReservation:
    if fragment_size <= 0:
        raise CaddyGenerationError("generation filesystem fragment size is invalid")
    binary_size = _binary_source_size(payload.binary)
    payload_sizes = (
        binary_size,
        len(payload.environment),
        len(canonical_json_bytes(payload.configuration)),
        len(canonical_json_bytes(payload.route_metadata)),
        MAX_CADDY_MANIFEST_BYTES,
    )

    def allocated(size: int) -> int:
        return ((size + fragment_size - 1) // fragment_size) * fragment_size

    # Charge the generation directory and worst-case root namespace growth for
    # temporary creation plus same-directory publication rename.
    return CapacityReservation(
        allocated_bytes=(3 * fragment_size) + sum(allocated(size) for size in payload_sizes),
        unique_inodes=len(payload_sizes) + 1,
    )


def _binary_source_size(source: CaddyBinarySource) -> int:
    try:
        descriptor = os.open(source.path, _FILE_READ_FLAGS)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENXIO}:
            raise CaddyGenerationError(
                "staged Caddy binary is not a no-follow regular file"
            ) from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != source.owner
            or metadata.st_gid != source.group
            or stat.S_IMODE(metadata.st_mode) != source.mode
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_CADDY_BINARY_BYTES
        ):
            raise CaddyGenerationError("staged Caddy binary metadata is unsafe")
        return metadata.st_size
    finally:
        os.close(descriptor)


def _validate_exact_inventory(directory_fd: int) -> None:
    scan_fd = _reopen_directory(directory_fd)
    try:
        with os.scandir(scan_fd) as iterator:
            names = {entry.name for entry in iterator}
    finally:
        os.close(scan_fd)
    if names != _INVENTORY_NAMES:
        raise CaddyGenerationError("Caddy generation inventory is not exact")


def _read_named_file(  # noqa: PLR0913
    directory_fd: int,
    name: str,
    *,
    owner: int,
    group: int,
    mode: int,
    maximum_bytes: int,
) -> bytes:
    descriptor, _digest = _open_and_hash_payload(
        directory_fd,
        name,
        owner=owner,
        group=group,
        mode=mode,
        maximum_bytes=maximum_bytes,
        expected_size=None,
    )
    try:
        return _read_pinned(descriptor, maximum_bytes)
    finally:
        os.close(descriptor)


def _open_and_hash_payload(  # noqa: PLR0913
    directory_fd: int,
    name: str,
    *,
    owner: int,
    group: int,
    mode: int,
    maximum_bytes: int,
    expected_size: int | None,
) -> tuple[int, str]:
    try:
        descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENXIO}:
            raise CaddyGenerationError(
                "generation payload is not a no-follow regular file"
            ) from error
        raise
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_gid != group
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
            or (expected_size is not None and before.st_size != expected_size)
        ):
            raise CaddyGenerationError("generation payload metadata is unsafe")
        digest = hashlib.sha256()
        read = 0
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            read += len(chunk)
            if read > maximum_bytes:
                raise CaddyGenerationError("generation payload exceeds its byte limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _snapshot(before) != _snapshot(after) or read != before.st_size:
            raise CaddyGenerationError("generation payload changed while verifying")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, digest.hexdigest()
    except BaseException:
        os.close(descriptor)
        raise


def _read_pinned(descriptor: int, maximum_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, _COPY_CHUNK_BYTES))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > maximum_bytes:
        raise CaddyGenerationError("generation payload exceeds its read limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return data


def _require_canonical_object(data: bytes, maximum_bytes: int, label: str) -> dict[str, object]:
    document = decode_json_object(data, maximum_bytes=maximum_bytes)
    if canonical_json_bytes(document, maximum_bytes=maximum_bytes) != data:
        raise CaddyGenerationError(f"Caddy {label} is not canonical")
    return document


def _parse_manifest(
    document: dict[str, object],
    *,
    expected_generation_id: str,
) -> CaddyGenerationManifest:
    if set(document) != {"files", "generationId", "routeStateDigest", "schema"}:
        raise CaddyGenerationError("Caddy generation manifest has unexpected members")
    if document["schema"] != CADDY_GENERATION_SCHEMA:
        raise CaddyGenerationError("Caddy generation manifest schema is not recognized")
    if document["generationId"] != expected_generation_id:
        raise CaddyGenerationError("Caddy generation manifest ID does not match its directory")
    raw_files = document["files"]
    if type(raw_files) is not list:
        raise CaddyGenerationError("Caddy generation manifest files are invalid")
    files: list[CaddyGenerationFile] = []
    for raw_file in raw_files:
        if type(raw_file) is not dict or set(raw_file) != {"mode", "name", "sha256", "size"}:
            raise CaddyGenerationError("Caddy generation manifest file entry is invalid")
        raw_mode = raw_file["mode"]
        if type(raw_mode) is not str or re.fullmatch(r"0[0-7]{3}", raw_mode) is None:
            raise CaddyGenerationError("Caddy generation manifest mode is invalid")
        files.append(
            CaddyGenerationFile(
                raw_file["name"],
                int(raw_mode, 8),
                raw_file["size"],
                raw_file["sha256"],
            )
        )
    return CaddyGenerationManifest(
        expected_generation_id,
        _parse_digest(document["routeStateDigest"]),
        tuple(files),
    )


def _snapshot(metadata: os.stat_result) -> tuple[int, ...]:
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
