"""Bounded structural validation for hostile deployment ZIP snapshots."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import unicodedata
import zlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityProjection,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)

MEBIBYTE: Final = 1024 * 1024
_MAXIMUM_ARCHIVE_BYTES: Final = 100 * MEBIBYTE
_MAXIMUM_CENTRAL_DIRECTORY_BYTES: Final = 8 * MEBIBYTE
_MAXIMUM_ENTRIES: Final = 5_000
_MAXIMUM_EXPANDED_BYTES: Final = 100 * MEBIBYTE
_MAXIMUM_FILE_BYTES: Final = 25 * MEBIBYTE
_MAXIMUM_EXPANSION_RATIO: Final = 100
_MAXIMUM_PATH_BYTES: Final = 1_024
_MAXIMUM_COMPONENT_BYTES: Final = 255
_MAXIMUM_PATH_DEPTH: Final = 32
_MAXIMUM_EXTRA_BYTES: Final = 1_024
_EOCD = struct.Struct("<I4H2IH")
_CENTRAL = struct.Struct("<I6H3I5H2I")
_LOCAL = struct.Struct("<I5H3I2H")
_EXTRA_HEADER = struct.Struct("<HH")
_EOCD_SIGNATURE: Final = 0x06054B50
_CENTRAL_SIGNATURE: Final = 0x02014B50
_LOCAL_SIGNATURE: Final = 0x04034B50
_UTF8_FLAG: Final = 0x0800
_DEFLATE_OPTION_FLAGS: Final = 0x0006
_STORED_METHOD: Final = 0
_DEFLATE_METHOD: Final = 8
_EXTENDED_TIMESTAMP_EXTRA: Final = 0x5455
_NTFS_TIMESTAMP_EXTRA: Final = 0x000A
_ZIP64_SENTINEL_16: Final = 0xFFFF
_ZIP64_SENTINEL_32: Final = 0xFFFFFFFF
_HASH_CHUNK_BYTES: Final = MEBIBYTE
_MAXIMUM_DECODER_VERSION: Final = 20
_DRIVE_PREFIX_BYTES: Final = 2
_UNIX_MADE_BY_HOST: Final = 3
_NTFS_TIMESTAMP_VALUE_BYTES: Final = 32
_SNAPSHOT_OPEN_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY_OPEN_FLAGS: Final = (
    os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
_FILE_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_EXTRACTION_CHUNK_BYTES: Final = 64 * 1024
_BLOCK_UNIT_BYTES: Final = 512
_STAGING_PARENT_MODE: Final = 0o700
_DIRECTORY_MODE: Final = 0o755
_FILE_MODE: Final = 0o644


class ZipStructureError(RuntimeError):
    """A ZIP snapshot violates the bounded structural contract."""


class ZipExtractionError(ZipStructureError):
    """A structurally admitted ZIP could not produce one safe release tree."""


@dataclass(frozen=True, slots=True)
class ZipLimits:
    """Tightenable deployment-ZIP limits committed by ADR 0019."""

    maximum_archive_bytes: int = _MAXIMUM_ARCHIVE_BYTES
    maximum_central_directory_bytes: int = _MAXIMUM_CENTRAL_DIRECTORY_BYTES
    maximum_entries: int = _MAXIMUM_ENTRIES
    maximum_expanded_bytes: int = _MAXIMUM_EXPANDED_BYTES
    maximum_file_bytes: int = _MAXIMUM_FILE_BYTES
    maximum_expansion_ratio: int = _MAXIMUM_EXPANSION_RATIO
    maximum_path_bytes: int = _MAXIMUM_PATH_BYTES
    maximum_component_bytes: int = _MAXIMUM_COMPONENT_BYTES
    maximum_path_depth: int = _MAXIMUM_PATH_DEPTH
    maximum_extra_bytes: int = _MAXIMUM_EXTRA_BYTES

    def __post_init__(self) -> None:
        values = (
            self.maximum_archive_bytes,
            self.maximum_central_directory_bytes,
            self.maximum_entries,
            self.maximum_expanded_bytes,
            self.maximum_file_bytes,
            self.maximum_expansion_ratio,
            self.maximum_path_bytes,
            self.maximum_component_bytes,
            self.maximum_path_depth,
            self.maximum_extra_bytes,
        )
        committed = (
            _MAXIMUM_ARCHIVE_BYTES,
            _MAXIMUM_CENTRAL_DIRECTORY_BYTES,
            _MAXIMUM_ENTRIES,
            _MAXIMUM_EXPANDED_BYTES,
            _MAXIMUM_FILE_BYTES,
            _MAXIMUM_EXPANSION_RATIO,
            _MAXIMUM_PATH_BYTES,
            _MAXIMUM_COMPONENT_BYTES,
            _MAXIMUM_PATH_DEPTH,
            _MAXIMUM_EXTRA_BYTES,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("ZIP limits must be nonnegative integers")
        if any(value > boundary for value, boundary in zip(values, committed, strict=True)):
            raise ValueError("ZIP limits cannot weaken the committed M3 boundaries")


class ZipEntryType(StrEnum):
    """The only materialized inode types admitted from a deployment ZIP."""

    DIRECTORY = "directory"
    REGULAR_FILE = "regular-file"


@dataclass(frozen=True, slots=True)
class ZipMember:
    """One explicit central record after local-header agreement."""

    source_name: str
    normalized_path: str
    entry_type: ZipEntryType
    compression_method: int
    crc32: int
    compressed_bytes: int
    expanded_bytes: int
    local_header_offset: int
    data_offset: int


@dataclass(frozen=True, slots=True)
class ZipStructure:
    """A completely bounded deployment ZIP preflight result."""

    archive_bytes: int
    artifact_sha256: str
    central_directory_offset: int
    central_directory_bytes: int
    members: tuple[ZipMember, ...]
    materialized_paths: tuple[str, ...]
    expanded_regular_file_bytes: int

    @property
    def materialized_entry_count(self) -> int:
        return len(self.materialized_paths)


@dataclass(frozen=True, slots=True)
class ZipExtraction:
    """One complete but still unpublished normalized staging tree."""

    structure: ZipStructure
    staging_name: str
    capacity_projection: CapacityProjection
    allocated_bytes: int
    unique_inodes: int


@dataclass(frozen=True, slots=True)
class _CentralEntry:
    made_by: int
    version_needed: int
    flags: int
    method: int
    modified_time: int
    modified_date: int
    crc32: int
    compressed_bytes: int
    expanded_bytes: int
    external_attributes: int
    local_header_offset: int
    raw_name: bytes
    source_name: str
    normalized_path: str
    entry_type: ZipEntryType


@dataclass(frozen=True, slots=True)
class _PathClaim:
    source_path: str
    normalized_path: str
    entry_type: ZipEntryType
    explicit: bool


class _Source(Protocol):
    size: int

    def read(self, offset: int, length: int) -> bytes: ...


class _DescriptorSource:
    def __init__(self, descriptor: int, size: int) -> None:
        self._descriptor = descriptor
        self.size = size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ZipStructureError("ZIP region lies outside the snapshot")
        chunks: list[bytes] = []
        remaining = length
        position = offset
        while remaining:
            chunk = os.pread(self._descriptor, remaining, position)
            if not chunk:
                raise ZipStructureError("ZIP snapshot ended inside a declared region")
            chunks.append(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


DEFAULT_ZIP_LIMITS: Final = ZipLimits()


def inspect_deployment_zip(
    path: Path,
    *,
    expected_owner: int,
    expected_mode: int = 0o600,
    limits: ZipLimits = DEFAULT_ZIP_LIMITS,
) -> ZipStructure:
    """Inspect one stable, root-owned ZIP snapshot without invoking a decoder."""

    descriptor: int | None = None
    try:
        descriptor = os.open(path, _SNAPSHOT_OPEN_FLAGS)
        before = _validate_snapshot(
            os.fstat(descriptor),
            expected_owner=expected_owner,
            expected_mode=expected_mode,
            limits=limits,
        )
        current = path.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ZipStructureError("ZIP snapshot inode changed while it was opened")
        source = _DescriptorSource(descriptor, before.st_size)
        structure = _inspect(source, limits=limits)
        digest = _sha256(descriptor, before.st_size)
        after = _validate_snapshot(
            os.fstat(descriptor),
            expected_owner=expected_owner,
            expected_mode=expected_mode,
            limits=limits,
        )
        current = path.stat(follow_symlinks=False)
        if _metadata_generation(before) != _metadata_generation(after) or _metadata_generation(
            after
        ) != _metadata_generation(current):
            raise ZipStructureError("ZIP snapshot changed during structural inspection")
        return ZipStructure(
            archive_bytes=structure.archive_bytes,
            artifact_sha256=digest,
            central_directory_offset=structure.central_directory_offset,
            central_directory_bytes=structure.central_directory_bytes,
            members=structure.members,
            materialized_paths=structure.materialized_paths,
            expanded_regular_file_bytes=structure.expanded_regular_file_bytes,
        )
    except OSError as error:
        raise ZipStructureError("ZIP snapshot cannot be opened safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def extract_deployment_zip(  # noqa: PLR0913,PLR0915 - keep trust boundaries explicit
    path: Path,
    *,
    staging_parent: Path,
    staging_name: str,
    expected_owner: int,
    retained_usage: ReleaseCapacityUsage,
    expected_mode: int = 0o600,
    limits: ZipLimits = DEFAULT_ZIP_LIMITS,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> ZipExtraction:
    """Structurally admit and stream one ZIP into a new descriptor-relative tree."""

    _validate_staging_name(staging_name)
    source_fd: int | None = None
    parent_fd: int | None = None
    created = False
    try:
        source_fd = os.open(path, _SNAPSHOT_OPEN_FLAGS)
        before = _validate_snapshot(
            os.fstat(source_fd),
            expected_owner=expected_owner,
            expected_mode=expected_mode,
            limits=limits,
        )
        _validate_open_identity(path, before, "ZIP snapshot inode changed while it was opened")
        source = _DescriptorSource(source_fd, before.st_size)
        inspected = _inspect(source, limits=limits)
        structure = ZipStructure(
            archive_bytes=inspected.archive_bytes,
            artifact_sha256=_sha256(source_fd, before.st_size),
            central_directory_offset=inspected.central_directory_offset,
            central_directory_bytes=inspected.central_directory_bytes,
            members=inspected.members,
            materialized_paths=inspected.materialized_paths,
            expanded_regular_file_bytes=inspected.expanded_regular_file_bytes,
        )

        parent_fd = os.open(staging_parent, _DIRECTORY_OPEN_FLAGS)
        parent_metadata = _validate_staging_parent(
            os.fstat(parent_fd),
            expected_owner=expected_owner,
        )
        _validate_open_identity(
            staging_parent,
            parent_metadata,
            "ZIP staging parent changed while it was opened",
        )
        if parent_metadata.st_dev != before.st_dev:
            raise ZipExtractionError("ZIP artifact and staging tree span filesystems")
        reservation = _extraction_reservation(structure, parent_fd)
        projection = admit_release_capacity(
            retained_usage,
            reservation,
            measure_filesystem_capacity_descriptor(parent_fd),
            limits=capacity_limits,
        )

        os.mkdir(staging_name, mode=_DIRECTORY_MODE, dir_fd=parent_fd)
        created = True
        root_fd = os.open(staging_name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
        try:
            os.fchmod(root_fd, _DIRECTORY_MODE)
            _extract_members(
                source,
                structure,
                root_fd=root_fd,
                expected_owner=expected_owner,
                limits=limits,
            )
            allocated_bytes, unique_inodes = _validate_extracted_tree(
                root_fd,
                structure,
                expected_owner=expected_owner,
                reservation=reservation,
            )
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        os.fsync(parent_fd)

        after = _validate_snapshot(
            os.fstat(source_fd),
            expected_owner=expected_owner,
            expected_mode=expected_mode,
            limits=limits,
        )
        _validate_open_identity(
            path,
            after,
            "ZIP snapshot changed during extraction",
        )
        if _metadata_generation(before) != _metadata_generation(after):
            raise ZipExtractionError("ZIP snapshot changed during extraction")
        _validate_remaining_capacity(parent_fd, projection)
        return ZipExtraction(
            structure=structure,
            staging_name=staging_name,
            capacity_projection=projection,
            allocated_bytes=allocated_bytes,
            unique_inodes=unique_inodes,
        )
    except OSError as error:
        if created and parent_fd is not None:
            _remove_extraction(parent_fd, staging_name)
        raise ZipExtractionError("ZIP extraction could not complete safely") from error
    except BaseException:
        if created and parent_fd is not None:
            _remove_extraction(parent_fd, staging_name)
        raise
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if source_fd is not None:
            os.close(source_fd)


def _inspect(source: _Source, *, limits: ZipLimits) -> ZipStructure:
    if source.size < _EOCD.size or source.size > limits.maximum_archive_bytes:
        raise ZipStructureError("ZIP snapshot crosses its compressed-byte boundary")
    eocd_offset = source.size - _EOCD.size
    eocd = _EOCD.unpack(source.read(eocd_offset, _EOCD.size))
    (
        signature,
        disk_number,
        central_disk,
        records_on_disk,
        record_count,
        central_bytes,
        central_offset,
        comment_bytes,
    ) = eocd
    if signature != _EOCD_SIGNATURE:
        raise ZipStructureError("ZIP has no end record at its physical end")
    if disk_number or central_disk or records_on_disk != record_count:
        raise ZipStructureError("multi-disk ZIPs are not accepted")
    if comment_bytes:
        raise ZipStructureError("ZIP archive comments are not accepted")
    if record_count in {0, _ZIP64_SENTINEL_16}:
        raise ZipStructureError("ZIP entry count is empty or requires ZIP64")
    if record_count > limits.maximum_entries:
        raise ZipStructureError("ZIP central record count crosses its boundary")
    if central_bytes in {_ZIP64_SENTINEL_32} or central_offset in {_ZIP64_SENTINEL_32}:
        raise ZipStructureError("ZIP64 metadata is not accepted")
    if central_bytes > limits.maximum_central_directory_bytes:
        raise ZipStructureError("ZIP central directory crosses its byte boundary")
    if central_offset + central_bytes != eocd_offset:
        raise ZipStructureError("ZIP central directory is not adjacent to its end record")

    central_data = source.read(central_offset, central_bytes)
    entries = _parse_central(
        central_data,
        expected_records=record_count,
        limits=limits,
    )
    materialized = _materialized_paths(entries, limits=limits)
    members = _validate_local_regions(
        source,
        entries,
        central_offset=central_offset,
        limits=limits,
    )
    expanded = sum(
        member.expanded_bytes
        for member in members
        if member.entry_type is ZipEntryType.REGULAR_FILE
    )
    if expanded > limits.maximum_expanded_bytes:
        raise ZipStructureError("ZIP expanded bytes cross the tenant-tree boundary")
    return ZipStructure(
        archive_bytes=source.size,
        artifact_sha256="",
        central_directory_offset=central_offset,
        central_directory_bytes=central_bytes,
        members=members,
        materialized_paths=materialized,
        expanded_regular_file_bytes=expanded,
    )


def _parse_central(
    data: bytes,
    *,
    expected_records: int,
    limits: ZipLimits,
) -> tuple[_CentralEntry, ...]:
    entries: list[_CentralEntry] = []
    cursor = 0
    for _record_number in range(expected_records):
        fixed_end = cursor + _CENTRAL.size
        if fixed_end > len(data):
            raise ZipStructureError("ZIP central directory ends inside a fixed record")
        fields = _CENTRAL.unpack(data[cursor:fixed_end])
        if fields[0] != _CENTRAL_SIGNATURE:
            raise ZipStructureError("ZIP central record has an invalid signature")
        name_bytes, extra_bytes, comment_bytes = fields[10:13]
        variable_end = fixed_end + name_bytes + extra_bytes + comment_bytes
        if variable_end > len(data):
            raise ZipStructureError("ZIP central variable fields cross their region")
        if extra_bytes > limits.maximum_extra_bytes:
            raise ZipStructureError("ZIP central extra field crosses its byte boundary")
        if comment_bytes:
            raise ZipStructureError("ZIP entry comments are not accepted")
        if fields[13]:
            raise ZipStructureError("ZIP central record starts on another disk")
        raw_name = data[fixed_end : fixed_end + name_bytes]
        extra = data[fixed_end + name_bytes : fixed_end + name_bytes + extra_bytes]
        _validate_extra(extra, central=True)
        entries.append(
            _central_entry(
                fields,
                raw_name=raw_name,
                limits=limits,
            )
        )
        cursor = variable_end
    if cursor != len(data):
        raise ZipStructureError("ZIP central record count does not consume its directory")
    return tuple(entries)


def _central_entry(
    fields: tuple[int, ...],
    *,
    raw_name: bytes,
    limits: ZipLimits,
) -> _CentralEntry:
    (
        _signature,
        made_by,
        version_needed,
        flags,
        method,
        modified_time,
        modified_date,
        crc32,
        compressed_bytes,
        expanded_bytes,
        _name_bytes,
        _extra_bytes,
        _comment_bytes,
        _disk_number,
        _internal_attributes,
        external_attributes,
        local_header_offset,
    ) = fields
    if version_needed > _MAXIMUM_DECODER_VERSION:
        raise ZipStructureError("ZIP record requires an unsupported decoder version")
    _validate_flags_and_method(flags, method)
    if _ZIP64_SENTINEL_32 in {compressed_bytes, expanded_bytes}:
        raise ZipStructureError("ZIP64 entry sizes are not accepted")
    source_name, normalized_path, marker_is_directory = _decode_name(
        raw_name,
        flags=flags,
        limits=limits,
    )
    entry_type = _entry_type(
        made_by=made_by,
        external_attributes=external_attributes,
        marker_is_directory=marker_is_directory,
    )
    if entry_type is ZipEntryType.DIRECTORY:
        if method != _STORED_METHOD or compressed_bytes or expanded_bytes or crc32:
            raise ZipStructureError("ZIP directory record carries file data")
    else:
        if expanded_bytes > limits.maximum_file_bytes:
            raise ZipStructureError("ZIP regular file crosses its expanded-byte boundary")
        if method == _STORED_METHOD and compressed_bytes != expanded_bytes:
            raise ZipStructureError("stored ZIP entry has unequal compressed and expanded sizes")
        if expanded_bytes and (
            compressed_bytes == 0
            or expanded_bytes > compressed_bytes * limits.maximum_expansion_ratio
        ):
            raise ZipStructureError("ZIP entry crosses its declared expansion-ratio boundary")
    return _CentralEntry(
        made_by=made_by,
        version_needed=version_needed,
        flags=flags,
        method=method,
        modified_time=modified_time,
        modified_date=modified_date,
        crc32=crc32,
        compressed_bytes=compressed_bytes,
        expanded_bytes=expanded_bytes,
        external_attributes=external_attributes,
        local_header_offset=local_header_offset,
        raw_name=raw_name,
        source_name=source_name,
        normalized_path=normalized_path,
        entry_type=entry_type,
    )


def _validate_flags_and_method(flags: int, method: int) -> None:
    if method == _STORED_METHOD:
        allowed = _UTF8_FLAG
    elif method == _DEFLATE_METHOD:
        allowed = _UTF8_FLAG | _DEFLATE_OPTION_FLAGS
    else:
        raise ZipStructureError("ZIP compression method is not stored or Deflate")
    if flags & ~allowed:
        raise ZipStructureError("ZIP general-purpose flags are not accepted")


def _decode_name(  # noqa: PLR0912 - keep hostile-path rejection branches explicit
    raw_name: bytes,
    *,
    flags: int,
    limits: ZipLimits,
) -> tuple[str, str, bool]:
    if not raw_name:
        raise ZipStructureError("ZIP member name is empty")
    try:
        if flags & _UTF8_FLAG:
            decoded = raw_name.decode("utf-8", errors="strict")
        else:
            decoded = raw_name.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ZipStructureError("ZIP member name does not satisfy its encoding flag") from error
    if "\\" in decoded:
        raise ZipStructureError("ZIP member name has ambiguous separators")
    marker_is_directory = decoded.endswith("/")
    source_path = decoded[:-1] if marker_is_directory else decoded
    if (
        not source_path
        or source_path.startswith("/")
        or source_path.endswith("/")
        or "//" in source_path
    ):
        raise ZipStructureError("ZIP member path has an absolute or empty component")
    components = source_path.split("/")
    if len(components) > limits.maximum_path_depth:
        raise ZipStructureError("ZIP member path crosses its depth boundary")
    if (
        len(components[0]) >= _DRIVE_PREFIX_BYTES
        and components[0][0].isalpha()
        and components[0][1] == ":"
    ):
        raise ZipStructureError("ZIP member path has a drive-qualified root")
    normalized_components: list[str] = []
    for component in components:
        if component in {".", ".."}:
            raise ZipStructureError("ZIP member path traverses a relative component")
        if any(unicodedata.category(character) == "Cc" for character in component):
            raise ZipStructureError("ZIP member path contains a control character")
        normalized = unicodedata.normalize("NFC", component)
        if not normalized or len(normalized.encode("utf-8")) > limits.maximum_component_bytes:
            raise ZipStructureError("ZIP member component crosses its byte boundary")
        normalized_components.append(normalized)
    normalized_path = "/".join(normalized_components)
    if len(normalized_path.encode("utf-8")) > limits.maximum_path_bytes:
        raise ZipStructureError("ZIP member path crosses its byte boundary")
    if normalized_components[0].casefold() == "cdn-cgi":
        raise ZipStructureError("ZIP member uses Cloudflare's reserved first component")
    return source_path, normalized_path, marker_is_directory


def _entry_type(
    *,
    made_by: int,
    external_attributes: int,
    marker_is_directory: bool,
) -> ZipEntryType:
    host = made_by >> 8
    unix_mode = (external_attributes >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    dos_volume_label = bool(external_attributes & 0x08)
    dos_directory = bool(external_attributes & 0x10)
    if dos_volume_label:
        raise ZipStructureError("ZIP entry has a DOS volume-label inode type")
    if host == _UNIX_MADE_BY_HOST and file_type:
        if stat.S_ISDIR(unix_mode):
            attribute_type = ZipEntryType.DIRECTORY
        elif stat.S_ISREG(unix_mode):
            attribute_type = ZipEntryType.REGULAR_FILE
        else:
            raise ZipStructureError("ZIP entry has a link or special Unix inode type")
        if dos_directory and attribute_type is not ZipEntryType.DIRECTORY:
            raise ZipStructureError("ZIP DOS and Unix inode types disagree")
        if (attribute_type is ZipEntryType.DIRECTORY) != marker_is_directory:
            raise ZipStructureError("ZIP Unix inode type disagrees with its name marker")
        return attribute_type
    if dos_directory and not marker_is_directory:
        raise ZipStructureError("ZIP DOS directory attribute disagrees with its name marker")
    return ZipEntryType.DIRECTORY if marker_is_directory else ZipEntryType.REGULAR_FILE


def _materialized_paths(
    entries: tuple[_CentralEntry, ...],
    *,
    limits: ZipLimits,
) -> tuple[str, ...]:
    claims: dict[str, list[_PathClaim]] = {}
    casefolded: dict[str, _PathClaim] = {}

    def add_claim(claim: _PathClaim) -> None:
        established = claims.setdefault(claim.normalized_path, [])
        if any(item.source_path != claim.source_path for item in established):
            raise ZipStructureError("ZIP member paths collide after NFC normalization")
        folded = unicodedata.normalize("NFC", claim.normalized_path.casefold())
        established_folded = casefolded.get(folded)
        if established_folded is not None and (
            established_folded.normalized_path != claim.normalized_path
            or established_folded.source_path != claim.source_path
        ):
            raise ZipStructureError("ZIP member paths have a case-folding collision")
        if any(item.entry_type is not claim.entry_type for item in established):
            raise ZipStructureError("ZIP member path is both a file and a directory")
        if not claim.explicit and established:
            return
        if claim.explicit and any(item.explicit for item in established):
            raise ZipStructureError("ZIP contains a duplicate explicit member")
        established.append(claim)
        casefolded.setdefault(folded, claim)
        if len(claims) > limits.maximum_entries:
            raise ZipStructureError("ZIP materialized tree crosses its entry boundary")

    for entry in entries:
        source_components = entry.source_name.split("/")
        normalized_components = entry.normalized_path.split("/")
        for depth in range(1, len(source_components)):
            add_claim(
                _PathClaim(
                    source_path="/".join(source_components[:depth]),
                    normalized_path="/".join(normalized_components[:depth]),
                    entry_type=ZipEntryType.DIRECTORY,
                    explicit=False,
                )
            )
        add_claim(
            _PathClaim(
                source_path=entry.source_name,
                normalized_path=entry.normalized_path,
                entry_type=entry.entry_type,
                explicit=True,
            )
        )
    index_claims = claims.get("index.html", [])
    if not any(
        claim.explicit and claim.entry_type is ZipEntryType.REGULAR_FILE for claim in index_claims
    ):
        raise ZipStructureError("deployment ZIP has no root-level index.html regular file")
    return tuple(sorted(claims, key=lambda path: path.encode("utf-8")))


def _validate_local_regions(
    source: _Source,
    entries: tuple[_CentralEntry, ...],
    *,
    central_offset: int,
    limits: ZipLimits,
) -> tuple[ZipMember, ...]:
    members: list[ZipMember] = []
    regions: list[tuple[int, int]] = []
    local_offsets = [entry.local_header_offset for entry in entries]
    if len(set(local_offsets)) != len(local_offsets):
        raise ZipStructureError("ZIP local regions overlap, alias, or leave padding")
    for entry in entries:
        fixed = _LOCAL.unpack(source.read(entry.local_header_offset, _LOCAL.size))
        if fixed[0] != _LOCAL_SIGNATURE:
            raise ZipStructureError("ZIP local header has an invalid signature")
        name_bytes, extra_bytes = fixed[9:11]
        if extra_bytes > limits.maximum_extra_bytes:
            raise ZipStructureError("ZIP local extra field crosses its byte boundary")
        variable_offset = entry.local_header_offset + _LOCAL.size
        raw_name = source.read(variable_offset, name_bytes)
        extra = source.read(variable_offset + name_bytes, extra_bytes)
        _validate_extra(extra, central=False)
        expected = (
            entry.version_needed,
            entry.flags,
            entry.method,
            entry.modified_time,
            entry.modified_date,
            entry.crc32,
            entry.compressed_bytes,
            entry.expanded_bytes,
        )
        if fixed[1:9] != expected or raw_name != entry.raw_name:
            raise ZipStructureError("ZIP local header disagrees with its central record")
        data_offset = variable_offset + name_bytes + extra_bytes
        data_end = data_offset + entry.compressed_bytes
        if data_end > central_offset:
            raise ZipStructureError("ZIP local data region crosses into central metadata")
        regions.append((entry.local_header_offset, data_end))
        members.append(
            ZipMember(
                source_name=entry.source_name,
                normalized_path=entry.normalized_path,
                entry_type=entry.entry_type,
                compression_method=entry.method,
                crc32=entry.crc32,
                compressed_bytes=entry.compressed_bytes,
                expanded_bytes=entry.expanded_bytes,
                local_header_offset=entry.local_header_offset,
                data_offset=data_offset,
            )
        )
    cursor = 0
    for start, end in sorted(regions):
        if start != cursor or end < start:
            raise ZipStructureError("ZIP local regions overlap, alias, or leave padding")
        cursor = end
    if cursor != central_offset:
        raise ZipStructureError("ZIP local regions do not exactly cover the data area")
    return tuple(members)


def _validate_extra(data: bytes, *, central: bool) -> None:
    cursor = 0
    seen: set[int] = set()
    while cursor < len(data):
        if cursor + _EXTRA_HEADER.size > len(data):
            raise ZipStructureError("ZIP extra field ends inside its header")
        identifier, size = _EXTRA_HEADER.unpack(data[cursor : cursor + _EXTRA_HEADER.size])
        cursor += _EXTRA_HEADER.size
        end = cursor + size
        if end > len(data):
            raise ZipStructureError("ZIP extra field ends inside its value")
        if identifier in seen:
            raise ZipStructureError("ZIP repeats an extra-field identifier")
        seen.add(identifier)
        value = data[cursor:end]
        if identifier == _EXTENDED_TIMESTAMP_EXTRA:
            if not value or value[0] & ~0x07:
                raise ZipStructureError("ZIP extended-timestamp field is malformed")
            expected_values = bool(value and value[0] & 0x01) if central else value[0].bit_count()
            if len(value) != 1 + 4 * expected_values:
                raise ZipStructureError("ZIP extended-timestamp field is malformed")
        elif identifier == _NTFS_TIMESTAMP_EXTRA:
            if (
                len(value) != _NTFS_TIMESTAMP_VALUE_BYTES
                or value[:4] != b"\0\0\0\0"
                or struct.unpack("<HH", value[4:8]) != (1, 24)
            ):
                raise ZipStructureError("ZIP NTFS-timestamp field is malformed")
        else:
            raise ZipStructureError("ZIP extra-field identifier is not accepted")
        cursor = end


def _validate_snapshot(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
    limits: ZipLimits,
) -> os.stat_result:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_nlink != 1
    ):
        raise ZipStructureError("ZIP snapshot has an unsafe inode shape")
    if metadata.st_size > limits.maximum_archive_bytes:
        raise ZipStructureError("ZIP snapshot crosses its compressed-byte boundary")
    return metadata


def _sha256(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(_HASH_CHUNK_BYTES, size - offset), offset)
        if not chunk:
            raise ZipStructureError("ZIP snapshot ended during artifact hashing")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _metadata_generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_blocks,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_staging_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\0" in name
        or Path(name).is_absolute()
        or unicodedata.normalize("NFC", name) != name
        or any(unicodedata.category(character) == "Cc" for character in name)
    ):
        raise ValueError("ZIP staging name must be one canonical relative component")


def _validate_open_identity(path: Path, opened: os.stat_result, message: str) -> None:
    current = path.stat(follow_symlinks=False)
    if _metadata_generation(opened) != _metadata_generation(current):
        raise ZipExtractionError(message)


def _validate_staging_parent(
    metadata: os.stat_result,
    *,
    expected_owner: int,
) -> os.stat_result:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != _STAGING_PARENT_MODE
    ):
        raise ZipExtractionError("ZIP staging parent has an unsafe inode shape")
    return metadata


def _extraction_reservation(structure: ZipStructure, parent_fd: int) -> CapacityReservation:
    filesystem = os.fstatvfs(parent_fd)
    fragment = filesystem.f_frsize or filesystem.f_bsize
    if fragment <= 0:
        raise ZipExtractionError("ZIP staging filesystem has no allocation fragment")
    file_allocation = sum(
        ((member.expanded_bytes + fragment - 1) // fragment) * fragment
        for member in structure.members
        if member.entry_type is ZipEntryType.REGULAR_FILE
    )
    namespace_allocation = fragment * (structure.materialized_entry_count + 1)
    return CapacityReservation(
        allocated_bytes=file_allocation + namespace_allocation,
        unique_inodes=structure.materialized_entry_count + 1,
    )


def _extract_members(
    source: _Source,
    structure: ZipStructure,
    *,
    root_fd: int,
    expected_owner: int,
    limits: ZipLimits,
) -> None:
    directories = _extracted_directories(structure)
    for path in sorted(directories, key=lambda value: (value.count("/"), value.encode())):
        parent_components, name = _split_components(path)
        parent_fd = _open_directory_chain(root_fd, parent_components, expected_owner=expected_owner)
        try:
            os.mkdir(name, mode=_DIRECTORY_MODE, dir_fd=parent_fd)
            directory_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
            try:
                os.fchmod(directory_fd, _DIRECTORY_MODE)
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    expanded_bytes = 0
    regular_members = sorted(
        (member for member in structure.members if member.entry_type is ZipEntryType.REGULAR_FILE),
        key=lambda member: member.normalized_path.encode(),
    )
    for member in regular_members:
        expanded_bytes += _extract_regular_member(
            source,
            member,
            root_fd=root_fd,
            expected_owner=expected_owner,
            limits=limits,
        )
        if expanded_bytes > limits.maximum_expanded_bytes:
            raise ZipExtractionError("ZIP observed expanded bytes cross their boundary")

    for path in sorted(directories, key=lambda value: (-value.count("/"), value.encode())):
        directory_fd = _open_directory_chain(
            root_fd,
            tuple(path.split("/")),
            expected_owner=expected_owner,
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _extracted_directories(structure: ZipStructure) -> set[str]:
    regular = {
        member.normalized_path
        for member in structure.members
        if member.entry_type is ZipEntryType.REGULAR_FILE
    }
    return set(structure.materialized_paths) - regular


def _split_components(path: str) -> tuple[tuple[str, ...], str]:
    components = tuple(path.split("/"))
    return components[:-1], components[-1]


def _open_directory_chain(
    root_fd: int,
    components: tuple[str, ...],
    *,
    expected_owner: int,
) -> int:
    current = os.dup(root_fd)
    try:
        _validate_extracted_inode(
            os.fstat(current),
            expected_owner=expected_owner,
            expected_mode=_DIRECTORY_MODE,
            is_directory=True,
        )
        for component in components:
            child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=current)
            try:
                _validate_extracted_inode(
                    os.fstat(child),
                    expected_owner=expected_owner,
                    expected_mode=_DIRECTORY_MODE,
                    is_directory=True,
                )
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _extract_regular_member(
    source: _Source,
    member: ZipMember,
    *,
    root_fd: int,
    expected_owner: int,
    limits: ZipLimits,
) -> int:
    parent_components, name = _split_components(member.normalized_path)
    parent_fd = _open_directory_chain(root_fd, parent_components, expected_owner=expected_owner)
    file_fd: int | None = None
    try:
        file_fd = os.open(name, _FILE_CREATE_FLAGS, _FILE_MODE, dir_fd=parent_fd)
        os.fchmod(file_fd, _FILE_MODE)
        try:
            crc32, expanded = _stream_member(source, member, file_fd=file_fd, limits=limits)
        except zlib.error as error:
            raise ZipExtractionError("ZIP Deflate stream is invalid") from error
        os.fsync(file_fd)
        metadata = _validate_extracted_inode(
            os.fstat(file_fd),
            expected_owner=expected_owner,
            expected_mode=_FILE_MODE,
            is_directory=False,
        )
        if metadata.st_size != member.expanded_bytes or expanded != member.expanded_bytes:
            raise ZipExtractionError("ZIP observed file size disagrees with structural metadata")
        if crc32 != member.crc32:
            raise ZipExtractionError("ZIP observed CRC-32 disagrees with structural metadata")
        os.fsync(parent_fd)
        return expanded
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def _stream_member(
    source: _Source,
    member: ZipMember,
    *,
    file_fd: int,
    limits: ZipLimits,
) -> tuple[int, int]:
    compressed_remaining = member.compressed_bytes
    input_offset = member.data_offset
    expanded = 0
    crc32 = 0
    decoder = zlib.decompressobj(wbits=-zlib.MAX_WBITS) if member.compression_method else None
    while compressed_remaining:
        chunk = source.read(input_offset, min(compressed_remaining, _EXTRACTION_CHUNK_BYTES))
        compressed_remaining -= len(chunk)
        input_offset += len(chunk)
        if decoder is None:
            crc32, expanded = _write_extracted(
                file_fd,
                chunk,
                crc32=crc32,
                expanded=expanded,
                member=member,
                limits=limits,
            )
            continue
        pending = chunk
        while pending:
            output = decoder.decompress(
                pending,
                min(_EXTRACTION_CHUNK_BYTES, member.expanded_bytes - expanded + 1),
            )
            pending = decoder.unconsumed_tail
            crc32, expanded = _write_extracted(
                file_fd,
                output,
                crc32=crc32,
                expanded=expanded,
                member=member,
                limits=limits,
            )
            if not output and pending:
                raise ZipExtractionError("ZIP Deflate decoder made no bounded progress")
    if decoder is not None and (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        raise ZipExtractionError("ZIP Deflate stream does not end at its declared boundary")
    return crc32 & 0xFFFFFFFF, expanded


def _write_extracted(  # noqa: PLR0913 - preserve explicit streaming counters
    file_fd: int,
    data: bytes,
    *,
    crc32: int,
    expanded: int,
    member: ZipMember,
    limits: ZipLimits,
) -> tuple[int, int]:
    projected = expanded + len(data)
    if projected > member.expanded_bytes or projected > limits.maximum_file_bytes:
        raise ZipExtractionError("ZIP observed file bytes cross their declared boundary")
    remaining = memoryview(data)
    while remaining:
        written = os.write(file_fd, remaining)
        if written <= 0:
            raise ZipExtractionError("ZIP extraction write made no progress")
        remaining = remaining[written:]
    return zlib.crc32(data, crc32), projected


def _validate_extracted_tree(
    root_fd: int,
    structure: ZipStructure,
    *,
    expected_owner: int,
    reservation: CapacityReservation,
) -> tuple[int, int]:
    observed_paths: set[str] = set()
    allocated_bytes = 0
    unique_inodes = 0
    stack: list[tuple[int, tuple[str, ...]]] = [
        (os.open(".", _DIRECTORY_OPEN_FLAGS, dir_fd=root_fd), ())
    ]
    try:
        while stack:
            directory_fd, parent = stack.pop()
            try:
                directory_metadata = _validate_extracted_inode(
                    os.fstat(directory_fd),
                    expected_owner=expected_owner,
                    expected_mode=_DIRECTORY_MODE,
                    is_directory=True,
                )
                allocated_bytes += directory_metadata.st_blocks * _BLOCK_UNIT_BYTES
                unique_inodes += 1
                with os.scandir(directory_fd) as iterator:
                    entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
                for entry in entries:
                    components = (*parent, entry.name)
                    normalized_path = "/".join(components)
                    observed_paths.add(normalized_path)
                    metadata = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        child = os.open(entry.name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
                        stack.append((child, components))
                    else:
                        _validate_extracted_inode(
                            metadata,
                            expected_owner=expected_owner,
                            expected_mode=_FILE_MODE,
                            is_directory=False,
                        )
                        allocated_bytes += metadata.st_blocks * _BLOCK_UNIT_BYTES
                        unique_inodes += 1
            finally:
                os.close(directory_fd)
    except BaseException:
        for descriptor, _path in stack:
            os.close(descriptor)
        raise
    if observed_paths != set(structure.materialized_paths):
        raise ZipExtractionError("ZIP extracted namespace disagrees with structural preflight")
    if allocated_bytes > reservation.allocated_bytes or unique_inodes != reservation.unique_inodes:
        raise ZipExtractionError("ZIP extraction crossed its capacity reservation")
    return allocated_bytes, unique_inodes


def _validate_extracted_inode(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
    is_directory: bool,
) -> os.stat_result:
    expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or (not is_directory and metadata.st_nlink != 1)
    ):
        raise ZipExtractionError("ZIP extracted inode has an unsafe shape")
    return metadata


def _validate_remaining_capacity(parent_fd: int, projection: CapacityProjection) -> None:
    filesystem = measure_filesystem_capacity_descriptor(parent_fd)
    if (
        filesystem.available_bytes < projection.required_available_bytes
        or filesystem.available_inodes < projection.required_available_inodes
    ):
        raise ZipExtractionError("ZIP extraction crossed the host free-space floor")


def _remove_extraction(parent_fd: int, name: str) -> None:
    try:
        root_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        _remove_directory_contents(root_fd)
    finally:
        os.close(root_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _remove_directory_contents(directory_fd: int) -> None:
    with os.scandir(directory_fd) as iterator:
        entries = list(iterator)
    for entry in entries:
        metadata = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(entry.name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
            try:
                _remove_directory_contents(child)
            finally:
                os.close(child)
            os.rmdir(entry.name, dir_fd=directory_fd)
        else:
            os.unlink(entry.name, dir_fd=directory_fd)
