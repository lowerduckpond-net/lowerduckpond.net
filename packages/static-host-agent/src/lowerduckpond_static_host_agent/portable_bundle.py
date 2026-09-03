"""Canonical v1 portable-bundle construction from a private release snapshot."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import struct
import unicodedata
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_contracts import (
    ContractError,
    ContractKind,
    Digest,
    canonical_json_bytes,
    decode_contract,
    manifest_digest,
    validate_contract,
)

from lowerduckpond_static_host_agent import zip_structure as _zip
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityProjection,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.release_tree import (
    DEFAULT_RELEASE_TREE_LIMITS,
    RELEASE_TREE_FORMAT,
    ReleaseTreeLimits,
    ReleaseTreeMeasurement,
    measure_release_tree_snapshot,
)

PORTABLE_BUNDLE_FORMAT: Final = "lowerduckpond-archive-v1"
PORTABLE_ENVELOPE: Final = "lowerduckpond-export-v1"
FORMAT_BYTES: Final = b'{"format":"lowerduckpond-export","version":1}\n'
MAXIMUM_PORTABLE_BUNDLE_BYTES: Final = 120 * 1024 * 1024
MAXIMUM_CHECKSUM_BYTES: Final = 5_495_158
_LOCAL = struct.Struct("<I5H3I2H")
_CENTRAL = struct.Struct("<I6H3I5H2I")
_EOCD = struct.Struct("<I4H2IH")
_LOCAL_SIGNATURE: Final = 0x04034B50
_CENTRAL_SIGNATURE: Final = 0x02014B50
_EOCD_SIGNATURE: Final = 0x06054B50
_MADE_BY: Final = 0x0314
_VERSION_NEEDED: Final = 0x0014
_UTF8_FLAG: Final = 0x0800
_STORED_METHOD: Final = 0
_DOS_TIME: Final = 0x0000
_DOS_DATE: Final = 0x0021
_REGULAR_ATTRIBUTES: Final = 0x81A40000
_DIRECTORY_ATTRIBUTES: Final = 0x41ED0010
_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_OUTPUT_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_BYTES: Final = 64 * 1024
_OUTPUT_MODE: Final = 0o600
_PRIVATE_PARENT_MODE: Final = 0o700
_MAXIMUM_CENTRAL_BYTES: Final = 8 * 1024 * 1024
_MAXIMUM_PORTABLE_RECORDS: Final = 5_004
_MAXIMUM_PORTABLE_EXPANDED_BYTES: Final = 106 * 1024 * 1024
_MAXIMUM_MANIFEST_BYTES: Final = 16 * 1024
_CHECKSUM_LINE_PREFIX_BYTES: Final = 66
_FIXED_ENVELOPE_RECORDS: Final = 4
_MAXIMUM_ENVELOPE_NAME_BYTES: Final = 1_057
_DIRECTORY_MODE: Final = 0o755
_FILE_MODE: Final = 0o644


class PortableBundleError(RuntimeError):
    """A private snapshot could not produce one canonical portable bundle."""


@dataclass(frozen=True, slots=True)
class PortableBundle:
    """Exact identifiers for one completed canonical v1 bundle."""

    output_name: str
    bundle_size: int
    bundle_digest: Digest
    manifest_digest: Digest
    release_tree: ReleaseTreeMeasurement


@dataclass(frozen=True, slots=True)
class PortableBundleInspection:
    """Validated provenance and content boundaries from one canonical v1 bundle."""

    bundle_size: int
    bundle_digest: Digest
    provenance_manifest: dict[str, object]
    provenance_manifest_digest: Digest
    release_tree_digest: Digest
    content_paths: tuple[str, ...]
    content_bytes: int


@dataclass(frozen=True, slots=True)
class PortableBundleImport:
    """One complete, unpublished content tree imported from a v1 bundle."""

    inspection: PortableBundleInspection
    staging_name: str
    capacity_projection: CapacityProjection
    allocated_bytes: int
    unique_inodes: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    size: int
    blocks: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def capture(cls, metadata: os.stat_result) -> _Snapshot:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            owner=metadata.st_uid,
            links=metadata.st_nlink,
            size=metadata.st_size,
            blocks=metadata.st_blocks,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class _SourceEntry:
    components: tuple[str, ...]
    path_bytes: bytes
    is_directory: bool
    snapshot: _Snapshot
    crc32: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class _CentralRecord:
    name: bytes
    crc32: int
    size: int
    external_attributes: int
    local_offset: int


@dataclass(frozen=True, slots=True)
class _PortableRecord:
    name: bytes
    is_directory: bool
    crc32: int
    size: int
    local_offset: int
    data_offset: int


@dataclass(frozen=True, slots=True)
class _PortableAdmission:
    inspection: PortableBundleInspection
    content_structure: _zip.ZipStructure


class _DigestWriter(Protocol):
    def update(self, value: bytes, /) -> None: ...


def build_portable_bundle(  # noqa: PLR0912,PLR0913,PLR0915 - explicit trust workflow
    release_root: Path,
    manifest: dict[str, object],
    *,
    output_parent: Path,
    output_name: str,
    lock_manager: LockManager,
    expected_owner: int,
    limits: ReleaseTreeLimits = DEFAULT_RELEASE_TREE_LIMITS,
) -> PortableBundle:
    """Construct one byte-canonical stored ZIP while the export lock remains held."""

    lock_manager.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    _validate_output_name(output_name)
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_identifier = manifest_digest(manifest)
    initial_measurement = measure_release_tree_snapshot(
        release_root,
        lock_manager=lock_manager,
        expected_owner=expected_owner,
        limits=limits,
    )
    root_fd: int | None = None
    parent_fd: int | None = None
    output_fd: int | None = None
    temporary_name: str | None = None
    temporary_created = False
    final_linked = False
    try:
        root_fd = os.open(release_root, _DIRECTORY_FLAGS)
        root_snapshot = _validate_root(
            release_root,
            root_fd,
            expected_owner=expected_owner,
        )
        entries = _scan_snapshot(
            root_fd,
            expected_owner=expected_owner,
            expected_device=root_snapshot.device,
            limits=limits,
        )
        if (
            len(entries) != initial_measurement.entry_count
            or sum(entry.snapshot.size for entry in entries if not entry.is_directory)
            != initial_measurement.logical_content_bytes
        ):
            raise PortableBundleError("portable source disagrees with its release measurement")
        if not any(
            entry.path_bytes == b"index.html" and not entry.is_directory for entry in entries
        ):
            raise PortableBundleError("portable source has no root-level index.html regular file")
        checksums = _checksums(entries, manifest_bytes)

        parent_fd = os.open(output_parent, _DIRECTORY_FLAGS)
        _validate_output_parent(
            output_parent,
            parent_fd,
            expected_owner=expected_owner,
        )
        _require_output_absent(parent_fd, output_name)
        temporary_name = f".m3-portable-{secrets.token_hex(16)}.partial"
        output_fd = os.open(temporary_name, _OUTPUT_FLAGS, _OUTPUT_MODE, dir_fd=parent_fd)
        temporary_created = True
        os.fchmod(output_fd, _OUTPUT_MODE)
        digest = hashlib.sha256()
        records: list[_CentralRecord] = []
        offset = 0
        for name, data in (
            (_envelope_name("format.json"), FORMAT_BYTES),
            (_envelope_name("manifest.json"), manifest_bytes),
            (_envelope_name("checksums.sha256"), checksums),
        ):
            offset = _write_bytes_member(
                output_fd,
                digest,
                records,
                offset=offset,
                name=name,
                data=data,
            )
        offset = _write_directory_member(
            output_fd,
            digest,
            records,
            offset=offset,
            name=_envelope_name("content/"),
        )
        for entry in entries:
            name = _content_name(entry.path_bytes, is_directory=entry.is_directory)
            if entry.is_directory:
                offset = _write_directory_member(
                    output_fd,
                    digest,
                    records,
                    offset=offset,
                    name=name,
                )
            else:
                offset = _write_file_member(
                    root_fd,
                    output_fd,
                    digest,
                    records,
                    entry,
                    offset=offset,
                    name=name,
                )
        final_size = _write_central(output_fd, digest, records, offset=offset)
        os.fsync(output_fd)
        output_metadata = _Snapshot.capture(os.fstat(output_fd))
        if (
            not stat.S_ISREG(output_metadata.mode)
            or output_metadata.owner != expected_owner
            or stat.S_IMODE(output_metadata.mode) != _OUTPUT_MODE
            or output_metadata.links != 1
            or output_metadata.size != final_size
        ):
            raise PortableBundleError("portable output has an unsafe final inode shape")
        final_measurement = measure_release_tree_snapshot(
            release_root,
            lock_manager=lock_manager,
            expected_owner=expected_owner,
            limits=limits,
        )
        if final_measurement != initial_measurement:
            raise PortableBundleError("portable source changed during bundle construction")
        _validate_root_generation(release_root, root_fd, root_snapshot)
        _validate_source_generation(root_fd, entries)
        os.link(
            temporary_name,
            output_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        final_linked = True
        os.unlink(temporary_name, dir_fd=parent_fd)
        temporary_created = False
        os.fsync(parent_fd)
        published = _Snapshot.capture(os.fstat(output_fd))
        named = _Snapshot.capture(os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False))
        if (
            published != named
            or not stat.S_ISREG(published.mode)
            or published.owner != expected_owner
            or stat.S_IMODE(published.mode) != _OUTPUT_MODE
            or published.links != 1
            or published.size != final_size
        ):
            raise PortableBundleError("portable output changed during atomic publication")
        _validate_output_parent(
            output_parent,
            parent_fd,
            expected_owner=expected_owner,
        )
        return PortableBundle(
            output_name=output_name,
            bundle_size=final_size,
            bundle_digest=Digest(PORTABLE_BUNDLE_FORMAT, "sha256", digest.hexdigest()),
            manifest_digest=manifest_identifier,
            release_tree=initial_measurement,
        )
    except OSError as error:
        if parent_fd is not None:
            if final_linked:
                _remove_output(parent_fd, output_name)
            if temporary_created and temporary_name is not None:
                _remove_output(parent_fd, temporary_name)
        raise PortableBundleError("portable bundle could not be constructed safely") from error
    except BaseException:
        if parent_fd is not None:
            if final_linked:
                _remove_output(parent_fd, output_name)
            if temporary_created and temporary_name is not None:
                _remove_output(parent_fd, temporary_name)
        raise
    finally:
        for descriptor in (output_fd, parent_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)


def inspect_portable_bundle(
    path: Path,
    *,
    expected_owner: int,
    expected_mode: int = _OUTPUT_MODE,
) -> PortableBundleInspection:
    """Validate one exact canonical portable bundle without a general ZIP decoder."""

    descriptor: int | None = None
    try:
        descriptor = os.open(path, _zip._SNAPSHOT_OPEN_FLAGS)
        before = _validate_portable_snapshot(
            os.fstat(descriptor), expected_owner=expected_owner, expected_mode=expected_mode
        )
        _validate_portable_identity(
            path,
            before,
            "portable bundle changed while it was opened",
        )
        source = _zip._DescriptorSource(descriptor, before.st_size)
        admission = _inspect_portable_source(source, descriptor=descriptor)
        after = _validate_portable_snapshot(
            os.fstat(descriptor), expected_owner=expected_owner, expected_mode=expected_mode
        )
        _validate_portable_identity(path, after, "portable bundle changed during inspection")
        if _zip._metadata_generation(before) != _zip._metadata_generation(after):
            raise PortableBundleError("portable bundle changed during inspection")
        return admission.inspection
    except _zip.ZipStructureError as error:
        raise PortableBundleError("portable bundle violates its structural contract") from error
    except OSError as error:
        raise PortableBundleError("portable bundle cannot be opened safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def import_portable_bundle(  # noqa: PLR0913,PLR0915 - explicit import trust workflow
    path: Path,
    *,
    staging_parent: Path,
    staging_name: str,
    expected_owner: int,
    retained_usage: ReleaseCapacityUsage,
    lock_manager: LockManager,
    expected_mode: int = _OUTPUT_MODE,
    limits: _zip.ZipLimits = _zip.DEFAULT_ZIP_LIMITS,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> PortableBundleImport:
    """Validate and extract only content/ as a new unpublished deployment tree."""

    lock_manager.require_held(LockName.INTAKE, mode=LockMode.EXCLUSIVE)
    _zip._validate_staging_name(staging_name)
    source_fd: int | None = None
    parent_fd: int | None = None
    root_fd: int | None = None
    created_identity: tuple[int, int] | None = None
    created = False
    try:
        source_fd = os.open(path, _zip._SNAPSHOT_OPEN_FLAGS)
        before = _validate_portable_snapshot(
            os.fstat(source_fd), expected_owner=expected_owner, expected_mode=expected_mode
        )
        _validate_portable_identity(
            path,
            before,
            "portable bundle changed while it was opened",
        )
        source = _zip._DescriptorSource(source_fd, before.st_size)
        admission = _inspect_portable_source(source, descriptor=source_fd, content_limits=limits)
        structure = admission.content_structure

        parent_fd = os.open(staging_parent, _zip._DIRECTORY_OPEN_FLAGS)
        parent_metadata = _zip._validate_staging_parent(
            os.fstat(parent_fd),
            expected_owner=expected_owner,
        )
        _validate_portable_identity(
            staging_parent,
            parent_metadata,
            "portable staging parent changed while it was opened",
        )
        reservation = _zip._extraction_reservation(structure, parent_fd)
        projection = admit_release_capacity(
            retained_usage,
            reservation,
            measure_filesystem_capacity_descriptor(parent_fd),
            limits=capacity_limits,
        )
        os.mkdir(staging_name, mode=_DIRECTORY_MODE, dir_fd=parent_fd)
        created = True
        root_fd, created_identity = _zip._open_created_staging(parent_fd, staging_name)
        os.fchmod(root_fd, _DIRECTORY_MODE)
        _zip._extract_members(
            source,
            structure,
            root_fd=root_fd,
            expected_owner=expected_owner,
            limits=limits,
        )
        allocated_bytes, unique_inodes = _zip._validate_extracted_tree(
            root_fd,
            structure,
            expected_owner=expected_owner,
            reservation=reservation,
        )
        os.fsync(root_fd)
        os.fsync(parent_fd)

        after = _validate_portable_snapshot(
            os.fstat(source_fd), expected_owner=expected_owner, expected_mode=expected_mode
        )
        _validate_portable_identity(path, after, "portable bundle changed during import")
        if _zip._metadata_generation(before) != _zip._metadata_generation(after):
            raise PortableBundleError("portable bundle changed during import")
        _zip._validate_remaining_capacity(parent_fd, projection)
        _zip._validate_staging_result(
            staging_parent,
            parent_fd=parent_fd,
            staging_name=staging_name,
            root_fd=root_fd,
            expected_owner=expected_owner,
        )
        return PortableBundleImport(
            inspection=admission.inspection,
            staging_name=staging_name,
            capacity_projection=projection,
            allocated_bytes=allocated_bytes,
            unique_inodes=unique_inodes,
        )
    except _zip.ZipStructureError as error:
        if created and parent_fd is not None and created_identity is not None:
            _zip._remove_extraction(
                parent_fd,
                staging_name,
                expected_identity=created_identity,
            )
        raise PortableBundleError("portable import violates its extraction contract") from error
    except OSError as error:
        if created and parent_fd is not None and created_identity is not None:
            _zip._remove_extraction(
                parent_fd,
                staging_name,
                expected_identity=created_identity,
            )
        raise PortableBundleError("portable import could not complete safely") from error
    except BaseException:
        if created and parent_fd is not None and created_identity is not None:
            _zip._remove_extraction(
                parent_fd,
                staging_name,
                expected_identity=created_identity,
            )
        raise
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        if source_fd is not None:
            os.close(source_fd)


def _validate_portable_snapshot(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
) -> os.stat_result:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_nlink != 1
        or metadata.st_size > MAXIMUM_PORTABLE_BUNDLE_BYTES
    ):
        raise PortableBundleError("portable bundle has an unsafe snapshot inode")
    return metadata


def _validate_portable_identity(
    path: Path,
    opened: os.stat_result,
    message: str,
) -> None:
    current = path.stat(follow_symlinks=False)
    if _zip._metadata_generation(opened) != _zip._metadata_generation(current):
        raise PortableBundleError(message)


def _inspect_portable_source(
    source: _zip._Source,
    *,
    descriptor: int,
    content_limits: _zip.ZipLimits = _zip.DEFAULT_ZIP_LIMITS,
) -> _PortableAdmission:
    if source.size < _EOCD.size or source.size > MAXIMUM_PORTABLE_BUNDLE_BYTES:
        raise PortableBundleError("portable bundle crosses its encoded byte boundary")
    eocd_offset = source.size - _EOCD.size
    (
        signature,
        disk_number,
        central_disk,
        records_on_disk,
        record_count,
        central_bytes,
        central_offset,
        comment_bytes,
    ) = _EOCD.unpack(source.read(eocd_offset, _EOCD.size))
    if signature != _EOCD_SIGNATURE or comment_bytes:
        raise PortableBundleError("portable bundle has a noncanonical end record")
    if (
        disk_number
        or central_disk
        or records_on_disk != record_count
        or not _FIXED_ENVELOPE_RECORDS <= record_count <= _MAXIMUM_PORTABLE_RECORDS
    ):
        raise PortableBundleError("portable bundle has a noncanonical disk or record count")
    if central_bytes > _MAXIMUM_CENTRAL_BYTES or central_offset + central_bytes != eocd_offset:
        raise PortableBundleError("portable central directory crosses its boundary")
    records = _parse_portable_central(
        source,
        central_offset=central_offset,
        central_bytes=central_bytes,
        record_count=record_count,
    )
    records = _validate_portable_locals(source, records, central_offset=central_offset)
    content_structure = _validate_portable_envelope(
        records,
        bundle_size=source.size,
        central_offset=central_offset,
        central_bytes=central_bytes,
        limits=content_limits,
    )
    format_record, manifest_record, checksum_record = records[:3]
    format_bytes, format_sha = _read_portable_record(
        source, format_record, maximum_bytes=len(FORMAT_BYTES)
    )
    if format_bytes != FORMAT_BYTES:
        raise PortableBundleError("portable format.json is not the exact v1 identifier")
    manifest_bytes, manifest_sha = _read_portable_record(
        source,
        manifest_record,
        maximum_bytes=_MAXIMUM_MANIFEST_BYTES,
    )
    try:
        provenance_manifest = decode_contract(
            manifest_bytes,
            expected_kind=ContractKind.SITE,
            maximum_raw_bytes=_MAXIMUM_MANIFEST_BYTES,
        )
    except ContractError as error:
        raise PortableBundleError("portable manifest.json violates its contract") from error
    if canonical_json_bytes(provenance_manifest) != manifest_bytes:
        raise PortableBundleError("portable manifest.json is not canonical")
    checksum_bytes, _checksum_sha = _read_portable_record(
        source,
        checksum_record,
        maximum_bytes=MAXIMUM_CHECKSUM_BYTES,
    )
    expected_checksums: list[tuple[bytes, str]] = [
        (b"format.json", format_sha),
        (b"manifest.json", manifest_sha),
    ]
    release_digest = hashlib.sha256()
    release_digest.update(RELEASE_TREE_FORMAT.encode("ascii") + b"\0")
    release_digest.update(len(content_structure.materialized_paths).to_bytes(4, "big"))
    for record, member in zip(records[4:], content_structure.members, strict=True):
        path_bytes = member.normalized_path.encode("utf-8")
        release_digest.update(b"D" if record.is_directory else b"F")
        release_digest.update(len(path_bytes).to_bytes(4, "big"))
        release_digest.update(path_bytes)
        if not record.is_directory:
            data, sha256 = _read_portable_record(
                source,
                record,
                maximum_bytes=member.expanded_bytes,
            )
            release_digest.update(member.expanded_bytes.to_bytes(8, "big"))
            release_digest.update(data)
            expected_checksums.append((b"content/" + path_bytes, sha256))
    _validate_checksum_manifest(checksum_bytes, expected_checksums)
    bundle_digest = Digest(
        PORTABLE_BUNDLE_FORMAT,
        "sha256",
        _zip._sha256(descriptor, source.size),
    )
    inspection = PortableBundleInspection(
        bundle_size=source.size,
        bundle_digest=bundle_digest,
        provenance_manifest=provenance_manifest,
        provenance_manifest_digest=manifest_digest(provenance_manifest),
        release_tree_digest=Digest(
            RELEASE_TREE_FORMAT,
            "sha256",
            release_digest.hexdigest(),
        ),
        content_paths=content_structure.materialized_paths,
        content_bytes=content_structure.expanded_regular_file_bytes,
    )
    return _PortableAdmission(inspection, content_structure)


def _parse_portable_central(
    source: _zip._Source,
    *,
    central_offset: int,
    central_bytes: int,
    record_count: int,
) -> tuple[_PortableRecord, ...]:
    data = source.read(central_offset, central_bytes)
    cursor = 0
    records: list[_PortableRecord] = []
    expanded = 0
    for _record_number in range(record_count):
        fixed_end = cursor + _CENTRAL.size
        if fixed_end > len(data):
            raise PortableBundleError("portable central directory ends inside a record")
        fields = _CENTRAL.unpack(data[cursor:fixed_end])
        name_bytes, extra_bytes, comment_bytes = fields[10:13]
        variable_end = fixed_end + name_bytes + extra_bytes + comment_bytes
        if variable_end > len(data):
            raise PortableBundleError("portable central variable fields cross their region")
        name = data[fixed_end : fixed_end + name_bytes]
        _validate_portable_central_fields(fields, name=name)
        is_directory = name.endswith(b"/")
        size = int(fields[9])
        if not is_directory:
            expanded += size
            if expanded > _MAXIMUM_PORTABLE_EXPANDED_BYTES:
                raise PortableBundleError("portable declared bytes cross their boundary")
        records.append(
            _PortableRecord(
                name=name,
                is_directory=is_directory,
                crc32=int(fields[7]),
                size=size,
                local_offset=int(fields[16]),
                data_offset=0,
            )
        )
        cursor = variable_end
    if cursor != len(data):
        raise PortableBundleError("portable record count does not consume its central directory")
    return tuple(records)


def _validate_portable_central_fields(fields: tuple[int, ...], *, name: bytes) -> None:
    if (
        fields[0] != _CENTRAL_SIGNATURE
        or fields[1] != _MADE_BY
        or fields[2] != _VERSION_NEEDED
        or fields[3] != _UTF8_FLAG
        or fields[4] != _STORED_METHOD
        or fields[5] != _DOS_TIME
        or fields[6] != _DOS_DATE
        or fields[8] != fields[9]
        or fields[11]
        or fields[12]
        or fields[13]
        or fields[14]
    ):
        raise PortableBundleError("portable central record is not canonical")
    if not name or len(name) > _MAXIMUM_ENVELOPE_NAME_BYTES:
        raise PortableBundleError("portable member name crosses its envelope boundary")
    try:
        decoded = name.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PortableBundleError("portable member name is not UTF-8") from error
    if (
        unicodedata.normalize("NFC", decoded) != decoded
        or "\\" in decoded
        or any(unicodedata.category(character) == "Cc" for character in decoded)
    ):
        raise PortableBundleError("portable member name is not canonical")
    expected_attributes = _DIRECTORY_ATTRIBUTES if name.endswith(b"/") else _REGULAR_ATTRIBUTES
    if fields[15] != expected_attributes:
        raise PortableBundleError("portable member attributes are not canonical")
    if name.endswith(b"/") and (fields[7] or fields[8] or fields[9]):
        raise PortableBundleError("portable directory record carries file data")


def _validate_portable_locals(
    source: _zip._Source,
    records: tuple[_PortableRecord, ...],
    *,
    central_offset: int,
) -> tuple[_PortableRecord, ...]:
    validated: list[_PortableRecord] = []
    regions: list[tuple[int, int]] = []
    for record in records:
        fields = _LOCAL.unpack(source.read(record.local_offset, _LOCAL.size))
        expected = (
            _LOCAL_SIGNATURE,
            _VERSION_NEEDED,
            _UTF8_FLAG,
            _STORED_METHOD,
            _DOS_TIME,
            _DOS_DATE,
            record.crc32,
            record.size,
            record.size,
            len(record.name),
            0,
        )
        if fields != expected:
            raise PortableBundleError("portable local header disagrees with its central record")
        name_offset = record.local_offset + _LOCAL.size
        if source.read(name_offset, len(record.name)) != record.name:
            raise PortableBundleError("portable local name disagrees with its central record")
        data_offset = name_offset + len(record.name)
        data_end = data_offset + record.size
        if data_end > central_offset:
            raise PortableBundleError("portable member data crosses into central metadata")
        regions.append((record.local_offset, data_end))
        validated.append(
            _PortableRecord(
                name=record.name,
                is_directory=record.is_directory,
                crc32=record.crc32,
                size=record.size,
                local_offset=record.local_offset,
                data_offset=data_offset,
            )
        )
    cursor = 0
    for start, end in regions:
        if start != cursor or end < start:
            raise PortableBundleError(
                "portable local regions are reordered, alias, overlap, or leave padding"
            )
        cursor = end
    if cursor != central_offset:
        raise PortableBundleError("portable local regions do not exactly cover their area")
    return tuple(validated)


def _validate_portable_envelope(
    records: tuple[_PortableRecord, ...],
    *,
    bundle_size: int,
    central_offset: int,
    central_bytes: int,
    limits: _zip.ZipLimits,
) -> _zip.ZipStructure:
    fixed_names = (
        _envelope_name("format.json"),
        _envelope_name("manifest.json"),
        _envelope_name("checksums.sha256"),
        _envelope_name("content/"),
    )
    if tuple(record.name for record in records[:4]) != fixed_names:
        raise PortableBundleError("portable fixed envelope records are missing or reordered")
    if any(record.is_directory for record in records[:3]) or not records[3].is_directory:
        raise PortableBundleError("portable fixed envelope record types are invalid")
    if records[0].size != len(FORMAT_BYTES):
        raise PortableBundleError("portable format.json has an invalid size")
    if records[1].size > _MAXIMUM_MANIFEST_BYTES:
        raise PortableBundleError("portable manifest.json crosses its byte boundary")
    if records[2].size > MAXIMUM_CHECKSUM_BYTES:
        raise PortableBundleError("portable checksums.sha256 crosses its byte boundary")
    prefix = fixed_names[3]
    central_entries: list[_zip._CentralEntry] = []
    members: list[_zip.ZipMember] = []
    ordered_paths: list[bytes] = []
    for record in records[4:]:
        if not record.name.startswith(prefix) or record.name == prefix:
            raise PortableBundleError("portable member lies outside content/")
        raw_relative = record.name[len(prefix) :]
        source_name, normalized_path, marker = _zip._decode_name(
            raw_relative,
            flags=_UTF8_FLAG,
            limits=limits,
        )
        if source_name != normalized_path or marker != record.is_directory:
            raise PortableBundleError("portable content path is not canonical")
        entry_type = (
            _zip.ZipEntryType.DIRECTORY if record.is_directory else _zip.ZipEntryType.REGULAR_FILE
        )
        if not record.is_directory and record.size > limits.maximum_file_bytes:
            raise PortableBundleError("portable content file crosses its byte boundary")
        central_entries.append(
            _zip._CentralEntry(
                made_by=_MADE_BY,
                version_needed=_VERSION_NEEDED,
                flags=_UTF8_FLAG,
                method=_STORED_METHOD,
                modified_time=_DOS_TIME,
                modified_date=_DOS_DATE,
                crc32=record.crc32,
                compressed_bytes=record.size,
                expanded_bytes=record.size,
                external_attributes=(
                    _DIRECTORY_ATTRIBUTES if record.is_directory else _REGULAR_ATTRIBUTES
                ),
                local_header_offset=record.local_offset,
                raw_name=raw_relative,
                source_name=source_name,
                normalized_path=normalized_path,
                entry_type=entry_type,
            )
        )
        members.append(
            _zip.ZipMember(
                source_name=source_name,
                normalized_path=normalized_path,
                entry_type=entry_type,
                compression_method=_STORED_METHOD,
                crc32=record.crc32,
                compressed_bytes=record.size,
                expanded_bytes=record.size,
                local_header_offset=record.local_offset,
                data_offset=record.data_offset,
            )
        )
        ordered_paths.append(normalized_path.encode())
    if ordered_paths != sorted(ordered_paths):
        raise PortableBundleError("portable content records are not in canonical path order")
    materialized = _zip._materialized_paths(tuple(central_entries), limits=limits)
    explicit_paths = tuple(entry.normalized_path for entry in central_entries)
    if materialized != explicit_paths:
        raise PortableBundleError("portable content directories must have explicit records")
    expanded = sum(
        member.expanded_bytes
        for member in members
        if member.entry_type is _zip.ZipEntryType.REGULAR_FILE
    )
    if expanded > limits.maximum_expanded_bytes:
        raise PortableBundleError("portable content bytes cross their tenant-tree boundary")
    return _zip.ZipStructure(
        archive_bytes=bundle_size,
        artifact_sha256="",
        central_directory_offset=central_offset,
        central_directory_bytes=central_bytes,
        members=tuple(members),
        materialized_paths=materialized,
        expanded_regular_file_bytes=expanded,
    )


def _read_portable_record(
    source: _zip._Source,
    record: _PortableRecord,
    *,
    maximum_bytes: int,
) -> tuple[bytes, str]:
    if record.size > maximum_bytes:
        raise PortableBundleError("portable member crosses its read boundary")
    data = source.read(record.data_offset, record.size)
    if zlib.crc32(data) & 0xFFFFFFFF != record.crc32:
        raise PortableBundleError("portable member CRC-32 does not match its bytes")
    return data, hashlib.sha256(data).hexdigest()


def _validate_checksum_manifest(
    data: bytes,
    expected: list[tuple[bytes, str]],
) -> None:
    if not data.endswith(b"\n") or b"\r" in data:
        raise PortableBundleError("portable checksum manifest has noncanonical line endings")
    observed: list[tuple[bytes, str]] = []
    for line in data.splitlines():
        if len(line) <= _CHECKSUM_LINE_PREFIX_BYTES or line[64:66] != b"  ":
            raise PortableBundleError("portable checksum line has an invalid shape")
        digest_bytes = line[:64]
        if any(byte not in b"0123456789abcdef" for byte in digest_bytes):
            raise PortableBundleError("portable checksum digest is not lowercase SHA-256")
        path = line[66:]
        if not path or b"\0" in path or b"\\" in path:
            raise PortableBundleError("portable checksum path is not canonical")
        observed.append((path, digest_bytes.decode("ascii")))
    canonical_expected = sorted(expected, key=lambda item: item[0])
    if observed != canonical_expected:
        raise PortableBundleError("portable checksum manifest does not bind exact content")


def _validate_output_name(name: str) -> None:
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
        raise ValueError("portable output name must be one canonical relative component")


def _validate_root(
    path: Path,
    descriptor: int,
    *,
    expected_owner: int,
) -> _Snapshot:
    snapshot = _Snapshot.capture(os.fstat(descriptor))
    if (
        not stat.S_ISDIR(snapshot.mode)
        or snapshot.owner != expected_owner
        or stat.S_IMODE(snapshot.mode) != _DIRECTORY_MODE
    ):
        raise PortableBundleError("portable source root has an unsafe inode shape")
    _validate_root_generation(path, descriptor, snapshot)
    return snapshot


def _validate_root_generation(path: Path, descriptor: int, expected: _Snapshot) -> None:
    opened = _Snapshot.capture(os.fstat(descriptor))
    named = _Snapshot.capture(path.stat(follow_symlinks=False))
    if opened != expected or named != expected:
        raise PortableBundleError("portable source root changed during construction")


def _validate_output_parent(
    path: Path,
    descriptor: int,
    *,
    expected_owner: int,
) -> None:
    opened = _Snapshot.capture(os.fstat(descriptor))
    named = _Snapshot.capture(path.stat(follow_symlinks=False))
    if (
        opened != named
        or not stat.S_ISDIR(opened.mode)
        or opened.owner != expected_owner
        or stat.S_IMODE(opened.mode) != _PRIVATE_PARENT_MODE
    ):
        raise PortableBundleError("portable output parent has an unsafe inode shape")


def _require_output_absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise PortableBundleError("portable output must not replace an existing path")


def _scan_snapshot(
    root_fd: int,
    *,
    expected_owner: int,
    expected_device: int,
    limits: ReleaseTreeLimits,
) -> tuple[_SourceEntry, ...]:
    entries: list[_SourceEntry] = []
    stack: list[tuple[tuple[str, ...], _Snapshot | None]] = [((), None)]
    while stack:
        parent, expected_directory = stack.pop()
        directory_fd = _open_source_directory(root_fd, parent)
        try:
            if (
                expected_directory is not None
                and _Snapshot.capture(os.fstat(directory_fd)) != expected_directory
            ):
                raise PortableBundleError("portable source directory changed")
            with os.scandir(directory_fd) as iterator:
                children = sorted(iterator, key=lambda item: os.fsencode(item.name))
            directories: list[tuple[tuple[str, ...], _Snapshot]] = []
            for child in children:
                components = (*parent, child.name)
                path_bytes = _validate_source_path(components, limits=limits)
                snapshot = _Snapshot.capture(
                    os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
                )
                is_directory = stat.S_ISDIR(snapshot.mode)
                _validate_source_inode(
                    snapshot,
                    is_directory=is_directory,
                    expected_owner=expected_owner,
                    expected_device=expected_device,
                )
                if is_directory:
                    directories.append((components, snapshot))
                    entry = _SourceEntry(components, path_bytes, True, snapshot, 0, None)
                else:
                    crc32, sha256 = _hash_source_file(
                        root_fd,
                        components,
                        snapshot,
                    )
                    entry = _SourceEntry(
                        components,
                        path_bytes,
                        False,
                        snapshot,
                        crc32,
                        sha256,
                    )
                entries.append(entry)
                if len(entries) > limits.maximum_entries:
                    raise PortableBundleError("portable source crosses its entry boundary")
            stack.extend(reversed(directories))
        finally:
            os.close(directory_fd)
    return tuple(sorted(entries, key=lambda entry: entry.path_bytes))


def _validate_source_path(components: tuple[str, ...], *, limits: ReleaseTreeLimits) -> bytes:
    if len(components) > limits.maximum_depth:
        raise PortableBundleError("portable source path crosses its depth boundary")
    encoded: list[bytes] = []
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or "/" in component
            or "\\" in component
            or unicodedata.normalize("NFC", component) != component
            or any(unicodedata.category(character) == "Cc" for character in component)
        ):
            raise PortableBundleError("portable source path is not canonical")
        value = component.encode("utf-8", errors="strict")
        if len(value) > limits.maximum_component_bytes:
            raise PortableBundleError("portable source component crosses its byte boundary")
        encoded.append(value)
    path = b"/".join(encoded)
    if len(path) > limits.maximum_path_bytes:
        raise PortableBundleError("portable source path crosses its byte boundary")
    if components[0].casefold() == "cdn-cgi":
        raise PortableBundleError("portable source uses Cloudflare's reserved component")
    return path


def _validate_source_inode(
    snapshot: _Snapshot,
    *,
    is_directory: bool,
    expected_owner: int,
    expected_device: int,
) -> None:
    expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
    expected_mode = _DIRECTORY_MODE if is_directory else _FILE_MODE
    if (
        not expected_type(snapshot.mode)
        or snapshot.owner != expected_owner
        or stat.S_IMODE(snapshot.mode) != expected_mode
        or snapshot.device != expected_device
    ):
        raise PortableBundleError("portable source contains an unsafe inode")


def _open_source_file(root_fd: int, components: tuple[str, ...]) -> tuple[int, int]:
    parent_fd = os.open(".", _DIRECTORY_FLAGS, dir_fd=root_fd)
    try:
        for component in components[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        file_fd = os.open(components[-1], _FILE_FLAGS, dir_fd=parent_fd)
        return parent_fd, file_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _open_source_directory(root_fd: int, components: tuple[str, ...]) -> int:
    directory_fd = os.open(".", _DIRECTORY_FLAGS, dir_fd=root_fd)
    try:
        for component in components:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
        return directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def _validate_source_generation(
    root_fd: int,
    entries: tuple[_SourceEntry, ...],
) -> None:
    for entry in entries:
        parent_fd = _open_source_directory(root_fd, entry.components[:-1])
        descriptor: int | None = None
        try:
            flags = _DIRECTORY_FLAGS if entry.is_directory else _FILE_FLAGS
            descriptor = os.open(entry.components[-1], flags, dir_fd=parent_fd)
            opened = _Snapshot.capture(os.fstat(descriptor))
            named = _Snapshot.capture(
                os.stat(entry.components[-1], dir_fd=parent_fd, follow_symlinks=False)
            )
            if opened != entry.snapshot or named != entry.snapshot:
                raise PortableBundleError("portable source entry changed during construction")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)


def _hash_source_file(
    root_fd: int,
    components: tuple[str, ...],
    expected: _Snapshot,
) -> tuple[int, str]:
    parent_fd, file_fd = _open_source_file(root_fd, components)
    try:
        if _Snapshot.capture(os.fstat(file_fd)) != expected:
            raise PortableBundleError("portable source file changed before hashing")
        crc32 = 0
        digest = hashlib.sha256()
        remaining = expected.size
        while remaining:
            chunk = os.read(file_fd, min(remaining, _READ_BYTES))
            if not chunk:
                raise PortableBundleError("portable source file became shorter")
            remaining -= len(chunk)
            crc32 = zlib.crc32(chunk, crc32)
            digest.update(chunk)
        if os.read(file_fd, 1):
            raise PortableBundleError("portable source file became longer")
        final = _Snapshot.capture(os.fstat(file_fd))
        named = _Snapshot.capture(os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False))
        if final != expected or named != expected:
            raise PortableBundleError("portable source file changed while hashing")
        return crc32 & 0xFFFFFFFF, digest.hexdigest()
    finally:
        os.close(file_fd)
        os.close(parent_fd)


def _checksums(entries: tuple[_SourceEntry, ...], manifest_bytes: bytes) -> bytes:
    records: list[tuple[bytes, str]] = [
        (b"format.json", hashlib.sha256(FORMAT_BYTES).hexdigest()),
        (b"manifest.json", hashlib.sha256(manifest_bytes).hexdigest()),
    ]
    for entry in entries:
        if not entry.is_directory:
            if entry.sha256 is None:
                raise PortableBundleError("portable regular file has no content checksum")
            records.append((b"content/" + entry.path_bytes, entry.sha256))
    encoded = b"".join(
        digest.encode("ascii") + b"  " + path + b"\n"
        for path, digest in sorted(records, key=lambda item: item[0])
    )
    if len(encoded) > MAXIMUM_CHECKSUM_BYTES:
        raise PortableBundleError("portable checksum manifest crosses its byte boundary")
    return encoded


def _envelope_name(relative: str) -> bytes:
    return f"{PORTABLE_ENVELOPE}/{relative}".encode()


def _content_name(path: bytes, *, is_directory: bool) -> bytes:
    suffix = b"/" if is_directory else b""
    return PORTABLE_ENVELOPE.encode("ascii") + b"/content/" + path + suffix


def _write_bytes_member(  # noqa: PLR0913 - canonical ZIP fields remain explicit
    output_fd: int,
    digest: _DigestWriter,
    records: list[_CentralRecord],
    *,
    offset: int,
    name: bytes,
    data: bytes,
) -> int:
    crc32 = zlib.crc32(data) & 0xFFFFFFFF
    record = _CentralRecord(name, crc32, len(data), _REGULAR_ATTRIBUTES, offset)
    offset = _write_local(output_fd, digest, record, offset=offset)
    offset = _write_output(output_fd, digest, data, offset=offset)
    records.append(record)
    return offset


def _write_directory_member(
    output_fd: int,
    digest: _DigestWriter,
    records: list[_CentralRecord],
    *,
    offset: int,
    name: bytes,
) -> int:
    record = _CentralRecord(name, 0, 0, _DIRECTORY_ATTRIBUTES, offset)
    offset = _write_local(output_fd, digest, record, offset=offset)
    records.append(record)
    return offset


def _write_file_member(  # noqa: PLR0913 - canonical ZIP fields remain explicit
    root_fd: int,
    output_fd: int,
    digest: _DigestWriter,
    records: list[_CentralRecord],
    entry: _SourceEntry,
    *,
    offset: int,
    name: bytes,
) -> int:
    record = _CentralRecord(name, entry.crc32, entry.snapshot.size, _REGULAR_ATTRIBUTES, offset)
    offset = _write_local(output_fd, digest, record, offset=offset)
    parent_fd, file_fd = _open_source_file(root_fd, entry.components)
    try:
        if _Snapshot.capture(os.fstat(file_fd)) != entry.snapshot:
            raise PortableBundleError("portable source file changed before encoding")
        remaining = entry.snapshot.size
        while remaining:
            chunk = os.read(file_fd, min(remaining, _READ_BYTES))
            if not chunk:
                raise PortableBundleError("portable source file became shorter while encoding")
            remaining -= len(chunk)
            offset = _write_output(output_fd, digest, chunk, offset=offset)
        if os.read(file_fd, 1):
            raise PortableBundleError("portable source file became longer while encoding")
        final = _Snapshot.capture(os.fstat(file_fd))
        named = _Snapshot.capture(
            os.stat(entry.components[-1], dir_fd=parent_fd, follow_symlinks=False)
        )
        if final != entry.snapshot or named != entry.snapshot:
            raise PortableBundleError("portable source file changed while encoding")
    finally:
        os.close(file_fd)
        os.close(parent_fd)
    records.append(record)
    return offset


def _write_local(
    output_fd: int,
    digest: _DigestWriter,
    record: _CentralRecord,
    *,
    offset: int,
) -> int:
    header = _LOCAL.pack(
        _LOCAL_SIGNATURE,
        _VERSION_NEEDED,
        _UTF8_FLAG,
        _STORED_METHOD,
        _DOS_TIME,
        _DOS_DATE,
        record.crc32,
        record.size,
        record.size,
        len(record.name),
        0,
    )
    offset = _write_output(output_fd, digest, header, offset=offset)
    return _write_output(output_fd, digest, record.name, offset=offset)


def _write_central(
    output_fd: int,
    digest: _DigestWriter,
    records: list[_CentralRecord],
    *,
    offset: int,
) -> int:
    central_offset = offset
    for record in records:
        header = _CENTRAL.pack(
            _CENTRAL_SIGNATURE,
            _MADE_BY,
            _VERSION_NEEDED,
            _UTF8_FLAG,
            _STORED_METHOD,
            _DOS_TIME,
            _DOS_DATE,
            record.crc32,
            record.size,
            record.size,
            len(record.name),
            0,
            0,
            0,
            0,
            record.external_attributes,
            record.local_offset,
        )
        offset = _write_output(output_fd, digest, header, offset=offset)
        offset = _write_output(output_fd, digest, record.name, offset=offset)
    end = _EOCD.pack(
        _EOCD_SIGNATURE,
        0,
        0,
        len(records),
        len(records),
        offset - central_offset,
        central_offset,
        0,
    )
    return _write_output(output_fd, digest, end, offset=offset)


def _write_output(
    output_fd: int,
    digest: _DigestWriter,
    data: bytes,
    *,
    offset: int,
) -> int:
    projected = offset + len(data)
    if projected > MAXIMUM_PORTABLE_BUNDLE_BYTES:
        raise PortableBundleError("portable bundle crosses its byte boundary")
    remaining = memoryview(data)
    while remaining:
        written = os.write(output_fd, remaining)
        if written <= 0:
            raise PortableBundleError("portable bundle write made no progress")
        digest.update(bytes(remaining[:written]))
        remaining = remaining[written:]
    return projected


def _remove_output(parent_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    os.fsync(parent_fd)
