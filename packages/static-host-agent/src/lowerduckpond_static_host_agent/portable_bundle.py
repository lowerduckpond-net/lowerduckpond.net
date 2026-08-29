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
    ContractKind,
    Digest,
    canonical_json_bytes,
    manifest_digest,
    validate_contract,
)

from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.release_tree import (
    DEFAULT_RELEASE_TREE_LIMITS,
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
