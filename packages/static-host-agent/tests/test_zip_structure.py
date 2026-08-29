from __future__ import annotations

import hashlib
import os
import stat
import struct
import tempfile
import zlib
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path

import lowerduckpond_static_host_agent.zip_structure as zip_structure_module
import pytest
from hypothesis import HealthCheck, given, settings, strategies
from lowerduckpond_static_host_agent import (
    CapacityProjection,
    CapacityRejectedError,
    FilesystemCapacity,
    InodeAllocation,
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    ReleaseCapacityUsage,
    ZipEntryType,
    ZipExtraction,
    ZipExtractionError,
    ZipLimits,
    ZipStructure,
    ZipStructureError,
    inspect_deployment_zip,
)
from lowerduckpond_static_host_agent import (
    extract_deployment_zip as _extract_deployment_zip,
)

_OWNER = os.geteuid()
_LOCAL = struct.Struct("<I5H3I2H")
_CENTRAL = struct.Struct("<I6H3I5H2I")
_EOCD = struct.Struct("<I4H2IH")
_LOCAL_SIGNATURE = 0x04034B50
_CENTRAL_SIGNATURE = 0x02014B50
_EOCD_SIGNATURE = 0x06054B50
_UTF8_FLAG = 0x0800
_STORED = 0
_DEFLATE = 8
_REGULAR_ATTRIBUTES = (stat.S_IFREG | 0o644) << 16
_DIRECTORY_ATTRIBUTES = ((stat.S_IFDIR | 0o755) << 16) | 0x10
_UNIX_VERSION = 0x0314
_DECODER_VERSION = 20
_CENTRAL_COMPRESSED_SIZE_OFFSET = 20
_CENTRAL_EXPANDED_SIZE_OFFSET = 24
_CENTRAL_LOCAL_OFFSET = 42
_LOCAL_FLAGS_OFFSET = 6
_LOCAL_METHOD_OFFSET = 8
_LOCAL_COMPRESSED_SIZE_OFFSET = 18
_LOCAL_EXPANDED_SIZE_OFFSET = 22
_FINAL_PATH_STAT_CALL = 2
_MAXIMUM_ENTRIES = 5_000
_NORMALIZED_DIRECTORY_MODE = 0o755
_NORMALIZED_FILE_MODE = 0o644
_CAPACITY_CHECKS = 2
_MAXIMUM_VALIDATION_DESCRIPTORS = 16


@pytest.fixture(autouse=True)
def _reported_inode_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give the container overlay the concrete inode counts production ext4 reports."""

    def measure(file_descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            device=os.fstat(file_descriptor).st_dev,
            fragment_size=4_096,
            total_blocks=4_000_000,
            available_blocks=3_000_000,
            total_inodes=4_000_000,
            available_inodes=3_000_000,
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.zip_structure.measure_filesystem_capacity_descriptor",
        measure,
    )


@dataclass(frozen=True, slots=True)
class _MemberSpec:
    name: bytes
    content: bytes = b""
    method: int = _STORED
    flags: int = 0
    external_attributes: int = _REGULAR_ATTRIBUTES
    made_by: int = _UNIX_VERSION
    version_needed: int = _DECODER_VERSION
    local_extra: bytes = b""
    central_extra: bytes = b""
    compressed: bytes | None = None
    crc32: int | None = None
    expanded_bytes: int | None = None
    local_offset: int | None = None


def _deflate(content: bytes) -> bytes:
    encoder = zlib.compressobj(level=6, wbits=-15)
    return encoder.compress(content) + encoder.flush()


def _archive(*members: _MemberSpec, prefix: bytes = b"") -> bytes:
    local = bytearray(prefix)
    central = bytearray()
    central_records: list[tuple[_MemberSpec, int, bytes, int, int]] = []
    for member in members:
        compressed = member.compressed
        if compressed is None:
            compressed = _deflate(member.content) if member.method == _DEFLATE else member.content
        crc32 = zlib.crc32(member.content) if member.crc32 is None else member.crc32
        expanded = len(member.content) if member.expanded_bytes is None else member.expanded_bytes
        local_offset = len(local)
        local.extend(
            _LOCAL.pack(
                _LOCAL_SIGNATURE,
                member.version_needed,
                member.flags,
                member.method,
                0,
                0,
                crc32,
                len(compressed),
                expanded,
                len(member.name),
                len(member.local_extra),
            )
        )
        local.extend(member.name)
        local.extend(member.local_extra)
        local.extend(compressed)
        central_records.append((member, local_offset, compressed, crc32, expanded))
    central_offset = len(local)
    for member, actual_offset, compressed, crc32, expanded in central_records:
        central.extend(
            _CENTRAL.pack(
                _CENTRAL_SIGNATURE,
                member.made_by,
                member.version_needed,
                member.flags,
                member.method,
                0,
                0,
                crc32,
                len(compressed),
                expanded,
                len(member.name),
                len(member.central_extra),
                0,
                0,
                0,
                member.external_attributes,
                actual_offset if member.local_offset is None else member.local_offset,
            )
        )
        central.extend(member.name)
        central.extend(member.central_extra)
    return bytes(
        local
        + central
        + _EOCD.pack(
            _EOCD_SIGNATURE,
            0,
            0,
            len(members),
            len(members),
            len(central),
            central_offset,
            0,
        )
    )


def _write(tmp_path: Path, data: bytes, name: str = "deployment.zip") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _staging_parent(tmp_path: Path) -> Path:
    parent = tmp_path / "staging"
    parent.mkdir()
    parent.chmod(0o700)
    return parent


def _extract_with_intake_lock(
    path: Path,
    *,
    staging_parent: Path,
    staging_name: str,
    expected_owner: int,
    retained_usage: ReleaseCapacityUsage,
) -> ZipExtraction:
    lock_root = path.parent / ".intake-locks"
    lock_root.mkdir(mode=0o700, exist_ok=True)
    lock_root.chmod(0o700)
    with (
        LockManager.initialize(lock_root, expected_owner=expected_owner) as manager,
        manager.acquire(LockName.INTAKE),
    ):
        return _extract_deployment_zip(
            path,
            staging_parent=staging_parent,
            staging_name=staging_name,
            expected_owner=expected_owner,
            retained_usage=retained_usage,
            lock_manager=manager,
        )


def _extract(tmp_path: Path, data: bytes, name: str = "candidate") -> tuple[Path, ZipExtraction]:
    source = _write(tmp_path, data)
    parent = _staging_parent(tmp_path)
    result = _extract_with_intake_lock(
        source,
        staging_parent=parent,
        staging_name=name,
        expected_owner=_OWNER,
        retained_usage=ReleaseCapacityUsage(()),
    )
    return parent, result


def _inspect(
    tmp_path: Path,
    data: bytes,
    *,
    limits: ZipLimits | None = None,
) -> ZipStructure:
    path = _write(tmp_path, data)
    if limits is None:
        return inspect_deployment_zip(path, expected_owner=_OWNER)
    return inspect_deployment_zip(path, expected_owner=_OWNER, limits=limits)


def _central_offset(data: bytes) -> int:
    return int(_EOCD.unpack(data[-_EOCD.size :])[6])


def _replace_u16(data: bytes, offset: int, value: int) -> bytes:
    changed = bytearray(data)
    struct.pack_into("<H", changed, offset, value)
    return bytes(changed)


def _replace_u32(data: bytes, offset: int, value: int) -> bytes:
    changed = bytearray(data)
    struct.pack_into("<I", changed, offset, value)
    return bytes(changed)


def test_accepts_bounded_stored_and_deflated_members(tmp_path: Path) -> None:
    data = _archive(
        _MemberSpec(name=b"index.html", content=b"home"),
        _MemberSpec(
            name="nested/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt".encode(),
            content=b"compressed content" * 8,
            method=_DEFLATE,
            flags=_UTF8_FLAG,
        ),
    )

    structure = _inspect(tmp_path, data)

    assert structure.artifact_sha256 == hashlib.sha256(data).hexdigest()
    assert structure.archive_bytes == len(data)
    assert structure.expanded_regular_file_bytes == len(b"home") + len(b"compressed content" * 8)
    assert structure.materialized_paths == (
        "index.html",
        "nested",
        "nested/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt",
    )
    assert [member.entry_type for member in structure.members] == [
        ZipEntryType.REGULAR_FILE,
        ZipEntryType.REGULAR_FILE,
    ]
    assert [member.compression_method for member in structure.members] == [_STORED, _DEFLATE]


def test_explicit_directory_can_merge_with_its_implicit_parent(tmp_path: Path) -> None:
    structure = _inspect(
        tmp_path,
        _archive(
            _MemberSpec(
                name=b"assets/",
                external_attributes=_DIRECTORY_ATTRIBUTES,
            ),
            _MemberSpec(name=b"assets/site.css", content=b"body{}"),
            _MemberSpec(name=b"index.html", content=b"home"),
        ),
    )

    assert structure.materialized_paths == ("assets", "assets/site.css", "index.html")


@pytest.mark.parametrize(
    ("members", "message"),
    [
        ((_MemberSpec(name=b"nested/file.txt"),), "root-level index"),
        (
            (
                _MemberSpec(name=b"index.html"),
                _MemberSpec(name=b"index.html"),
            ),
            "duplicate explicit",
        ),
        (
            (
                _MemberSpec(name=b"index.html"),
                _MemberSpec(name=b"A.txt"),
                _MemberSpec(name=b"a.txt"),
            ),
            "case-folding collision",
        ),
        (
            (
                _MemberSpec(name=b"index.html"),
                _MemberSpec(name="e\N{COMBINING ACUTE ACCENT}.txt".encode(), flags=_UTF8_FLAG),
                _MemberSpec(
                    name="\N{LATIN SMALL LETTER E WITH ACUTE}.txt".encode(), flags=_UTF8_FLAG
                ),
            ),
            "NFC normalization",
        ),
        (
            (
                _MemberSpec(name=b"index.html"),
                _MemberSpec(name=b"node", content=b"file"),
                _MemberSpec(name=b"node/child.txt"),
            ),
            "both a file and a directory",
        ),
    ],
)
def test_tree_collisions_and_missing_index_fail_closed(
    tmp_path: Path,
    members: tuple[_MemberSpec, ...],
    message: str,
) -> None:
    with pytest.raises(ZipStructureError, match=message):
        _inspect(tmp_path, _archive(*members))


@pytest.mark.parametrize(
    "name",
    [
        b"../index.html",
        b"/index.html",
        b"C:/index.html",
        b"a//index.html",
        b"./index.html",
        b"index.html/",
        b"line\nfeed/index.html",
        b"back\\slash/index.html",
        b"cdn-cgi/index.html",
        b"CDN-CGI/index.html",
    ],
)
def test_ambiguous_or_reserved_paths_fail_closed(tmp_path: Path, name: bytes) -> None:
    with pytest.raises(ZipStructureError):
        _inspect(tmp_path, _archive(_MemberSpec(name=name)))


def test_non_ascii_name_requires_utf8_flag(tmp_path: Path) -> None:
    with pytest.raises(ZipStructureError, match="encoding flag"):
        _inspect(
            tmp_path,
            _archive(_MemberSpec(name="\N{LATIN SMALL LETTER E WITH ACUTE}.html".encode())),
        )


@pytest.mark.parametrize(
    ("limits", "name", "message"),
    [
        (ZipLimits(maximum_component_bytes=4), b"index.html", "component"),
        (ZipLimits(maximum_path_bytes=9), b"index.html", "path crosses"),
        (ZipLimits(maximum_path_depth=1), b"a/index.html", "depth"),
        (ZipLimits(maximum_entries=1), b"a/index.html", "entry boundary"),
    ],
)
def test_tightened_path_and_materialization_limits_are_enforced(
    tmp_path: Path,
    limits: ZipLimits,
    name: bytes,
    message: str,
) -> None:
    with pytest.raises(ZipStructureError, match=message):
        _inspect(tmp_path, _archive(_MemberSpec(name=name)), limits=limits)


@pytest.mark.parametrize("method", [1, 9, 12, 14, 93])
def test_only_stored_and_deflate_methods_are_accepted(tmp_path: Path, method: int) -> None:
    with pytest.raises(ZipStructureError, match="compression method"):
        _inspect(tmp_path, _archive(_MemberSpec(name=b"index.html", method=method)))


@pytest.mark.parametrize("flags", [0x0001, 0x0008, 0x0010, 0x2000])
def test_encryption_descriptors_and_unknown_flags_are_rejected(
    tmp_path: Path,
    flags: int,
) -> None:
    with pytest.raises(ZipStructureError, match="flags"):
        _inspect(tmp_path, _archive(_MemberSpec(name=b"index.html", flags=flags)))


@pytest.mark.parametrize("unix_type", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK])
def test_link_and_special_inode_types_are_rejected(tmp_path: Path, unix_type: int) -> None:
    member = _MemberSpec(
        name=b"index.html",
        external_attributes=(unix_type | 0o644) << 16,
    )
    with pytest.raises(ZipStructureError, match="link or special"):
        _inspect(tmp_path, _archive(member))


@pytest.mark.parametrize(
    "member",
    [
        _MemberSpec(name=b"index.html/", external_attributes=_REGULAR_ATTRIBUTES),
        _MemberSpec(name=b"index.html", external_attributes=_DIRECTORY_ATTRIBUTES),
    ],
)
def test_inode_attributes_must_agree_with_name_marker(
    tmp_path: Path,
    member: _MemberSpec,
) -> None:
    with pytest.raises(ZipStructureError, match="disagrees"):
        _inspect(tmp_path, _archive(member))


def test_unix_regular_file_cannot_also_claim_the_dos_directory_type(tmp_path: Path) -> None:
    member = _MemberSpec(
        name=b"index.html",
        external_attributes=_REGULAR_ATTRIBUTES | 0x10,
    )

    with pytest.raises(ZipStructureError, match="DOS and Unix inode types disagree"):
        _inspect(tmp_path, _archive(member))


def test_local_and_central_records_must_agree(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html", content=b"home"))
    changed = _replace_u16(data, _LOCAL_METHOD_OFFSET, _DEFLATE)
    with pytest.raises(ZipStructureError, match="local header disagrees"):
        _inspect(tmp_path, changed)


def test_local_and_central_supported_timestamp_fields_may_differ(tmp_path: Path) -> None:
    local_timestamp = struct.pack("<HHBII", 0x5455, 9, 3, 1, 2)
    central_timestamp = struct.pack("<HHBI", 0x5455, 5, 3, 1)

    structure = _inspect(
        tmp_path,
        _archive(
            _MemberSpec(
                name=b"index.html",
                local_extra=local_timestamp,
                central_extra=central_timestamp,
            )
        ),
    )

    assert structure.materialized_paths == ("index.html",)


@pytest.mark.parametrize(
    "extra",
    [
        struct.pack("<HH", 0x0001, 0),
        struct.pack("<HH", 0x5455, 8) + b"short",
        struct.pack("<HHB", 0x5455, 1, 0x08),
        struct.pack("<HH", 0x5455, 0),
        struct.pack("<HH", 0x5455, 1) + b"\0" + struct.pack("<HH", 0x5455, 1) + b"\0",
    ],
)
def test_unknown_or_malformed_extra_fields_are_rejected(tmp_path: Path, extra: bytes) -> None:
    with pytest.raises(ZipStructureError, match=r"extra|timestamp"):
        _inspect(
            tmp_path,
            _archive(_MemberSpec(name=b"index.html", local_extra=extra, central_extra=extra)),
        )


def test_supported_timestamp_extra_fields_are_accepted(tmp_path: Path) -> None:
    local_extended = struct.pack("<HHBII", 0x5455, 9, 3, 1, 2)
    central_extended = struct.pack("<HHBI", 0x5455, 5, 3, 1)
    ntfs_value = b"\0" * 4 + struct.pack("<HH", 1, 24) + b"\0" * 24
    ntfs = struct.pack("<HH", 0x000A, len(ntfs_value)) + ntfs_value

    structure = _inspect(
        tmp_path,
        _archive(
            _MemberSpec(
                name=b"index.html",
                local_extra=local_extended + ntfs,
                central_extra=central_extended + ntfs,
            )
        ),
    )

    assert structure.materialized_paths == ("index.html",)


def test_extra_field_byte_boundary_is_enforced(tmp_path: Path) -> None:
    extra = struct.pack("<HH", 0x5455, 0) + b"x" * 8
    limits = ZipLimits(maximum_extra_bytes=4)
    with pytest.raises(ZipStructureError, match="extra field crosses"):
        _inspect(
            tmp_path,
            _archive(_MemberSpec(name=b"index.html", local_extra=extra, central_extra=extra)),
            limits=limits,
        )


def test_prepended_bytes_are_rejected_as_unclaimed_local_padding(tmp_path: Path) -> None:
    with pytest.raises(ZipStructureError, match="padding"):
        _inspect(tmp_path, _archive(_MemberSpec(name=b"index.html"), prefix=b"hostile"))


@pytest.mark.parametrize("suffix", [b"x", b"\0" * _EOCD.size, b"comment"])
def test_trailing_bytes_and_archive_comments_are_rejected(tmp_path: Path, suffix: bytes) -> None:
    data = _archive(_MemberSpec(name=b"index.html")) + suffix
    with pytest.raises(ZipStructureError, match="end record"):
        _inspect(tmp_path, data)


def test_duplicate_local_offset_is_rejected(tmp_path: Path) -> None:
    data = _archive(
        _MemberSpec(name=b"index.html"),
        _MemberSpec(name=b"other.txt", local_offset=0),
    )
    with pytest.raises(ZipStructureError, match="overlap, alias, or leave padding"):
        _inspect(tmp_path, data)


def test_central_directory_bounds_and_record_count_are_enforced(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html"))
    eocd_offset = len(data) - _EOCD.size
    wrong_count = _replace_u16(data, eocd_offset + 8, 2)
    wrong_count = _replace_u16(wrong_count, eocd_offset + 10, 2)
    with pytest.raises(ZipStructureError, match="central directory ends"):
        _inspect(tmp_path, wrong_count)

    wrong_offset = _replace_u32(data, eocd_offset + 16, _central_offset(data) + 1)
    with pytest.raises(ZipStructureError, match="not adjacent"):
        _inspect(tmp_path, wrong_offset)


def test_zip64_and_multi_disk_metadata_are_rejected(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html"))
    eocd_offset = len(data) - _EOCD.size
    zip64 = _replace_u16(data, eocd_offset + 8, 0xFFFF)
    zip64 = _replace_u16(zip64, eocd_offset + 10, 0xFFFF)
    with pytest.raises(ZipStructureError, match="ZIP64"):
        _inspect(tmp_path, zip64)

    multi_disk = _replace_u16(data, eocd_offset + 4, 1)
    with pytest.raises(ZipStructureError, match="multi-disk"):
        _inspect(tmp_path, multi_disk)


def test_declared_size_and_expansion_boundaries_are_enforced(tmp_path: Path) -> None:
    content = b"x" * 101
    compressed = b"x"
    member = _MemberSpec(
        name=b"index.html",
        method=_DEFLATE,
        content=content,
        compressed=compressed,
    )
    with pytest.raises(ZipStructureError, match="expansion-ratio"):
        _inspect(tmp_path, _archive(member))

    with pytest.raises(ZipStructureError, match="expanded-byte boundary"):
        _inspect(
            tmp_path,
            _archive(replace(member, content=b"small", expanded_bytes=11, compressed=b"x" * 11)),
            limits=ZipLimits(maximum_file_bytes=10),
        )


def test_archive_and_central_directory_byte_limits_are_enforced(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html", content=b"home"))
    with pytest.raises(ZipStructureError, match="compressed-byte boundary"):
        _inspect(tmp_path, data, limits=ZipLimits(maximum_archive_bytes=len(data) - 1))
    with pytest.raises(ZipStructureError, match="central directory"):
        _inspect(tmp_path, data, limits=ZipLimits(maximum_central_directory_bytes=1))


def test_snapshot_inode_mode_owner_and_link_count_are_fail_closed(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html"))
    path = _write(tmp_path, data)
    path.chmod(0o644)
    with pytest.raises(ZipStructureError, match="unsafe inode shape"):
        inspect_deployment_zip(path, expected_owner=_OWNER)

    path.chmod(0o600)
    os.link(path, tmp_path / "alias.zip")
    with pytest.raises(ZipStructureError, match="unsafe inode shape"):
        inspect_deployment_zip(path, expected_owner=_OWNER)

    path.unlink()
    symlink = tmp_path / "symlink.zip"
    symlink.symlink_to(tmp_path / "alias.zip")
    with pytest.raises(ZipStructureError, match="opened safely"):
        inspect_deployment_zip(symlink, expected_owner=_OWNER)


def test_fifo_snapshot_fails_without_waiting_for_a_writer(tmp_path: Path) -> None:
    path = tmp_path / "deployment.zip"
    os.mkfifo(path, mode=0o600)

    with pytest.raises(ZipStructureError, match="unsafe inode shape"):
        inspect_deployment_zip(path, expected_owner=_OWNER)


def test_final_named_inode_check_detects_same_inode_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    real_stat = Path.stat
    path_stats = 0

    def mutate_before_final_stat(
        candidate: Path,
        *,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal path_stats
        if candidate == path:
            path_stats += 1
            if path_stats == _FINAL_PATH_STAT_CALL:
                os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        return real_stat(candidate, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", mutate_before_final_stat)

    with pytest.raises(ZipStructureError, match="changed during structural inspection"):
        inspect_deployment_zip(path, expected_owner=_OWNER)


def test_limits_are_tighten_only_nonnegative_integers() -> None:
    with pytest.raises(ValueError, match="cannot weaken"):
        ZipLimits(maximum_entries=5_001)
    with pytest.raises(ValueError, match="nonnegative integers"):
        ZipLimits(maximum_entries=-1)
    with pytest.raises(ValueError, match="nonnegative integers"):
        ZipLimits(maximum_entries=True)


def test_local_size_mutation_is_rejected_before_any_decoder(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html", content=b"home"))
    changed = _replace_u32(data, _LOCAL_COMPRESSED_SIZE_OFFSET, 3)
    changed = _replace_u32(changed, _LOCAL_EXPANDED_SIZE_OFFSET, 3)
    with pytest.raises(ZipStructureError, match="local header disagrees"):
        _inspect(tmp_path, changed)


def test_central_size_mutation_cannot_alias_decoder_input(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html", content=b"home"))
    central = _central_offset(data)
    changed = _replace_u32(data, central + _CENTRAL_COMPRESSED_SIZE_OFFSET, 3)
    changed = _replace_u32(changed, central + _CENTRAL_EXPANDED_SIZE_OFFSET, 3)
    with pytest.raises(ZipStructureError):
        _inspect(tmp_path, changed)


def test_central_local_offset_outside_snapshot_is_rejected(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html"))
    changed = _replace_u32(data, _central_offset(data) + _CENTRAL_LOCAL_OFFSET, len(data))
    with pytest.raises(ZipStructureError, match="outside the snapshot"):
        _inspect(tmp_path, changed)


def test_local_flag_mutation_is_rejected(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html"))
    changed = _replace_u16(data, _LOCAL_FLAGS_OFFSET, _UTF8_FLAG)
    with pytest.raises(ZipStructureError, match="local header disagrees"):
        _inspect(tmp_path, changed)


def test_dos_volume_label_is_rejected_as_a_special_inode(tmp_path: Path) -> None:
    with pytest.raises(ZipStructureError, match="volume-label"):
        _inspect(
            tmp_path,
            _archive(
                _MemberSpec(
                    name=b"index.html",
                    made_by=_DECODER_VERSION,
                    external_attributes=0x08,
                )
            ),
        )


def test_shared_implicit_parents_coalesce_at_the_entry_boundary(tmp_path: Path) -> None:
    parent = "/".join(f"p{index}" for index in range(31))
    maximum_files = _MAXIMUM_ENTRIES - 31 - 1
    members = [_MemberSpec(name=b"index.html")]
    members.extend(
        _MemberSpec(name=f"{parent}/f{index:04}.txt".encode()) for index in range(maximum_files)
    )

    structure = _inspect(tmp_path, _archive(*members))

    assert structure.materialized_entry_count == _MAXIMUM_ENTRIES


@given(strategies.binary(max_size=2_048))
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_arbitrary_structural_bytes_fail_only_with_the_domain_error(
    tmp_path: Path,
    data: bytes,
) -> None:
    with suppress(ZipStructureError):
        _inspect(tmp_path, data)


def test_extraction_streams_stored_and_deflated_files_into_normalized_tree(
    tmp_path: Path,
) -> None:
    data = _archive(
        _MemberSpec(
            name=b"index.html",
            content=b"home",
            external_attributes=(stat.S_IFREG | 0o777) << 16,
        ),
        _MemberSpec(
            name=b"assets/",
            external_attributes=((stat.S_IFDIR | 0o700) << 16) | 0x10,
        ),
        _MemberSpec(
            name=b"assets/site.css",
            content=b"body { color: green; }" * 100,
            method=_DEFLATE,
        ),
        _MemberSpec(name=b"empty.txt"),
    )

    parent, result = _extract(tmp_path, data)
    root = parent / result.staging_name

    assert result.structure.artifact_sha256 == hashlib.sha256(data).hexdigest()
    assert (root / "index.html").read_bytes() == b"home"
    assert (root / "assets/site.css").read_bytes() == b"body { color: green; }" * 100
    assert (root / "empty.txt").read_bytes() == b""
    assert stat.S_IMODE(root.stat().st_mode) == _NORMALIZED_DIRECTORY_MODE
    assert stat.S_IMODE((root / "assets").stat().st_mode) == _NORMALIZED_DIRECTORY_MODE
    assert stat.S_IMODE((root / "index.html").stat().st_mode) == _NORMALIZED_FILE_MODE
    assert result.unique_inodes == result.structure.materialized_entry_count + 1
    assert result.allocated_bytes <= result.capacity_projection.projected_allocated_bytes


def test_extraction_requires_the_exclusive_intake_lock(tmp_path: Path) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    lock_root = tmp_path / "locks"
    lock_root.mkdir(mode=0o700)

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.INTAKE, mode=LockMode.SHARED),
        pytest.raises(LockOrderError, match="exclusive"),
    ):
        _extract_deployment_zip(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
            lock_manager=manager,
        )

    assert list(parent.iterdir()) == []


@pytest.mark.parametrize("method", [_STORED, _DEFLATE])
def test_extraction_rechecks_crc_and_removes_partial_tree(
    tmp_path: Path,
    method: int,
) -> None:
    data = bytearray(_archive(_MemberSpec(name=b"index.html", content=b"content", method=method)))
    data_offset = _LOCAL.size + len(b"index.html")
    data[data_offset] ^= 0xFF
    source = _write(tmp_path, bytes(data))
    parent = _staging_parent(tmp_path)

    with pytest.raises(ZipExtractionError):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert list(parent.iterdir()) == []


@pytest.mark.parametrize("declared_size", [3, 5])
def test_extraction_rechecks_observed_expanded_size(
    tmp_path: Path,
    declared_size: int,
) -> None:
    data = _archive(
        _MemberSpec(
            name=b"index.html",
            content=b"home",
            method=_DEFLATE,
            expanded_bytes=declared_size,
        )
    )
    source = _write(tmp_path, data)
    parent = _staging_parent(tmp_path)

    with pytest.raises(ZipExtractionError, match="observed"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert not (parent / "candidate").exists()


def test_extraction_rejects_deflate_data_after_the_stream_end(tmp_path: Path) -> None:
    content = b"home"
    data = _archive(
        _MemberSpec(
            name=b"index.html",
            content=content,
            method=_DEFLATE,
            compressed=_deflate(content) + b"trailing",
        )
    )
    source = _write(tmp_path, data)
    parent = _staging_parent(tmp_path)

    with pytest.raises(ZipExtractionError, match="declared boundary"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert not (parent / "candidate").exists()


def test_extraction_never_writes_more_than_the_declared_size(tmp_path: Path) -> None:
    content = b"x" * 10_000
    data = _archive(
        _MemberSpec(
            name=b"index.html",
            content=content,
            method=_DEFLATE,
            expanded_bytes=1,
        )
    )
    source = _write(tmp_path, data)
    parent = _staging_parent(tmp_path)

    with pytest.raises(ZipExtractionError, match="observed file bytes"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert not (parent / "candidate").exists()


def test_extraction_refuses_an_existing_destination_without_removing_it(tmp_path: Path) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html")))
    parent = _staging_parent(tmp_path)
    existing = parent / "candidate"
    existing.mkdir()
    marker = existing / "marker"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(ZipExtractionError, match="could not complete safely"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert marker.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b", "line\nfeed"])
def test_extraction_requires_one_canonical_staging_component(
    tmp_path: Path,
    name: str,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html")))
    parent = _staging_parent(tmp_path)
    with pytest.raises(ValueError, match="staging name"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name=name,
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )


def test_extraction_requires_a_private_owned_staging_parent(tmp_path: Path) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html")))
    parent = _staging_parent(tmp_path)
    parent.chmod(0o755)

    with pytest.raises(ZipExtractionError, match="staging parent"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )


def test_extraction_allows_artifact_and_staging_on_different_filesystems(
    tmp_path: Path,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    try:
        temporary = tempfile.TemporaryDirectory(dir="/dev/shm")
    except FileNotFoundError, PermissionError:
        pytest.skip("no writable independent tmpfs is available")
    with temporary:
        parent = Path(temporary.name)
        parent.chmod(0o700)
        if source.stat().st_dev == parent.stat().st_dev:
            pytest.skip("the available staging root is not an independent filesystem")

        result = _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

        assert (parent / result.staging_name / "index.html").read_bytes() == b"home"


def test_extraction_validation_bounds_descriptors_for_a_wide_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directories = tuple(
        _MemberSpec(
            name=f"directory-{index:04d}/".encode(),
            external_attributes=_DIRECTORY_ATTRIBUTES,
        )
        for index in range(64)
    )
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html"), *directories))
    parent = _staging_parent(tmp_path)
    real_open = os.open
    real_close = os.close
    tracked: set[int] = set()
    peak = 0

    def track_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal peak
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        tracked.add(descriptor)
        peak = max(peak, len(tracked))
        return descriptor

    def track_close(descriptor: int) -> None:
        tracked.discard(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "close", track_close)

    _extract_with_intake_lock(
        source,
        staging_parent=parent,
        staging_name="candidate",
        expected_owner=_OWNER,
        retained_usage=ReleaseCapacityUsage(()),
    )

    assert peak < _MAXIMUM_VALIDATION_DESCRIPTORS


def test_extraction_runs_capacity_admission_before_creating_the_tree(tmp_path: Path) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    device = parent.stat().st_dev
    retained = ReleaseCapacityUsage((InodeAllocation(device, 1, 10 * 1024 * 1024 * 1024),))

    with pytest.raises(CapacityRejectedError, match="host byte ceiling"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=retained,
        )

    assert list(parent.iterdir()) == []


def test_extraction_detects_source_mutation_and_removes_the_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _archive(_MemberSpec(name=b"index.html", content=b"home"))
    source = _write(tmp_path, data)
    parent = _staging_parent(tmp_path)
    original_write = os.write
    changed = False

    def mutate_after_write(file_descriptor: int, content: bytes | memoryview) -> int:
        nonlocal changed
        written = original_write(file_descriptor, content)
        if not changed:
            changed = True
            with source.open("r+b") as mutable:
                mutable.seek(_LOCAL.size + len(b"index.html"))
                byte = mutable.read(1)
                mutable.seek(-1, os.SEEK_CUR)
                mutable.write(bytes([byte[0] ^ 0xFF]))
                mutable.flush()
                os.fsync(mutable.fileno())
        return written

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.zip_structure.os.write",
        mutate_after_write,
    )

    with pytest.raises(ZipExtractionError, match="changed during extraction"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert not (parent / "candidate").exists()


def test_extraction_rechecks_the_free_space_floor_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    calls = 0

    def capacity(file_descriptor: int) -> FilesystemCapacity:
        nonlocal calls
        calls += 1
        return FilesystemCapacity(
            device=os.fstat(file_descriptor).st_dev,
            fragment_size=4_096,
            total_blocks=4_000_000,
            available_blocks=3_000_000 if calls == 1 else 1,
            total_inodes=4_000_000,
            available_inodes=3_000_000,
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.zip_structure.measure_filesystem_capacity_descriptor",
        capacity,
    )

    with pytest.raises(ZipExtractionError, match="free-space floor"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert calls == _CAPACITY_CHECKS
    assert not (parent / "candidate").exists()


def test_extraction_revalidates_the_named_staging_parent_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    moved_parent = tmp_path / "moved-staging"
    real_validate = zip_structure_module._validate_remaining_capacity

    def replace_parent(
        parent_fd: int,
        projection: CapacityProjection,
    ) -> None:
        real_validate(parent_fd, projection)
        parent.rename(moved_parent)
        parent.mkdir(mode=0o700)

    monkeypatch.setattr(zip_structure_module, "_validate_remaining_capacity", replace_parent)

    with pytest.raises(ZipExtractionError, match="staging parent changed"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert list(parent.iterdir()) == []
    assert list(moved_parent.iterdir()) == []


def test_extraction_does_not_remove_a_replacement_staging_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    candidate = parent / "candidate"
    moved_candidate = parent / "moved-candidate"
    real_validate = zip_structure_module._validate_remaining_capacity

    def replace_candidate(
        parent_fd: int,
        projection: CapacityProjection,
    ) -> None:
        real_validate(parent_fd, projection)
        candidate.rename(moved_candidate)
        candidate.mkdir(mode=0o755)
        (candidate / "unrelated").write_bytes(b"keep")

    monkeypatch.setattr(zip_structure_module, "_validate_remaining_capacity", replace_candidate)

    with pytest.raises(ZipExtractionError, match="staging candidate changed"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert (candidate / "unrelated").read_bytes() == b"keep"
    assert (moved_candidate / "index.html").read_bytes() == b"home"


def test_extraction_detects_candidate_replacement_between_creation_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    candidate = parent / "candidate"
    moved_candidate = parent / "moved-candidate"
    real_open = os.open
    replaced = False

    def replace_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == "candidate" and dir_fd is not None and not replaced:
            replaced = True
            candidate.rename(moved_candidate)
            candidate.mkdir(mode=_NORMALIZED_DIRECTORY_MODE)
            (candidate / "unrelated").write_bytes(b"keep")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_before_open)

    with pytest.raises(ZipExtractionError, match="changed while it was opened"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert (candidate / "unrelated").read_bytes() == b"keep"
    assert list(moved_candidate.iterdir()) == []


def test_extraction_removes_the_created_candidate_when_initial_open_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write(tmp_path, _archive(_MemberSpec(name=b"index.html", content=b"home")))
    parent = _staging_parent(tmp_path)
    real_open = os.open

    def fail_candidate_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "candidate" and dir_fd is not None:
            raise OSError("simulated descriptor exhaustion")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_candidate_open)

    with pytest.raises(ZipExtractionError, match="could not complete safely"):
        _extract_with_intake_lock(
            source,
            staging_parent=parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert list(parent.iterdir()) == []


@given(
    content=strategies.binary(max_size=65_536),
    method=strategies.sampled_from([_STORED, _DEFLATE]),
)
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_bounded_valid_content_round_trips_through_extraction(
    content: bytes,
    method: int,
) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        parent, result = _extract(
            root,
            _archive(_MemberSpec(name=b"index.html", content=content, method=method)),
        )

        assert (parent / result.staging_name / "index.html").read_bytes() == content
