from __future__ import annotations

import hashlib
import os
import stat
import struct
import zlib
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies
from lowerduckpond_static_host_agent import (
    ZipEntryType,
    ZipLimits,
    ZipStructure,
    ZipStructureError,
    inspect_deployment_zip,
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


def test_local_and_central_records_must_agree(tmp_path: Path) -> None:
    data = _archive(_MemberSpec(name=b"index.html", content=b"home"))
    changed = _replace_u16(data, _LOCAL_METHOD_OFFSET, _DEFLATE)
    with pytest.raises(ZipStructureError, match="local header disagrees"):
        _inspect(tmp_path, changed)


def test_local_and_central_supported_timestamp_fields_may_differ(tmp_path: Path) -> None:
    local_timestamp = struct.pack("<HHBII", 0x5455, 9, 3, 1, 2)
    central_timestamp = struct.pack("<HHBI", 0x5455, 5, 1, 1)

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
    extended = struct.pack("<HHBII", 0x5455, 9, 3, 1, 2)
    ntfs_value = b"\0" * 4 + struct.pack("<HH", 1, 24) + b"\0" * 24
    ntfs = struct.pack("<HH", 0x000A, len(ntfs_value)) + ntfs_value

    structure = _inspect(
        tmp_path,
        _archive(
            _MemberSpec(
                name=b"index.html",
                local_extra=extended + ntfs,
                central_extra=extended + ntfs,
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
