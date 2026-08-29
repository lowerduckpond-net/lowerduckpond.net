from __future__ import annotations

import hashlib
import os
import stat
import struct
import zipfile
import zlib
from pathlib import Path

import lowerduckpond_static_host_agent.portable_bundle as portable_bundle_module
import lowerduckpond_static_host_agent.zip_structure as zip_structure_module
import pytest
from lowerduckpond_static_contracts import ContractError, ContractKind, decode_contract
from lowerduckpond_static_host_agent import (
    FORMAT_BYTES,
    PORTABLE_BUNDLE_FORMAT,
    PORTABLE_ENVELOPE,
    FilesystemCapacity,
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    PortableBundle,
    PortableBundleError,
    ReleaseCapacityUsage,
    ZipLimits,
    ZipMember,
    ZipStructureError,
    build_portable_bundle,
    import_portable_bundle,
    inspect_deployment_zip,
    inspect_portable_bundle,
)

_OWNER = os.geteuid()
_FIXTURE = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted/site.json"
_DIRECTORY_MODE = 0o755
_FILE_MODE = 0o644
_PRIVATE_MODE = 0o700
_OUTPUT_MODE = 0o600
_MADE_BY_SYSTEM = 3
_VERSION = 20
_UTF8_FLAG = 0x0800
_REGULAR_ATTRIBUTES = 0x81A40000
_DIRECTORY_ATTRIBUTES = 0x41ED0010
_PINNED_BUNDLE_BYTES = 2_346
_PINNED_BUNDLE_SHA256 = "c949c78143843e2c867033e98d9ae8a43577250b0287aca63c0a95dde92a6f18"
_HARDLINK_TREE_COUNT = 2
_MAXIMUM_OBSERVED_DIRECTORY_DESCRIPTORS = 32
_ZIP_NAME_RECORD_COUNT = 2
_IMPORTED_INODES = 6
_LOCAL = struct.Struct("<I5H3I2H")
_CENTRAL = struct.Struct("<I6H3I5H2I")
_EOCD = struct.Struct("<I4H2IH")


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
        "lowerduckpond_static_host_agent.portable_bundle.measure_filesystem_capacity_descriptor",
        measure,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.zip_structure.measure_filesystem_capacity_descriptor",
        measure,
    )


def _manifest() -> dict[str, object]:
    return decode_contract(_FIXTURE.read_bytes(), expected_kind=ContractKind.SITE)


def _release(tmp_path: Path, name: str = "release") -> Path:
    root = tmp_path / name
    root.mkdir()
    root.chmod(_DIRECTORY_MODE)
    return root


def _directory(root: Path, relative: str) -> Path:
    path = root / relative
    path.mkdir(parents=True)
    for candidate in (path, *path.parents):
        if candidate == root.parent:
            break
        candidate.chmod(_DIRECTORY_MODE)
    return path


def _file(root: Path, relative: str, content: bytes) -> Path:
    path = root / relative
    if path.parent != root:
        _directory(root, str(path.parent.relative_to(root)))
    path.write_bytes(content)
    path.chmod(_FILE_MODE)
    return path


def _private_directory(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.mkdir()
    path.chmod(_PRIVATE_MODE)
    return path


def _build(
    tmp_path: Path,
    root: Path,
    *,
    output_name: str = "export.zip",
    manifest: dict[str, object] | None = None,
) -> tuple[Path, PortableBundle]:
    lock_root = _private_directory(tmp_path, f"locks-{output_name}")
    output_parent = _private_directory(tmp_path, f"output-{output_name}")
    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
    ):
        bundle = build_portable_bundle(
            root,
            _manifest() if manifest is None else manifest,
            output_parent=output_parent,
            output_name=output_name,
            lock_manager=manager,
            expected_owner=_OWNER,
        )
    return output_parent / output_name, bundle


def _populated_release(tmp_path: Path, name: str = "release") -> Path:
    root = _release(tmp_path, name)
    _file(root, "index.html", b"home\n")
    _file(root, "assets/site.css", b"body{}\n")
    _file(root, "empty.txt", b"")
    _directory(root, "vacant")
    return root


def _rewrite_stored_member(path: Path, member_name: str, replacement: bytes) -> None:
    """Replace one stored member while preserving a structurally canonical ZIP."""

    data = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(member_name)
        if len(replacement) != member.file_size:
            raise AssertionError("replacement must preserve the member size")
        local = _LOCAL.unpack_from(data, member.header_offset)
        data_offset = member.header_offset + _LOCAL.size + local[9] + local[10]
        data[data_offset : data_offset + member.file_size] = replacement

    crc32 = zlib.crc32(replacement) & 0xFFFFFFFF
    struct.pack_into("<I", data, member.header_offset + 14, crc32)
    eocd = _EOCD.unpack_from(data, len(data) - _EOCD.size)
    cursor = eocd[6]
    for _record_number in range(eocd[4]):
        central = _CENTRAL.unpack_from(data, cursor)
        fixed_end = cursor + _CENTRAL.size
        name = bytes(data[fixed_end : fixed_end + central[10]])
        if name.decode() == member_name:
            struct.pack_into("<I", data, cursor + 16, crc32)
            break
        cursor = fixed_end + central[10] + central[11] + central[12]
    else:
        raise AssertionError("member has no central record")
    path.write_bytes(data)
    path.chmod(_OUTPUT_MODE)


def _central_records(data: bytes) -> tuple[tuple[int, int, bytes, int], ...]:
    eocd = _EOCD.unpack_from(data, len(data) - _EOCD.size)
    cursor = eocd[6]
    records: list[tuple[int, int, bytes, int]] = []
    for _record_number in range(eocd[4]):
        central = _CENTRAL.unpack_from(data, cursor)
        end = cursor + _CENTRAL.size + central[10] + central[11] + central[12]
        name = data[cursor + _CENTRAL.size : cursor + _CENTRAL.size + central[10]]
        records.append((cursor, end, name, central[16]))
        cursor = end
    return tuple(records)


def _reorder_local_members(path: Path, first_name: str, second_name: str) -> None:
    data = path.read_bytes()
    eocd = _EOCD.unpack_from(data, len(data) - _EOCD.size)
    records = _central_records(data)
    ordered = sorted(records, key=lambda record: record[3])
    chunks: dict[bytes, bytes] = {}
    for position, record in enumerate(ordered):
        next_offset = ordered[position + 1][3] if position + 1 < len(ordered) else eocd[6]
        chunks[record[2]] = data[record[3] : next_offset]
    names = [record[2] for record in ordered]
    first = first_name.encode()
    second = second_name.encode()
    first_index = names.index(first)
    second_index = names.index(second)
    names[first_index], names[second_index] = names[second_index], names[first_index]

    offsets: dict[bytes, int] = {}
    local = bytearray()
    for name in names:
        offsets[name] = len(local)
        local.extend(chunks[name])

    central_bytes = bytearray()
    for start, end, name, _offset in records:
        encoded = bytearray(data[start:end])
        struct.pack_into("<I", encoded, 42, offsets[name])
        central_bytes.extend(encoded)
    path.write_bytes(bytes(local) + bytes(central_bytes) + data[-_EOCD.size :])
    path.chmod(_OUTPUT_MODE)


def _remove_member(path: Path, member_name: str) -> None:
    data = path.read_bytes()
    eocd = list(_EOCD.unpack_from(data, len(data) - _EOCD.size))
    records = _central_records(data)
    target_name = member_name.encode()
    ordered = sorted(records, key=lambda record: record[3])
    target_index = next(index for index, record in enumerate(ordered) if record[2] == target_name)
    target = ordered[target_index]
    local_end = ordered[target_index + 1][3] if target_index + 1 < len(ordered) else eocd[6]
    removed_local_bytes = local_end - target[3]
    local = data[: target[3]] + data[local_end : eocd[6]]

    central_bytes = bytearray()
    for start, end, name, offset in records:
        if name == target_name:
            continue
        encoded = bytearray(data[start:end])
        if offset > target[3]:
            struct.pack_into("<I", encoded, 42, offset - removed_local_bytes)
        central_bytes.extend(encoded)
    eocd[3] -= 1
    eocd[4] -= 1
    eocd[5] = len(central_bytes)
    eocd[6] = len(local)
    path.write_bytes(bytes(local) + bytes(central_bytes) + _EOCD.pack(*eocd))
    path.chmod(_OUTPUT_MODE)


def test_builder_emits_the_exact_canonical_v1_envelope(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)

    path, result = _build(tmp_path, root)

    data = path.read_bytes()
    assert result.bundle_size == len(data) == _PINNED_BUNDLE_BYTES
    assert result.bundle_digest.format == PORTABLE_BUNDLE_FORMAT
    assert result.bundle_digest.value == hashlib.sha256(data).hexdigest() == _PINNED_BUNDLE_SHA256
    assert result.manifest_digest != result.bundle_digest
    assert result.release_tree.digest != result.bundle_digest
    assert stat.S_IMODE(path.stat().st_mode) == _OUTPUT_MODE
    assert path.stat().st_nlink == 1

    with zipfile.ZipFile(path) as archive:
        assert archive.comment == b""
        assert archive.namelist() == [
            f"{PORTABLE_ENVELOPE}/format.json",
            f"{PORTABLE_ENVELOPE}/manifest.json",
            f"{PORTABLE_ENVELOPE}/checksums.sha256",
            f"{PORTABLE_ENVELOPE}/content/",
            f"{PORTABLE_ENVELOPE}/content/assets/",
            f"{PORTABLE_ENVELOPE}/content/assets/site.css",
            f"{PORTABLE_ENVELOPE}/content/empty.txt",
            f"{PORTABLE_ENVELOPE}/content/index.html",
            f"{PORTABLE_ENVELOPE}/content/vacant/",
        ]
        assert archive.read(f"{PORTABLE_ENVELOPE}/format.json") == FORMAT_BYTES
        canonical_manifest = archive.read(f"{PORTABLE_ENVELOPE}/manifest.json")
        assert canonical_manifest.endswith(b"\n")
        assert decode_contract(canonical_manifest, expected_kind=ContractKind.SITE) == _manifest()
        expected_checksums = b"".join(
            digest + b"  " + name + b"\n"
            for name, digest in sorted(
                [
                    (b"format.json", hashlib.sha256(FORMAT_BYTES).hexdigest().encode()),
                    (b"manifest.json", hashlib.sha256(canonical_manifest).hexdigest().encode()),
                    (b"content/assets/site.css", hashlib.sha256(b"body{}\n").hexdigest().encode()),
                    (b"content/empty.txt", hashlib.sha256(b"").hexdigest().encode()),
                    (b"content/index.html", hashlib.sha256(b"home\n").hexdigest().encode()),
                ],
                key=lambda item: item[0],
            )
        )
        assert archive.read(f"{PORTABLE_ENVELOPE}/checksums.sha256") == expected_checksums
        for info in archive.infolist():
            assert info.create_system == _MADE_BY_SYSTEM
            assert info.create_version == _VERSION
            assert info.extract_version == _VERSION
            assert info.flag_bits == _UTF8_FLAG
            assert info.compress_type == zipfile.ZIP_STORED
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.extra == b""
            assert info.comment == b""
            expected_attributes = _DIRECTORY_ATTRIBUTES if info.is_dir() else _REGULAR_ATTRIBUTES
            assert info.external_attr == expected_attributes


def test_creation_order_timestamps_and_manifest_member_order_do_not_change_bytes(
    tmp_path: Path,
) -> None:
    first = _release(tmp_path, "first")
    _file(first, "index.html", b"home")
    _file(first, "z.txt", b"last")
    _file(first, "a/child.txt", b"child")
    second = _release(tmp_path, "second")
    _file(second, "a/child.txt", b"child")
    _file(second, "z.txt", b"last")
    _file(second, "index.html", b"home")
    os.utime(first / "z.txt", ns=(1_000_000_000, 1_000_000_000))
    os.utime(second / "z.txt", ns=(2_000_000_000, 2_000_000_000))
    manifest = _manifest()
    reversed_manifest = dict(reversed(list(manifest.items())))

    first_path, first_result = _build(
        tmp_path,
        first,
        output_name="first.zip",
        manifest=manifest,
    )
    second_path, second_result = _build(
        tmp_path,
        second,
        output_name="second.zip",
        manifest=reversed_manifest,
    )

    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_result.bundle_digest == second_result.bundle_digest


def test_builder_requires_export_lock_before_reading_the_snapshot(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        pytest.raises(LockOrderError, match=r"export\.lock"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


def test_builder_requires_the_export_lock_exclusively(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT, mode=LockMode.SHARED),
        pytest.raises(LockOrderError, match="exclusive mode"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


def test_builder_rejects_noncanonical_manifest_before_creating_output(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    invalid = _manifest()
    invalid["unknown"] = True
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(ContractError),
    ):
        build_portable_bundle(
            root,
            invalid,
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


def test_builder_rejects_a_release_without_root_index(tmp_path: Path) -> None:
    root = _release(tmp_path)
    _file(root, "nested/file.txt", b"content")

    with pytest.raises(PortableBundleError, match="root-level index"):
        _build(tmp_path, root)


def test_builder_does_not_replace_or_remove_an_existing_output(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    output = output_parent / "export.zip"
    output.write_bytes(b"keep")
    output.chmod(_OUTPUT_MODE)

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(PortableBundleError, match="must not replace"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name=output.name,
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert output.read_bytes() == b"keep"


def test_builder_does_not_publish_the_final_name_until_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    output = output_parent / "export.zip"
    real_write = os.write
    observed_during_write = False

    def observe_private_write(file_descriptor: int, content: bytes | memoryview) -> int:
        nonlocal observed_during_write
        assert not output.exists()
        observed_during_write = True
        return real_write(file_descriptor, content)

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.portable_bundle.os.write",
        observe_private_write,
    )

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name=output.name,
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert observed_during_write
    assert output.is_file()
    assert [path.name for path in output_parent.iterdir()] == [output.name]


def test_interrupted_builder_leaves_no_final_or_temporary_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")

    def interrupt_write(_file_descriptor: int, _content: bytes | memoryview) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.portable_bundle.os.write",
        interrupt_write,
    )

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(KeyboardInterrupt),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


def test_builder_removes_partial_output_when_the_source_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    source = root / "index.html"
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    real_write = os.write
    mutated = False

    def mutate_after_output(file_descriptor: int, content: bytes | memoryview) -> int:
        nonlocal mutated
        written = real_write(file_descriptor, content)
        if not mutated:
            mutated = True
            source.write_bytes(b"changed")
            source.chmod(_FILE_MODE)
        return written

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.portable_bundle.os.write",
        mutate_after_output,
    )

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(PortableBundleError, match="changed"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


def test_builder_revalidates_source_generation_after_the_final_measurement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    source = root / "index.html"
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    real_validate_root = portable_bundle_module._validate_root_generation
    validations = 0

    def mutate_and_restore_after_final_measurement(
        path: Path,
        descriptor: int,
        expected: portable_bundle_module._Snapshot,
    ) -> None:
        nonlocal validations
        validations += 1
        real_validate_root(path, descriptor, expected)
        if validations == _HARDLINK_TREE_COUNT:
            source.write_bytes(b"other\n")
            source.write_bytes(b"home\n")
            source.chmod(_FILE_MODE)

    monkeypatch.setattr(
        portable_bundle_module,
        "_validate_root_generation",
        mutate_and_restore_after_final_measurement,
    )

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(PortableBundleError, match="source entry changed"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


def test_builder_revalidates_the_named_output_parent_after_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    moved_parent = tmp_path / "moved-output"
    parent_metadata = output_parent.stat()
    parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
    real_fsync = os.fsync
    replaced = False

    def replace_parent_after_publication(descriptor: int) -> None:
        nonlocal replaced
        metadata = os.fstat(descriptor)
        if not replaced and (metadata.st_dev, metadata.st_ino) == parent_identity:
            replaced = True
            output_parent.rename(moved_parent)
            output_parent.mkdir()
            output_parent.chmod(_PRIVATE_MODE)
        real_fsync(descriptor)

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.portable_bundle.os.fsync",
        replace_parent_after_publication,
    )

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(PortableBundleError, match="output parent"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []
    assert list(moved_parent.iterdir()) == []


def test_builder_accepts_release_files_that_share_an_inode(tmp_path: Path) -> None:
    root = _release(tmp_path)
    index = _file(root, "index.html", b"shared")
    os.link(index, root / "copy.html")

    path, result = _build(tmp_path, root)

    with zipfile.ZipFile(path) as archive:
        assert archive.read(f"{PORTABLE_ENVELOPE}/content/index.html") == b"shared"
        assert archive.read(f"{PORTABLE_ENVELOPE}/content/copy.html") == b"shared"
    assert result.release_tree.entry_count == _HARDLINK_TREE_COUNT
    assert len(result.release_tree.allocations) == _HARDLINK_TREE_COUNT


def test_builder_bounds_open_descriptors_for_many_sibling_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _release(tmp_path)
    _file(root, "index.html", b"home")
    for number in range(96):
        _directory(root, f"directory-{number:03d}")
    real_open = os.open
    real_close = os.close
    tracked: set[int] = set()
    peak = 0

    def track_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal peak
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_DIRECTORY:
            tracked.add(descriptor)
            peak = max(peak, len(tracked))
        return descriptor

    def track_close(descriptor: int) -> None:
        tracked.discard(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "close", track_close)

    _build(tmp_path, root)

    assert peak < _MAXIMUM_OBSERVED_DIRECTORY_DESCRIPTORS


def test_builder_fails_closed_at_the_encoded_bundle_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.portable_bundle.MAXIMUM_PORTABLE_BUNDLE_BYTES",
        1,
    )

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(PortableBundleError, match="byte boundary"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )

    assert list(output_parent.iterdir()) == []


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b", "line\nfeed"])
def test_builder_requires_one_canonical_output_component(tmp_path: Path, name: str) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, f"locks-{hash(name)}")
    output_parent = _private_directory(tmp_path, f"output-{hash(name)}")
    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(ValueError, match="output name"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name=name,
            lock_manager=manager,
            expected_owner=_OWNER,
        )


def test_builder_requires_a_private_owned_output_parent(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    lock_root = _private_directory(tmp_path, "locks")
    output_parent = _private_directory(tmp_path, "output")
    output_parent.chmod(_DIRECTORY_MODE)

    with (
        LockManager.initialize(lock_root, expected_owner=_OWNER) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(PortableBundleError, match="output parent"),
    ):
        build_portable_bundle(
            root,
            _manifest(),
            output_parent=output_parent,
            output_name="export.zip",
            lock_manager=manager,
            expected_owner=_OWNER,
        )


def test_inspector_validates_exact_envelope_checksums_and_provenance(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    path, bundle = _build(tmp_path, root)

    inspection = inspect_portable_bundle(path, expected_owner=_OWNER)

    assert inspection.bundle_size == bundle.bundle_size
    assert inspection.bundle_digest == bundle.bundle_digest
    assert inspection.provenance_manifest == _manifest()
    assert inspection.provenance_manifest_digest == bundle.manifest_digest
    assert inspection.content_paths == (
        "assets",
        "assets/site.css",
        "empty.txt",
        "index.html",
        "vacant",
    )
    assert inspection.content_bytes == len(b"body{}\nhome\n")


def test_importer_materializes_only_content_as_an_unpublished_tree(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    path, bundle = _build(tmp_path, root)
    staging_parent = _private_directory(tmp_path, "staging")

    imported = import_portable_bundle(
        path,
        staging_parent=staging_parent,
        staging_name="candidate",
        expected_owner=_OWNER,
        retained_usage=ReleaseCapacityUsage(()),
    )

    candidate = staging_parent / "candidate"
    assert imported.inspection.bundle_digest == bundle.bundle_digest
    assert imported.inspection.provenance_manifest == _manifest()
    assert imported.staging_name == "candidate"
    assert imported.unique_inodes == _IMPORTED_INODES
    assert (candidate / "index.html").read_bytes() == b"home\n"
    assert (candidate / "assets/site.css").read_bytes() == b"body{}\n"
    assert (candidate / "empty.txt").read_bytes() == b""
    assert (candidate / "vacant").is_dir()
    assert not (candidate / PORTABLE_ENVELOPE).exists()
    assert not (candidate / "manifest.json").exists()
    assert stat.S_IMODE(candidate.stat().st_mode) == _DIRECTORY_MODE
    assert stat.S_IMODE((candidate / "index.html").stat().st_mode) == _FILE_MODE


def test_portable_bundle_is_not_an_ordinary_deployment_zip(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)

    with pytest.raises(ZipStructureError):
        inspect_deployment_zip(path, expected_owner=_OWNER)


@pytest.mark.parametrize(
    ("member_name", "replacement", "message"),
    [
        (
            f"{PORTABLE_ENVELOPE}/format.json",
            FORMAT_BYTES.replace(b'"version":1', b'"version":2'),
            "format.json",
        ),
        (
            f"{PORTABLE_ENVELOPE}/content/index.html",
            b"Home\n",
            "does not bind exact content",
        ),
    ],
)
def test_inspector_rejects_crc_consistent_bytes_not_bound_by_the_envelope(
    tmp_path: Path,
    member_name: str,
    replacement: bytes,
    message: str,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    _rewrite_stored_member(path, member_name, replacement)

    with pytest.raises(PortableBundleError, match=message):
        inspect_portable_bundle(path, expected_owner=_OWNER)


def test_inspector_rejects_a_checksum_manifest_that_does_not_bind_exact_content(
    tmp_path: Path,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    member_name = f"{PORTABLE_ENVELOPE}/checksums.sha256"
    with zipfile.ZipFile(path) as archive:
        checksums = bytearray(archive.read(member_name))
    checksums[0] = ord("0") if checksums[0] != ord("0") else ord("1")
    _rewrite_stored_member(path, member_name, bytes(checksums))

    with pytest.raises(PortableBundleError, match="does not bind exact content"):
        inspect_portable_bundle(path, expected_owner=_OWNER)


def test_inspector_rejects_noncanonical_zip_metadata(tmp_path: Path) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    data = bytearray(path.read_bytes())
    central_offset = _EOCD.unpack_from(data, len(data) - _EOCD.size)[6]
    struct.pack_into("<H", data, central_offset + 8, 0)
    path.write_bytes(data)
    path.chmod(_OUTPUT_MODE)

    with pytest.raises(PortableBundleError, match="central record is not canonical"):
        inspect_portable_bundle(path, expected_owner=_OWNER)


def test_inspector_rejects_local_members_reordered_behind_canonical_central_records(
    tmp_path: Path,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    _reorder_local_members(
        path,
        f"{PORTABLE_ENVELOPE}/content/empty.txt",
        f"{PORTABLE_ENVELOPE}/content/index.html",
    )

    with pytest.raises(PortableBundleError, match="local regions are reordered"):
        inspect_portable_bundle(path, expected_owner=_OWNER)


def test_inspector_rejects_an_implicitly_materialized_content_directory(
    tmp_path: Path,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    _remove_member(path, f"{PORTABLE_ENVELOPE}/content/assets/")

    with pytest.raises(PortableBundleError, match="directories must have explicit records"):
        inspect_portable_bundle(path, expected_owner=_OWNER)


def test_inspector_translates_shared_path_rejection_to_the_portable_boundary(
    tmp_path: Path,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    original = f"{PORTABLE_ENVELOPE}/content/empty.txt".encode()
    reserved = f"{PORTABLE_ENVELOPE}/content/cdn-cgi/x".encode()
    data = path.read_bytes()
    assert len(original) == len(reserved)
    assert data.count(original) == _ZIP_NAME_RECORD_COUNT
    path.write_bytes(data.replace(original, reserved))
    path.chmod(_OUTPUT_MODE)

    with pytest.raises(PortableBundleError, match="structural contract") as raised:
        inspect_portable_bundle(path, expected_owner=_OWNER)

    assert isinstance(raised.value.__cause__, ZipStructureError)


def test_failed_import_removes_the_unpublished_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    staging_parent = _private_directory(tmp_path, "staging")

    def fail_write(*_arguments: object, **_keywords: object) -> tuple[int, int]:
        raise OSError("simulated write failure")

    monkeypatch.setattr(zip_structure_module, "_write_extracted", fail_write)

    with pytest.raises(PortableBundleError, match="could not complete safely"):
        import_portable_bundle(
            path,
            staging_parent=staging_parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert list(staging_parent.iterdir()) == []


def test_import_detects_source_generation_change_and_removes_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _populated_release(tmp_path)
    path, _bundle = _build(tmp_path, root)
    staging_parent = _private_directory(tmp_path, "staging")
    original = path.stat()
    real_write = zip_structure_module._write_extracted
    changed = False

    def mutate_source(  # noqa: PLR0913 - mirrors the explicit extraction boundary
        file_descriptor: int,
        data: bytes,
        *,
        crc32: int,
        expanded: int,
        member: ZipMember,
        limits: ZipLimits,
    ) -> tuple[int, int]:
        nonlocal changed
        result = real_write(
            file_descriptor,
            data,
            crc32=crc32,
            expanded=expanded,
            member=member,
            limits=limits,
        )
        if not changed:
            changed = True
            os.utime(
                path,
                ns=(original.st_atime_ns, original.st_mtime_ns + 1),
                follow_symlinks=False,
            )
        return result

    monkeypatch.setattr(zip_structure_module, "_write_extracted", mutate_source)

    with pytest.raises(PortableBundleError, match="changed during import"):
        import_portable_bundle(
            path,
            staging_parent=staging_parent,
            staging_name="candidate",
            expected_owner=_OWNER,
            retained_usage=ReleaseCapacityUsage(()),
        )

    assert list(staging_parent.iterdir()) == []
