from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import ContractError, ContractKind, decode_contract
from lowerduckpond_static_host_agent import (
    FORMAT_BYTES,
    PORTABLE_BUNDLE_FORMAT,
    PORTABLE_ENVELOPE,
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    PortableBundle,
    PortableBundleError,
    build_portable_bundle,
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
