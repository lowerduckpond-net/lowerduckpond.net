from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    ReleaseTreeBoundary,
    ReleaseTreeError,
    ReleaseTreeLimits,
    measure_release_tree,
)

_OWNER = os.geteuid()
_PINNED_ENTRY_COUNT = 5
_HARDLINKED_ENTRY_COUNT = 2
_FIRST_OVER_LIMIT_OBSERVATIONS = 2


def _release_root(tmp_path: Path, name: str = "release") -> Path:
    root = tmp_path / name
    root.mkdir()
    root.chmod(0o755)
    return root


def _directory(root: Path, relative: str) -> Path:
    path = root / relative
    path.mkdir(parents=True)
    for parent in (path, *path.parents):
        if parent == root.parent:
            break
        parent.chmod(0o755)
    return path


def _file(root: Path, relative: str, content: bytes) -> Path:
    path = root / relative
    if path.parent != root:
        _directory(root, str(path.parent.relative_to(root)))
    path.write_bytes(content)
    path.chmod(0o644)
    return path


def _expected_digest(records: list[tuple[bytes, bytes, bytes | None]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"lowerduckpond-release-tree-v1\0")
    digest.update(len(records).to_bytes(4, "big"))
    for kind, path, content in records:
        digest.update(kind)
        digest.update(len(path).to_bytes(4, "big"))
        digest.update(path)
        if content is not None:
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
    return digest.hexdigest()


def test_digest_pins_exact_versioned_stream_and_bytewise_path_order(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    _file(root, "z.txt", b"last")
    _file(root, "a/child.txt", b"child")
    _file(root, "a-x.txt", b"between")
    _directory(root, "empty")

    measurement = measure_release_tree(root, expected_owner=_OWNER)

    records = [
        (b"D", b"a", None),
        (b"F", b"a-x.txt", b"between"),
        (b"F", b"a/child.txt", b"child"),
        (b"D", b"empty", None),
        (b"F", b"z.txt", b"last"),
    ]
    assert measurement.digest.to_dict() == {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": _expected_digest(records),
    }
    assert measurement.entry_count == _PINNED_ENTRY_COUNT
    assert measurement.logical_content_bytes == len(b"betweenchildlast")


def test_empty_tree_has_a_pinned_zero_entry_digest(tmp_path: Path) -> None:
    root = _release_root(tmp_path)

    measurement = measure_release_tree(root, expected_owner=_OWNER)

    assert measurement.digest.value == _expected_digest([])
    assert measurement.entry_count == 0
    assert measurement.logical_content_bytes == 0
    assert measurement.unique_inode_count == 1  # The release root still consumes capacity.


def test_digest_ignores_creation_order_timestamps_and_inode_identity(tmp_path: Path) -> None:
    first = _release_root(tmp_path, "first")
    second = _release_root(tmp_path, "second")
    _file(first, "nested/index.html", b"content")
    _file(first, "other.txt", b"other")
    _file(second, "other.txt", b"other")
    _file(second, "nested/index.html", b"content")
    os.utime(first / "other.txt", ns=(1_000_000_000, 1_000_000_000))
    os.utime(second / "other.txt", ns=(2_000_000_000, 2_000_000_000))

    first_measurement = measure_release_tree(first, expected_owner=_OWNER)
    second_measurement = measure_release_tree(second, expected_owner=_OWNER)

    assert first_measurement.digest == second_measurement.digest
    assert first_measurement.allocations != second_measurement.allocations


def test_hardlinked_paths_are_both_digested_but_charged_once(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    first = _file(root, "first.txt", b"same inode")
    os.link(first, root / "second.txt")

    measurement = measure_release_tree(root, expected_owner=_OWNER)

    assert measurement.entry_count == _HARDLINKED_ENTRY_COUNT
    assert measurement.unique_inode_count == _HARDLINKED_ENTRY_COUNT
    assert measurement.digest.value == _expected_digest(
        [
            (b"F", b"first.txt", b"same inode"),
            (b"F", b"second.txt", b"same inode"),
        ]
    )


@pytest.mark.parametrize("special", ["fifo", "symlink"])
def test_special_or_link_entries_fail_closed_without_opening_them(
    tmp_path: Path,
    special: str,
) -> None:
    root = _release_root(tmp_path)
    if special == "fifo":
        os.mkfifo(root / "hostile")
    else:
        (root / "hostile").symlink_to("missing")

    with pytest.raises(ReleaseTreeError, match="disallowed inode type"):
        measure_release_tree(root, expected_owner=_OWNER)


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("A.txt", "case-folding collision"),
        ("e\N{COMBINING ACUTE ACCENT}.txt", "NFC normalized"),
        ("line\nfeed", "control character"),
        ("back\\slash", "invalid path component"),
    ],
)
def test_noncanonical_names_are_rejected(tmp_path: Path, name: str, message: str) -> None:
    root = _release_root(tmp_path)
    if name == "A.txt":
        _file(root, "a.txt", b"first")
    _file(root, name, b"content")

    with pytest.raises(ReleaseTreeError, match=message):
        measure_release_tree(root, expected_owner=_OWNER)


def test_non_utf8_filesystem_name_is_rejected(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        file_fd = os.open(b"\xff", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=root_fd)
        os.close(file_fd)
    finally:
        os.close(root_fd)

    with pytest.raises(ReleaseTreeError, match="valid UTF-8"):
        measure_release_tree(root, expected_owner=_OWNER)


@pytest.mark.parametrize("reserved", ["cdn-cgi", "CDN-CGI"])
def test_cloudflare_reserved_first_component_is_rejected(
    tmp_path: Path,
    reserved: str,
) -> None:
    root = _release_root(tmp_path)
    _file(root, f"{reserved}/probe", b"content")

    with pytest.raises(ReleaseTreeError, match="reserved first component"):
        measure_release_tree(root, expected_owner=_OWNER)


@pytest.mark.parametrize(
    ("limits", "paths", "message"),
    [
        (ReleaseTreeLimits(maximum_entries=1), ("one", "two"), "entry limit"),
        (
            ReleaseTreeLimits(maximum_file_bytes=1, maximum_content_bytes=4),
            ("large",),
            "file exceeds",
        ),
        (
            ReleaseTreeLimits(maximum_file_bytes=2, maximum_content_bytes=3),
            ("one", "two"),
            "content limit",
        ),
        (ReleaseTreeLimits(maximum_depth=1), ("deep/child",), "depth limit"),
        (ReleaseTreeLimits(maximum_path_bytes=3), ("four",), "path exceeds"),
        (ReleaseTreeLimits(maximum_component_bytes=3), ("four",), "component exceeds"),
    ],
)
def test_every_tree_limit_fails_at_one_past_its_boundary(
    tmp_path: Path,
    limits: ReleaseTreeLimits,
    paths: tuple[str, ...],
    message: str,
) -> None:
    root = _release_root(tmp_path)
    for path in paths:
        _file(root, path, b"xx")

    with pytest.raises(ReleaseTreeError, match=message):
        measure_release_tree(root, expected_owner=_OWNER, limits=limits)


def test_entry_limit_stops_streaming_before_later_names_are_inspected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _release_root(tmp_path)
    for name in ("one", "two", "three", "four"):
        _file(root, name, b"content")
    original_stat = os.stat
    inspected = 0

    def counted_stat(
        path: os.PathLike[str] | str | bytes | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal inspected
        if dir_fd is not None:
            inspected += 1
        return original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", counted_stat)
    with pytest.raises(ReleaseTreeError, match="entry limit"):
        measure_release_tree(
            root,
            expected_owner=_OWNER,
            limits=ReleaseTreeLimits(maximum_entries=1),
        )

    assert inspected == _FIRST_OVER_LIMIT_OBSERVATIONS


@pytest.mark.parametrize("wrong_shape", ["root-mode", "directory-mode", "file-mode", "owner"])
def test_owner_and_exact_normalized_modes_are_revalidated(
    tmp_path: Path,
    wrong_shape: str,
) -> None:
    root = _release_root(tmp_path)
    file = _file(root, "nested/file", b"content")
    if wrong_shape == "root-mode":
        root.chmod(0o750)
    elif wrong_shape == "directory-mode":
        (root / "nested").chmod(0o700)
    elif wrong_shape == "file-mode":
        file.chmod(0o600)

    owner = _OWNER + 1 if wrong_shape == "owner" else _OWNER
    with pytest.raises(ReleaseTreeError, match=r"wrong (owner|mode)"):
        measure_release_tree(root, expected_owner=owner)


def test_file_replacement_after_scan_is_detected(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    target = _file(root, "index.html", b"old")

    def replace(boundary: ReleaseTreeBoundary, _path: bytes | None) -> None:
        if boundary is ReleaseTreeBoundary.AFTER_SCAN:
            replacement = root / "replacement"
            replacement.write_bytes(b"new")
            replacement.chmod(0o644)
            replacement.replace(target)

    with pytest.raises(ReleaseTreeError, match="changed before"):
        measure_release_tree(root, expected_owner=_OWNER, measurement_hook=replace)


def test_namespace_mutation_after_hashing_is_detected(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    _file(root, "index.html", b"stable")

    def add_entry(boundary: ReleaseTreeBoundary, _path: bytes | None) -> None:
        if boundary is ReleaseTreeBoundary.BEFORE_FINAL_VALIDATION:
            _file(root, "late", b"mutation")

    with pytest.raises(ReleaseTreeError, match="root changed"):
        measure_release_tree(root, expected_owner=_OWNER, measurement_hook=add_entry)


def test_content_mutation_after_hashing_is_detected(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    target = _file(root, "index.html", b"old")

    def mutate(boundary: ReleaseTreeBoundary, _path: bytes | None) -> None:
        if boundary is ReleaseTreeBoundary.BEFORE_FINAL_VALIDATION:
            target.write_bytes(b"new")
            target.chmod(0o644)

    with pytest.raises(ReleaseTreeError, match="final validation"):
        measure_release_tree(root, expected_owner=_OWNER, measurement_hook=mutate)


def test_file_content_mutation_during_read_is_detected(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    target = _file(root, "large", b"a" * (128 * 1024))
    changed = False

    def mutate(boundary: ReleaseTreeBoundary, _path: bytes | None) -> None:
        nonlocal changed
        if boundary is ReleaseTreeBoundary.FILE_CHUNK and not changed:
            changed = True
            with target.open("r+b") as stream:
                stream.seek(64 * 1024)
                stream.write(b"b")

    with pytest.raises(ReleaseTreeError, match="changed while"):
        measure_release_tree(root, expected_owner=_OWNER, measurement_hook=mutate)


def test_allocated_bytes_are_derived_from_unique_stat_blocks(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    file = _file(root, "payload", b"content")

    measurement = measure_release_tree(root, expected_owner=_OWNER)

    expected = (root.stat().st_blocks + file.stat().st_blocks) * 512
    assert measurement.allocated_bytes == expected


def test_sparse_logical_bytes_do_not_replace_physical_block_accounting(tmp_path: Path) -> None:
    root = _release_root(tmp_path)
    sparse = root / "sparse"
    logical_size = 2 * 1024 * 1024
    with sparse.open("wb") as stream:
        stream.seek(logical_size - 1)
        stream.write(b"\0")
    sparse.chmod(0o644)

    measurement = measure_release_tree(root, expected_owner=_OWNER)

    assert measurement.logical_content_bytes == logical_size
    assert measurement.allocated_bytes < measurement.logical_content_bytes


def test_callers_cannot_weaken_versioned_tree_limits() -> None:
    with pytest.raises(ValueError, match="cannot weaken"):
        ReleaseTreeLimits(maximum_entries=5_001)
