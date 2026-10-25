"""Whole-tree preservation keeps original bytes on every incomplete copy."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest

from scripts import m3_11_frozen_export as export
from scripts.m3_11_retirement_files import digest


@pytest.fixture
def trees(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "original"
    root.mkdir(mode=0o700)
    (root / "empty").write_bytes(b"")
    (root / "private").mkdir(mode=0o700)
    (root / "private/evidence").write_bytes(b"original retained evidence")
    (root / "uncertain.json").write_bytes(b'{"outcome":"unknown"}')
    (root / "link").symlink_to("private/evidence")
    (root / "external-link").symlink_to("/unavailable/source")
    return root, tmp_path / "preserved"


def preserve(root: Path, output: Path) -> dict[str, object]:
    return export.preserve(root, output, limits=export.Limits(1024 * 1024, 100), guard=lambda: None)


def test_full_manifest_private_regular_blobs_and_independent_reread(
    trees: tuple[Path, Path],
) -> None:
    root, output = trees
    result = preserve(root, output)
    rows = cast(list[dict[str, object]], result["entries"])
    assert {row["path"] for row in rows} == {
        "empty",
        "private",
        "private/evidence",
        "uncertain.json",
        "link",
        "external-link",
    }
    for row in rows:
        if row["type"] == "file":
            path = output / "blobs" / digest(row["path"])
            assert stat.S_IMODE(path.stat().st_mode) == 0o600  # noqa: PLR2004 - private evidence
            assert path.read_bytes() == (root / str(row["path"])).read_bytes()
        if row["type"] == "symlink":
            assert not (output / "blobs" / digest(row["path"])).exists()
    assert (
        export.verify(root, output, limits=export.Limits(1024 * 1024, 100), guard=lambda: None)
        == result
    )


@pytest.mark.parametrize(
    "kind", ["fifo", "hardlink", "byte-bound", "entry-bound", "overlap", "source-link"]
)
def test_unsupported_source_or_bound_stops_without_omission(
    trees: tuple[Path, Path], kind: str
) -> None:
    root, output = trees
    limits = export.Limits(1024 * 1024, 100)
    if kind == "fifo":
        os.mkfifo(root / "pipe")
    elif kind == "hardlink":
        os.link(root / "uncertain.json", root / "linked")
    elif kind == "byte-bound":
        limits = export.Limits(1, 100)
    elif kind == "entry-bound":
        limits = export.Limits(1024 * 1024, 1)
    elif kind == "overlap":
        output = root / "preserved"
    else:
        link = root.parent / "alias"
        link.symlink_to(root, target_is_directory=True)
        root = link
    before = (root / "uncertain.json").read_bytes()
    with pytest.raises((ValueError, OSError)):
        export.preserve(root, output, limits=limits, guard=lambda: None)
    assert (root / "uncertain.json").read_bytes() == before
    assert not (output / "verified.json").exists()


@pytest.mark.parametrize("boundary", ["write", "file-fsync", "rename", "parent-fsync", "reread"])
def test_copy_crash_never_removes_original_or_publishes_verified(
    trees: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    root, output = trees
    original = (root / "private/evidence").read_bytes()
    real_blob = export._blob
    if boundary == "write":

        def fail_write(*_args: object, **_kwargs: object) -> str:
            raise OSError("synthetic write failure")

        monkeypatch.setattr(export, "_blob", fail_write)
    elif boundary in {"file-fsync", "parent-fsync"}:
        real_sync = os.fsync

        def fail_sync(fd: int) -> None:
            mode = os.fstat(fd).st_mode
            if (boundary == "file-fsync" and stat.S_ISREG(mode)) or (
                boundary == "parent-fsync" and (output / "blobs").exists() and stat.S_ISDIR(mode)
            ):
                raise OSError("synthetic fsync failure")
            real_sync(fd)

        monkeypatch.setattr(os, "fsync", fail_sync)
    elif boundary == "rename":

        def fail_rename(*_args: object) -> None:
            raise OSError("synthetic rename failure")

        monkeypatch.setattr(export, "_rename_noreplace", fail_rename)
    else:

        def corrupt(parent: int, name: str, descriptor: int, size: int, guard: object) -> str:
            result = real_blob(parent, name, descriptor, size, cast("Callable[[], None]", guard))
            if size:
                descriptor = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    os.write(descriptor, b"x" * size)
                finally:
                    os.close(descriptor)
            return result

        monkeypatch.setattr(export, "_blob", corrupt)
    with pytest.raises((ValueError, OSError)):
        preserve(root, output)
    assert (root / "private/evidence").read_bytes() == original
    assert not (output / "verified.json").exists()


def test_source_replacement_during_descriptor_read_is_rejected(
    trees: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, output = trees
    original = export.chunks
    changed = False

    def replace(fd: int, size: int, guard: object) -> Iterator[bytes]:
        nonlocal changed
        yield from original(fd, size, cast("Callable[[], None]", guard))
        if size and not changed:
            changed = True
            path = root / "private/evidence"
            body = path.read_bytes()
            path.unlink()
            path.write_bytes(body)

    monkeypatch.setattr(export, "chunks", replace)
    with pytest.raises(ValueError, match="changed"):
        preserve(root, output)
    assert not (output / "verified.json").exists()


def test_old_complete_export_is_not_replaced_or_used_after_source_drift(
    trees: tuple[Path, Path],
) -> None:
    root, output = trees
    preserve(root, output)
    original = (output / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        preserve(root, output)
    (root / "uncertain.json").write_bytes(b"new evidence must not be discarded")
    with pytest.raises(ValueError, match="no longer"):
        export.verify(root, output, limits=export.Limits(1024 * 1024, 100), guard=lambda: None)
    assert (output / "manifest.json").read_bytes() == original


def test_destination_swap_cannot_redirect_any_private_bytes(
    trees: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, output = trees
    foreign = output.parent / "foreign"
    foreign.mkdir(mode=0o700)
    original = export._blob
    swapped = False

    def swap(parent: int, name: str, descriptor: int, size: int, guard: object) -> str:
        nonlocal swapped
        if not swapped:
            swapped = True
            (output / "blobs").rename(output / "original-blobs")
            (output / "blobs").symlink_to(foreign, target_is_directory=True)
        return original(parent, name, descriptor, size, cast("Callable[[], None]", guard))

    monkeypatch.setattr(export, "_blob", swap)
    with pytest.raises((ValueError, OSError)):
        preserve(root, output)
    assert not list(foreign.iterdir())
    assert not (output / "verified.json").exists()


@pytest.mark.parametrize("relative", ["", "private", "private/evidence"])
def test_extended_attributes_are_not_silently_omitted(
    trees: tuple[Path, Path], relative: str
) -> None:
    root, output = trees
    os.setxattr(root / relative, "user.synthetic-preservation", b"must remain available")
    with pytest.raises(ValueError, match="attributes"):
        preserve(root, output)
    assert not (output / "verified.json").exists()


def test_destination_parent_replacement_cannot_publish_a_different_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    (root / "evidence").write_bytes(b"original")
    parent = tmp_path / "destination-parent"
    parent.mkdir(mode=0o700)
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    output = parent / "export"
    original = export._blob
    moved = tmp_path / "moved-parent"

    def swap(fd: int, name: str, descriptor: int, size: int, guard: Callable[[], None]) -> str:
        parent.rename(moved)
        parent.symlink_to(foreign, target_is_directory=True)
        return original(fd, name, descriptor, size, guard)

    monkeypatch.setattr(export, "_blob", swap)
    with pytest.raises((ValueError, OSError)):
        preserve(root, output)
    assert not list(foreign.iterdir())
    assert not (moved / "export/verified.json").exists()
