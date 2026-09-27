"""Real durable publication and offline ext4 reads, including interrupted evidence."""

from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts import m3_11_retirement_files as files
from scripts.m3_11_retirement_ext4 import Ext4


def test_partial_copy_restarts_without_authorizing_incomplete_bytes(tmp_path: Path) -> None:
    target = tmp_path / "archive.bin"
    raw = b"complete original bytes"

    def interrupted() -> Iterator[bytes]:
        yield raw[:5]
        raise ConnectionError("lost stream")

    with pytest.raises(ConnectionError):
        files.preserve(target, interrupted(), len(raw), hashlib.sha256(raw).hexdigest())
    assert not target.exists()
    assert target.with_suffix(".bin.partial").read_bytes() == raw[:5]
    result = files.preserve(target, iter([raw]), len(raw), hashlib.sha256(raw).hexdigest())
    assert result == {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    assert target.stat().st_nlink == 1
    assert not target.with_suffix(".bin.partial").exists()


@pytest.mark.parametrize("fault", ["short", "long", "digest", "chunk"])
def test_bad_stream_never_publishes(tmp_path: Path, fault: str) -> None:
    target = tmp_path / "archive.bin"
    data = b"aa" if fault != "chunk" else b"a" * (files.CHUNK + 1)
    size = {"short": 3, "long": 1, "digest": 2, "chunk": len(data)}[fault]
    with pytest.raises(ValueError):
        files.preserve(target, iter([data]), size, "a" * 64)
    assert not target.exists()


def test_copy_with_lost_receipt_compares_complete_original_stream(tmp_path: Path) -> None:
    target = tmp_path / "state.ext4"
    files.preserve(target, iter([b"original"]), 8)
    assert files.preserve(target, iter([b"original"]), 8)["size"] == len(b"original")
    with pytest.raises(ValueError, match="original source"):
        files.preserve(target, iter([b"modified"]), 8)
    assert target.read_bytes() == b"original"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode", "partial-link"])
def test_unsafe_evidence_cannot_be_adopted(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "archive.bin"
    other = tmp_path / "other"
    other.write_bytes(b"secret")
    other.chmod(0o600)
    if kind == "symlink":
        target.symlink_to(other)
    elif kind == "hardlink":
        target.hardlink_to(other)
    elif kind == "partial-link":
        target.with_suffix(".bin.partial").symlink_to(other)
    else:
        target.write_bytes(b"secret")
        target.chmod(0o644)
    with pytest.raises((OSError, ValueError)):
        files.preserve(target, iter([b"secret"]), 6)
    assert other.read_bytes() == b"secret"


@pytest.mark.parametrize("bytes_free,inodes,total_inodes", [(0, 1000, 2000), (10**9, 0, 2000)])
def test_inadequate_capacity_cannot_create_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bytes_free: int, inodes: int, total_inodes: int
) -> None:
    monkeypatch.setattr(
        os,
        "statvfs",
        lambda _: SimpleNamespace(
            f_bavail=bytes_free, f_frsize=1, f_favail=inodes, f_files=total_inodes
        ),
    )
    with pytest.raises(ValueError, match="capacity"):
        files.preserve(tmp_path / "copy", iter([b"a"]), 1)
    assert not list(tmp_path.iterdir())


def run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True, timeout=15)  # noqa: S603 - fixed fixture commands


@pytest.fixture
def ext4(tmp_path: Path) -> tuple[Path, Path]:
    path = tmp_path / "state.ext4"
    with path.open("xb") as stream:
        stream.truncate(16 * 1024 * 1024)
    path.chmod(0o600)
    run("/usr/sbin/mkfs.ext4", "-F", "-q", "-E", "root_owner=0:0", str(path))
    payload = tmp_path / "payload"
    payload.write_bytes(b'{"original":"record"}')
    for command in (
        "mkdir /state",
        "mkdir /foreign",
        "set_inode_field /foreign uid 1234",
        f"write {payload} /state/record.json",
        "set_inode_field /state/record.json uid 0",
        "set_inode_field /state/record.json mode 0100600",
    ):
        run("/usr/sbin/debugfs", "-w", "-R", command, str(path))
    return path, payload


def test_real_offline_reader_leaves_image_bytes_unchanged(ext4: tuple[Path, Path]) -> None:
    path, payload = ext4
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    reader = Ext4(path)
    assert reader.read("/state/record.json") == payload.read_bytes()
    assert reader.names("/state") == {"record.json": "regular"}
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize(
    "fault", ["symlink", "hardlink", "foreign-owner", "writable", "dirty", "traversal"]
)
def test_offline_reader_refuses_unsafe_paths(ext4: tuple[Path, Path], fault: str) -> None:
    path, _ = ext4
    target = "/state/record.json"
    commands = {
        "symlink": "symlink /alias state",
        "hardlink": "set_inode_field /state/record.json links_count 2",
        "foreign-owner": "set_inode_field /state uid 1234",
        "writable": "set_inode_field /state mode 040777",
        "dirty": "set_super_value state 0",
    }
    if fault in commands:
        run("/usr/sbin/debugfs", "-w", "-R", commands[fault], str(path))
    if fault == "symlink":
        target = "/alias/record.json"
    elif fault == "traversal":
        target = "/foreign/../state/record.json"
    with pytest.raises((ValueError, KeyError)):
        Ext4(path).read(target)


@pytest.mark.parametrize("published", [False, True])
def test_interruption_at_atomic_publication_resumes_without_linked_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, published: bool
) -> None:
    rename = _rename_noreplace
    target = tmp_path / "copy"
    raw = b"original evidence"

    def interrupted(parent: int, old: str, new: str) -> None:
        if published:
            rename(parent, old, new)
        raise OSError("controller stopped during publication")

    monkeypatch.setattr(files, "_rename_noreplace", interrupted)
    with pytest.raises(OSError):
        files.preserve(target, iter([raw]), len(raw))
    assert target.exists() is published
    monkeypatch.setattr(files, "_rename_noreplace", rename)
    files.preserve(target, iter([raw]), len(raw))
    assert target.read_bytes() == raw
    assert target.stat().st_nlink == 1
    assert not target.with_suffix(".partial").exists()
