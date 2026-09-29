"""Checkout provenance must not inherit private retained-evidence metadata rules."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_debug_capture as capture
from scripts import m3_11_debug_runner as runner
from scripts.m3_11_debug_files import MAX_FILE, fingerprint
from scripts.m3_11_private_inputs import PRIVATE_FILE_MODE, read_private
from scripts.m3_11_qualification_evidence import MAX_BYTES
from scripts.production_qualification_inputs import git


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "scripts").mkdir()
    (root / "scripts/helper.py").write_bytes(b"print('helper')\n")
    installed = root / "config/ansible/molecule/m3_8/tests/ansible_output.py"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(b"print('installed helper')\n")
    git(root, "init", "--quiet")
    git(root, "add", ".")
    git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "--quiet",
        "-m",
        "test checkout",
    )
    monkeypatch.setattr(capture, "REPOSITORY", root)
    return root


@pytest.mark.parametrize("mode", [0o644, 0o664])
@pytest.mark.parametrize("repair", [False, True])
def test_real_controller_capture_reaches_stages_on_normal_checkouts(
    checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, repair: bool
) -> None:
    source = checkout / "scripts/helper.py"
    source.chmod(mode)
    installed = checkout / "config/ansible/molecule/m3_8/tests/ansible_output.py"
    installed.chmod(mode)
    (tmp_path / "attempts").mkdir(mode=0o700)
    execute = Mock(return_value=0)
    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(
        tmp_path,
        {},
        start=None,
        guard=Mock(),
        prepare=lambda attempt: capture.controller(attempt, source if repair else None),
        capture=Mock(),
        repair=repair,
    )
    assert result["outcome"] == "diagnostic-complete"
    assert execute.call_count == len(runner.STAGES) + int(repair)
    (attempt,) = (tmp_path / "attempts").iterdir()
    record = read_private(attempt / "controller.json")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert record["helpers"] == {
        "scripts/helper.py": digest,
        str(installed.relative_to(checkout)): hashlib.sha256(installed.read_bytes()).hexdigest(),
    }
    assert record["revision"] == git(checkout, "rev-parse", "HEAD").decode().strip()
    assert source.stat().st_mode & 0o777 == mode
    for name in ("controller.json", "controller.patch"):
        assert (attempt / name).stat().st_mode & 0o777 == PRIVATE_FILE_MODE
    if repair:
        assert record["repair_sha256"] == fingerprint(attempt / "repair.py") == digest
        assert (attempt / "repair.py").stat().st_mode & 0o777 == PRIVATE_FILE_MODE
        source.write_bytes(b"print('later change')\n")
        assert fingerprint(attempt / "repair.py") == digest
    if mode == 0o664:  # noqa: PLR2004 - normal group-writable checkout
        with pytest.raises(ValueError, match="unsafe metadata"):
            fingerprint(source)


def test_empty_package_marker_is_recorded_and_untracked_helpers_are_included(
    checkout: Path, tmp_path: Path
) -> None:
    (checkout / "scripts/__init__.py").touch()
    capture.controller(tmp_path, None)
    helpers = cast("dict[str, str]", read_private(tmp_path / "controller.json")["helpers"])
    assert helpers["scripts/__init__.py"] == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("enabled", [False, True])
def test_dns_retirement_authorization_is_captured(
    checkout: Path, tmp_path: Path, enabled: bool
) -> None:
    capture.controller(tmp_path, None, retire_stale_dns=enabled)
    assert read_private(tmp_path / "controller.json")["retire_stale_dns"] is enabled


@pytest.mark.parametrize(
    "unsafe", ["symlink", "ancestor", "fifo", "oversize", "changed", "hardlink", "world-writable"]
)
def test_source_capture_rejects_redirected_unbounded_or_changing_files(
    checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    source = checkout / "scripts/helper.py"
    if unsafe == "symlink":
        source.rename(checkout / "other.py")
        source.symlink_to(checkout / "other.py")
    elif unsafe == "ancestor":
        source.parent.rename(checkout / "other")
        (checkout / "scripts").symlink_to(checkout / "other")
    elif unsafe == "fifo":
        source.unlink()
        os.mkfifo(source)
    elif unsafe == "oversize":
        with source.open("wb") as stream:
            stream.truncate(MAX_FILE + 1)
    elif unsafe == "hardlink":
        os.link(source, checkout / "other.py")
    elif unsafe == "world-writable":
        source.chmod(0o666)
    else:
        original = os.fstat
        identity = source.stat().st_ino
        reads = 0

        def change_after_read(fd: int) -> os.stat_result:
            nonlocal reads
            if original(fd).st_ino != identity:
                return original(fd)
            reads += 1
            if reads == 2:  # noqa: PLR2004 - second stat follows the read
                source.write_bytes(b"changed source")
            return original(fd)

        monkeypatch.setattr(os, "fstat", change_after_read)
    with pytest.raises(ValueError):
        capture.controller(tmp_path, None)
    assert not (tmp_path / "controller.json").exists()


@pytest.mark.parametrize("size", [0, MAX_BYTES + 1])
def test_invalid_repair_size_fails_before_any_stage(
    checkout: Path, tmp_path: Path, size: int
) -> None:
    source = checkout / "scripts/helper.py"
    with source.open("wb") as stream:
        stream.truncate(size)
    with pytest.raises(ValueError):
        capture.controller(tmp_path, source)
    assert not (tmp_path / "repair.py").exists()
    assert not (tmp_path / "controller.json").exists()
