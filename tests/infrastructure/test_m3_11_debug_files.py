"""Exploration retains failed provenance and cannot acquire qualification authority."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_debug_files as files
from scripts.m3_10_qualification_report import create_report
from scripts.m3_11_combined_inputs import allocate
from scripts.m3_11_private_inputs import PRIVATE_FILE_MODE, read_private, write_private


@pytest.fixture
def retained(tmp_path: Path) -> Path:
    allocate(tmp_path, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
    write_private(tmp_path / "failure-exit.json", {"phase": "verify", "exit_status": 2})
    write_private(tmp_path / "failure.json", {"original_exit_status": 2})
    for name in files.COPY_FILES:
        path = tmp_path / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(path, {"original": name})
    return tmp_path


def test_adoption_retains_bytes_and_can_resume_interrupted_preparation(
    retained: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = (retained / "failure.json").read_bytes()
    copy = files.copy
    count = 0

    def interrupted(source: Path, target: Path) -> None:
        nonlocal count
        count += 1
        if count == 3:  # noqa: PLR2004 - interruption after two real copies
            raise OSError("interrupted")
        copy(source, target)

    monkeypatch.setattr(files, "copy", interrupted)
    with pytest.raises(OSError):
        files.workspace(retained)
    monkeypatch.setattr(files, "copy", copy)
    root = files.workspace(retained)
    assert root == files.workspace(retained)
    files.require_original_unchanged(root)
    assert (retained / "failure.json").read_bytes() == failure
    assert read_private(root / files.MARKER)["qualification_authority"] == "none"
    assert (
        read_private(root / "fixture.json")["run_id"]
        == read_private(retained / "fixture.json")["run_id"]
    )
    assert (root / "fixture/static-host-agent.tar").stat().st_mode & 0o777 == PRIVATE_FILE_MODE


@pytest.mark.parametrize("location", ["original", "copy", "coordinates", "marker"])
def test_changed_evidence_or_coordinates_prevent_more_mutations(
    retained: Path, location: str
) -> None:
    root = files.workspace(retained)
    paths = {
        "original": retained / "failure.json",
        "copy": root / "live-storage.json",
        "coordinates": root / "fixture.json",
        "marker": retained / files.MARKER,
    }
    paths[location].write_bytes(b"{}\n")
    with pytest.raises(ValueError):
        files.require_original_unchanged(root)


@pytest.mark.parametrize("unsafe", ["symlink", "ancestor", "hardlink", "writable", "fifo"])
def test_unsafe_files_are_refused_without_following_them(tmp_path: Path, unsafe: str) -> None:
    parent = tmp_path / "inputs"
    parent.mkdir(mode=0o700)
    path = parent / "original"
    path.write_bytes(b"original")
    if unsafe == "symlink":
        path.rename(parent / "other")
        path.symlink_to(parent / "other")
    elif unsafe == "ancestor":
        parent.rename(tmp_path / "other")
        parent.symlink_to(tmp_path / "other")
    elif unsafe == "hardlink":
        os.link(path, parent / "other")
    elif unsafe == "writable":
        path.chmod(0o666)
    else:
        path.unlink()
        os.mkfifo(path)
    with pytest.raises((ValueError, OSError)):
        files.fingerprint(path)


@pytest.mark.parametrize(
    "authority",
    ["qualification.json", "combined.json", "owned-teardown", "failed-archive-retirement"],
)
def test_other_cleanup_or_passing_authority_cannot_be_adopted(
    retained: Path, authority: str
) -> None:
    (retained / authority).mkdir()
    with pytest.raises(ValueError, match="completed or retired"):
        files.workspace(retained)


@pytest.mark.parametrize("phase,status", [("verify", 0), ("create", 2)])
def test_only_failed_verification_is_adopted(retained: Path, phase: str, status: int) -> None:
    (retained / "failure-exit.json").unlink()
    write_private(retained / "failure-exit.json", {"phase": phase, "exit_status": status})
    with pytest.raises(ValueError, match="original failed"):
        files.workspace(retained)


def test_original_and_projection_cannot_package_a_pass(retained: Path) -> None:
    root = files.workspace(retained)
    for path in (retained, root):
        with pytest.raises(ValueError, match="diagnostic continuation"):
            create_report(path, milestone="3.11")


def test_setup_errors_keep_private_tracebacks_without_printing_values(
    retained: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import m3_11_debug as cli  # noqa: PLC0415 - isolate entrypoint

    monkeypatch.setattr(cli, "original", Mock(side_effect=ValueError("private-canary")))
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        Mock(
            return_value=Mock(
                directory=retained, exclusive_archive_writers=True, repair=None, start=None
            )
        ),
    )
    assert cli.main() == 1
    output = capsys.readouterr().out
    assert "private-canary" not in output
    (log,) = retained.glob("debug-setup-*.log")
    assert "private-canary" in log.read_text()
    assert log.stat().st_mode & 0o777 == PRIVATE_FILE_MODE
