from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import audit_archive_workspace as workspace
from lowerduckpond_static_host_agent.audit_archive_formats import (
    MAX_DESCRIPTOR_BYTES,
    MAX_SEGMENT_BYTES,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.durable import StatePathError
from test_audit_archive_admission import available_capacity


@pytest.fixture
def work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    tmp_path.chmod(0o700)
    monkeypatch.setattr(workspace, "measure_filesystem_capacity_descriptor", available_capacity)
    return tmp_path


def put(work: Path, name: str, data: bytes = b"bounded abandoned output") -> Path:
    target = work / name
    target.write_bytes(data)
    target.chmod(0o600)
    return target


def test_owned_abandoned_outputs_are_cleared_before_and_after_verification(work: Path) -> None:
    put(work, "descriptor.json")
    put(work, ".ldp-state-" + "a" * 32)
    with workspace.verification_workspace(work, expected_owner=os.geteuid()) as directory:
        assert list(work.iterdir()) == []
        assert (
            workspace.restore_payload(directory, "segment.jsonl", b"segment", os.geteuid())
            == b"segment"
        )
    assert list(work.iterdir()) == []


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "directory",
        "symlink",
        "hardlink",
        "mode",
        "oversize",
        "inode-bound",
        "byte-bound",
    ],
)
def test_entire_inventory_is_classified_before_any_cleanup(
    work: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    safe = put(work, "descriptor.json")
    unsafe = put(work, "segment.jsonl")
    if fault == "unknown":
        unsafe.rename(work / "unrecognized.json")
    elif fault in {"symlink", "directory"}:
        unsafe.unlink()
        if fault == "symlink":
            unsafe.symlink_to(safe)
        else:
            unsafe.mkdir(mode=0o700)
    elif fault == "hardlink":
        os.link(safe, work / "witness.json")
    elif fault == "mode":
        unsafe.chmod(0o644)
    elif fault == "oversize":
        with unsafe.open("r+b") as stream:
            stream.truncate(MAX_SEGMENT_BYTES + 1)
    elif fault == "inode-bound":
        monkeypatch.setattr(workspace, "MAX_WORKSPACE_INODES", 2)
    else:
        monkeypatch.setattr(workspace, "MAX_WORKSPACE_BYTES", 1)
    with (
        pytest.raises((BackupIdentityError, StatePathError, OSError)),
        workspace.verification_workspace(work, expected_owner=os.geteuid()),
    ):
        pytest.fail("unsafe workspace admitted")
    assert safe.read_bytes() == b"bounded abandoned output"


def test_failed_restore_cleans_only_classified_private_outputs(work: Path) -> None:
    with (
        pytest.raises(RuntimeError, match="interrupted"),
        workspace.verification_workspace(work, expected_owner=os.geteuid()) as directory,
    ):
        workspace.restore_payload(directory, "descriptor.json", b"private", os.geteuid())
        raise RuntimeError("interrupted")
    assert list(work.iterdir()) == []


def test_unknown_output_on_failure_is_preserved_for_diagnosis(work: Path) -> None:
    with (
        pytest.raises(BackupIdentityError),
        workspace.verification_workspace(work, expected_owner=os.geteuid()) as directory,
    ):
        workspace.restore_payload(directory, "descriptor.json", b"private", os.geteuid())
        put(work, "unknown")
    assert (work / "descriptor.json").read_bytes() == b"private"
    assert (work / "unknown").exists()


@pytest.mark.parametrize(
    "name,data",
    [
        ("../escape", b"x"),
        ("descriptor.json", b""),
        ("descriptor.json", b"x" * (MAX_DESCRIPTOR_BYTES + 1)),
    ],
)
def test_restore_payload_has_no_arbitrary_path_or_size_capability(
    work: Path, name: str, data: bytes
) -> None:
    with (
        workspace.verification_workspace(work, expected_owner=os.geteuid()) as directory,
        pytest.raises(BackupIdentityError),
    ):
        workspace.restore_payload(directory, name, data, os.geteuid())
