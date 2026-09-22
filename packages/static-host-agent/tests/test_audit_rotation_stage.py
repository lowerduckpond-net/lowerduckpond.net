from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_rotation_local as rotation
from lowerduckpond_static_host_agent import audit_rotation_snapshot as snapshot
from lowerduckpond_static_host_agent import audit_rotation_stage as stage
from lowerduckpond_static_host_agent.audit_archive_admission import AuditArchiveCapacityError
from lowerduckpond_static_host_agent.audit_archive_local import archive_transaction, observe_archive
from lowerduckpond_static_host_agent.audit_archive_restic import SNAPSHOT_SOURCE
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.capacity import CapacityError, FilesystemCapacity
from lowerduckpond_static_host_agent.durable import StatePathError
from test_audit_archive_admission import available_capacity
from test_audit_archive_formats import descriptor, entry
from test_audit_archive_local import closed as closed  # noqa: PLC0414 - shared private fixture
from test_audit_archive_store import lineage
from test_audit_archive_store import state as state  # noqa: PLC0414 - fixture dependency
from test_audit_archived_history import LIMITS


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "snapshot"
    path.mkdir(mode=0o700)
    monkeypatch.setattr(stage, "measure_filesystem_capacity_descriptor", available_capacity)
    return path


def test_sealed_inputs_are_idempotent_and_safe_partial_cleanup_can_resume(source: Path) -> None:
    segment = canonical_json_bytes(entry())
    record = descriptor(segment)
    stage.stage_attempt(source, record, segment, os.geteuid())
    inodes = {path.name: path.stat().st_ino for path in source.iterdir()}
    stage.stage_attempt(source, record, segment, os.geteuid())
    assert {path.name: path.stat().st_ino for path in source.iterdir()} == inodes
    (source / "descriptor.json").unlink()
    stage.discard_stage(source, os.geteuid(), record=record)
    assert not list(source.iterdir())
    stage.discard_stage(source, os.geteuid(), record=record)


@pytest.mark.parametrize(
    "fault", ["unknown", "symlink", "hardlink", "mode", "oversized", "descriptor", "segment"]
)
def test_staging_faults_preserve_every_remaining_file_before_any_cleanup(
    source: Path, fault: str
) -> None:
    segment = canonical_json_bytes(entry())
    record = descriptor(segment)
    stage.stage_attempt(source, record, segment, os.geteuid())
    target = source / "segment.jsonl"
    if fault == "unknown":
        (source / "unknown").write_bytes(b"preserve")
    elif fault == "symlink":
        target.unlink()
        target.symlink_to(source / "descriptor.json")
    elif fault == "hardlink":
        os.link(target, source.parent / "other-link")
    elif fault == "mode":
        target.chmod(0o644)
    elif fault == "oversized":
        with target.open("r+b") as stream:
            stream.truncate(formats.MAX_SEGMENT_BYTES + 1)
    elif fault == "descriptor":
        (source / "descriptor.json").write_bytes(b"{}\n")
    else:
        target.write_bytes(b"corrupt")
    before = {path.name: (path.lstat().st_ino, path.read_bytes()) for path in source.iterdir()}
    actions: tuple[Callable[[], None], ...] = (
        lambda: stage.stage_attempt(source, record, segment, os.geteuid()),
        lambda: stage.discard_stage(source, os.geteuid(), record=record),
    )
    for action in actions:
        with pytest.raises((BackupIdentityError, StatePathError, OSError)):
            action()
        assert {
            path.name: (path.lstat().st_ino, path.read_bytes()) for path in source.iterdir()
        } == before


@pytest.mark.parametrize(
    "fault", ["ordinary", "metadata", "metadata-inodes", "free-blocks", "free-inodes"]
)
def test_rotation_never_borrows_administrator_reserve_or_free_space_floors(
    closed: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    def capacity(descriptor: int) -> FilesystemCapacity:
        value = available_capacity(descriptor)
        return (
            replace(value, available_blocks=1)
            if fault == "free-blocks"
            else replace(value, available_inodes=1)
            if fault == "free-inodes"
            else value
        )

    monkeypatch.setattr(rotation, "measure_filesystem_capacity_descriptor", capacity)
    with archive_transaction(closed, os.geteuid()) as root:
        current = observe_archive(root, lineage(closed), os.geteuid(), limits=LIMITS)
        if fault == "ordinary":
            current = replace(
                current, audit=replace(current.audit, allocated_bytes=128 * 1024 * 1024)
            )
        elif fault == "metadata":
            current = replace(
                current, prefix=replace(current.prefix, allocated_bytes=32 * 1024 * 1024)
            )
        elif fault == "metadata-inodes":
            current = replace(current, prefix=replace(current.prefix, inodes=8192))
        with pytest.raises((AuditArchiveCapacityError, CapacityError)):
            rotation.require_rotation_capacity(root, current)
    assert not (closed / "audit/archive/rotation-intent.json").exists()


@pytest.mark.parametrize(
    "output",
    [
        b"{}",
        b'{"message_type":"summary","snapshot_id":"short"}',
        b'{"message_type":"status","snapshot_id":"' + b"c" * 64 + b'"}',
    ],
)
def test_snapshot_adapter_requires_a_full_terminal_response(
    monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    monkeypatch.setattr(snapshot, "_restic", lambda *_args: output)
    with pytest.raises(BackupIdentityError):
        snapshot.create_rotation_snapshot(
            descriptor(canonical_json_bytes(entry())),
            {"LOWERDUCKPOND_BACKUP_NODE_NAME": "test-node"},
        )


def test_snapshot_adapter_uses_only_fixed_source_protected_tags_and_bounded_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = []

    def restic(arguments: tuple[str, ...], environment: Mapping[str, str], limit: int) -> bytes:
        observed.append((arguments, environment, limit))
        return b'{"message_type":"summary","snapshot_id":"' + b"c" * 64 + b'"}'

    monkeypatch.setattr(snapshot, "_restic", restic)
    record = descriptor(canonical_json_bytes(entry()))
    environment = {"LOWERDUCKPOND_BACKUP_NODE_NAME": "test-node"}
    assert snapshot.create_rotation_snapshot(record, environment) == "c" * 64
    arguments, captured, limit = observed[0]
    assert arguments[:5] == ("backup", "--json", "--quiet", "--host", "test-node")
    assert arguments[-1] == SNAPSHOT_SOURCE
    assert arguments[5:-1:2] == ("--tag",) * len(formats.required_archive_tags(record))
    assert arguments[6:-1:2] == formats.required_archive_tags(record)
    assert "scheduled" not in arguments and captured == environment and limit == 32 * 1024
