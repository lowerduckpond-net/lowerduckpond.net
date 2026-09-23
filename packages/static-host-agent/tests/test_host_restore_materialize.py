from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_materialize as materialize
from lowerduckpond_static_host_agent.backup_sources import SOURCE_PATHS, STAGED_PATHS
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_gate import close_gate, restore_admission
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from lowerduckpond_static_host_agent.host_restore_validation import validate_restored_authority
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - pytest fixture
from test_backup_capture import Capture
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_snapshot import inspect
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414


def _filesystem(device: int, available: int) -> FilesystemCapacity:
    return FilesystemCapacity(device, 4096, 8_000_000, available, 2_000_000, 1_500_000)


def test_reservation_aggregates_shared_devices_and_never_credits_existing_roots() -> None:
    labels = set(SOURCE_PATHS) | set(STAGED_PATHS)
    inventory: dict[str, object] = {
        "sourceUsage": {
            label: {"allocatedBytes": 1024**3, "entries": 100, "contentBytes": 10}
            for label in labels
        }
    }
    filesystems = {label: _filesystem(1, 2_500_000) for label in labels | {"workspace"}}
    # Each source would fit independently, but all five on one device do not.
    with pytest.raises(CapacityRejectedError):
        materialize.admit_restore_space(inventory, filesystems)
    filesystems = {
        label: _filesystem(index + 1, 2_500_000)
        for index, label in enumerate(sorted(labels | {"workspace"}))
    }
    assert len(materialize.admit_restore_space(inventory, filesystems)) == len(filesystems)
    filesystems["content"] = _filesystem(1, 1_300_000)
    with pytest.raises(CapacityRejectedError):
        materialize.admit_restore_space(inventory, filesystems)


def test_private_materialization_resumes_only_its_inodes_and_preserves_original_source(  # noqa: PLR0915
    capture: Capture,
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    journal: RestoreJournal,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, _ = restic
    inspection = inspect(snapshot)
    root = tmp_path / "coordinator"
    root.mkdir(mode=0o700)
    private = tmp_path / "destination"
    private.mkdir(mode=0o700)
    workspace = tmp_path / "materialization-workspace"
    workspace.mkdir(mode=0o700)
    paths = materialize.MaterializationPaths(
        {label: private / label for label in SOURCE_PATHS}, private / "staging", workspace
    )
    monkeypatch.setattr(
        materialize,
        "measure_filesystem_capacity",
        lambda path: _filesystem(path.stat().st_dev, 7_000_000),
    )
    calls: list[str] = []
    interrupted = True

    def restore(arguments: tuple[str, ...], *args: object, **kwargs: object) -> bytes:
        nonlocal interrupted
        assert arguments[:2] == ("--no-cache", "restore")
        assert arguments[3] == "--target" and arguments[5:] == ("--verify", "--quiet")
        source = arguments[2].removeprefix(snapshot.snapshot.snapshot_id + ":")
        target = Path(arguments[4])
        calls.append(source)
        assert not restore_admission(root, owner=os.geteuid(), caddy=True)
        if source in SOURCE_PATHS.values():
            label = next(label for label, path in SOURCE_PATHS.items() if path == source)
            shutil.copytree(
                capture.roots[label],
                target,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("intake", "exports", ".staging"),
            )
        else:
            assert source == str(Path(STAGED_PATHS["database"]).parent)
            for label, value in (("database", b"dump"), ("descriptor", snapshot.descriptor)):
                path = target / Path(STAGED_PATHS[label]).name
                path.write_bytes(value)
                path.chmod(0o600)
        if interrupted:
            interrupted = False
            raise RuntimeError("lost Restic process after writing its private target")
        return b""

    monkeypatch.setattr(materialize, "_run_restic", restore)
    journal = replace(
        journal,
        snapshot_id=snapshot.snapshot.snapshot_id,
        bindings={
            **journal.bindings,
            "backupDescriptor": cast(dict[str, str], inspection["descriptorDigest"]),
        },
    )
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        close_gate(store, journal.restore_id)
        store.begin(journal)
        with pytest.raises(RuntimeError, match="lost Restic"):
            materialize.materialize_snapshot(store, snapshot, paths, {}, inspection)
        identities = {label: path.stat().st_ino for label, path in paths.targets().items()}
        first = materialize.materialize_snapshot(store, snapshot, paths, {}, inspection)
        assert materialize.materialize_snapshot(store, snapshot, paths, {}, inspection) == first
        assert identities == {label: path.stat().st_ino for label, path in paths.targets().items()}
    assert capture.descriptor() == json.loads(snapshot.descriptor)
    validate_restored_authority(
        snapshot.descriptor,
        paths.roots,
        workspace,
        owner=os.geteuid(),
        content_group=os.getegid(),
        repository_genesis=capture.state.lineage,
        artifact_sha256="b" * 64,
        namespace=json.loads((capture.state.root / "platform/namespace.json").read_bytes()),
        launch=None,
    )
    assert len(calls) == 1 + 2 * len(paths.targets())
    path = paths.roots["state"]
    path.rename(path.with_name("unknown-prior"))
    path.mkdir(mode=0o700)
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        pytest.raises(HostRestoreError, match="identity"),
    ):
        materialize.materialize_snapshot(store, snapshot, paths, {}, inspection)
    assert (path.with_name("unknown-prior") / "platform/namespace.json").is_file()
