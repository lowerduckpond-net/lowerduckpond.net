from __future__ import annotations

import fcntl
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import backup_coordinator as coordinator
from lowerduckpond_static_host_agent import backup_entrypoint as entrypoint
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot, inherit_restic_leases
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.locks import LockName, LockOrderError
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - pytest fixture
from test_backup_capture import Capture
from test_backup_capture import capture as capture  # noqa: PLC0414 - pytest fixture
from test_backup_capture import fixture as fixture  # noqa: PLC0414 - pytest fixture


def _writer_probe(root: Path, *, busy: bool) -> None:
    for name in (LockName.PUBLICATION, LockName.TENANT_STATE):
        descriptor = os.open(root / "locks" / name.filename, os.O_RDWR | os.O_NOFOLLOW)
        try:
            if busy:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)


@pytest.mark.parametrize(
    "damage", [None, "discovery", "missing-genesis", "snapshot", "replaced-lock"]
)
def test_coordinator_holds_exact_shared_leases_through_readback_and_releases_on_failure(
    capture: Capture,
    monkeypatch: pytest.MonkeyPatch,
    damage: str | None,
) -> None:
    staging = capture.workspace.parent / "staging"
    staging.mkdir(mode=0o700)
    database = staging / "mariadb.sql.gz"
    database.write_bytes(b"private consistent database dump")
    database.chmod(0o600)
    paths = coordinator.CapturePaths(
        state=capture.state.root,
        content=capture.roots["content"],
        recovery=capture.roots["recovery"],
        staging=staging,
        workspace=capture.workspace,
        caddy=capture.caddy.root,
    )
    identity = RepositoryIdentity("a" * 64, "source-node", "/private/backup")
    called = []

    def discover(
        _environment: Mapping[str, str],
    ) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
        _writer_probe(paths.state, busy=False)
        if damage == "discovery":
            raise BackupIdentityError("repository is unavailable")
        return identity, ()

    def genesis(
        _identity: RepositoryIdentity,
        _snapshots: tuple[RepositorySnapshot, ...],
        _environment: Mapping[str, str],
    ) -> dict[str, object] | None:
        _writer_probe(paths.state, busy=False)
        return None if damage == "missing-genesis" else capture.state.lineage

    def snapshot(raw: bytes, _environment: Mapping[str, str]) -> str:
        called.append("snapshot")
        _writer_probe(paths.state, busy=True)
        assert (staging / "static-recovery.json").read_bytes() == raw
        assert decode_backup_descriptor(raw)["lineage"] == capture.state.lineage
        if damage == "snapshot":
            raise BackupIdentityError("snapshot failed after possible commit")
        if damage == "replaced-lock":
            path = paths.state / "locks/publication.lock"
            path.rename(path.with_suffix(".old"))
            path.write_bytes(b"")
            path.chmod(0o600)
        return "e" * 64

    def capacity(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            os.fstat(descriptor).st_dev, 4096, 32_000_000, 25_000_000, 2_000_000, 1_000_000
        )

    monkeypatch.setattr(coordinator, "discover_repository", discover)
    monkeypatch.setattr(coordinator, "repository_genesis", genesis)
    monkeypatch.setattr(coordinator, "create_coherent_snapshot", snapshot)
    monkeypatch.setattr(coordinator, "measure_filesystem_capacity_descriptor", capacity)
    instant = int(datetime(2026, 9, 21, 5, 0, 1, tzinfo=UTC).timestamp() * 1_000_000_000)
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.backup_coordinator.time.time_ns", lambda: instant
    )
    with (
        (staging / "repository.lock").open("wb") as repository,
        (staging / "selection.lock").open("wb") as selection,
        inherit_restic_leases((repository.fileno(), selection.fileno())),
    ):
        if damage is None:
            assert (
                coordinator.capture_backup(
                    paths,
                    {},
                    artifact_sha256="b" * 64,
                    expected_owner=os.geteuid(),
                    content_group=os.getegid(),
                )
                == "e" * 64
            )
        else:
            with pytest.raises((BackupIdentityError, LockOrderError)):
                coordinator.capture_backup(
                    paths,
                    {},
                    artifact_sha256="b" * 64,
                    expected_owner=os.geteuid(),
                    content_group=os.getegid(),
                )
    _writer_probe(paths.state, busy=False)
    assert len(called) == int(damage not in {"discovery", "missing-genesis"})
    assert database.read_bytes() == b"private consistent database dump"


@pytest.mark.parametrize("arguments,owner", [([], 1000), (["/other/source"], 0)])
def test_capture_entrypoint_rejects_nonroot_and_caller_selected_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    owner: int,
) -> None:
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.backup_entrypoint.os.geteuid", lambda: owner
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.backup_entrypoint.sys.argv", ["capture", *arguments]
    )
    assert entrypoint.capture_main(-1, "b" * 64) == 1
    assert capsys.readouterr().err == "backup_static_invalid_invocation\n"


def test_capture_entrypoint_does_not_emit_private_failure_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def rejected(_descriptors: tuple[int, ...]) -> None:
        raise BackupIdentityError("private-provider-canary")

    monkeypatch.setattr("lowerduckpond_static_host_agent.backup_entrypoint.os.geteuid", lambda: 0)
    monkeypatch.setattr("lowerduckpond_static_host_agent.backup_entrypoint.sys.argv", ["capture"])
    monkeypatch.setattr(entrypoint, "inherit_restic_leases", rejected)
    assert entrypoint.capture_main(-1, "b" * 64) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "backup_static_unverified\n"
