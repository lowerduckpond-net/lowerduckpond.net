from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import host_restore_archive_helper as helper
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore
from lowerduckpond_static_host_agent.locks import LockName
from test_archive_journal import MemoryRemote
from test_repository import _state_root


@pytest.mark.parametrize("failure", [False, True])
def test_helper_keeps_export_exclusion_without_writing_read_only_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: bool
) -> None:
    state = _state_root(tmp_path)
    exports = state / "exports"
    exports.mkdir(mode=0o700)
    recovery = tmp_path / "recovery"
    recovery.mkdir(mode=0o700)
    monkeypatch.setattr(helper, "STATE_ROOT", state)
    monkeypatch.setattr(helper, "RECOVERY_ROOT", recovery)
    configuration = ArchiveConfiguration("ams3", "example-archives", "fixture", "fixture")
    remote = ArchiveRemoteStore(MemoryRemote(), bucket=configuration.bucket)
    monkeypatch.setattr(ArchiveConfiguration, "remote_store", lambda _: remote)
    mkdir = os.mkdir
    export_identity = exports.stat()

    def read_only_exports(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if dir_fd is not None:
            parent = os.fstat(dir_fd)
            if (parent.st_dev, parent.st_ino) == (
                export_identity.st_dev,
                export_identity.st_ino,
            ):
                raise OSError(errno.EROFS, "read-only restored exports")
        mkdir(path, mode, dir_fd=dir_fd)

    # Model the installed read-only state bind while keeping locks writable.
    monkeypatch.setattr(os, "mkdir", read_only_exports)
    with (
        RestoreStore.locked(recovery, owner=os.geteuid()) as store,
        (state / "locks" / LockName.EXPORT.filename).open("rb") as competitor,
    ):
        try:
            with helper.archive_journal(store, configuration) as journal:
                journal._require_lock()
                assert journal.remote is remote
                with pytest.raises(BlockingIOError):
                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if failure:
                    raise ValueError("remote proof failed")
        except ValueError:
            assert failure
        fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert not tuple(exports.iterdir())
