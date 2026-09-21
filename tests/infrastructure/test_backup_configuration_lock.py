from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

HELPER = Path(__file__).parents[2] / "config/ansible/roles/base/files/configure-backup-python"


@pytest.fixture
def helper(tmp_path: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("configure_backup_python", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module.__dict__.update(
        CACHE=tmp_path / "cache",
        CONFIGURATION=tmp_path / "backup.env",
        STATUS=tmp_path / "status",
        STATIC=tmp_path / "static",
        OWNER_UID=os.geteuid(),
        OWNER_GID=os.getegid(),
    )
    module.STATIC.mkdir(mode=0o700)
    for name in ("locks", "platform", "audit", "tenants"):
        (module.STATIC / name).mkdir(mode=0o700)
    return module


def test_bootstrap_creates_one_private_empty_inherited_repository_lease(helper: ModuleType) -> None:
    descriptor = helper._acquire()
    try:
        path = helper.CACHE / "repository.lock"
        assert os.get_inheritable(descriptor)
        assert path.stat().st_ino == os.fstat(descriptor).st_ino
        assert path.read_bytes() == b""
        assert path.stat().st_mode & 0o777 == 0o600  # noqa: PLR2004 - fixed lock mode
        with path.open("rb") as contender, pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)
    inode = path.stat().st_ino
    helper.CONFIGURATION.write_bytes(b"configured")
    descriptor = helper._acquire()
    os.close(descriptor)
    assert path.stat().st_ino == inode


@pytest.mark.parametrize(
    "evidence",
    [
        "configuration",
        "dangling-configuration",
        "genesis",
        "primary",
        "audit",
        "tenant",
        "status",
        "cache",
    ],
)
def test_existing_backup_or_history_never_authorizes_recreating_missing_lock(
    helper: ModuleType, evidence: str
) -> None:
    if evidence == "configuration":
        helper.CONFIGURATION.write_bytes(b"configured")
    elif evidence == "dangling-configuration":
        helper.CONFIGURATION.symlink_to("missing")
    elif evidence == "genesis":
        (helper.STATIC / "locks/audit-lineage-genesis.json").write_bytes(b"history")
    elif evidence == "primary":
        (helper.STATIC / "platform/audit-lineage.json").write_bytes(b"history")
    elif evidence in {"audit", "tenant"}:
        (helper.STATIC / ("audit" if evidence == "audit" else "tenants") / "history").write_bytes(
            b"history"
        )
    else:
        directory = helper.STATUS if evidence == "status" else helper.CACHE
        directory.mkdir(mode=0o700)
        (directory / "existing").write_bytes(b"history")
    with pytest.raises(ValueError, match="missing lock authority"):
        helper._acquire()
    assert not (helper.CACHE / "repository.lock").exists()


@pytest.mark.parametrize(
    "damage", ["symlink", "hardlink", "mode", "content", "fifo", "cache-symlink", "cache-mode"]
)
def test_unsafe_repository_inode_or_parent_cannot_authorize_activation(
    helper: ModuleType, damage: str
) -> None:
    descriptor = helper._acquire()
    os.close(descriptor)
    path = helper.CACHE / "repository.lock"
    if damage in {"symlink", "fifo"}:
        path.unlink()
        if damage == "symlink":
            path.symlink_to("missing")
        else:
            os.mkfifo(path, mode=0o600)
    elif damage == "hardlink":
        (helper.CACHE / "other").hardlink_to(path)
    elif damage == "mode":
        path.chmod(0o644)
    elif damage == "content":
        path.write_bytes(b"unexpected")
    elif damage == "cache-mode":
        helper.CACHE.chmod(0o755)
    else:
        target = helper.CACHE.with_name("moved")
        helper.CACHE.rename(target)
        helper.CACHE.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        helper._acquire()


def test_inode_replacement_while_waiting_does_not_authorize_activation(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = helper._acquire()
    os.close(descriptor)
    path = helper.CACHE / "repository.lock"
    acquire = fcntl.flock

    def replace_after(descriptor: int, operation: int) -> None:
        acquire(descriptor, operation)
        path.rename(path.with_name("old.lock"))
        path.write_bytes(b"")
        path.chmod(0o600)

    monkeypatch.setattr(fcntl, "flock", replace_after)
    with pytest.raises(ValueError, match="unsafe"):
        helper._acquire()


def test_backup_configuration_interpreter_remains_root_only(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit, match="backup_configuration_root_required"):
        helper.main()
