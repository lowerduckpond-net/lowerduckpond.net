from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

HELPER = Path(__file__).parents[2] / "config/ansible/roles/base/files/configure-static-python"


@pytest.fixture
def helper(tmp_path: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("configure_static_python", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module.ROOT = tmp_path / "state"
    module.ROOT.mkdir(mode=0o700)
    (module.ROOT / "locks").mkdir(mode=0o700)
    module.LOCKS = tuple(
        module.ROOT / "locks" / name for name in ("publication.lock", "tenant-state.lock")
    )
    module.ALL_LOCKS = (
        module.ROOT / "locks/intake.lock",
        module.ROOT / "locks/export.lock",
        *module.LOCKS,
    )
    module.ARTIFACT_SELECTOR = tmp_path / "current"
    module.BACKUP_CONFIGURATION = tmp_path / "backup.env"
    # Metadata observations use this component fixture's real owner. The
    # installed command's root-only invocation check is independent and fixed.
    module.OWNER_UID = os.geteuid()
    module.OWNER_GID = os.getegid()
    return module


def _initialize(helper: ModuleType) -> None:
    for path in helper.ALL_LOCKS:
        path.write_bytes(b"")
        path.chmod(0o600)


def test_configuration_exec_inherits_both_exclusive_writer_locks(helper: ModuleType) -> None:
    _initialize(helper)
    descriptors = helper._acquire()
    try:
        for path, descriptor in zip(helper.LOCKS, descriptors, strict=True):
            assert os.get_inheritable(descriptor)
            assert os.fstat(descriptor).st_ino == path.stat().st_ino
            contender = os.open(path, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_SH | fcntl.LOCK_NB)
            finally:
                os.close(contender)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_fresh_bootstrap_can_complete_partial_empty_lock_creation(helper: ModuleType) -> None:
    assert helper._acquire() == ()
    path = helper.ALL_LOCKS[0]
    path.write_bytes(b"")
    path.chmod(0o600)
    assert helper._acquire() == ()
    assert list((helper.ROOT / "locks").iterdir()) == [path]


@pytest.mark.parametrize(
    "evidence", ["artifact", "backup", "dangling-artifact", "genesis", "state"]
)
def test_existing_host_never_bypasses_missing_lock_exclusion(
    helper: ModuleType, evidence: str
) -> None:
    if evidence == "artifact":
        helper.ARTIFACT_SELECTOR.write_bytes(b"selected")
    elif evidence == "backup":
        helper.BACKUP_CONFIGURATION.write_bytes(b"configured")
    elif evidence == "dangling-artifact":
        helper.ARTIFACT_SELECTOR.symlink_to("missing-artifact")
    elif evidence == "genesis":
        (helper.ROOT / "locks/audit-lineage-genesis.json").write_bytes(b"history")
    else:
        (helper.ROOT / "audit").mkdir(mode=0o700)
        (helper.ROOT / "audit/segment.jsonl").write_bytes(b"history")
    with pytest.raises(ValueError, match="missing lock authority"):
        helper._acquire()


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "mode", "content"])
def test_unsafe_lock_cannot_enter_even_fresh_bootstrap(helper: ModuleType, damage: str) -> None:
    path = helper.ALL_LOCKS[0]
    if damage == "symlink":
        path.symlink_to(helper.ROOT / "missing")
    else:
        path.write_bytes(b"unexpected" if damage == "content" else b"")
        path.chmod(0o640 if damage == "mode" else 0o600)
        if damage == "hardlink":
            (helper.ROOT / "other-link").hardlink_to(path)
    with pytest.raises((ValueError, OSError)):
        helper._acquire()


def test_replaced_inode_after_acquisition_cannot_authorize_module_write(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _initialize(helper)
    original = fcntl.flock
    path = helper.LOCKS[0]
    inode = path.stat().st_ino

    def replace_after_acquire(descriptor: int, operation: int) -> None:
        original(descriptor, operation)
        if os.fstat(descriptor).st_ino == inode:
            path.rename(path.with_suffix(".old"))
            path.write_bytes(b"")
            path.chmod(0o600)

    monkeypatch.setattr(fcntl, "flock", replace_after_acquire)
    with pytest.raises(ValueError, match="unsafe"):
        helper._acquire()


def test_configuration_interpreter_is_root_only(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit, match="static_configuration_root_required"):
        helper.main()
