from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.host_restore_install import RootSwap, install_roots
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_locks import (
    recreate_kernel_locks,
    verify_kernel_locks,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockName
from test_host_restore_install import swaps as swaps  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414


@pytest.mark.parametrize("name", [lock.filename for lock in LockName])
@pytest.mark.parametrize(
    "boundary", ["original-renamed", "original-synced", "fresh-renamed", "fresh-synced"]
)
def test_kernel_lock_recreation_survives_hard_exit_without_replacing_durable_cursor(
    root: Path,
    swaps: dict[str, RootSwap],
    name: str,
    boundary: str,
) -> None:
    swap = swaps["state"]
    locks = swap.candidate / "locks"
    locks.mkdir(mode=0o700)
    originals: dict[str, int] = {}
    for lock in LockName:
        path = locks / lock.filename
        path.touch(mode=0o600)
        originals[lock.filename] = path.stat().st_ino
    cursor = locks / "authorization-recovery.cursor"
    cursor.write_bytes(b"original durable cursor bytes")
    cursor.chmod(0o600)
    cursor_inode = cursor.stat().st_ino
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        install_roots(store, swaps)

    def crash(actual_name: str, actual_boundary: str) -> None:
        if (actual_name, actual_boundary) == (name, boundary):
            os._exit(73)

    child = os.fork()
    if child == 0:
        with RestoreStore.locked(root, owner=os.geteuid()) as store:
            recreate_kernel_locks(store, swap.destination, swap.container, failure_hook=crash)
        os._exit(74)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 73  # noqa: PLR2004
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        first = recreate_kernel_locks(store, swap.destination, swap.container)
        assert recreate_kernel_locks(store, swap.destination, swap.container) == first
        current = store.read()
        assert current is not None
        store.advance(current, RestorePhase.INSTALLED, {"locks": first})
        assert verify_kernel_locks(store, swap.destination, swap.container) == first
    for lock in LockName:
        assert (swap.destination / "locks" / lock.filename).stat().st_ino != originals[
            lock.filename
        ]
        assert (swap.container / ("restored-" + lock.filename)).stat().st_ino == originals[
            lock.filename
        ]
    cursor = swap.destination / "locks" / cursor.name
    assert cursor.stat().st_ino == cursor_inode
    assert cursor.read_bytes() == b"original durable cursor bytes"
    with (
        LockManager(swap.destination / "locks", expected_owner=os.geteuid()) as manager,
        manager.acquire(LockName.PUBLICATION),
        manager.acquire(LockName.TENANT_STATE),
    ):
        pass


def test_uninstalled_state_cannot_recreate_even_an_inert_lock(
    root: Path,
    swaps: dict[str, RootSwap],
) -> None:
    swap = swaps["state"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        pytest.raises((HostRestoreError, FileNotFoundError)),
    ):
        recreate_kernel_locks(store, swap.candidate, swap.container)
    assert not (swap.container / "fresh-publication.lock").exists()


@pytest.mark.parametrize("damage", ["active", "retained", "receipt"])
def test_installed_lock_is_never_replaced_on_resume(
    root: Path, swaps: dict[str, RootSwap], damage: str
) -> None:
    swap = swaps["state"]
    locks = swap.candidate / "locks"
    locks.mkdir(mode=0o700)
    for lock in LockName:
        (locks / lock.filename).touch(mode=0o600)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        install_roots(store, swaps)
        recreate_kernel_locks(store, swap.destination, swap.container)
        current = store.read()
        assert current is not None
        store.advance(current, RestorePhase.INSTALLED, {"installed": True})
        if damage == "receipt":
            (root / "kernel-locks.json").unlink()
        else:
            path = (
                swap.destination / "locks" / LockName.PUBLICATION.filename
                if damage == "active"
                else swap.container / ("restored-" + LockName.PUBLICATION.filename)
            )
            path.rename(path.with_name("preserved-inert-lock"))
            path.touch(mode=0o600)
        with pytest.raises((HostRestoreError, FileNotFoundError)):
            verify_kernel_locks(store, swap.destination, swap.container)
        assert not list(swap.container.glob("fresh-*"))
