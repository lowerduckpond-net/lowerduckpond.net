from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import get_context
from multiprocessing.connection import Connection
from pathlib import Path
from threading import Event

import pytest
from lowerduckpond_static_host_agent import (
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    LockRequest,
    StateBusyError,
    StatePathError,
)

_LOCK_MODE = 0o600
_PROCESS_TIMEOUT_SECONDS = 10


def _manager(lock_root: Path) -> LockManager:
    return LockManager(lock_root, expected_owner=os.geteuid())


def _attempt_publication_lock(lock_root: str, connection: Connection) -> None:
    try:
        with _manager(Path(lock_root)) as manager, manager.acquire(LockName.PUBLICATION):
            connection.send("acquired")
    except StateBusyError:
        connection.send("busy")
    finally:
        connection.close()


def _hold_lock(
    manager: LockManager,
    name: LockName,
    mode: LockMode,
    entered: Event,
    release: Event,
) -> None:
    with manager.acquire(name, mode=mode):
        entered.set()
        if not release.wait(_PROCESS_TIMEOUT_SECONDS):
            raise TimeoutError("test did not release held lock")


def test_initialize_creates_exact_durable_lock_inodes(tmp_path: Path) -> None:
    with LockManager.initialize(tmp_path, expected_owner=os.geteuid()):
        pass

    assert {path.name for path in tmp_path.iterdir()} == {
        "intake.lock",
        "export.lock",
        "publication.lock",
        "tenant-state.lock",
    }
    for path in tmp_path.iterdir():
        assert path.read_bytes() == b""
        assert stat.S_IMODE(path.stat().st_mode) == _LOCK_MODE
        assert path.stat().st_nlink == 1


def test_initialize_is_idempotent_but_validates_on_acquisition(tmp_path: Path) -> None:
    first = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    first.close()
    second = LockManager.initialize(tmp_path, expected_owner=os.geteuid())

    with second, second.acquire(LockName.PUBLICATION):
        pass


def test_initialize_rejects_an_existing_untrusted_lock_inode(tmp_path: Path) -> None:
    (tmp_path / "publication.lock").write_bytes(b"")
    (tmp_path / "publication.lock").chmod(0o640)

    with pytest.raises(StatePathError):
        LockManager.initialize(tmp_path, expected_owner=os.geteuid())


def test_complete_outer_to_inner_lock_order_is_permitted(tmp_path: Path) -> None:
    with (
        LockManager.initialize(tmp_path, expected_owner=os.geteuid()) as manager,
        manager.acquire(LockName.INTAKE),
        manager.acquire(LockName.EXPORT),
        manager.acquire(LockName.PUBLICATION),
        manager.acquire(LockName.TENANT_STATE),
    ):
        pass


@pytest.mark.parametrize(
    ("outer", "inner"),
    [
        (LockName.EXPORT, LockName.INTAKE),
        (LockName.PUBLICATION, LockName.EXPORT),
        (LockName.TENANT_STATE, LockName.PUBLICATION),
        (LockName.TENANT_STATE, LockName.INTAKE),
    ],
)
def test_lock_order_inversion_is_rejected_before_kernel_acquisition(
    tmp_path: Path,
    outer: LockName,
    inner: LockName,
) -> None:
    with (
        LockManager.initialize(tmp_path, expected_owner=os.geteuid()) as manager,
        manager.acquire(outer),
        pytest.raises(LockOrderError),
        manager.acquire(inner),
    ):
        pass


def test_recursive_lock_acquisition_is_rejected(tmp_path: Path) -> None:
    with (
        LockManager.initialize(tmp_path, expected_owner=os.geteuid()) as manager,
        manager.acquire(LockName.EXPORT),
        pytest.raises(LockOrderError),
        manager.acquire(LockName.EXPORT),
    ):
        pass


def test_lock_order_is_global_across_manager_instances(tmp_path: Path) -> None:
    outer = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    inner = _manager(tmp_path)
    with (
        outer,
        inner,
        outer.acquire(LockName.TENANT_STATE),
        pytest.raises(LockOrderError),
        inner.acquire(LockName.EXPORT),
    ):
        pass


def test_nonblocking_exclusive_contention_returns_busy(tmp_path: Path) -> None:
    first = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    second = _manager(tmp_path)
    entered = Event()
    release = Event()
    with first, second, ThreadPoolExecutor(max_workers=1) as executor:
        holder = executor.submit(
            _hold_lock,
            first,
            LockName.PUBLICATION,
            LockMode.EXCLUSIVE,
            entered,
            release,
        )
        assert entered.wait(_PROCESS_TIMEOUT_SECONDS)
        with pytest.raises(StateBusyError), second.acquire(LockName.PUBLICATION):
            pass
        release.set()
        holder.result(_PROCESS_TIMEOUT_SECONDS)


def test_nonblocking_contention_returns_busy_in_a_fresh_process(tmp_path: Path) -> None:
    context = get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(
        target=_attempt_publication_lock,
        args=(str(tmp_path), sending),
    )
    try:
        with (
            LockManager.initialize(tmp_path, expected_owner=os.geteuid()) as manager,
            manager.acquire(LockName.PUBLICATION),
        ):
            process.start()
            sending.close()
            assert receiving.poll(_PROCESS_TIMEOUT_SECONDS)
            assert receiving.recv() == "busy"
        process.join(_PROCESS_TIMEOUT_SECONDS)
        assert process.exitcode == 0
    finally:
        receiving.close()
        if process.is_alive():
            process.terminate()
            process.join(_PROCESS_TIMEOUT_SECONDS)


def test_shared_readers_coexist_and_exclude_a_writer(tmp_path: Path) -> None:
    first = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    second = _manager(tmp_path)
    writer = _manager(tmp_path)
    first_entered = Event()
    second_entered = Event()
    release = Event()
    with first, second, writer, ThreadPoolExecutor(max_workers=2) as executor:
        first_holder = executor.submit(
            _hold_lock,
            first,
            LockName.TENANT_STATE,
            LockMode.SHARED,
            first_entered,
            release,
        )
        second_holder = executor.submit(
            _hold_lock,
            second,
            LockName.TENANT_STATE,
            LockMode.SHARED,
            second_entered,
            release,
        )
        assert first_entered.wait(_PROCESS_TIMEOUT_SECONDS)
        assert second_entered.wait(_PROCESS_TIMEOUT_SECONDS)
        with pytest.raises(StateBusyError), writer.acquire(LockName.TENANT_STATE):
            pass
        release.set()
        first_holder.result(_PROCESS_TIMEOUT_SECONDS)
        second_holder.result(_PROCESS_TIMEOUT_SECONDS)


def test_acquire_many_releases_earlier_locks_when_a_later_lock_is_busy(tmp_path: Path) -> None:
    blocker = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    transaction = _manager(tmp_path)
    observer = _manager(tmp_path)
    requests = [
        LockRequest(LockName.EXPORT),
        LockRequest(LockName.TENANT_STATE),
    ]

    entered = Event()
    release = Event()
    with blocker, transaction, observer, ThreadPoolExecutor(max_workers=1) as executor:
        holder = executor.submit(
            _hold_lock,
            blocker,
            LockName.TENANT_STATE,
            LockMode.EXCLUSIVE,
            entered,
            release,
        )
        assert entered.wait(_PROCESS_TIMEOUT_SECONDS)
        with pytest.raises(StateBusyError), transaction.acquire_many(requests):
            pass
        with observer.acquire(LockName.EXPORT):
            pass
        release.set()
        holder.result(_PROCESS_TIMEOUT_SECONDS)


@pytest.mark.parametrize(
    "requests",
    [
        [LockRequest(LockName.PUBLICATION), LockRequest(LockName.EXPORT)],
        [LockRequest(LockName.EXPORT), LockRequest(LockName.EXPORT)],
        [LockRequest(LockName.TENANT_STATE), LockRequest(LockName.INTAKE)],
    ],
)
def test_acquire_many_rejects_an_invalid_sequence_before_any_lock(
    tmp_path: Path,
    requests: list[LockRequest],
) -> None:
    manager = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    observer = _manager(tmp_path)
    with manager, observer:
        with pytest.raises(LockOrderError), manager.acquire_many(requests):
            pass
        with observer.acquire(LockName.PUBLICATION):
            pass


def test_lock_reader_rejects_symlink_substitution(tmp_path: Path) -> None:
    manager = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    manager.close()
    (tmp_path / "publication.lock").unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(b"")
    outside.chmod(_LOCK_MODE)
    (tmp_path / "publication.lock").symlink_to(outside)

    with (
        _manager(tmp_path) as substituted,
        pytest.raises(StatePathError),
        substituted.acquire(LockName.PUBLICATION),
    ):
        pass


def test_lock_reader_rejects_mode_and_link_count_drift(tmp_path: Path) -> None:
    manager = LockManager.initialize(tmp_path, expected_owner=os.geteuid())
    manager.close()
    publication = tmp_path / "publication.lock"
    publication.chmod(0o640)

    with (
        _manager(tmp_path) as wrong_mode,
        pytest.raises(StatePathError),
        wrong_mode.acquire(LockName.PUBLICATION),
    ):
        pass

    publication.chmod(_LOCK_MODE)
    os.link(publication, tmp_path / "extra-link")
    with (
        _manager(tmp_path) as linked,
        pytest.raises(StatePathError),
        linked.acquire(LockName.PUBLICATION),
    ):
        pass


def test_close_refuses_to_invalidate_a_held_lock(tmp_path: Path) -> None:
    manager = LockManager.initialize(tmp_path, expected_owner=os.geteuid())

    with manager.acquire(LockName.EXPORT), pytest.raises(RuntimeError, match="held"):
        manager.close()
    manager.close()
