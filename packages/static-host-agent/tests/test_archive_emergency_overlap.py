from __future__ import annotations

import socket
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event, current_thread

import pytest
from lowerduckpond_static_host_agent import emergency_entrypoint
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from test_archive_activate import _activate, _prepared
from test_archive_cleanup_service import _serve
from test_archive_journal import (
    _OWNER,
    capacity,  # noqa: F401 - shared autouse capacity fixture
)
from test_emergency_delete import _local_recovery_entrypoint


def test_emergency_scan_cannot_interrupt_private_archive_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached_scan = Event()
    release_scan = Event()
    acquire = LockManager.acquire

    @contextmanager
    def pause_scan(
        manager: LockManager,
        name: LockName,
        *,
        mode: LockMode = LockMode.EXCLUSIVE,
        blocking: bool = False,
    ) -> Iterator[None]:
        recovery = current_thread().name.startswith("emergency-scan")
        if recovery and name is LockName.EXPORT:
            reached_scan.set()
        with acquire(manager, name, mode=mode, blocking=blocking):
            if recovery and name is LockName.TENANT_STATE:
                reached_scan.set()
                assert release_scan.wait(5), "archive cleanup did not release the scan"
            yield

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="emergency-scan") as recovery:
        with _prepared(tmp_path, "active") as (journal, store, prepared, runtime):
            _activate(journal, store, prepared, runtime)
            _local_recovery_entrypoint(tmp_path, monkeypatch)
            monkeypatch.setattr(LockManager, "acquire", pause_scan)
            future = recovery.submit(emergency_entrypoint.emergency_delete_main, ["--recover"])
            try:
                assert reached_scan.wait(5), "emergency recovery did not reach discovery"
                sender, receiver = socket.socketpair()
                with ThreadPoolExecutor() as service:
                    cleanup = service.submit(_serve, receiver, tmp_path / "state", journal.remote)
                    try:
                        ArchiveCleanupClient(
                            journal.spool, connector=lambda: sender, expected_peer_uid=_OWNER
                        ).finish(
                            str(prepared.job.document["jobId"]),
                            prepared.plan.construction_intent_id,
                        )
                    finally:
                        cleanup.result(timeout=5)
                assert not journal.repository.measure_intent_records().records
            finally:
                release_scan.set()
        assert future.result(timeout=5) == 0
