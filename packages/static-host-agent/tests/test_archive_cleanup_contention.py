from __future__ import annotations

import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from lowerduckpond_static_host_agent import archive_cleanup_service
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_cleanup_service import _serve
from test_archive_handler import _host
from test_archive_journal import (
    _NOW,
    _OWNER,
    MemoryRemote,
    capacity,  # noqa: F401 - capacity fixture
    prepared_source,
)
from test_restore_handler import extraction_capacity  # noqa: F401 - extraction capacity fixture


@pytest.mark.parametrize(
    "boundary", ["authority", "discovery", "terminal", "bindings", "removal", "quarantine"]
)
@pytest.mark.parametrize("operation", ["archive", "restore", "delete"])
def test_initial_cleanup_waits_for_concurrent_state_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, operation: str
) -> None:
    with _host(tmp_path, restore=operation == "restore", deletion=operation == "delete") as (
        executor,
        job_id,
        repository,
        remote,
        _runtime,
        services,
    ):
        reached, proceed, cleanup_started = Event(), Event(), Event()
        original_authority = cast(Callable[..., object], archive_cleanup_service._cleanup_authority)

        def enter_cleanup(*args: object, **kwargs: object) -> object:
            cleanup_started.set()
            return original_authority(*args, **kwargs)

        monkeypatch.setattr(archive_cleanup_service, "_cleanup_authority", enter_cleanup)
        target, name = {
            "authority": (archive_cleanup_service, "_cleanup_authority"),
            "discovery": (ArchiveJournal, "_remote_intent"),
            "terminal": (ArchiveJournal, "_terminal_result"),
            "bindings": (ArchiveJournal, "bound_versions"),
            "removal": (StateRepository, "remove_reconciled_intent"),
            "quarantine": (ArchiveQuarantine, "resolve"),
        }[boundary]
        original = cast(Callable[..., object], getattr(target, name))

        def pause_at_cleanup_state(*args: object, **kwargs: object) -> object:
            if boundary == "authority" or cleanup_started.is_set():
                reached.set()
                assert proceed.wait(5), "cleanup did not receive its lock probe"
            return original(*args, **kwargs)

        monkeypatch.setattr(target, name, pause_at_cleanup_state)
        with ThreadPoolExecutor() as pool:
            execution = pool.submit(executor.execute, job_id, blocking=True)
            try:
                assert reached.wait(5), "execution did not reach cleanup"
                # Hold the real kernel lock as a concurrent reconciler would.
                # No remote failure or retry is injected: this request must wait.
                with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True) as transaction:
                    pending = transaction.read(StateRecordPath.authorization_job(job_id)).document
                    assert pending["phase"] == "completed"
                    assert pending["executionValidated"] is False
                    durable = transaction.read(
                        StateRecordPath.authorization_result(job_id)
                    ).document
                    assert durable["status"] == "succeeded"
                    proceed.set()
                    with pytest.raises(TimeoutError):
                        execution.result(timeout=0.1)
            finally:
                proceed.set()
            result = execution.result(timeout=5).result
        assert result["status"] == "succeeded"
        terminal = repository.read(StateRecordPath.authorization_job(job_id)).document
        assert terminal["executionValidated"] is True
        assert terminal["phase"] == "completed"
        assert not repository.measure_intent_records().records
        assert remote.calls.count("put") == 1
        assert remote.calls.count("delete") == (0 if operation == "archive" else 1)
        assert len(remote.versions) == (1 if operation == "archive" else 0)
        for service in services:
            service.result(timeout=5)


@pytest.mark.parametrize("boundary", ["authority", "discovery", "bindings"])
@pytest.mark.parametrize("lost_response", [False, True])
def test_unbound_purge_waits_without_repeating_the_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, lost_response: bool
) -> None:
    remote = MemoryRemote()
    remote.lose_response = lost_response
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        if lost_response:
            with pytest.raises(TimeoutError):
                journal.construct(job_id, snapshot, now=_NOW)
        else:
            journal.construct(job_id, snapshot, now=_NOW)
        intent = journal.repository.measure_intent_records().records[0]
        reached, proceed, finished = Event(), Event(), Event()
        target, name = {
            "authority": (archive_cleanup_service, "_cleanup_authority"),
            "discovery": (ArchiveJournal, "_remote_intent"),
            "bindings": (ArchiveJournal, "bound_versions"),
        }[boundary]
        original = cast(Callable[..., object], getattr(target, name))

        def pause_at_cleanup_state(*args: object, **kwargs: object) -> object:
            reached.set()
            assert proceed.wait(5)
            return original(*args, **kwargs)

        def contend() -> None:
            assert reached.wait(5)
            with journal.repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True):
                proceed.set()
                assert not finished.wait(0.1), "purge aborted instead of waiting for state"

        monkeypatch.setattr(target, name, pause_at_cleanup_state)
        sender, receiver = socket.socketpair()
        with ThreadPoolExecutor() as pool:
            service = pool.submit(_serve, receiver, tmp_path / "state", journal.remote)
            holder = pool.submit(contend)
            try:
                ArchiveCleanupClient(
                    journal.spool, connector=lambda: sender, expected_peer_uid=_OWNER
                ).purge_construction(job_id, intent.intent_id)
            finally:
                finished.set()
                proceed.set()
            holder.result(timeout=5)
            service.result(timeout=5)
        assert not remote.versions
        assert remote.calls.count("put") == 1
        assert journal.repository.measure_intent_records().records == (intent,)
        with pytest.raises(FileNotFoundError):
            journal.repository.read(StateRecordPath.authorization_result(job_id))
