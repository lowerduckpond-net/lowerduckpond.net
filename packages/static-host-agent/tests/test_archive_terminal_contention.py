from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from lowerduckpond_static_host_agent import archive_verification
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_handler import _host
from test_archive_journal import capacity  # noqa: F401 - capacity fixture
from test_restore_handler import extraction_capacity  # noqa: F401 - extraction capacity fixture


@pytest.mark.parametrize("boundary", ["authority", "bindings", "quarantine"])
@pytest.mark.parametrize("operation", ["archive", "restore", "delete"])
def test_terminal_replay_waits_for_concurrent_state_access(
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
        completed = executor.execute(job_id)
        before = repository.read(StateRecordPath.authorization_job(job_id)).document
        assert before["executionValidated"] is True
        versions_before = list(remote.versions)
        calls_before = list(remote.calls)
        reached, proceed = Event(), Event()
        target, name = {
            "authority": (archive_verification, "_terminal_authority"),
            "bindings": (ArchiveJournal, "bound_versions"),
            "quarantine": (ArchiveQuarantine, "resolve"),
        }[boundary]
        original = cast(Callable[..., object], getattr(target, name))

        def pause_at_state_access(*args: object, **kwargs: object) -> object:
            reached.set()
            assert proceed.wait(5), "terminal verification did not receive its lock probe"
            return original(*args, **kwargs)

        with monkeypatch.context() as patch, ThreadPoolExecutor() as pool:
            patch.setattr(target, name, pause_at_state_access)
            replay = pool.submit(executor.execute, job_id, blocking=True)
            try:
                assert reached.wait(5), "replay did not reach terminal verification"
                # Model a reconciler holding this actual kernel lock. Verification
                # must wait rather than turn normal contention into a failed worker.
                with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True):
                    proceed.set()
                    with pytest.raises(TimeoutError):
                        replay.result(timeout=0.1)
            finally:
                proceed.set()
            assert replay.result(timeout=5).result == completed.result
        assert repository.read(StateRecordPath.authorization_job(job_id)).document == before
        assert not repository.measure_intent_records().records
        assert remote.versions == versions_before
        assert remote.calls.count("put") == calls_before.count("put")
        assert remote.calls.count("delete") == calls_before.count("delete")
        for service in services:
            service.result(timeout=5)
