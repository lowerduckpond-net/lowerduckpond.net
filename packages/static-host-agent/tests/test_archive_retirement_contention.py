from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from lowerduckpond_static_host_agent import archive_service, delete_handler, restore_handler
from lowerduckpond_static_host_agent.archive_journal import ArchiveRetirementJournal
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_handler import _host
from test_archive_journal import _TENANT, capacity  # noqa: F401 - shared capacity fixture
from test_restore_handler import extraction_capacity  # noqa: F401 - extraction capacity fixture


@pytest.mark.parametrize(
    ("operation", "boundary"),
    [
        ("restore", "download"),
        ("restore", "prepare"),
        ("delete", "prepare"),
        ("restore", "cancel"),
        ("delete", "cancel"),
    ],
)
def test_archive_retirement_waits_for_concurrent_state_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, boundary: str
) -> None:
    with _host(tmp_path, restore=operation == "restore", deletion=operation == "delete") as (
        executor,
        job_id,
        repository,
        remote,
        _runtime,
        services,
    ):
        source = repository.read(StateRecordPath.tenant_desired(_TENANT))
        versions = list(remote.versions)
        reached, proceed = Event(), Event()
        target, name = (
            (archive_service, "_read_authority")
            if boundary == "download"
            else (
                ArchiveRetirementJournal,
                "cancel_unstarted_retirement" if boundary == "cancel" else "prepare",
            )
        )
        original = cast(Callable[..., object], getattr(target, name))

        def pause_at_state(*args: object, **kwargs: object) -> object:
            reached.set()
            assert proceed.wait(5), "retirement did not receive its lock probe"
            return original(*args, **kwargs)

        if boundary == "cancel":

            def unavailable(*_args: object, **_kwargs: object) -> None:
                raise RuntimeError("injected local preparation failure")

            monkeypatch.setattr(
                restore_handler if operation == "restore" else delete_handler,
                f"prepare_{operation}_transition",
                unavailable,
            )
        monkeypatch.setattr(target, name, pause_at_state)
        with ThreadPoolExecutor() as pool:
            execution = pool.submit(executor.execute, job_id, blocking=True)
            try:
                assert reached.wait(5), "execution did not reach retirement"
                with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True):
                    proceed.set()
                    with pytest.raises(TimeoutError):
                        execution.result(timeout=0.1)
            finally:
                proceed.set()
            if boundary == "cancel":
                with pytest.raises(RuntimeError, match="injected local preparation failure"):
                    execution.result(timeout=5)
                assert (
                    repository.read(StateRecordPath.tenant_desired(_TENANT)).revision
                    == source.revision
                )
                assert remote.versions == versions
            else:
                result = execution.result(timeout=5).result
                assert result["status"] == "succeeded"
                assert not remote.versions
                job = repository.read(StateRecordPath.authorization_job(job_id)).document
                assert job["executionValidated"] is True
                assert job["phase"] == "completed"
        assert not repository.measure_intent_records().records
        assert remote.calls.count("put") == 1
        for service in services:
            service.result(timeout=5)
