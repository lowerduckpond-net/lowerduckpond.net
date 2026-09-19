from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import cast

import pytest
from lowerduckpond_static_host_agent import archive_construction_service
from lowerduckpond_static_host_agent.archive_journal import (
    ArchiveConstructionJournal,
    ArchiveJournal,
)
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_handler import _host
from test_archive_journal import capacity  # noqa: F401 - shared capacity fixture


@pytest.mark.parametrize(
    "boundary",
    ["prepare", "confirm", "ready-authority", "upload-authority", "prepared", "bindings"],
)
def test_construction_waits_for_concurrent_state_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    with _host(tmp_path) as (executor, job_id, repository, remote, _runtime, services):
        reached, proceed = Event(), Event()
        target, name = (
            (ArchiveConstructionJournal, boundary)
            if boundary in {"prepare", "confirm"}
            else (ArchiveJournal, "bound_versions")
            if boundary == "bindings"
            else (archive_construction_service, "_read_authority")
        )
        original = cast(Callable[..., object], getattr(target, name))

        def pause_at_state(*args: object, **kwargs: object) -> object:
            if reached.is_set() or (
                boundary in {"ready-authority", "upload-authority", "prepared"}
                and (kwargs["intent_id"] is None) != (boundary == "ready-authority")
            ):
                return original(*args, **kwargs)
            # Hold state after the second authority read to exercise the
            # service's separate prepared-intent read, not the authority read.
            result = original(*args, **kwargs) if boundary == "prepared" else None
            reached.set()
            assert proceed.wait(5), "construction did not receive its lock probe"
            return result if boundary == "prepared" else original(*args, **kwargs)

        monkeypatch.setattr(target, name, pause_at_state)
        with ThreadPoolExecutor() as pool:
            execution = pool.submit(executor.execute, job_id, blocking=True)
            try:
                assert reached.wait(5), "execution did not reach construction"
                with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True) as transaction:
                    job = transaction.read(StateRecordPath.authorization_job(job_id)).document
                    assert job["phase"] == "claimed"
                    assert job["executionValidated"] is False
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
        assert len(remote.versions) == 1
        for service in services:
            service.result(timeout=5)


@pytest.mark.parametrize("failure", ["inventory", "lost-upload-response"])
def test_construction_persists_quarantine_through_state_contention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    with _host(tmp_path, lost_response=failure == "lost-upload-response") as (
        executor,
        job_id,
        repository,
        remote,
        _runtime,
        services,
    ):
        if failure == "inventory":

            def unavailable(**_kwargs: object) -> dict[str, object]:
                raise TimeoutError("injected unavailable inventory")

            monkeypatch.setattr(remote, "list_object_versions", unavailable)
        reached, proceed = Event(), Event()
        original = ArchiveQuarantine.record

        def pause_at_quarantine(*args: object, **kwargs: object) -> object:
            reached.set()
            assert proceed.wait(5), "quarantine did not receive its lock probe"
            return cast(Callable[..., object], original)(*args, **kwargs)

        monkeypatch.setattr(ArchiveQuarantine, "record", pause_at_quarantine)
        with ThreadPoolExecutor() as pool:
            execution = pool.submit(executor.execute, job_id, blocking=True)
            try:
                assert reached.wait(5), "construction did not reach quarantine"
                with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True):
                    proceed.set()
                    with pytest.raises(TimeoutError):
                        execution.result(timeout=0.1)
            finally:
                proceed.set()
            with pytest.raises(ArchiveRemoteError):
                execution.result(timeout=5)
        with pytest.raises(TimeoutError):
            services[0].result(timeout=5)
        quarantine = json.loads((tmp_path / "state/platform/archive-quarantine.json").read_text())
        assert quarantine["discoveryIncomplete"] is True
        job = repository.read(StateRecordPath.authorization_job(job_id)).document
        assert job["phase"] == "claimed"
        assert job["executionValidated"] is False
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job_id))
        assert len(repository.measure_intent_records().records) == 1
        assert remote.calls.count("put") == (1 if failure == "lost-upload-response" else 0)
