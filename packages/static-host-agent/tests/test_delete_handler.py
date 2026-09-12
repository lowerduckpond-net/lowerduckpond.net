from __future__ import annotations

from functools import partial
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import delete_handler as handler_module
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.delete_commit import DeleteCommitBoundary
from lowerduckpond_static_host_agent.delete_publication import activate_delete_transition
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_handler import _host
from test_archive_journal import _TENANT, capacity  # noqa: F401 - capacity fixture


class InterruptedDeleteError(BaseException):
    pass


@pytest.mark.parametrize(
    "boundary",
    [
        None,
        DeleteCommitBoundary.AUDIT_SYNC,
        DeleteCommitBoundary.STATE_RECORD_REMOVED,
        DeleteCommitBoundary.TENANT_REMOVED,
        DeleteCommitBoundary.RESULT_SYNC,
    ],
)
def test_delete_dispatch_commits_or_recovers_and_purges_only_after_tombstone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: DeleteCommitBoundary | None
) -> None:
    def interrupt(current: DeleteCommitBoundary) -> None:
        if boundary == current:
            raise InterruptedDeleteError

    with _host(tmp_path, deletion=True) as (executor, job_id, repository, remote, runtime, futures):
        if boundary is not None:
            with monkeypatch.context() as patch:
                patch.setattr(
                    handler_module,
                    "activate_delete_transition",
                    partial(activate_delete_transition, failure_hook=interrupt),
                )
                with pytest.raises(InterruptedDeleteError):
                    executor.execute(job_id)
            assert remote.versions
        outcome = executor.execute(job_id)
        assert outcome.result["status"] == "succeeded"
        assert outcome.result["operation"] == "delete"
        assert "manifest" not in outcome.result
        assert not remote.versions
        assert not (tmp_path / "state" / "tenants" / _TENANT).exists()
        assert not (tmp_path / "sites" / _TENANT).exists()
        assert not runtime.snapshots[runtime.active].tenants
        assert not repository.measure_intent_records().records
        assert executor.execute(job_id).result == outcome.result
        for future in futures:
            future.result(timeout=5)
        assert remote.calls.count("put") == 1


def test_delete_rechecks_remote_bytes_when_recovering_before_tombstone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _host(tmp_path, deletion=True) as (
        executor,
        job_id,
        repository,
        remote,
        _runtime,
        futures,
    ):

        def interrupt(*_args: object, **_kwargs: object) -> None:
            raise InterruptedDeleteError

        with monkeypatch.context() as patch:
            patch.setattr(handler_module, "activate_delete_transition", interrupt)
            with pytest.raises(InterruptedDeleteError):
                executor.execute(job_id)
        source = repository.read(StateRecordPath.tenant_desired(_TENANT))
        remote.body = b"x" * len(remote.body)
        with pytest.raises(ArchiveRemoteError):
            executor.execute(job_id)
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).revision == source.revision
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job_id))
        for future in futures[:-1]:
            future.result(timeout=5)
        with pytest.raises(ArchiveRemoteError):
            futures[-1].result(timeout=5)
