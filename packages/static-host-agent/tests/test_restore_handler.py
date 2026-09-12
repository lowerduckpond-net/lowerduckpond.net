from __future__ import annotations

import os
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent import restore_handler as handler_module
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.restore_activate import activate_restore_transition
from lowerduckpond_static_host_agent.restore_commit import RestoreCommitBoundary
from test_archive_handler import _host
from test_archive_journal import _OWNER, _TENANT, capacity  # noqa: F401 - capacity fixture


class InterruptedRestoreError(BaseException):
    pass


@pytest.fixture(autouse=True)
def extraction_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in ("portable_bundle", "zip_structure"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.measure_filesystem_capacity_descriptor",
            lambda fd: FilesystemCapacity(
                os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
            ),
        )


def test_restore_dispatch_downloads_bound_bytes_commits_and_purges_through_private_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _host(tmp_path, restore=True) as (executor, job_id, repository, remote, runtime, futures):
        source = repository.read(StateRecordPath.tenant_desired(_TENANT)).document
        outcome = executor.execute(job_id)
        assert outcome.result["status"] == "succeeded"
        manifest = cast(dict[str, object], outcome.result["manifest"])
        assert manifest["metadata"] == source["metadata"]
        assert cast(dict[str, object], manifest["spec"])["desiredState"] == "active"
        assert (
            cast(dict[str, object], manifest["spec"])["desiredDeployment"]
            != cast(dict[str, object], source["spec"])["desiredDeployment"]
        )
        assert remote.versions == []
        assert remote.calls.count("put") == 1
        assert not repository.measure_intent_records().records
        assert executor.execute(job_id).result == outcome.result
        assert runtime.active == runtime.running
        monkeypatch.setattr(entrypoints, "TENANT_RELEASE_ROOT", str(tmp_path / "sites"))
        monkeypatch.setattr(entrypoints, "_EXPECTED_OWNER", _OWNER)
        monkeypatch.setattr(entrypoints, "_RELEASE_STAGING_OWNER", _OWNER)
        monkeypatch.setattr(entrypoints, "_RELEASE_STAGING_GROUP", os.getegid())
        assert entrypoints._all_tenant_release_state_matches(repository)
        for future in futures:
            future.result(timeout=5)


@pytest.mark.parametrize(
    "boundary",
    [
        RestoreCommitBoundary.DEPLOYMENT_SYNC,
        RestoreCommitBoundary.ARCHIVE_UNBOUND,
        RestoreCommitBoundary.RESULT_SYNC,
    ],
)
def test_restore_dispatch_recovers_partial_commit_without_another_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: RestoreCommitBoundary
) -> None:
    def interrupt(current: RestoreCommitBoundary) -> None:
        if current == boundary:
            raise InterruptedRestoreError

    with _host(tmp_path, restore=True) as (executor, job_id, repository, remote, _runtime, futures):
        with monkeypatch.context() as patch:
            patch.setattr(
                handler_module,
                "activate_restore_transition",
                partial(activate_restore_transition, failure_hook=interrupt),
            )
            with pytest.raises(InterruptedRestoreError):
                executor.execute(job_id)
        assert remote.versions
        assert executor.execute(job_id).result["status"] == "succeeded"
        assert not remote.versions
        assert not repository.measure_intent_records().records
        assert remote.calls.count("put") == 1
        for future in futures:
            future.result(timeout=5)


def test_restore_retries_download_after_retirement_sync_and_before_local_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _host(tmp_path, restore=True) as (executor, job_id, repository, remote, _runtime, futures):

        def interrupt(*_args: object, **_kwargs: object) -> None:
            raise InterruptedRestoreError

        with monkeypatch.context() as patch:
            patch.setattr(handler_module, "prepare_restore_transition", interrupt)
            with pytest.raises(InterruptedRestoreError):
                executor.execute(job_id)
        assert len(repository.measure_intent_records().records) == 1
        assert executor.execute(job_id).result["status"] == "succeeded"
        assert not remote.versions
        for future in futures:
            future.result(timeout=5)


def test_restore_rejects_corrupt_remote_bytes_before_local_mutation(tmp_path: Path) -> None:
    with _host(tmp_path, restore=True) as (executor, job_id, repository, remote, runtime, futures):
        source = repository.read(StateRecordPath.tenant_desired(_TENANT))
        selected = runtime.active
        remote.body = b"x" * len(remote.body)
        with pytest.raises(ArchiveRemoteError):
            executor.execute(job_id)
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).revision == source.revision
        assert runtime.active == selected
        assert not repository.measure_intent_records().records
        for future in futures[:-1]:
            future.result(timeout=5)
        with pytest.raises(ArchiveRemoteError):
            futures[-1].result(timeout=5)
