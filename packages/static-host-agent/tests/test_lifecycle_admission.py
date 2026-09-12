from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import archive_prepare
from lowerduckpond_static_host_agent.archive_journal import ArchiveRetirementJournal
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_activate import _activate, _prepared
from test_archive_handler import _host
from test_archive_journal import (
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)
from test_restore_commit import _restore, _restoring


def _spare_inodes(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    filesystem = FilesystemCapacity(1, 4096, 8_000_000, 7_000_000, 1_000_000, 100_000 + count)
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _self: filesystem,
    )


def _assert_no_local_intent(tmp_path: Path) -> None:
    with (
        StateRepository(tmp_path / "state", expected_owner=_OWNER) as repository,
        repository.publication_transaction() as transaction,
    ):
        assert all(
            transaction.read_intent(value.intent_id)[1].document["kind"] != "TransactionIntent"
            for value in transaction.measure_intent_records().records
        )


@pytest.mark.parametrize("spare,accepted", [(6, False), (7, True)])
def test_archive_admits_its_intent_and_terminal_batch_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spare: int, accepted: bool
) -> None:
    preparing = _prepared(
        tmp_path, "active", before_prepare=lambda: _spare_inodes(monkeypatch, spare)
    )
    if not accepted:
        with pytest.raises(CapacityRejectedError, match="free-inode floor"), preparing:
            pytest.fail("archive published an intent without capacity for its terminal batch")
        _assert_no_local_intent(tmp_path)
    else:
        with preparing as (journal, store, prepared, runtime):
            _spare_inodes(monkeypatch, spare - 1)
            _activate(journal, store, prepared, runtime)
            journal.finish(prepared.plan.construction_intent_id)
            assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize("spare,accepted", [(6, False), (7, True)])
def test_restore_admits_its_intent_and_terminal_batch_after_writing_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spare: int, accepted: bool
) -> None:
    preparing = _restoring(
        tmp_path, monkeypatch, before_prepare=lambda: _spare_inodes(monkeypatch, spare)
    )
    if not accepted:
        with pytest.raises(CapacityRejectedError, match="free-inode floor"), preparing:
            pytest.fail("restore published an intent without capacity for its terminal batch")
        _assert_no_local_intent(tmp_path)
        assert not list((tmp_path / "sites/.staging").iterdir())
    else:
        with preparing as (journal, store, prepared, runtime):
            _spare_inodes(monkeypatch, spare - 1)
            _restore(journal, store, prepared, runtime)
            journal.finish(str(prepared.retirement.document["intentId"]))
            assert not journal.repository.measure_intent_records().records


def test_archive_requires_terminal_audit_headroom_before_any_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote) as (journal, job_id, snapshot, _quarantine):
        # Enough for the old journal-only check, but not the terminal audit segment.
        available = (5 * 1024**3 + 1024**2) // 4096
        filesystem = FilesystemCapacity(1, 4096, 8_000_000, available, 4_000_000, 3_000_000)
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
            lambda _self: filesystem,
        )
        with pytest.raises(CapacityRejectedError, match="free-block floor"):
            journal.construct(job_id, snapshot, now=_NOW)
        assert "put" not in remote.calls
        assert not remote.versions
        assert not journal.repository.measure_intent_records().records


def test_restore_cannot_cancel_retirement_after_its_local_intent_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _restoring(tmp_path, monkeypatch) as (journal, store, prepared, runtime):
        before = journal.repository.measure_intent_records().records
        retirement = ArchiveRetirementJournal(
            journal.repository, journal.spool, bucket=journal.remote.bucket
        )
        assert not retirement.cancel_unstarted_restore(
            str(prepared.job.document["jobId"]), prepared.retirement
        )
        assert journal.repository.measure_intent_records().records == before
        _restore(journal, store, prepared, runtime)
        journal.finish(str(prepared.retirement.document["intentId"]))
        assert not journal.repository.measure_intent_records().records


def test_archive_retires_an_upload_if_later_capacity_refuses_local_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise CapacityRejectedError("terminal batch no longer fits")

    with _host(tmp_path) as (executor, job_id, repository, remote, runtime, futures):
        source = repository.read(StateRecordPath.tenant_desired(_TENANT))
        selected = runtime.active
        monkeypatch.setattr(archive_prepare, "admit_archive_records", refuse)
        outcome = executor.execute(job_id)
        assert outcome.result["status"] == "failed"
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).revision == source.revision
        assert runtime.active == runtime.running == selected
        assert "discarded" in runtime.events
        assert remote.calls.count("put") == 1
        assert not remote.versions
        assert not repository.measure_intent_records().records
        for future in futures:
            future.result(timeout=5)
