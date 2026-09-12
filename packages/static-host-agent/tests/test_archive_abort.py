from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.archive_abort import (
    ArchiveAbortBoundary,
    ArchiveAbortError,
    finalize_failed_construction,
)
from lowerduckpond_static_host_agent.archive_journal import ArchiveConstructionJournal
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_activate import SimulatedCrashError, _prepared
from test_archive_journal import (
    _BUCKET,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
@pytest.mark.parametrize("uploaded", [False, True])
@pytest.mark.parametrize("boundary", ArchiveAbortBoundary)
def test_unpublished_failure_replays_each_boundary_before_independent_remote_cleanup(
    tmp_path: Path, lifecycle: str, uploaded: bool, boundary: ArchiveAbortBoundary
) -> None:
    remote = MemoryRemote()
    with prepared_source(tmp_path, remote, lifecycle=lifecycle) as (
        journal,
        job_id,
        snapshot,
        quarantine,
    ):
        if uploaded:
            journal.construct(job_id, snapshot, now=_NOW)
        else:
            ArchiveConstructionJournal(
                journal.repository,
                journal.spool,
                expected_owner=_OWNER,
                bucket=_BUCKET,
                require_quarantine_empty=quarantine.require_empty,
            ).prepare(job_id, snapshot, now=_NOW)
        intent = journal.repository.measure_intent_records().records[0]
        source = journal.repository.read(StateRecordPath.tenant_desired(_TENANT))
        observed = journal.repository.read(StateRecordPath.tenant_observed(_TENANT))

        def interrupt(event: ArchiveAbortBoundary) -> None:
            if event == boundary:
                raise SimulatedCrashError

        with pytest.raises(SimulatedCrashError):
            finalize_failed_construction(
                journal.repository, journal.spool, job_id, failure_hook=interrupt
            )
        result = finalize_failed_construction(journal.repository, journal.spool, job_id).result
        assert result["status"] == "failed"
        assert (result["archiveRecord"] is not None) == uploaded
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).revision
            == source.revision
        )
        assert (
            journal.repository.read(StateRecordPath.tenant_observed(_TENANT)).revision
            == observed.revision
        )
        assert journal.repository.measure_intent_records().records == (intent,)
        journal.finish(intent.intent_id)
        assert not remote.versions
        assert not journal.repository.measure_intent_records().records
        assert journal.repository.inspect_audit().entry_count == 1


def test_unpublished_failure_cannot_abort_a_prepared_local_transition(tmp_path: Path) -> None:
    with _prepared(tmp_path, "active") as (journal, _store, prepared, _runtime):
        with pytest.raises(ArchiveAbortError, match="exclusive source"):
            finalize_failed_construction(
                journal.repository, journal.spool, str(prepared.job.document["jobId"])
            )
        assert journal.repository.inspect_audit().entry_count == 0
