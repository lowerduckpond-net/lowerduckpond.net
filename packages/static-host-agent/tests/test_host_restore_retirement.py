from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import archive_record_digest
from lowerduckpond_static_host_agent.archive_journal import ArchiveRetirementJournal
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_retirement import reconcile_unstarted_retirement
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import begin
from test_restore_commit import _restoring


class CapturedPreparationError(Exception):
    pass


def _capture() -> None:
    raise CapturedPreparationError


@pytest.mark.parametrize("boundary", ["decision", "removed", "result", "missing-version"])
def test_unstarted_retirement_preserves_archived_source_and_resumes_exact_failure(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    with (
        pytest.raises(CapturedPreparationError),
        _restoring(tmp_path, monkeypatch, before_prepare=_capture),
    ):
        pytest.fail("capture must precede local tenant restoration")
    state = tmp_path / "state"
    with (
        StateRepository(state, expected_owner=os.geteuid()) as repository,
        ExportSpool(state, expected_owner=os.geteuid()) as spool,
        spool.construction(),
    ):
        spool.discard_workspace()
        identity = repository.measure_intent_records().records[0]
        original = repository.read(
            StateRecordPath.archive_retirement_intent(identity.intent_id)
        ).document
        job_id = str(cast(dict[str, object], original["provenance"])["jobId"])
        source = repository.read(StateRecordPath.tenant_desired(original["tenantId"])).document
        archive = cast(dict[str, object], original["archiveRecord"])
    proof = {
        "archives": [
            {
                "archiveDigest": archive_record_digest(archive).to_dict(),
                "required": True,
                "present": boundary != "missing-version",
            }
        ],
        "multipartCount": 0,
    }
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        begin(store, journal)

    def resume(*, crash: bool) -> dict[str, object]:
        def hook(actual: str) -> None:
            if crash and actual == boundary:
                os._exit(73)

        with (
            RestoreStore.locked(root, owner=os.geteuid()) as store,
            StateRepository(state, expected_owner=os.geteuid()) as repository,
            ExportSpool(state, expected_owner=os.geteuid()) as spool,
            spool.construction(),
        ):
            retirement = ArchiveRetirementJournal(repository, spool, bucket=str(original["bucket"]))
            return reconcile_unstarted_retirement(
                store, retirement, identity.intent_id, proof, failure_hook=hook
            )

    if boundary == "missing-version":
        with pytest.raises(HostRestoreError, match="archive_proof_unavailable"):
            resume(crash=False)
        with StateRepository(state, expected_owner=os.geteuid()) as repository:
            assert (
                repository.read(
                    StateRecordPath.archive_retirement_intent(identity.intent_id)
                ).document
                == original
            )
            with pytest.raises(FileNotFoundError):
                repository.read(StateRecordPath.authorization_result(job_id))
        return
    child = os.fork()
    if child == 0:
        resume(crash=True)
        os._exit(74)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 73  # noqa: PLR2004 - owned crash boundary
    decision = resume(crash=False)
    assert resume(crash=False) == decision
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        assert not repository.measure_intent_records().records
        assert (
            repository.read(StateRecordPath.tenant_desired(original["tenantId"])).document == source
        )
        assert (
            repository.read(StateRecordPath.authorization_result(job_id)).document["errorCode"]
            == "unavailable"
        )
        assert (
            repository.read(StateRecordPath.authorization_job(job_id)).document["phase"] == "failed"
        )
        assert (
            repository.read(
                StateRecordPath.tenant_archive(original["tenantId"], archive["deploymentId"])
            ).document
            == archive
        )
