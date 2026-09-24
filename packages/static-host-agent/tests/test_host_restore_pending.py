from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import ContractError, ContractKind, validate_contract
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    AuthorizationExecutor,
    StateRecordPath,
    StateRepository,
)
from lowerduckpond_static_host_agent.host_restore_pending import finish_missing_input
from lowerduckpond_static_host_agent.repository import _StateTransaction
from test_execution import (
    _DEPLOYMENT_ID,
    _TENANT_ID,
    _fixture,
    _issue_deploy,
    _state_root,
    _write,
    _write_observed_for_manifest,
)
from test_execution import _capacity_isolated as _capacity_isolated  # noqa: PLC0414


@pytest.mark.parametrize("operation", ["deploy", "import"])
@pytest.mark.parametrize("phase", ["pending", "claimed"])
def test_excluded_input_failure_repairs_its_lost_audit_reply_and_replays_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    phase: str,
) -> None:
    root = _state_root(tmp_path)
    manifest = _fixture("site.json")
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
        _fixture("deployment-record.json"),
    )
    _write_observed_for_manifest(root, manifest)
    before = (root / "tenants" / _TENANT_ID / "desired.json").read_bytes()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued, _artifact, _correlation = _issue_deploy(repository, intake, operation=operation)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        if phase == "claimed":
            document = job.document
            document["phase"] = "claimed"
            repository.compare_and_swap(
                StateRecordPath.authorization_job(issued.job_id), job.revision, document
            )
        for path in (root / "intake").iterdir():
            path.unlink()
        append = _StateTransaction.append_audit

        def fail_after_result(self: _StateTransaction, document: dict[str, object]) -> object:
            raise RuntimeError("interrupted before audit commit")

        monkeypatch.setattr(_StateTransaction, "append_audit", fail_after_result)
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(RuntimeError, match="before audit"),
        ):
            finish_missing_input(transaction, issued.job_id)
        result_path = root / "authorization/results" / (issued.job_id + ".json")
        original = result_path.read_bytes()
        monkeypatch.setattr(_StateTransaction, "append_audit", append)
        with repository.publication_transaction() as transaction:
            result = finish_missing_input(transaction, issued.job_id)
            assert result is not None and result["errorCode"] == "restore_input_unavailable"
            assert finish_missing_input(transaction, issued.job_id) == result
            assert transaction.inspect_audit().entry_count == 1
        replay = AuthorizationExecutor(repository, intake).execute(issued.job_id)
        assert not replay.created and replay.result == result
        assert (
            repository.read(StateRecordPath.authorization_job(issued.job_id)).document["phase"]
            == "failed"
        )
        assert result_path.read_bytes() == original
    assert (root / "tenants" / _TENANT_ID / "desired.json").read_bytes() == before
    assert not list((root / "intake").iterdir())
    invalid = dict(result)
    invalid["operation"] = "rename"
    with pytest.raises(ContractError):
        validate_contract(invalid, expected_kind=ContractKind.OPERATION_RESULT)
