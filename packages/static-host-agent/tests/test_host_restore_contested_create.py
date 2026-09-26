from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    AuthorizationExecutor,
    AuthorizationIssuer,
    ExecutionError,
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
    StateRecordPath,
    StateRepository,
)
from lowerduckpond_static_host_agent.host_restore_verification import verify_authorization
from test_execution import (
    _NOW,
    _CompletingCreateHandler,
    _create_intent,
    _fixture,
    _issue_create,
    _OpenGate,
    _state_root,
    _write,
    _write_observed_for_manifest,
)
from test_execution import _capacity_isolated as _capacity_isolated  # noqa: PLC0414


@pytest.mark.parametrize("damage", ["none", "active-intent", "audit", "result"])
def test_contested_create_rejection_remains_replayable_and_restorable(
    tmp_path: Path, damage: str
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        loser = _issue_create(repository)
        request = _fixture("operation-request.json")
        request["correlationId"] = "0198d17f-6f4a-7000-8000-000000000008"
        winner = AuthorizationIssuer(
            repository, gate=_OpenGate(), entropy=lambda length: b"\x09" * length
        ).issue(
            canonical_json_bytes(request),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )

        class ContestedCreate:
            def execute(
                self, job_id: str, *, claim: LifecycleArtifact | None, blocking: bool
            ) -> ExecutionOutcome:
                # Both requests were issued against the same absent slug. The
                # winner commits after the loser's dispatch inventory was bound
                # but before its handler can prepare an intent.
                assert job_id == loser.job_id
                assert claim is None
                bound = repository.read(StateRecordPath.authorization_job(job_id)).document
                assert bound["dispatchTenantIds"] == []
                AuthorizationExecutor(
                    repository,
                    intake,
                    handlers={"create": _CompletingCreateHandler(repository, state_root=root)},
                    tenant_runtime_validator=lambda *_: True,
                ).execute(winner.job_id, blocking=blocking)
                raise LifecycleJobRejectionError("state_drift")

        executor = AuthorizationExecutor(repository, intake, handlers={"create": ContestedCreate()})
        result = executor.execute(loser.job_id).result
        assert result["status"] == "failed"
        assert result["errorCode"] == "state_drift"
        assert result["failurePublisher"] == "authorization-executor"
        assert (
            repository.read(StateRecordPath.authorization_job(loser.job_id)).document[
                "executionValidated"
            ]
            is True
        )
        path = root.joinpath(*StateRecordPath.authorization_result(loser.job_id).components)
        original_result = path.read_bytes()
        if damage == "active-intent":
            intent = _create_intent(result["correlationId"])
            repository.create_immutable(
                StateRecordPath.transaction_intent(intent["intentId"]), intent
            )
        elif damage == "audit":
            next((root / "audit").glob("segment-*.jsonl")).unlink()
        elif damage == "result":
            sequence = result["failureAuditSequence"]
            assert isinstance(sequence, int)
            damaged = {**result, "failureAuditSequence": sequence + 1}
            _write(root, StateRecordPath.authorization_result(loser.job_id), damaged)
        if damage != "none":
            with pytest.raises(ExecutionError):
                verify_authorization(repository, settled=True)
            return
        # Restore must accept the same history the ordinary executor accepts.
        verify_authorization(repository, settled=True)
        assert executor.execute(loser.job_id).result == result
        assert path.read_bytes() == original_result


@pytest.mark.parametrize("kind", ["archive", "deployment"])
@pytest.mark.parametrize("damage", ["addition", "removal"])
def test_executor_rejection_preserves_unrelated_legacy_tenant_history(
    tmp_path: Path, kind: str, damage: str
) -> None:
    root = _state_root(tmp_path)
    tenant_id = "0198d17f-6f4a-7000-8000-000000000010"
    original_id = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
    extra_id = "0198d17f-6f4a-7000-8000-000000000011"
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    legacy = _fixture("site.json")
    metadata = legacy["metadata"]
    assert isinstance(metadata, dict)
    metadata.update(
        id=tenant_id,
        slug="unrelated-legacy-tenant",
        canonicalOrigin="t-0198d17f6f4a70008000000000000010.lowerduckpond.com",
    )
    # This tenant predates global history binding: no earlier authorization job
    # provides an independent retained-history snapshot to catch the corruption.
    _write(root, StateRecordPath.tenant_desired(tenant_id), legacy)
    _write_observed_for_manifest(root, legacy)
    archive = {**_fixture("archive-record.json"), "tenantId": tenant_id}
    deployment = {**_fixture("deployment-record.json"), "tenantId": tenant_id}
    _write(root, StateRecordPath.tenant_archive(tenant_id, original_id), archive)
    _write(root, StateRecordPath.tenant_deployment(tenant_id, original_id), deployment)

    class RejectedCreate:
        def execute(
            self, job_id: str, *, claim: LifecycleArtifact | None, blocking: bool
        ) -> ExecutionOutcome:
            raise LifecycleJobRejectionError("state_drift")

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue_create(repository)
        executor = AuthorizationExecutor(repository, intake, handlers={"create": RejectedCreate()})
        result = executor.execute(issued.job_id).result
        assert result["failurePublisher"] == "authorization-executor"
        job = repository.read(StateRecordPath.authorization_job(issued.job_id)).document
        assert job["dispatchTenantRecordHistories"] == [[tenant_id, [original_id], [original_id]]]
        verify_authorization(repository, settled=True)
        assert executor.execute(issued.job_id).result == result

        path_for = (
            StateRecordPath.tenant_archive
            if kind == "archive"
            else StateRecordPath.tenant_deployment
        )
        if damage == "addition":
            record = (
                {**archive, "deploymentId": extra_id}
                if kind == "archive"
                else {**deployment, "id": extra_id}
            )
            _write(root, path_for(tenant_id, extra_id), record)
        else:
            root.joinpath(*path_for(tenant_id, original_id).components).unlink()
        with pytest.raises(ExecutionError, match="unrelated tenant retained history"):
            verify_authorization(repository, settled=True)
        with pytest.raises(ExecutionError, match="unrelated tenant retained history"):
            executor.execute(issued.job_id)
