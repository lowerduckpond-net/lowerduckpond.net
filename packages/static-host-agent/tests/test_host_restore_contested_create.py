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
