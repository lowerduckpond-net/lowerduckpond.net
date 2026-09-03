from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Protocol

import pytest
from lowerduckpond_static_contracts import (
    HEADER_SIZE,
    FrameKind,
    canonical_json_bytes,
    decode_header,
    decode_result,
    manifest_digest,
    result_digest,
)
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    AuthorizationExecutor,
    AuthorizationIssuer,
    CapacityProjection,
    CorrelationAdmission,
    CorrelationReconciliation,
    DeadlineWriter,
    FilesystemCapacity,
    IssuedAuthorization,
    LockManager,
    OperatorSession,
    ResultWaiter,
    RuntimeBoundaryError,
    StartupReconciler,
    StateRecordPath,
    StateRepository,
    SystemdJobHandoff,
    VerifiedArtifact,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


class _OpenGate:
    def require_enabled(self) -> None:
        return


class _Entropy:
    def __call__(self, length: int) -> bytes:
        return b"\x09" * length


class _ExecutorHandoff:
    def __init__(self, executor: AuthorizationExecutor) -> None:
        self._executor = executor
        self.enqueued: list[str] = []

    def enqueue(self, job_id: str) -> None:
        self.enqueued.append(job_id)
        self._executor.execute(job_id)

    def await_completion(self, job_id: str, *, timeout_seconds: float) -> None:
        assert timeout_seconds > 0
        self.enqueue(job_id)


class _CaptureHandoff:
    def __init__(self) -> None:
        self.enqueued: list[str] = []

    def enqueue(self, job_id: str) -> None:
        self.enqueued.append(job_id)

    def await_completion(self, job_id: str, *, timeout_seconds: float) -> None:
        assert timeout_seconds > 0
        self.enqueue(job_id)


class _IssuedAdapter:
    def __init__(self, issued: IssuedAuthorization) -> None:
        self._issued = issued

    def receive(
        self,
        *,
        operator_principal: str,
    ) -> IssuedAuthorization:
        assert operator_principal == "operator@example.test"
        return self._issued


class _AdvancingClock:
    def __init__(self) -> None:
        self._value = 0.0

    def __call__(self) -> float:
        self._value += 1.0
        return self._value


class _ManualClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class _CompletedRun(Protocol):
    returncode: int


@pytest.fixture(autouse=True)
def _capacity_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _transaction: FilesystemCapacity(
            device=1,
            fragment_size=4096,
            total_blocks=100_000_000,
            available_blocks=80_000_000,
            total_inodes=1_000_000,
            available_inodes=900_000,
        ),
    )
    for module in ("correlations", "execution", "intake"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.admit_release_capacity",
            lambda *_args, **_kwargs: CapacityProjection(
                projected_allocated_bytes=0,
                projected_unique_inodes=0,
                remaining_available_bytes=1,
                remaining_available_inodes=1,
                required_available_bytes=0,
                required_available_inodes=0,
            ),
        )


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(0o700)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root)
    for components in (
        ("platform",),
        ("tenants",),
        ("authorization",),
        ("authorization", "correlations"),
        ("authorization", "jobs"),
        ("authorization", "results"),
        ("audit",),
        ("intents",),
        ("intake",),
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    LockManager.initialize(root / "locks", expected_owner=os.geteuid()).close()
    target = root / "platform" / "namespace.json"
    target.write_bytes(canonical_json_bytes(_fixture("platform-namespace.json")))
    target.chmod(0o600)
    return root


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def _append_result_audit(
    repository: StateRepository,
    job: dict[str, object],
    result: dict[str, object],
) -> None:
    state = repository.inspect_audit()
    repository.append_audit(
        {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "AuditEntry",
            "sequence": state.entry_count,
            "previousEntryDigest": state.terminal_digest,
            "timestamp": job["acceptedAt"],
            "operatorPrincipal": job["operatorPrincipal"],
            "operation": result["operation"],
            "tenantId": result["tenantId"],
            "correlationId": result["correlationId"],
            "resultDigest": result_digest(result).to_dict(),
            "resultStatus": result["status"],
        }
    )


def _issue(repository: StateRepository) -> IssuedAuthorization:
    return AuthorizationIssuer(
        repository,
        gate=_OpenGate(),
        entropy=_Entropy(),
    ).issue(
        canonical_json_bytes(_fixture("operation-request.json")),
        operator_principal="operator@example.test",
        now=_NOW,
        artifact=None,
    )


def _create_intent(correlation_id: object) -> dict[str, object]:
    intent = _fixture("transaction-intent.json")
    result = _fixture("operation-result.json")
    candidate_manifest = result["manifest"]
    assert type(candidate_manifest) is dict
    candidate_digest = manifest_digest(candidate_manifest).to_dict()
    intent["correlationId"] = correlation_id
    intent["operation"] = "create"
    intent["sourceManifest"] = None
    intent["sourceManifestDigest"] = None
    intent["candidateManifest"] = candidate_manifest
    intent["candidateManifestDigest"] = candidate_digest
    candidate = _fixture("tenant-observed-state.json")
    candidate.update(
        {
            "desiredManifestDigest": candidate_digest,
            "observedState": "undeployed",
            "activeDeploymentId": None,
            "runtimeGenerationId": None,
        }
    )
    intent["lifecycleRecovery"] = {
        "sourceObservedState": None,
        "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
        "sourceRouteSet": "absent",
        "candidateObservedState": candidate,
        "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
        "candidateRouteSet": "absent",
    }
    return intent


def _issue_number(repository: StateRepository, number: int) -> IssuedAuthorization:
    request = _fixture("operation-request.json")
    request["correlationId"] = f"0198d17f-6f4a-7000-8000-{number:012d}"
    request["slug"] = f"duck-repair-{number}"
    return AuthorizationIssuer(
        repository,
        gate=_OpenGate(),
        entropy=lambda length: bytes([number]) * length,
    ).issue(
        canonical_json_bytes(request),
        operator_principal="operator@example.test",
        now=_NOW + timedelta(milliseconds=number),
        artifact=None,
    )


def test_result_waiter_hands_off_only_the_issued_uuid_and_returns_its_result(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        issued = _issue(repository)
        handoff = _ExecutorHandoff(AuthorizationExecutor(repository, intake))
        result = ResultWaiter(repository, handoff).retrieve(issued)

    assert handoff.enqueued == [issued.job_id]
    assert result["provenance"] == {
        "kind": "authorization-job",
        "jobId": issued.job_id,
    }
    assert result["errorCode"] == "not_implemented"


def test_result_waiter_rejects_worker_completion_with_an_active_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        with pytest.raises(RuntimeBoundaryError, match="active lifecycle intent"):
            ResultWaiter(repository, handoff).retrieve(issued)

    assert handoff.enqueued == [issued.job_id]


def test_result_waiter_rechecks_intents_after_worker_completion(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        correlation_id = request["correlationId"]
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation_id,
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }

        class _ResultThenIntentHandoff:
            def __init__(self) -> None:
                self.enqueued: list[str] = []

            def enqueue(self, job_id: str) -> None:
                self.enqueued.append(job_id)
                if len(self.enqueued) != 1:
                    return
                job = repository.read(StateRecordPath.authorization_job(job_id))
                claimed = job.document
                claimed["phase"] = "claimed"
                repository.compare_and_swap(
                    StateRecordPath.authorization_job(job_id),
                    job.revision,
                    claimed,
                )
                intent = _create_intent(correlation_id)
                repository.create_immutable(
                    StateRecordPath.transaction_intent(intent["intentId"]),
                    intent,
                )
                repository.create_immutable(
                    StateRecordPath.authorization_result(job_id),
                    result,
                )

            def await_completion(self, job_id: str, *, timeout_seconds: float) -> None:
                assert timeout_seconds > 0
                self.enqueue(job_id)

        handoff = _ResultThenIntentHandoff()
        with pytest.raises(RuntimeBoundaryError, match="active lifecycle intent"):
            ResultWaiter(
                repository,
                handoff,
                sleep=lambda _seconds: None,
            ).retrieve(issued)

    assert handoff.enqueued == [issued.job_id]


def test_result_waiter_retries_a_contended_read_after_worker_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    sleeps: list[float] = []

    def record_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "not_implemented",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        _append_result_audit(repository, issued.document, result)
        waiter = ResultWaiter(
            repository,
            handoff,
            sleep=record_sleep,
        )
        reads = iter((None, None, result))
        monkeypatch.setattr(waiter, "_read", lambda _job_id: next(reads))

        retrieved = waiter.retrieve(issued)

    assert retrieved == result
    assert handoff.enqueued == [issued.job_id]
    assert sleeps == [0.05]


def test_result_waiter_rejects_a_result_that_disagrees_with_its_active_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        intent = _create_intent(request["correlationId"])
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        metadata = manifest["metadata"]
        assert type(metadata) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        metadata["slug"] = "unauthorized-result"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        with pytest.raises(RuntimeBoundaryError, match="lifecycle authority"):
            ResultWaiter(repository, handoff).retrieve(issued)

    assert handoff.enqueued == []


def test_operator_session_returns_one_bound_versioned_response_frame(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    read_fd, write_fd = os.pipe()
    try:
        with (
            StateRepository(root, expected_owner=os.geteuid()) as repository,
            ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        ):
            issued = _issue(repository)
            handoff = _ExecutorHandoff(AuthorizationExecutor(repository, intake))
            result = OperatorSession(
                _IssuedAdapter(issued),
                ResultWaiter(repository, handoff),
                state_root=root,
                expected_owner=os.geteuid(),
                writer=DeadlineWriter(write_fd),
            ).run(operator_principal="operator@example.test")
        os.close(write_fd)
        write_fd = -1
        response = os.read(read_fd, 64 * 1024)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)

    header = decode_header(response[:HEADER_SIZE], expected_kind=FrameKind.RESPONSE)
    assert header.payload_length is None
    assert decode_result(response[HEADER_SIZE:]) == result


def test_result_waiter_rejects_an_exhausted_completion_deadline(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        with pytest.raises(RuntimeBoundaryError, match="timed out"):
            ResultWaiter(
                repository,
                handoff,
                clock=_AdvancingClock(),
                sleep=lambda _seconds: None,
                total_seconds=1.0,
            ).retrieve(issued)

    assert handoff.enqueued == []


def test_result_waiter_rejects_a_result_with_another_correlation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "OperationResult",
                "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
                "correlationId": "0198d17f-6f4a-7000-8000-000000000099",
                "operation": "create",
                "status": "failed",
                "errorCode": "not_implemented",
                "tenantId": None,
            },
        )
        with pytest.raises(RuntimeBoundaryError, match="does not match"):
            ResultWaiter(repository, handoff).retrieve(issued)

    assert handoff.enqueued == []


def test_result_waiter_accepts_the_generated_tenant_from_a_successful_create(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        _write(root, StateRecordPath.tenant_desired(result["tenantId"]), manifest)
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        _append_result_audit(repository, issued.document, result)
        retrieved = ResultWaiter(repository, handoff).retrieve(issued)

    assert retrieved["status"] == "succeeded"
    assert retrieved["tenantId"] == _fixture("operation-result.json")["tenantId"]
    assert handoff.enqueued == [issued.job_id]


def test_result_waiter_returns_an_audited_success_after_later_state_change(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        _append_result_audit(repository, issued.document, result)
        desired = json.loads(json.dumps(manifest))
        metadata = desired["metadata"]
        assert type(metadata) is dict
        metadata["slug"] = "later-duck"
        _write(root, StateRecordPath.tenant_desired(result["tenantId"]), desired)
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        retrieved = ResultWaiter(repository, handoff).retrieve(issued)

    assert retrieved == result
    assert handoff.enqueued == [issued.job_id]


def test_result_waiter_rejects_an_intent_free_success_with_a_mismatched_audit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    handoff = _CaptureHandoff()
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result = _fixture("operation-result.json")
        provenance = result["provenance"]
        manifest = result["manifest"]
        assert type(provenance) is dict
        assert type(manifest) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        _append_result_audit(repository, issued.document, result)
        metadata = manifest["metadata"]
        assert type(metadata) is dict
        metadata["slug"] = "forged-after-audit"
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        with pytest.raises(RuntimeBoundaryError, match="lifecycle authority"):
            ResultWaiter(repository, handoff).retrieve(issued)

    assert handoff.enqueued == []


def test_deadline_writer_reports_an_authenticated_disconnect() -> None:
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        with pytest.raises(RuntimeBoundaryError, match="disconnected"):
            DeadlineWriter(write_fd).write(b"terminal result")
    finally:
        os.close(write_fd)


def test_deadline_writer_starts_deadlines_at_the_first_response_byte() -> None:
    read_fd, write_fd = os.pipe()
    clock = _ManualClock()
    writer = DeadlineWriter(
        write_fd,
        clock=clock,
        total_seconds=20.0,
        idle_seconds=5.0,
    )
    assert os.get_blocking(write_fd) is False
    clock.value = 60.0
    try:
        writer.write(b"terminal result")
        assert os.read(read_fd, 64) == b"terminal result"
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_deadline_writer_retries_a_nonblocking_write_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    real_write = os.write
    attempts = 0
    expected_attempts = 2

    def write_once_blocked(file_descriptor: int, data: bytes | memoryview) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise BlockingIOError
        return real_write(file_descriptor, data)

    monkeypatch.setattr(os, "write", write_once_blocked)
    try:
        DeadlineWriter(write_fd).write(b"terminal result")
        assert os.read(read_fd, 64) == b"terminal result"
    finally:
        os.close(read_fd)
        os.close(write_fd)

    assert attempts == expected_attempts


def test_startup_reconciliation_requeues_only_unfinished_authority(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        pending = _issue(repository)

    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        first = StartupReconciler(repository, intake, handoff).reconcile()
        AuthorizationExecutor(repository, intake).execute(pending.job_id)
        second = StartupReconciler(repository, intake, handoff).reconcile()

    assert first.enqueued_jobs == (pending.job_id,)
    assert handoff.enqueued == [pending.job_id]
    assert second.enqueued_jobs == ()


def test_startup_reconciliation_snapshots_jobs_and_intents_in_one_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    snapshots: list[object] = []

    def reconcile_transaction(
        _admission: CorrelationAdmission,
        transaction: object,
    ) -> CorrelationReconciliation:
        snapshots.append(transaction)
        return CorrelationReconciliation(jobs=(), repaired_records=0)

    def active_intents(transaction: object, jobs: object) -> set[str]:
        assert snapshots == [transaction]
        assert jobs == ()
        return set()

    monkeypatch.setattr(
        CorrelationAdmission,
        "reconcile_transaction",
        reconcile_transaction,
    )
    monkeypatch.setattr(
        StartupReconciler,
        "_active_intent_job_ids",
        staticmethod(active_intents),
    )
    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = StartupReconciler(repository, intake, handoff).reconcile()

    assert len(snapshots) == 1
    assert outcome.enqueued_jobs == ()


def test_startup_reconciliation_requeues_a_result_phase_repair(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        pending = _issue(repository)
        request = pending.document["request"]
        assert type(request) is dict
        repository.create_immutable(
            StateRecordPath.authorization_result(pending.job_id),
            {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "OperationResult",
                "provenance": {
                    "kind": "authorization-job",
                    "jobId": pending.job_id,
                },
                "correlationId": request["correlationId"],
                "operation": "create",
                "status": "failed",
                "errorCode": "not_implemented",
                "tenantId": None,
            },
        )

    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = StartupReconciler(repository, intake, handoff).reconcile()

    assert outcome.enqueued_jobs == (pending.job_id,)
    assert handoff.enqueued == [pending.job_id]


def test_startup_reconciliation_requeues_unvalidated_terminal_work(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        terminal = job.document
        terminal["phase"] = "failed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            terminal,
        )

    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = StartupReconciler(repository, intake, handoff).reconcile()

    assert outcome.enqueued_jobs == (issued.job_id,)
    assert handoff.enqueued == [issued.job_id]


def test_startup_reconciliation_requeues_a_terminal_job_with_active_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = _issue(repository)
        request = issued.document["request"]
        assert type(request) is dict
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": request["correlationId"],
            "operation": "create",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": None,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        failed = job.document
        failed["phase"] = "failed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            failed,
        )
        intent = _fixture("transaction-intent.json")
        repository.create_immutable(
            StateRecordPath.transaction_intent(intent["intentId"]),
            intent,
        )

    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = StartupReconciler(repository, intake, handoff).reconcile()

    assert outcome.enqueued_jobs == (issued.job_id,)
    assert handoff.enqueued == [issued.job_id]


@pytest.mark.parametrize("active_intent", [True, False])
def test_startup_reconciliation_retains_artifact_for_unfinished_replay(
    tmp_path: Path,
    active_intent: bool,
) -> None:
    root = _state_root(tmp_path)
    tenant_id = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
    source_manifest = _fixture("site.json")
    source_digest = manifest_digest(source_manifest).to_dict()
    _write(root, StateRecordPath.tenant_desired(tenant_id), source_manifest)
    _write(
        root,
        StateRecordPath.tenant_deployment(
            tenant_id,
            "0191e2ca-49f2-7608-8cf3-f80ab2cab151",
        ),
        _fixture("deployment-record.json"),
    )
    payload = b"replay-bound deployment"
    artifact = VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())
    correlation_id = "0198d17f-6f4a-7000-8000-000000000003"
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": correlation_id,
        "tenantId": tenant_id,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=correlation_id,
            declared=artifact,
            read=BytesIO(payload).read,
        ) as lease:
            issued = AuthorizationIssuer(
                repository,
                gate=_OpenGate(),
                entropy=_Entropy(),
            ).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()

        job = repository.read(StateRecordPath.authorization_job(issued.job_id))
        claimed = job.document
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(issued.job_id),
            job.revision,
            claimed,
        )
        candidate_manifest = json.loads(json.dumps(source_manifest))
        candidate_spec = candidate_manifest["spec"]
        assert type(candidate_spec) is dict
        candidate_deployment = candidate_spec["desiredDeployment"]
        assert type(candidate_deployment) is dict
        candidate_deployment["id"] = "0198d17f-6f4a-7000-8000-000000000005"
        candidate_deployment["archiveSha256"] = artifact.sha256
        candidate_digest = manifest_digest(candidate_manifest).to_dict()
        source_observed = _fixture("tenant-observed-state.json")
        source_observed["desiredManifestDigest"] = source_digest
        candidate_observed = json.loads(json.dumps(source_observed))
        candidate_observed["desiredManifestDigest"] = candidate_digest
        candidate_observed["activeDeploymentId"] = "0198d17f-6f4a-7000-8000-000000000005"
        candidate_observed["runtimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000006"
        intent = _fixture("transaction-intent.json")
        intent.update(
            {
                "tenantId": tenant_id,
                "correlationId": correlation_id,
                "operation": "deploy",
                "sourceManifest": source_manifest,
                "sourceManifestDigest": source_digest,
                "candidateManifest": candidate_manifest,
                "candidateManifestDigest": candidate_digest,
                "lifecycleRecovery": {
                    "sourceObservedState": source_observed,
                    "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
                    "sourceRouteSet": "both",
                    "candidateObservedState": candidate_observed,
                    "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
                    "candidateRouteSet": "both",
                },
            }
        )
        if active_intent:
            repository.create_immutable(
                StateRecordPath.transaction_intent(intent["intentId"]),
                intent,
            )
        else:
            current = repository.read(StateRecordPath.authorization_job(issued.job_id))
            terminal = current.document
            terminal["phase"] = "failed"
            repository.compare_and_swap(
                StateRecordPath.authorization_job(issued.job_id),
                current.revision,
                terminal,
            )
        result: dict[str, object] = {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "OperationResult",
            "provenance": {"kind": "authorization-job", "jobId": issued.job_id},
            "correlationId": correlation_id,
            "operation": "deploy",
            "status": "failed",
            "errorCode": "state_drift",
            "tenantId": tenant_id,
        }
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )

        handoff = _CaptureHandoff()
        outcome = StartupReconciler(repository, intake, handoff).reconcile()

    assert outcome.removed_intake_entries == 0
    assert outcome.enqueued_jobs == (issued.job_id,)
    assert handoff.enqueued == [issued.job_id]
    assert [path.name for path in (root / "intake").iterdir()] == [f"{correlation_id}.artifact"]


def test_startup_reconciliation_skips_emergency_retirement_intent(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        pending = _issue(repository)
        intent = _fixture("archive-retirement-intent.json")
        intent["correlationId"] = "0198d17f-6f4a-7000-8000-000000000009"
        intent["provenance"] = {
            "kind": "emergency-administrator",
            "reason": "reconcile separately through root recovery",
        }
        repository.create_immutable(
            StateRecordPath.archive_retirement_intent(intent["intentId"]),
            intent,
        )

    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        outcome = StartupReconciler(repository, intake, handoff).reconcile()

    assert outcome.enqueued_jobs == (pending.job_id,)
    assert handoff.enqueued == [pending.job_id]


def test_startup_reconciliation_batches_backlog_under_the_aggregate_limit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = [_issue_number(repository, number) for number in range(1, 5)]

    handoff = _CaptureHandoff()
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
    ):
        first = StartupReconciler(repository, intake, handoff).reconcile()
        for accepted in issued[:2]:
            AuthorizationExecutor(repository, intake).execute(accepted.job_id)
        second = StartupReconciler(repository, intake, handoff).reconcile()

    assert first.enqueued_jobs == tuple(accepted.job_id for accepted in issued[:2])
    assert first.deferred_jobs == len(issued[2:])
    assert second.enqueued_jobs == tuple(accepted.job_id for accepted in issued[2:])
    assert second.deferred_jobs == 0


def test_startup_reconciliation_durably_rotates_past_a_failing_prefix(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        issued = [_issue_number(repository, number) for number in range(1, 5)]

    handoff = _CaptureHandoff()
    batches: list[tuple[str, ...]] = []
    for _attempt in range(3):
        with (
            StateRepository(root, expected_owner=os.geteuid()) as repository,
            ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        ):
            batches.append(StartupReconciler(repository, intake, handoff).reconcile().enqueued_jobs)

    first = tuple(accepted.job_id for accepted in issued[:2])
    second = tuple(accepted.job_id for accepted in issued[2:])
    assert batches == [first, second, first]
    assert handoff.enqueued == [*first, *second, *first]


def test_systemd_handoff_uses_one_fixed_template_instance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "systemctl"
    job_id = "0198d17f-6f4a-7000-8000-000000000002"
    calls: list[list[str]] = []

    def run(arguments: list[str | os.PathLike[str]], **_kwargs: object) -> _CompletedRun:
        calls.append([os.fspath(argument) for argument in arguments])
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr("lowerduckpond_static_host_agent.job_runtime.subprocess.run", run)
    handoff = SystemdJobHandoff(executable)
    handoff.enqueue(job_id)
    handoff.await_completion(job_id, timeout_seconds=17.0)

    assert calls == [
        [
            os.fspath(executable),
            "start",
            "--no-block",
            f"lowerduckpond-static-worker@{job_id}.service",
        ],
        [
            os.fspath(executable),
            "start",
            "--wait",
            f"lowerduckpond-static-worker@{job_id}.service",
        ],
    ]
