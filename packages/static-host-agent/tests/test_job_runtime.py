from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

import pytest
from lowerduckpond_static_contracts import (
    HEADER_SIZE,
    FrameKind,
    canonical_json_bytes,
    decode_header,
    decode_result,
)
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    AuthorizationExecutor,
    AuthorizationIssuer,
    CapacityProjection,
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


class _CaptureHandoff:
    def __init__(self) -> None:
        self.enqueued: list[str] = []

    def enqueue(self, job_id: str) -> None:
        self.enqueued.append(job_id)


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
    for module in ("correlations", "execution"):
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


def test_result_waiter_bounds_a_lost_handoff(tmp_path: Path) -> None:
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

    assert handoff.enqueued == [issued.job_id]


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
        assert type(provenance) is dict
        provenance["jobId"] = issued.job_id
        result["correlationId"] = request["correlationId"]
        repository.create_immutable(
            StateRecordPath.authorization_result(issued.job_id),
            result,
        )
        retrieved = ResultWaiter(repository, handoff).retrieve(issued)

    assert retrieved["status"] == "succeeded"
    assert retrieved["tenantId"] == _fixture("operation-result.json")["tenantId"]
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
    SystemdJobHandoff(executable).enqueue(job_id)

    assert calls == [
        [
            os.fspath(executable),
            "start",
            "--no-block",
            f"lowerduckpond-static-worker@{job_id}.service",
        ]
    ]
