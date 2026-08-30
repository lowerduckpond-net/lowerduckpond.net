from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import request_digest
from lowerduckpond_static_host_agent import (
    CapacityProjection,
    CapacityRejectedError,
    CorrelationAdmission,
    CorrelationConflictError,
    CorrelationError,
    CorrelationRateLimitError,
    FilesystemCapacity,
    HostCapacityLimits,
    LockManager,
    StateAdmissionRejectedError,
    StateInventoryLimits,
    StateRecordError,
    StateRecordPath,
    StateRepository,
)
from lowerduckpond_static_host_agent.capacity import CapacityReservation

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_BASE_TIME = datetime(2026, 8, 29, 12, 0, 1, tzinfo=UTC)
_DIRECTORY_MODE = 0o700
_PAIR_RECORD_COUNT = 2


@pytest.fixture(autouse=True)
def _state_filesystem_with_inode_accounting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model the production ext4 inode counters absent from the test overlay."""

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


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(_DIRECTORY_MODE)


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
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _candidate(index: int, accepted_at: datetime = _BASE_TIME) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / "authorization-job.json").read_text())
    assert type(value) is dict
    value["jobId"] = f"0198d180-0001-7000-8000-{index:012x}"
    value["acceptedAt"] = accepted_at.isoformat().replace("+00:00", "Z")
    request = value["request"]
    assert type(request) is dict
    request["correlationId"] = f"0198d180-0002-7000-8000-{index:012x}"
    value["requestDigest"] = request_digest(request).to_dict()
    return value


def _repository(root: Path) -> StateRepository:
    return StateRepository(root, expected_owner=os.geteuid())


def test_new_correlation_durably_creates_the_index_and_job(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)

    with _repository(root) as repository:
        resolution = CorrelationAdmission(repository).resolve(candidate, now=_BASE_TIME)
        inventory = repository.measure_authorization_records()

    assert resolution.created is True
    assert resolution.repaired_records == 0
    assert resolution.job.document == candidate
    assert inventory.job_ids == (candidate["jobId"],)
    assert inventory.correlation_ids == (
        candidate["request"]["correlationId"],  # type: ignore[index]
    )


def test_exact_retry_returns_the_established_job_without_spending_capacity(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    retry = _candidate(2, _BASE_TIME + timedelta(minutes=1))
    retry_request = retry["request"]
    candidate_request = candidate["request"]
    assert type(retry_request) is dict and type(candidate_request) is dict
    retry_request["correlationId"] = candidate_request["correlationId"]
    retry["requestDigest"] = request_digest(retry_request).to_dict()

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        first = admission.resolve(candidate, now=_BASE_TIME)
        second = admission.resolve(retry, now=_BASE_TIME + timedelta(minutes=1))
        inventory = repository.measure_inventory()

    assert second.created is False
    assert second.job.document == first.job.document
    assert inventory.authorization_record_count == _PAIR_RECORD_COUNT


@pytest.mark.parametrize("changed_field", ["operator", "source"])
def test_changed_retry_binding_is_rejected(
    tmp_path: Path,
    changed_field: str,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    retry = deepcopy(candidate)
    retry["jobId"] = _candidate(2)["jobId"]
    retry["acceptedAt"] = "2026-08-29T12:01:01Z"
    if changed_field == "operator":
        retry["operatorPrincipal"] = "other@example.test"
    else:
        expected = retry["expectedSource"]
        assert type(expected) is dict
        digest = expected["platformStateDigest"]
        assert type(digest) is dict
        digest["value"] = "e" * 64

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        admission.resolve(candidate, now=_BASE_TIME)
        with pytest.raises(CorrelationConflictError, match="another"):
            admission.resolve(retry, now=_BASE_TIME + timedelta(minutes=1))


def test_burst_allows_five_and_rejects_the_sixth(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        for index in range(5):
            admission.resolve(_candidate(index), now=_BASE_TIME)
        with pytest.raises(CorrelationRateLimitError, match="burst"):
            admission.resolve(_candidate(5), now=_BASE_TIME)


def test_one_token_refills_after_one_minute(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        for index in range(5):
            admission.resolve(_candidate(index), now=_BASE_TIME)
        admission.resolve(
            _candidate(5, _BASE_TIME + timedelta(minutes=1)),
            now=_BASE_TIME + timedelta(minutes=1),
        )


def test_rolling_hour_rejects_the_sixty_first_identity(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        for index in range(60):
            accepted_at = _BASE_TIME + timedelta(minutes=index)
            admission.resolve(_candidate(index, accepted_at), now=accepted_at)
        attempted_at = _BASE_TIME + timedelta(minutes=59, seconds=1)
        with pytest.raises(CorrelationRateLimitError, match="rolling-hour"):
            admission.resolve(_candidate(60, attempted_at), now=attempted_at)


def test_clock_rollback_blocks_new_identity_but_not_exact_retry(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    earlier = _BASE_TIME - timedelta(seconds=1)

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        established = admission.resolve(candidate, now=_BASE_TIME)
        with pytest.raises(CorrelationRateLimitError, match="rollback"):
            admission.resolve(_candidate(2, earlier), now=earlier)

        retry = _candidate(3, earlier)
        request = retry["request"]
        original_request = candidate["request"]
        assert type(request) is dict and type(original_request) is dict
        request["correlationId"] = original_request["correlationId"]
        retry["requestDigest"] = request_digest(request).to_dict()
        resolution = admission.resolve(retry, now=earlier)

    assert resolution.created is False
    assert resolution.job.document == established.job.document


@pytest.mark.parametrize("survivor", ["correlation", "job"])
def test_interrupted_pair_is_repaired_before_retry(
    tmp_path: Path,
    survivor: str,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    request = candidate["request"]
    assert type(request) is dict
    correlation_id = request["correlationId"]
    path = (
        StateRecordPath.authorization_correlation(correlation_id)
        if survivor == "correlation"
        else StateRecordPath.authorization_job(candidate["jobId"])
    )

    with _repository(root) as repository:
        repository.create_immutable(path, candidate)
        resolution = CorrelationAdmission(repository).resolve(candidate, now=_BASE_TIME)
        inventory = repository.measure_authorization_records()

    assert resolution.created is False
    assert resolution.repaired_records == 1
    assert len(inventory.job_ids) == len(inventory.correlation_ids) == 1


@pytest.mark.parametrize("survivor", ["correlation", "job"])
def test_startup_reconciliation_repairs_and_returns_only_committed_jobs(
    tmp_path: Path,
    survivor: str,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    request = candidate["request"]
    assert type(request) is dict
    path = (
        StateRecordPath.authorization_correlation(request["correlationId"])
        if survivor == "correlation"
        else StateRecordPath.authorization_job(candidate["jobId"])
    )

    with _repository(root) as repository:
        repository.create_immutable(path, candidate)
        outcome = CorrelationAdmission(repository).reconcile()
        inventory = repository.measure_authorization_records()

    assert outcome.repaired_records == 1
    assert tuple(job.document for job in outcome.jobs) == (candidate,)
    assert len(inventory.job_ids) == len(inventory.correlation_ids) == 1


def test_pair_repair_respects_the_shared_record_ceiling(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    request = candidate["request"]
    assert type(request) is dict

    with _repository(root) as repository:
        repository.create_immutable(
            StateRecordPath.authorization_correlation(request["correlationId"]),
            candidate,
        )
        admission = CorrelationAdmission(
            repository,
            limits=StateInventoryLimits(maximum_authorization_records=1),
        )
        with pytest.raises(StateAdmissionRejectedError, match="record"):
            admission.resolve(candidate, now=_BASE_TIME)


def test_reconciliation_accepts_a_job_whose_phase_advanced_after_acceptance(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    retry = _candidate(2, _BASE_TIME + timedelta(minutes=1))
    request = retry["request"]
    original_request = candidate["request"]
    assert type(request) is dict and type(original_request) is dict
    request["correlationId"] = original_request["correlationId"]
    retry["requestDigest"] = request_digest(request).to_dict()

    with _repository(root) as repository:
        first = CorrelationAdmission(repository).resolve(candidate, now=_BASE_TIME)
        claimed = deepcopy(candidate)
        claimed["phase"] = "claimed"
        repository.compare_and_swap(
            StateRecordPath.authorization_job(candidate["jobId"]),
            first.job.revision,
            claimed,
        )
        result = CorrelationAdmission(repository).resolve(
            retry,
            now=_BASE_TIME + timedelta(minutes=1),
        )

    assert result.job.document["phase"] == "claimed"


def test_reconciliation_fails_closed_on_divergent_durable_pair(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    divergent = deepcopy(candidate)
    divergent["operatorPrincipal"] = "other@example.test"
    request = candidate["request"]
    assert type(request) is dict

    with _repository(root) as repository:
        repository.create_immutable(
            StateRecordPath.authorization_correlation(request["correlationId"]),
            candidate,
        )
        repository.create_immutable(
            StateRecordPath.authorization_job(candidate["jobId"]),
            divergent,
        )
        with pytest.raises(CorrelationError, match="bindings disagree"):
            CorrelationAdmission(repository).resolve(candidate, now=_BASE_TIME)


def test_new_correlation_cannot_reuse_an_established_job_identity(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    established = _candidate(1)
    candidate = _candidate(2, _BASE_TIME + timedelta(minutes=1))
    candidate["jobId"] = established["jobId"]

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        admission.resolve(established, now=_BASE_TIME)
        with pytest.raises(CorrelationConflictError, match="job identity"):
            admission.resolve(candidate, now=_BASE_TIME + timedelta(minutes=1))


def test_new_correlation_cannot_reuse_a_job_identity_repaired_in_this_admission(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    interrupted = _candidate(1)
    candidate = _candidate(2, _BASE_TIME + timedelta(minutes=1))
    candidate["jobId"] = interrupted["jobId"]
    request = interrupted["request"]
    assert type(request) is dict

    with _repository(root) as repository:
        repository.create_immutable(
            StateRecordPath.authorization_correlation(request["correlationId"]),
            interrupted,
        )
        with pytest.raises(CorrelationConflictError, match="job identity"):
            CorrelationAdmission(repository).resolve(
                candidate,
                now=_BASE_TIME + timedelta(minutes=1),
            )


def test_duplicate_correlation_job_claims_fail_before_any_repair(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    first = _candidate(1)
    second = _candidate(2)
    second["jobId"] = first["jobId"]
    second_request = second["request"]
    assert type(second_request) is dict
    second["requestDigest"] = request_digest(second_request).to_dict()
    first_request = first["request"]
    assert type(first_request) is dict

    with _repository(root) as repository:
        repository.create_immutable(
            StateRecordPath.authorization_correlation(first_request["correlationId"]),
            first,
        )
        repository.create_immutable(
            StateRecordPath.authorization_correlation(second_request["correlationId"]),
            second,
        )
        with pytest.raises(CorrelationError, match="multiple correlations"):
            CorrelationAdmission(repository).resolve(first, now=_BASE_TIME)
        inventory = repository.measure_authorization_records()

    assert inventory.job_ids == ()


@pytest.mark.parametrize("interrupted_repair", [False, True])
@pytest.mark.parametrize("floor", ["block", "inode"])
def test_correlation_writes_respect_filesystem_free_capacity_floors(
    tmp_path: Path,
    interrupted_repair: bool,
    floor: str,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    request = candidate["request"]
    assert type(request) is dict
    if interrupted_repair:
        with _repository(root) as repository:
            repository.create_immutable(
                StateRecordPath.authorization_correlation(request["correlationId"]),
                candidate,
            )

    limits = (
        HostCapacityLimits(minimum_available_bytes=1 << 60)
        if floor == "block"
        else HostCapacityLimits(minimum_available_inodes=1_000_000)
    )
    with _repository(root) as repository:
        with pytest.raises(CapacityRejectedError, match=f"free-{floor}"):
            CorrelationAdmission(repository, capacity_limits=limits).resolve(
                candidate,
                now=_BASE_TIME,
            )
        inventory = repository.measure_authorization_records()

    assert inventory.job_ids == ()
    assert len(inventory.correlation_ids) == int(interrupted_repair)


@pytest.mark.parametrize("interrupted_repair", [False, True])
def test_correlation_capacity_includes_transient_directory_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted_repair: bool,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    request = candidate["request"]
    assert type(request) is dict
    if interrupted_repair:
        with _repository(root) as repository:
            repository.create_immutable(
                StateRecordPath.authorization_correlation(request["correlationId"]),
                candidate,
            )

    observed: list[CapacityReservation] = []

    def capture_reservation(
        _usage: object,
        reservation: CapacityReservation,
        _filesystem: object,
        *,
        limits: object,
    ) -> CapacityProjection:
        del limits
        observed.append(reservation)
        return CapacityProjection(0, 0, 0, 0, 0, 0)

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.correlations.admit_release_capacity",
        capture_reservation,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.namespace_allocation_upper_bound",
        lambda _transaction, entry_count: entry_count * 8192,
    )

    with _repository(root) as repository:
        CorrelationAdmission(repository).resolve(candidate, now=_BASE_TIME)

    assert len(observed) == 1
    expected_records = 1 if interrupted_repair else 2
    assert observed[0].unique_inodes == expected_records
    assert observed[0].allocated_bytes >= expected_records * 8192


def test_correlation_record_cannot_be_replaced_through_repository_cas(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    request = candidate["request"]
    assert type(request) is dict
    path = StateRecordPath.authorization_correlation(request["correlationId"])

    with _repository(root) as repository:
        created = repository.create_immutable(path, candidate)
        replacement = deepcopy(candidate)
        replacement["operatorPrincipal"] = "other@example.test"
        with pytest.raises(StateRecordError, match="immutable"):
            repository.compare_and_swap(path, created.revision, replacement)
        established = repository.read(path)

    assert established.document == candidate


def test_new_admission_requires_pending_phase_and_current_timestamp(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate(1)
    candidate["phase"] = "claimed"

    with _repository(root) as repository:
        admission = CorrelationAdmission(repository)
        with pytest.raises(CorrelationError, match="pending"):
            admission.resolve(candidate, now=_BASE_TIME)

        candidate["phase"] = "pending"
        with pytest.raises(CorrelationError, match="timestamp"):
            admission.resolve(candidate, now=_BASE_TIME + timedelta(seconds=1))
