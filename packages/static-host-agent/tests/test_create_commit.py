from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import lowerduckpond_static_host_agent.create_commit as create_commit_module
import pytest
from lowerduckpond_static_contracts import (
    canonical_json_bytes,
    platform_state_digest,
)
from lowerduckpond_static_host_agent import (
    AuditState,
    CapacityProjection,
    CapacityReservation,
    CreateCommitBoundary,
    CreateCommitError,
    CreateTransitionPlan,
    FilesystemCapacity,
    LockManager,
    StateRecordPath,
    StateRepository,
    StoredContract,
    finalize_create_transition,
    plan_create_transition,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000004"
_CANDIDATE_GENERATION = "0198d17f-6f4a-7000-8000-000000000006"
_PARTIAL_REPLAY_RESERVED_INODES = 6


class _Entropy:
    def __init__(self) -> None:
        self._value = 0

    def __call__(self, length: int) -> bytes:
        self._value += 1
        return self._value.to_bytes(length, byteorder="big")


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
        ("audit",),
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    LockManager.initialize(root / "locks", expected_owner=os.geteuid()).close()
    return root


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def _prepared_create(
    root: Path,
) -> tuple[StateRepository, StoredContract, CreateTransitionPlan]:
    namespace = _fixture("platform-namespace.json")
    job = _fixture("authorization-job.json")
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected["platformStateDigest"] = platform_state_digest(namespace).to_dict()
    job["phase"] = "claimed"
    plan = plan_create_transition(
        job,
        namespace,
        source_runtime_generation_id=_SOURCE_GENERATION,
        candidate_runtime_generation_id=_CANDIDATE_GENERATION,
        audit_state=AuditState(0, 0, 0, None),
        now=datetime(2026, 9, 2, 12, 30, tzinfo=UTC),
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    _write(root, StateRecordPath.transaction_intent(plan.intent_id), plan.intent)
    repository = StateRepository(root, expected_owner=os.geteuid())
    stored_job = repository.read(StateRecordPath.authorization_job(job["jobId"]))
    return repository, stored_job, plan


def _assert_terminal_create(
    repository: StateRepository,
    job: StoredContract,
    plan: CreateTransitionPlan,
) -> None:
    assert repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document == plan.manifest
    assert (
        repository.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
        == plan.observed_state
    )
    assert (
        repository.read(StateRecordPath.authorization_result(job.document["jobId"])).document
        == plan.result
    )
    assert (
        repository.read(StateRecordPath.authorization_job(job.document["jobId"])).document["phase"]
        == "completed"
    )
    audit = repository.inspect_audit()
    assert audit.entry_count == 1
    assert audit.terminal_digest is not None
    with pytest.raises(FileNotFoundError):
        repository.read(StateRecordPath.transaction_intent(plan.intent_id))


def test_create_commit_publishes_one_exact_terminal_transaction(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    try:
        with repository.publication_transaction() as transaction:
            result = finalize_create_transition(transaction, job, plan)

        assert result == plan.result
        assert result is not plan.result
        _assert_terminal_create(repository, job, plan)
    finally:
        repository.close()


def test_create_commit_reports_exact_result_publication_ownership(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    try:
        with repository.publication_transaction() as transaction:
            first = create_commit_module.finalize_create_transition_outcome(
                transaction,
                job,
                plan,
            )
        with repository.publication_transaction() as transaction:
            second = create_commit_module.finalize_create_transition_outcome(
                transaction,
                job,
                plan,
            )

        assert first.result == second.result == plan.result
        assert first.created is True
        assert second.created is False
    finally:
        repository.close()


@pytest.mark.parametrize(
    "boundary",
    [
        CreateCommitBoundary.STATE_SYNC,
        CreateCommitBoundary.AUDIT_SYNC,
        CreateCommitBoundary.RESULT_SYNC,
        CreateCommitBoundary.JOB_SYNC,
    ],
)
def test_create_commit_replays_every_nonterminal_durable_boundary(
    tmp_path: Path,
    boundary: CreateCommitBoundary,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)

    def interrupt(current: CreateCommitBoundary) -> None:
        if current is boundary:
            raise RuntimeError(f"interrupted after {current}")

    try:
        with (
            pytest.raises(RuntimeError, match="interrupted"),
            repository.publication_transaction() as transaction,
        ):
            finalize_create_transition(
                transaction,
                job,
                plan,
                failure_hook=interrupt,
            )

        with repository.publication_transaction() as transaction:
            assert finalize_create_transition(transaction, job, plan) == plan.result

        _assert_terminal_create(repository, job, plan)
    finally:
        repository.close()


def test_create_commit_is_terminal_before_intent_removal_callback(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)

    def interrupt(boundary: CreateCommitBoundary) -> None:
        if boundary is CreateCommitBoundary.INTENT_REMOVED:
            raise RuntimeError("interrupted after terminal commit")

    try:
        with (
            pytest.raises(RuntimeError, match="terminal commit"),
            repository.publication_transaction() as transaction,
        ):
            finalize_create_transition(
                transaction,
                job,
                plan,
                failure_hook=interrupt,
            )

        with repository.publication_transaction() as transaction:
            assert finalize_create_transition(transaction, job, plan) == plan.result
        _assert_terminal_create(repository, job, plan)
    finally:
        repository.close()


def test_create_commit_freezes_caller_documents_before_mutation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    expected_result = deepcopy(plan.result)

    def mutate(boundary: CreateCommitBoundary) -> None:
        if boundary is CreateCommitBoundary.STATE_SYNC:
            plan.result["canonicalOrigin"] = "https://attacker.invalid"

    try:
        with repository.publication_transaction() as transaction:
            assert (
                finalize_create_transition(
                    transaction,
                    job,
                    plan,
                    failure_hook=mutate,
                )
                == expected_result
            )
        assert (
            repository.read(StateRecordPath.authorization_result(job.document["jobId"])).document
            == expected_result
        )
    finally:
        repository.close()


def test_create_commit_rejects_a_plan_bound_to_another_job(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    other_job = job.document
    other_job["operatorPrincipal"] = "other-operator@example.test"
    other = StoredContract(other_job, job.revision)
    try:
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(CreateCommitError, match="disagree"),
        ):
            finalize_create_transition(transaction, other, plan)
    finally:
        repository.close()


def test_create_commit_rejects_cross_document_state_drift_before_mutation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    digest = plan.observed_state["desiredManifestDigest"]
    assert type(digest) is dict
    digest["value"] = "b" * 64
    try:
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(CreateCommitError, match="disagree"),
        ):
            finalize_create_transition(transaction, job, plan)

        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id))
    finally:
        repository.close()


def test_create_commit_pins_the_exact_intent_before_terminal_mutation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    intent_path = StateRecordPath.transaction_intent(plan.intent_id)
    stored = repository.read(intent_path)
    changed = stored.document
    changed["createdAt"] = "2026-09-02T12:31:00Z"
    repository.compare_and_swap(intent_path, stored.revision, changed)
    try:
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(CreateCommitError, match="intent changed"),
        ):
            finalize_create_transition(transaction, job, plan)

        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id))
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job.document["jobId"]))
        assert repository.inspect_audit().entry_count == 0
    finally:
        repository.close()


def test_create_commit_admits_all_growth_before_first_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)

    def reject_capacity(*_args: object, **_kwargs: object) -> None:
        raise CreateCommitError("capacity rejected")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.create_commit.admit_release_capacity",
        reject_capacity,
    )
    try:
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(CreateCommitError, match="capacity rejected"),
        ):
            finalize_create_transition(transaction, job, plan)

        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id))
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job.document["jobId"]))
        assert repository.inspect_audit().entry_count == 0
        assert (
            repository.read(StateRecordPath.authorization_job(job.document["jobId"])).document[
                "phase"
            ]
            == "claimed"
        )
        assert repository.read(StateRecordPath.transaction_intent(plan.intent_id)).document == (
            plan.intent
        )
    finally:
        repository.close()


def test_create_commit_rejects_a_diverged_audit_chain_before_state_mutation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    try:
        repository.append_audit(_fixture("audit-entry.json"))
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(CreateCommitError, match="audit"),
        ):
            finalize_create_transition(transaction, job, plan)

        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id))
    finally:
        repository.close()


def test_create_commit_rejects_a_wrong_audit_predecessor_before_state_mutation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    plan.audit_entry["sequence"] = 1
    plan.audit_entry["previousEntryDigest"] = {
        "format": "lowerduckpond-audit-entry-v1",
        "algorithm": "sha256",
        "value": "a" * 64,
    }
    try:
        repository.append_audit(_fixture("audit-entry.json"))
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(CreateCommitError, match="audit"),
        ):
            finalize_create_transition(transaction, job, plan)

        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id))
    finally:
        repository.close()


def test_create_commit_reserves_missing_child_directories_during_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    repository, job, plan = _prepared_create(root)
    tenant_root = root / "tenants" / plan.tenant_id
    _mkdir(tenant_root)
    _mkdir(tenant_root / "deployments")
    reservations: list[CapacityReservation] = []

    def capture_reservation(
        _usage: object,
        reservation: CapacityReservation,
        _filesystem: object,
        *,
        limits: object,
    ) -> CapacityProjection:
        del limits
        reservations.append(reservation)
        return CapacityProjection(0, 0, 1, 1, 0, 0)

    monkeypatch.setattr(
        create_commit_module,
        "admit_release_capacity",
        capture_reservation,
    )
    try:
        with repository.publication_transaction() as transaction:
            finalize_create_transition(transaction, job, plan)

        assert len(reservations) == 1
        assert reservations[0].unique_inodes == _PARTIAL_REPLAY_RESERVED_INODES
        assert (tenant_root / "archives").is_dir()
    finally:
        repository.close()
