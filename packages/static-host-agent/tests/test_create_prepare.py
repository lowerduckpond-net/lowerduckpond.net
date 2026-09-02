from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import lowerduckpond_static_host_agent.repository as repository_module
import pytest
from lowerduckpond_static_contracts import (
    canonical_json_bytes,
    platform_state_digest,
)
from lowerduckpond_static_host_agent import (
    CaddyGenerationManifest,
    CaddyRuntime,
    CapacityRejectedError,
    CreateActivationError,
    CreateCommitBoundary,
    CreatePreparationError,
    FilesystemCapacity,
    HostCapacityLimits,
    LockManager,
    PinnedCaddyGeneration,
    PreparedCreateTransition,
    StateRecordPath,
    StateRepository,
    StoredContract,
    TenantRouteInput,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    activate_create_transition,
    prepare_create_transition,
    recover_create_transition,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000004"
_NOW = datetime(2026, 9, 2, 13, 45, tzinfo=UTC)


class _Entropy:
    def __init__(self) -> None:
        self._value = 0

    def __call__(self, length: int) -> bytes:
        self._value += 1
        return self._value.to_bytes(length, byteorder="big")


class _Gate:
    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def require_enabled(self) -> None:
        if not self.enabled:
            raise RuntimeError("publication_disabled")


class _Pinned:
    def __init__(self, manifest: _Candidate) -> None:
        self.manifest = cast(CaddyGenerationManifest, manifest)

    def __enter__(self) -> _Pinned:
        return self

    def __exit__(self, *_arguments: object) -> None:
        self.close()

    def close(self) -> None:
        return


@dataclass(frozen=True)
class _Selected:
    generation_id: str
    generation: _Pinned


@dataclass(frozen=True)
class _Candidate:
    generation_id: str
    marker: str = "exact"


class _Runtime:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.overlay: TenantRouteOverlay | None = None
        self.candidate: _Candidate | None = None
        self.source = _Candidate(_SOURCE_GENERATION)
        self.active = _SOURCE_GENERATION
        self.running = _SOURCE_GENERATION
        self.reference_temporaries = 0
        self.extra_tenants: tuple[TenantRouteInput, ...] = ()

    @contextmanager
    def using_held_publication_lock(self, _repository: StateRepository) -> Iterator[None]:
        self.events.append("locked")
        yield

    def open_active_verified(self) -> _Selected:
        self.events.append("active")
        return _Selected(self.active, _Pinned(self.source))

    def open_verified_generation(self, generation_id: str) -> _Pinned:
        self.events.append(f"opened:{generation_id}")
        if generation_id == self.source.generation_id:
            return _Pinned(self.source)
        if self.candidate is not None and generation_id == self.candidate.generation_id:
            return _Pinned(self.candidate)
        raise FileNotFoundError(generation_id)

    def read_active(self) -> str:
        self.events.append("read-active")
        return self.active

    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        self.events.append(f"snapshot:{generation_id}")
        if (
            self.candidate is None
            or generation_id != self.candidate.generation_id
            or self.overlay is None
        ):
            raise FileNotFoundError(generation_id)
        return TenantRouteSnapshot(
            _fixture("platform-namespace.json"),
            (self.overlay.tenant, *self.extra_tenants),
        )

    def select_active(self, generation_id: str) -> None:
        self.events.append(f"selected:{generation_id}")
        self.reference_temporaries = 0
        self.active = generation_id

    def remove_abandoned_reference_temporaries(self) -> int:
        self.events.append("cleaned-reference-temporaries")
        removed = self.reference_temporaries
        self.reference_temporaries = 0
        return removed

    def prune_unreferenced_generations(
        self,
        _protected: tuple[()],
        *,
        keep_newest_unprotected: int,
    ) -> tuple[str, ...]:
        assert keep_newest_unprotected == 1
        self.events.append("pruned")
        return ()

    def publish_candidate(
        self,
        generation_id: str,
        *,
        transaction: object,
        overlay: TenantRouteOverlay,
        gate: _Gate,
    ) -> CaddyGenerationManifest:
        del transaction
        gate.require_enabled()
        self.events.append("published")
        self.overlay = overlay
        self.candidate = _Candidate(generation_id)
        return cast(CaddyGenerationManifest, self.candidate)

    def discard_unselected_candidate(
        self,
        generation_id: str,
        manifest: CaddyGenerationManifest,
    ) -> None:
        assert generation_id == manifest.generation_id
        self.events.append("discarded")

    def reload(
        self,
        source: PinnedCaddyGeneration,
        candidate: PinnedCaddyGeneration,
    ) -> None:
        assert self.running == source.manifest.generation_id
        self.events.append("reloaded")
        self.running = candidate.manifest.generation_id

    def verify(self, generation: PinnedCaddyGeneration) -> None:
        self.events.append(f"verified:{generation.manifest.generation_id}")
        if self.running != generation.manifest.generation_id:
            raise RuntimeError("running generation disagrees")

    def restore(self, source: PinnedCaddyGeneration) -> None:
        self.events.append("restored")
        self.running = source.manifest.generation_id


@pytest.fixture(autouse=True)
def _capacity_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
        lambda _transaction: FilesystemCapacity(
            device=1,
            fragment_size=4096,
            total_blocks=10_000_000,
            available_blocks=9_000_000,
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


def _prepared_repository(root: Path) -> tuple[StateRepository, dict[str, object]]:
    namespace = _fixture("platform-namespace.json")
    job = _fixture("authorization-job.json")
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected["platformStateDigest"] = platform_state_digest(namespace).to_dict()
    job["phase"] = "claimed"
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    return StateRepository(root, expected_owner=os.geteuid()), job


def _write_correlation(root: Path, job: dict[str, object]) -> None:
    correlation = json.loads(json.dumps(job))
    assert type(correlation) is dict
    request = correlation["request"]
    assert type(request) is dict
    correlation["phase"] = "pending"
    _write(
        root,
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )


def _prepare(
    repository: StateRepository,
    runtime: _Runtime,
    job: dict[str, object],
    *,
    limits: HostCapacityLimits | None = None,
) -> PreparedCreateTransition:
    selected_limits = HostCapacityLimits() if limits is None else limits
    return prepare_create_transition(
        repository,
        cast(CaddyRuntime, runtime),
        _Gate(),
        job["jobId"],
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
        capacity_limits=selected_limits,
    )


def test_create_preparation_publishes_then_binds_one_exact_intent(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)

        assert runtime.events == ["locked", "active", "pruned", "published"]
        assert runtime.overlay is not None
        assert runtime.overlay.tenant.manifest == prepared.plan.manifest
        assert runtime.overlay.tenant.observed_state == prepared.plan.observed_state
        assert runtime.overlay.tenant.deployment is None
        assert prepared.plan.intent["lifecycleRecovery"] == {
            "sourceObservedState": None,
            "sourceRuntimeGenerationId": _SOURCE_GENERATION,
            "sourceRouteSet": "absent",
            "candidateObservedState": prepared.plan.observed_state,
            "candidateRuntimeGenerationId": prepared.candidate_manifest.generation_id,
            "candidateRouteSet": "absent",
        }
        assert (
            repository.read(StateRecordPath.transaction_intent(prepared.plan.intent_id)).document
            == prepared.plan.intent
        )
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_preparation_discards_candidate_when_intent_admission_fails(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    limits = HostCapacityLimits(minimum_available_bytes=100 * 1024 * 1024 * 1024)
    try:
        with pytest.raises(CapacityRejectedError):
            _prepare(repository, runtime, job, limits=limits)

        assert runtime.events[-2:] == ["published", "discarded"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_create_preparation_checks_gate_before_generation_cleanup(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        with pytest.raises(RuntimeError, match="publication_disabled"):
            prepare_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(enabled=False),
                job["jobId"],
                now=_NOW,
                clock=lambda: 1_777_000_000_000,
                entropy=_Entropy(),
            )

        assert runtime.events == ["locked"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_create_preparation_retains_candidate_on_ambiguous_intent_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    create = repository_module._StateTransaction.create_immutable

    def create_then_fail(
        transaction: repository_module._StateTransaction,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract:
        stored = create(transaction, path, document)
        if path.is_intent:
            raise OSError("injected ambiguous intent completion")
        return stored

    monkeypatch.setattr(repository_module._StateTransaction, "create_immutable", create_then_fail)
    try:
        with pytest.raises(CreatePreparationError, match="ambiguous durable completion"):
            _prepare(repository, runtime, job)

        assert "discarded" not in runtime.events
        assert len(repository.measure_intent_records().records) == 1
    finally:
        repository.close()


def test_create_activation_selects_reloads_and_commits_terminal_state(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        runtime.events.clear()

        result = activate_create_transition(
            repository,
            cast(CaddyRuntime, runtime),
            _Gate(),
            prepared,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        candidate_id = prepared.candidate_manifest.generation_id
        assert result == prepared.plan.result
        assert runtime.active == runtime.running == candidate_id
        assert runtime.events == [
            "locked",
            f"opened:{_SOURCE_GENERATION}",
            f"opened:{candidate_id}",
            "cleaned-reference-temporaries",
            "read-active",
            f"verified:{_SOURCE_GENERATION}",
            f"selected:{candidate_id}",
            "reloaded",
        ]
        assert (
            repository.read(StateRecordPath.authorization_job(job["jobId"])).document["phase"]
            == "completed"
        )
        assert repository.measure_intent_records().records == ()
        assert repository.measure_inventory().tenant_ids == (prepared.plan.tenant_id,)
    finally:
        repository.close()


def test_create_recovery_reconstructs_and_activates_durable_preparation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    _write_correlation(root, job)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        intent_id = prepared.plan.intent_id
        runtime.events.clear()

        result = recover_create_transition(
            repository,
            cast(CaddyRuntime, runtime),
            _Gate(),
            intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == prepared.plan.result
        assert runtime.active == runtime.running == prepared.candidate_manifest.generation_id
        assert repository.measure_intent_records().records == ()
        assert repository.measure_inventory().tenant_ids == (prepared.plan.tenant_id,)
    finally:
        repository.close()


def test_create_recovery_replays_an_already_appended_audit_entry(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    _write_correlation(root, job)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)

        def interrupt(boundary: CreateCommitBoundary) -> None:
            if boundary is CreateCommitBoundary.AUDIT_SYNC:
                raise RuntimeError("interrupted after audit append")

        with pytest.raises(RuntimeError, match="interrupted after audit append"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
                commit_failure_hook=interrupt,
            )

        assert repository.inspect_audit().entry_count == 1
        assert (
            recover_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared.plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
            == prepared.plan.result
        )
        assert repository.inspect_audit().entry_count == 1
    finally:
        repository.close()


def test_create_recovery_rejects_candidate_state_outside_the_intent(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    _write_correlation(root, job)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        assert runtime.overlay is not None
        runtime.overlay.tenant.observed_state["observedState"] = "suspended"

        with pytest.raises(RuntimeError, match="candidate tenant disagrees"):
            recover_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared.plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_recovery_rejects_an_unbound_candidate_route(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    _write_correlation(root, job)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        runtime.extra_tenants = (
            TenantRouteInput(
                {"metadata": {"id": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2101"}},
                {},
                None,
            ),
        )

        with pytest.raises(RuntimeError, match="route snapshot disagrees"):
            recover_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared.plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_preserves_preparation_capacity_limits(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    limits = HostCapacityLimits(maximum_unique_inodes=1)
    try:
        prepared = _prepare(repository, runtime, job, limits=limits)

        assert prepared.capacity_limits == limits
        with pytest.raises(CapacityRejectedError, match="inode ceiling"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert not any(event.startswith("selected:") for event in runtime.events)
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_cleans_reference_temporaries_before_capacity_rejection(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    limits = HostCapacityLimits(maximum_unique_inodes=1)
    try:
        prepared = _prepare(repository, runtime, job, limits=limits)
        runtime.reference_temporaries = 1
        runtime.events.clear()

        with pytest.raises(CapacityRejectedError, match="inode ceiling"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.reference_temporaries == 0
        assert runtime.events[:4] == [
            "locked",
            f"opened:{_SOURCE_GENERATION}",
            f"opened:{prepared.candidate_manifest.generation_id}",
            "cleaned-reference-temporaries",
        ]
        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert len(repository.measure_intent_records().records) == 1
    finally:
        repository.close()


def test_create_activation_restores_selected_candidate_after_capacity_rejection(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    limits = HostCapacityLimits(maximum_unique_inodes=1)
    try:
        prepared = _prepare(repository, runtime, job, limits=limits)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = runtime.running = candidate_id
        runtime.events.clear()

        with pytest.raises(CapacityRejectedError, match="inode ceiling"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-2:] == [f"selected:{_SOURCE_GENERATION}", "restored"]
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_restores_running_candidate_after_source_reselected(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    limits = HostCapacityLimits(maximum_unique_inodes=1)
    try:
        prepared = _prepare(repository, runtime, job, limits=limits)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = _SOURCE_GENERATION
        runtime.running = candidate_id
        runtime.events.clear()

        with pytest.raises(CapacityRejectedError, match="inode ceiling"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-3:] == [
            f"verified:{_SOURCE_GENERATION}",
            f"selected:{_SOURCE_GENERATION}",
            "restored",
        ]
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_capacity_recovery_restores_source_and_preserves_control_interruption(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    limits = HostCapacityLimits(maximum_unique_inodes=1)
    try:
        prepared = _prepare(repository, runtime, job, limits=limits)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = _SOURCE_GENERATION
        runtime.running = candidate_id
        runtime.events.clear()

        def interrupt(_generation: PinnedCaddyGeneration) -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=interrupt,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-2:] == [f"selected:{_SOURCE_GENERATION}", "restored"]
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_replays_selected_candidate_before_reload(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = candidate_id
        runtime.events.clear()

        activate_create_transition(
            repository,
            cast(CaddyRuntime, runtime),
            _Gate(),
            prepared,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert runtime.active == runtime.running == candidate_id
        assert f"verified:{candidate_id}" in runtime.events
        assert "reloaded" in runtime.events
    finally:
        repository.close()


def test_create_activation_repairs_running_source_before_reselecting_candidate(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = _SOURCE_GENERATION
        runtime.running = candidate_id
        runtime.events.clear()

        activate_create_transition(
            repository,
            cast(CaddyRuntime, runtime),
            _Gate(),
            prepared,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert runtime.active == runtime.running == candidate_id
        assert runtime.events[:7] == [
            "locked",
            f"opened:{_SOURCE_GENERATION}",
            f"opened:{candidate_id}",
            "cleaned-reference-temporaries",
            "read-active",
            f"verified:{_SOURCE_GENERATION}",
            "restored",
        ]
        assert runtime.events[-2:] == [f"selected:{candidate_id}", "reloaded"]
    finally:
        repository.close()


def test_create_activation_durably_reselects_an_already_running_candidate(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = runtime.running = candidate_id
        runtime.events.clear()

        activate_create_transition(
            repository,
            cast(CaddyRuntime, runtime),
            _Gate(),
            prepared,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert runtime.active == runtime.running == candidate_id
        assert runtime.events[-3:] == [
            "read-active",
            f"selected:{candidate_id}",
            f"verified:{candidate_id}",
        ]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_create_activation_restores_source_when_candidate_reselection_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = runtime.running = candidate_id
        runtime.events.clear()
        select_active = runtime.select_active

        def fail_candidate_selection(generation_id: str) -> None:
            if generation_id == candidate_id:
                runtime.events.append("candidate-selection-failed")
                raise RuntimeError("injected candidate reselection failure")
            select_active(generation_id)

        monkeypatch.setattr(runtime, "select_active", fail_candidate_selection)
        with pytest.raises(RuntimeError, match="candidate reselection failure"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-3:] == [
            "candidate-selection-failed",
            f"selected:{_SOURCE_GENERATION}",
            "restored",
        ]
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_restores_source_on_control_interruption(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.active = candidate_id
        runtime.running = candidate_id

        def interrupt(_generation: PinnedCaddyGeneration) -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=interrupt,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_restores_source_when_reload_fails(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        runtime.events.clear()

        def fail_reload(
            _source: PinnedCaddyGeneration,
            _candidate: PinnedCaddyGeneration,
        ) -> None:
            runtime.events.append("reload-failed")
            raise RuntimeError("injected reload failure")

        with pytest.raises(RuntimeError, match="injected reload failure"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=fail_reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-2:] == [f"selected:{_SOURCE_GENERATION}", "restored"]
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
        assert (
            repository.read(StateRecordPath.authorization_job(job["jobId"])).document["phase"]
            == "claimed"
        )
    finally:
        repository.close()


@pytest.mark.parametrize(
    "interrupted_boundary",
    [
        CreateCommitBoundary.STATE_SYNC,
        CreateCommitBoundary.JOB_SYNC,
        CreateCommitBoundary.INTENT_REMOVED,
    ],
)
def test_create_activation_keeps_candidate_during_terminal_commit_replay(
    tmp_path: Path,
    interrupted_boundary: CreateCommitBoundary,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id

        def interrupt(boundary: CreateCommitBoundary) -> None:
            if boundary is interrupted_boundary:
                raise RuntimeError("interrupted terminal commit")

        with pytest.raises(RuntimeError, match="interrupted terminal commit"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
                commit_failure_hook=interrupt,
            )

        assert runtime.active == runtime.running == candidate_id
        expected_intents = int(interrupted_boundary is not CreateCommitBoundary.INTENT_REMOVED)
        assert len(repository.measure_intent_records().records) == expected_intents

        assert (
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
            == prepared.plan.result
        )
        assert runtime.active == runtime.running == candidate_id
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_completed_create_cleans_its_intent_after_capacity_falls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id

        def interrupt(boundary: CreateCommitBoundary) -> None:
            if boundary is CreateCommitBoundary.JOB_SYNC:
                raise RuntimeError("interrupted after completed job")

        with pytest.raises(RuntimeError, match="interrupted after completed job"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
                commit_failure_hook=interrupt,
            )

        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
            lambda _transaction: FilesystemCapacity(
                device=1,
                fragment_size=4096,
                total_blocks=10_000_000,
                available_blocks=0,
                total_inodes=1_000_000,
                available_inodes=0,
            ),
        )
        runtime.events.clear()

        def reject_candidate_reselection(generation_id: str) -> None:
            if generation_id == candidate_id:
                raise OSError("no inode is available for active-reference staging")
            raise AssertionError("completed create must not select another generation")

        monkeypatch.setattr(runtime, "select_active", reject_candidate_reselection)
        assert (
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
            == prepared.plan.result
        )

        assert runtime.active == runtime.running == candidate_id
        assert not any(event.startswith("selected:") for event in runtime.events)
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_create_activation_rejects_an_unrelated_active_generation_before_mutation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        runtime.active = "0198d17f-6f4a-7000-8000-000000000099"
        runtime.events.clear()

        with pytest.raises(CreateActivationError, match="outside create recovery"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert not any(event.startswith("selected:") for event in runtime.events)
        assert len(repository.measure_intent_records().records) == 1
        assert repository.measure_inventory().tenant_ids == ()
    finally:
        repository.close()


def test_create_activation_checks_gate_before_inspecting_runtime(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        runtime.events.clear()

        with pytest.raises(RuntimeError, match="publication_disabled"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(enabled=False),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.events == ["locked"]
        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert len(repository.measure_intent_records().records) == 1
    finally:
        repository.close()


def test_create_activation_rejects_changed_candidate_before_selection(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root)
    runtime = _Runtime()
    try:
        prepared = _prepare(repository, runtime, job)
        candidate_id = prepared.candidate_manifest.generation_id
        runtime.candidate = _Candidate(candidate_id, marker="replaced")
        runtime.events.clear()

        with pytest.raises(CreateActivationError, match="manifest changed"):
            activate_create_transition(
                repository,
                cast(CaddyRuntime, runtime),
                _Gate(),
                prepared,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert not any(event.startswith("selected:") for event in runtime.events)
        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert len(repository.measure_intent_records().records) == 1
    finally:
        repository.close()
