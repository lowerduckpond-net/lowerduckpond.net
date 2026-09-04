from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import lowerduckpond_static_host_agent.route_handler as route_handler_module
import pytest
from lowerduckpond_static_contracts import (
    archive_record_digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    request_digest,
)
from lowerduckpond_static_host_agent import (
    AuditCapacityError,
    AuditState,
    CaddyGenerationManifest,
    CaddyRuntime,
    CapacityRejectedError,
    FilesystemCapacity,
    HostCapacityLimits,
    LifecycleArtifact,
    LifecycleJobRejectionError,
    LockManager,
    PinnedCaddyGeneration,
    PublicationGate,
    RouteLifecycleError,
    RouteLifecycleHandler,
    StateConflictError,
    StateRecordPath,
    StateRepository,
    StoredContract,
    TenantRouteInput,
    TenantRouteOverlay,
    TenantRouteSnapshot,
)
from lowerduckpond_static_host_agent.lifecycle_plan import (
    RouteTransitionPlan,
    plan_route_transition,
)
from lowerduckpond_static_host_agent.route_activate import (
    RouteActivationError,
    activate_route_transition,
    activate_route_transition_outcome,
)
from lowerduckpond_static_host_agent.route_commit import (
    RouteCommitBoundary,
    RouteCommitError,
    RouteCommitOutcome,
    finalize_route_transition_outcome,
    validate_route_transition,
)
from lowerduckpond_static_host_agent.route_prepare import PreparedRouteTransition
from lowerduckpond_static_host_agent.route_recover import (
    RouteRecoveryError,
    recover_route_transition,
    recover_route_transition_outcome,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    RouteSnapshotTransaction,
    snapshot_tenant_routes,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000004"
_CANDIDATE_GENERATION = "0198d17f-6f4a-7000-8000-000000000005"
_LATEST_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000006"
_NOW = datetime(2026, 9, 2, 13, 45, tzinfo=UTC)


class _Entropy:
    def __init__(self) -> None:
        self._value = 0

    def __call__(self, length: int) -> bytes:
        self._value += 1
        return self._value.to_bytes(length, byteorder="big")


class _Gate:
    def require_enabled(self) -> None:
        return


@dataclass(frozen=True, slots=True)
class _GenerationManifest:
    generation_id: str


class _Generation:
    def __init__(self, generation_id: str) -> None:
        self.manifest = _GenerationManifest(generation_id)

    def __enter__(self) -> _Generation:
        return self

    def __exit__(self, *_args: object) -> None:
        return

    def close(self) -> None:
        return


@dataclass(frozen=True, slots=True)
class _Selected:
    generation_id: str
    generation: _Generation


class _Runtime:
    def __init__(self) -> None:
        self.active = _SOURCE_GENERATION
        self.running = _SOURCE_GENERATION
        self.events: list[str] = []
        self.snapshots: dict[str, TenantRouteSnapshot] = {}

    @contextmanager
    def using_held_publication_lock(self, _repository: StateRepository) -> Iterator[None]:
        self.events.append("locked")
        yield

    def open_verified_generation(self, generation_id: object) -> _Generation:
        assert type(generation_id) is str
        self.events.append(f"opened:{generation_id}")
        return _Generation(generation_id)

    def open_active_verified(self) -> _Selected:
        self.events.append("active")
        return _Selected(self.active, _Generation(self.active))

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
        gate.require_enabled()
        self.events.append("published")
        self.snapshots[generation_id] = snapshot_tenant_routes(
            cast(RouteSnapshotTransaction, transaction),
            overlay=overlay,
        )
        return cast(CaddyGenerationManifest, _GenerationManifest(generation_id))

    def discard_unselected_candidate(
        self,
        generation_id: str,
        manifest: CaddyGenerationManifest,
    ) -> None:
        assert generation_id == manifest.generation_id
        self.snapshots.pop(generation_id, None)
        self.events.append("discarded")

    def remove_abandoned_reference_temporaries(self) -> None:
        self.events.append("cleaned-reference-temporaries")

    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        self.events.append(f"snapshot:{generation_id}")
        return deepcopy(self.snapshots[generation_id])

    def read_active(self) -> str:
        self.events.append("read-active")
        return self.active

    def select_active(self, generation_id: str) -> None:
        self.active = generation_id
        self.events.append(f"selected:{generation_id}")

    def reload(
        self,
        source: PinnedCaddyGeneration,
        candidate: PinnedCaddyGeneration,
    ) -> None:
        assert source.manifest.generation_id == _SOURCE_GENERATION
        assert self.active == candidate.manifest.generation_id
        self.running = candidate.manifest.generation_id
        self.events.append("reloaded")

    def restore(self, source: PinnedCaddyGeneration) -> None:
        assert self.active == source.manifest.generation_id
        self.running = source.manifest.generation_id
        self.events.append("restored")

    def verify(self, generation: PinnedCaddyGeneration) -> None:
        if self.running != generation.manifest.generation_id:
            raise RuntimeError("generation is not running")
        self.events.append(f"verified:{generation.manifest.generation_id}")


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


def _source(
    state: str,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object] | None,
    dict[str, object] | None,
]:
    manifest = _fixture("site.json")
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    spec["desiredState"] = state
    deployment: dict[str, object] | None = _fixture("deployment-record.json")
    archive: dict[str, object] | None = None
    if state == "undeployed":
        spec.pop("desiredDeployment")
        deployment = None
        active_deployment_id = None
    else:
        reference = cast(dict[str, object], spec["desiredDeployment"])
        active_deployment_id = reference["id"] if state != "archived" else None
        if state == "archived":
            archive = _fixture("archive-record.json")
            archive["manifestDigest"] = manifest_digest(manifest).to_dict()
    observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": metadata["id"],
        "desiredManifestDigest": manifest_digest(manifest).to_dict(),
        "observedState": state,
        "activeDeploymentId": active_deployment_id,
        "runtimeGenerationId": _SOURCE_GENERATION if state == "active" else None,
        "reconciledAt": "2026-09-02T12:00:00Z",
    }
    return manifest, observed, deployment, archive


def _job(  # noqa: PLR0913 - fixture authority remains explicit
    operation: str,
    namespace: dict[str, object],
    manifest: dict[str, object],
    deployment: dict[str, object] | None,
    archive: dict[str, object] | None,
    *,
    slug: str | None,
) -> dict[str, object]:
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": metadata["id"],
    }
    if slug is not None:
        request["slug"] = slug
    return {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuthorizationJob",
        "compatibilityVersion": "static-job-v2",
        "jobId": "0198d17f-6f4a-7000-8000-000000000002",
        "operatorPrincipal": "operator@example.test",
        "request": request,
        "requestDigest": request_digest(request).to_dict(),
        "artifact": None,
        "expectedSource": {
            "expectsTenantAbsent": False,
            "lifecycle": spec["desiredState"],
            "manifestDigest": manifest_digest(manifest).to_dict(),
            "deploymentDigest": (
                deployment_record_digest(deployment).to_dict() if deployment else None
            ),
            "archiveRecordDigest": archive_record_digest(archive).to_dict() if archive else None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        },
        "sourceAuthority": {"manifest": manifest, "archiveRecord": archive},
        "acceptedAt": "2026-09-02T12:00:01Z",
        "phase": "claimed",
        "executionValidated": False,
    }


def _prepared(  # noqa: PLR0913 - fixture authority controls stay explicit
    tmp_path: Path,
    *,
    operation: str = "suspend",
    state: str = "active",
    slug: str | None = None,
    selected_source_generation: str = _SOURCE_GENERATION,
    source_route_set: str | None = None,
    drift_observed: bool = False,
    create_intent: bool = True,
) -> tuple[StateRepository, dict[str, object], RouteTransitionPlan]:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _source(state)
    if drift_observed:
        observed["desiredManifestDigest"] = {
            "format": "lowerduckpond-manifest-v1",
            "algorithm": "sha256",
            "value": "f" * 64,
        }
        if state != "archived":
            observed["observedState"] = "suspended"
            observed["runtimeGenerationId"] = None
    job = _job(operation, namespace, manifest, deployment, archive, slug=slug)
    tenant_id = cast(str, cast(dict[str, object], manifest["metadata"])["id"])
    tenant_root = root / "tenants" / tenant_id
    _mkdir(tenant_root)
    _mkdir(tenant_root / "deployments")
    _mkdir(tenant_root / "archives")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(tenant_id), manifest)
    _write(root, StateRecordPath.tenant_observed(tenant_id), observed)
    if deployment is not None:
        _write(root, StateRecordPath.tenant_deployment(tenant_id, deployment["id"]), deployment)
    if archive is not None:
        _write(root, StateRecordPath.tenant_archive(tenant_id, archive["deploymentId"]), archive)
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    plan = plan_route_transition(
        job,
        namespace,
        manifest,
        observed,
        deployment,
        archive,
        source_route_set=("both" if state == "active" else "absent")
        if source_route_set is None
        else source_route_set,
        source_runtime_generation_id=selected_source_generation,
        candidate_runtime_generation_id=_CANDIDATE_GENERATION,
        audit_state=AuditState(0, 0, 0, None),
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    job["dispatchSourceObservedState"] = deepcopy(recovery["sourceObservedState"])
    job["dispatchSourceRuntimeGenerationId"] = recovery["sourceRuntimeGenerationId"]
    job["dispatchSourceRouteSet"] = recovery["sourceRouteSet"]
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    repository = StateRepository(root, expected_owner=os.geteuid())
    if create_intent:
        repository.create_immutable(
            StateRecordPath.transaction_intent(plan.intent_id),
            plan.intent,
        )
    return repository, job, plan


def _write_correlation(
    repository: StateRepository,
    job: dict[str, object],
) -> None:
    correlation = deepcopy(job)
    correlation["phase"] = "pending"
    correlation["dispatchSourceObservedState"] = None
    correlation.pop("dispatchSourceRuntimeGenerationId", None)
    correlation.pop("dispatchSourceRouteSet", None)
    request = cast(dict[str, object], job["request"])
    repository.create_immutable(
        StateRecordPath.authorization_correlation(request["correlationId"]),
        correlation,
    )


def _finalize(
    repository: StateRepository,
    job_id: object,
    plan: RouteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits | None = None,
    failure_hook: Callable[[RouteCommitBoundary], None] | None = None,
) -> RouteCommitOutcome:
    with repository.publication_transaction() as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        return finalize_route_transition_outcome(
            transaction,
            job,
            plan,
            capacity_limits=(HostCapacityLimits() if capacity_limits is None else capacity_limits),
            failure_hook=failure_hook,
        )


def _prepared_activation(
    repository: StateRepository,
    job_id: object,
    plan: RouteTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits | None = None,
) -> PreparedRouteTransition:
    return PreparedRouteTransition(
        repository.read(StateRecordPath.authorization_job(job_id)),
        plan,
        cast(CaddyGenerationManifest, _GenerationManifest(_CANDIDATE_GENERATION)),
        HostCapacityLimits() if capacity_limits is None else capacity_limits,
    )


def _recovery_runtime(
    repository: StateRepository,
    job: dict[str, object],
    plan: RouteTransitionPlan,
) -> _Runtime:
    _write_correlation(repository, job)
    source = cast(dict[str, object], plan.intent["sourceManifest"])
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    source_observed = cast(dict[str, object], recovery["sourceObservedState"])
    source_spec = cast(dict[str, object], source["spec"])
    selected = source_spec.get("desiredDeployment")
    deployment = None
    if type(selected) is dict:
        deployment = repository.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, selected["id"])
        ).document
    source_tenant = TenantRouteInput(source, source_observed, deployment)
    candidate_tenant = TenantRouteInput(plan.manifest, plan.observed_state, deployment)
    operation = cast(dict[str, object], job["request"])["operation"]
    observed_drift_tenant_id = plan.tenant_id if operation == "reconcile" else None
    with repository.publication_transaction() as transaction:
        source_snapshot = snapshot_tenant_routes(
            transaction,
            observed_drift_tenant_id=observed_drift_tenant_id,
        )
        candidate_snapshot = snapshot_tenant_routes(
            transaction,
            overlay=TenantRouteOverlay(
                RouteOverlayMode.REPLACE,
                candidate_tenant,
                source_tenant,
            ),
            observed_drift_tenant_id=observed_drift_tenant_id,
        )
    runtime = _Runtime()
    runtime.snapshots = {
        _SOURCE_GENERATION: source_snapshot,
        _CANDIDATE_GENERATION: candidate_snapshot,
    }
    return runtime


def _activate(
    repository: StateRepository,
    runtime: _Runtime,
    prepared: PreparedRouteTransition,
    *,
    failure_hook: Callable[[RouteCommitBoundary], None] | None = None,
) -> dict[str, object]:
    return activate_route_transition(
        repository,
        cast(CaddyRuntime, runtime),
        cast(PublicationGate, _Gate()),
        prepared,
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
        commit_failure_hook=failure_hook,
    )


def _route_handler(
    repository: StateRepository,
    runtime: _Runtime,
) -> RouteLifecycleHandler:
    return RouteLifecycleHandler(
        repository,
        cast(CaddyRuntime, runtime),
        cast(PublicationGate, _Gate()),
        now=lambda: _NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
    )


def test_route_handler_completes_and_replays_a_fresh_claimed_job(
    tmp_path: Path,
) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)
    runtime = _Runtime()
    with repository.publication_transaction() as transaction:
        runtime.snapshots[_SOURCE_GENERATION] = snapshot_tenant_routes(transaction)
    _write_correlation(repository, job)
    try:
        handler = _route_handler(repository, runtime)
        job_id = cast(str, job["jobId"])

        first = handler.execute(job_id, claim=None, blocking=False)
        completed_events = tuple(runtime.events)
        second = handler.execute(job_id, claim=None, blocking=False)

        assert first.result == second.result
        assert first.created is True
        assert second.created is False
        assert first.result["status"] == "succeeded"
        assert runtime.active == runtime.running
        assert runtime.active != _SOURCE_GENERATION
        assert runtime.events == list(completed_events)
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_handler_recovers_its_prepared_intent(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    try:
        outcome = _route_handler(repository, runtime).execute(
            cast(str, job["jobId"]),
            claim=None,
            blocking=False,
        )

        assert outcome.result == plan.result
        assert outcome.created is True
        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize("race_error", [RouteActivationError, RouteCommitError])
def test_route_handler_reclassifies_after_recovery_activation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race_error: type[RuntimeError],
) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    original = recover_route_transition_outcome
    raced = False

    def complete_then_race(*args: object, **kwargs: object) -> object:
        nonlocal raced
        outcome = cast(Callable[..., object], original)(*args, **kwargs)
        if not raced:
            raced = True
            raise race_error("injected post-activation race")
        return outcome

    monkeypatch.setattr(
        route_handler_module,
        "recover_route_transition_outcome",
        complete_then_race,
    )
    try:
        outcome = _route_handler(repository, runtime).execute(
            cast(str, job["jobId"]),
            claim=None,
            blocking=False,
        )

        assert raced is True
        assert outcome.result == plan.result
        assert outcome.created is False
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize("race_error", [RouteActivationError, RouteCommitError])
def test_route_handler_reclassifies_after_fresh_activation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race_error: type[RuntimeError],
) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)
    runtime = _Runtime()
    with repository.publication_transaction() as transaction:
        runtime.snapshots[_SOURCE_GENERATION] = snapshot_tenant_routes(transaction)
    _write_correlation(repository, job)
    original = activate_route_transition_outcome
    raced = False

    def complete_then_race(*args: object, **kwargs: object) -> object:
        nonlocal raced
        outcome = cast(Callable[..., object], original)(*args, **kwargs)
        if not raced:
            raced = True
            raise race_error("injected post-activation race")
        return outcome

    monkeypatch.setattr(
        route_handler_module,
        "activate_route_transition_outcome",
        complete_then_race,
    )
    try:
        outcome = _route_handler(repository, runtime).execute(
            cast(str, job["jobId"]),
            claim=None,
            blocking=False,
        )

        assert raced is True
        assert outcome.result["status"] == "succeeded"
        assert outcome.created is False
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_handler_marks_executor_failure_replay_as_existing(tmp_path: Path) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)
    request = cast(dict[str, object], job["request"])
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": request["operation"],
        "status": "failed",
        "errorCode": "state_drift",
        "failurePublisher": "authorization-executor",
        "failureAuditPredecessorDigest": None,
        "failureAuditSequence": 0,
        "tenantId": request["tenantId"],
    }
    repository.create_immutable(
        StateRecordPath.authorization_result(job["jobId"]),
        result,
    )
    try:
        outcome = _route_handler(repository, _Runtime()).execute(
            cast(str, job["jobId"]),
            claim=None,
            blocking=False,
        )

        assert outcome.result == result
        assert outcome.created is False
        assert outcome.replay_existing is True
    finally:
        repository.close()


def test_route_handler_rejects_invalid_transition_before_intent_creation(
    tmp_path: Path,
) -> None:
    repository, job, _plan = _prepared(
        tmp_path,
        operation="rename",
        slug="renamed-duck",
        create_intent=False,
    )
    job_path = StateRecordPath.authorization_job(job["jobId"])
    stored = repository.read(job_path)
    invalid = stored.document
    request = cast(dict[str, object], invalid["request"])
    manifest = repository.read(StateRecordPath.tenant_desired(request["tenantId"])).document
    metadata = cast(dict[str, object], manifest["metadata"])
    request["slug"] = metadata["slug"]
    invalid["requestDigest"] = request_digest(request).to_dict()
    repository.close()
    _write(tmp_path / "state", job_path, invalid)
    repository = StateRepository(tmp_path / "state", expected_owner=os.geteuid())
    runtime = _Runtime()
    with repository.publication_transaction() as transaction:
        runtime.snapshots[_SOURCE_GENERATION] = snapshot_tenant_routes(transaction)
    try:
        with pytest.raises(LifecycleJobRejectionError) as failure:
            _route_handler(repository, runtime).execute(
                cast(str, job["jobId"]),
                claim=None,
                blocking=False,
            )

        assert failure.value.error_code == "invalid_request"
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_handler_rejects_legacy_job_before_intent_creation(tmp_path: Path) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)
    job_path = StateRecordPath.authorization_job(job["jobId"])
    stored = repository.read(job_path)
    legacy = stored.document
    legacy["compatibilityVersion"] = "static-job-v1"
    legacy.pop("sourceAuthority", None)
    legacy.pop("executionValidated", None)
    legacy.pop("dispatchSourceObservedState", None)
    legacy.pop("dispatchSourceRuntimeGenerationId", None)
    legacy.pop("dispatchSourceRouteSet", None)
    repository.close()
    _write(tmp_path / "state", job_path, legacy)
    repository = StateRepository(tmp_path / "state", expected_owner=os.geteuid())
    try:
        with pytest.raises(LifecycleJobRejectionError) as failure:
            _route_handler(repository, _Runtime()).execute(
                cast(str, job["jobId"]),
                claim=None,
                blocking=False,
            )

        assert failure.value.error_code == "invalid_request"
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_handler_terminalizes_missing_observed_state_as_drift(tmp_path: Path) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)
    request = cast(dict[str, object], job["request"])
    observed_path = StateRecordPath.tenant_observed(request["tenantId"])
    (tmp_path / "state").joinpath(*observed_path.components).unlink()
    try:
        with pytest.raises(LifecycleJobRejectionError) as failure:
            _route_handler(repository, _Runtime()).execute(
                cast(str, job["jobId"]),
                claim=None,
                blocking=False,
            )

        assert failure.value.error_code == "state_drift"
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_handler_does_not_terminalize_missing_runtime_state(tmp_path: Path) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)

    class _MissingRuntime(_Runtime):
        def open_active_verified(self) -> _Selected:
            raise FileNotFoundError("injected missing Caddy runtime")

    try:
        with pytest.raises(FileNotFoundError, match="missing Caddy runtime"):
            _route_handler(repository, _MissingRuntime()).execute(
                cast(str, job["jobId"]),
                claim=None,
                blocking=False,
            )

        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_handler_rejects_artifact_authority(tmp_path: Path) -> None:
    repository, job, _plan = _prepared(tmp_path, create_intent=False)
    runtime = _Runtime()
    try:
        with pytest.raises(RouteLifecycleError, match="unexpectedly claimed"):
            _route_handler(repository, runtime).execute(
                cast(str, job["jobId"]),
                claim=cast(LifecycleArtifact, object()),
                blocking=False,
            )
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("operation", "state", "slug"),
    [
        ("suspend", "active", None),
        ("resume", "suspended", None),
        ("rename", "active", "renamed-duck"),
        ("reconcile", "archived", None),
    ],
)
def test_route_commit_completes_and_replays_exact_state(
    tmp_path: Path,
    operation: str,
    state: str,
    slug: str | None,
) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        operation=operation,
        state=state,
        slug=slug,
    )
    try:
        first = _finalize(repository, job["jobId"], plan)
        second = _finalize(repository, job["jobId"], plan)

        assert first.created is True
        assert second.created is False
        assert first.result == second.result == plan.result
        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == plan.manifest
        )
        assert (
            repository.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
            == plan.observed_state
        )
        assert (
            repository.read(StateRecordPath.authorization_job(job["jobId"])).document["phase"]
            == "completed"
        )
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_commit_accepts_an_older_target_generation_than_the_rollback_source(
    tmp_path: Path,
) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        selected_source_generation=_LATEST_SOURCE_GENERATION,
    )
    try:
        outcome = _finalize(repository, job["jobId"], plan)

        recovery = plan.intent["lifecycleRecovery"]
        assert type(recovery) is dict
        source_observed = recovery["sourceObservedState"]
        assert type(source_observed) is dict
        assert recovery["sourceRuntimeGenerationId"] == _LATEST_SOURCE_GENERATION
        assert source_observed["runtimeGenerationId"] == _SOURCE_GENERATION
        assert outcome.result == plan.result
    finally:
        repository.close()


def test_route_commit_repairs_reconcile_observed_state_drift(tmp_path: Path) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        operation="reconcile",
        state="active",
        source_route_set="absent",
        drift_observed=True,
    )
    try:
        outcome = _finalize(repository, job["jobId"], plan)

        assert outcome.result == plan.result
        assert (
            repository.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
            == plan.observed_state
        )
        assert plan.observed_state["observedState"] == "active"
    finally:
        repository.close()


@pytest.mark.parametrize("boundary", list(RouteCommitBoundary))
def test_route_commit_recovers_every_durable_boundary(
    tmp_path: Path,
    boundary: RouteCommitBoundary,
) -> None:
    repository, job, plan = _prepared(tmp_path)

    def interrupt(current: RouteCommitBoundary) -> None:
        if current is boundary:
            raise RuntimeError(f"interrupted at {current}")

    try:
        with pytest.raises(RuntimeError, match="interrupted"):
            _finalize(repository, job["jobId"], plan, failure_hook=interrupt)
        outcome = _finalize(repository, job["jobId"], plan)

        assert outcome.result == plan.result
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_commit_refuses_observed_state_that_advanced_first(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    try:
        observed_path = StateRecordPath.tenant_observed(plan.tenant_id)
        current = repository.read(observed_path)
        repository.compare_and_swap(observed_path, current.revision, plan.observed_state)

        with pytest.raises(RouteCommitError, match="advanced before desired"):
            _finalize(repository, job["jobId"], plan)
    finally:
        repository.close()


def test_route_commit_refuses_state_outside_recovery_authority(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    try:
        desired_path = StateRecordPath.tenant_desired(plan.tenant_id)
        current = repository.read(desired_path)
        drifted = current.document
        cast(dict[str, object], drifted["metadata"])["slug"] = "other-duck"
        repository.compare_and_swap(desired_path, current.revision, drifted)

        with pytest.raises(StateConflictError, match="outside recovery authority"):
            _finalize(repository, job["jobId"], plan)
    finally:
        repository.close()


def test_route_commit_admits_capacity_before_state_mutation(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    try:
        with pytest.raises(CapacityRejectedError):
            _finalize(
                repository,
                job["jobId"],
                plan,
                capacity_limits=HostCapacityLimits(maximum_allocated_bytes=0),
            )

        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == source_manifest
        )
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_route_commit_admits_audit_before_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    source_observed = cast(
        dict[str, object],
        cast(dict[str, object], plan.intent["lifecycleRecovery"])["sourceObservedState"],
    )

    def reject_audit(_transaction: object, _document: object) -> None:
        raise AuditCapacityError("injected audit capacity rejection")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.admit_audit_append",
        reject_audit,
    )
    try:
        with pytest.raises(AuditCapacityError, match="injected audit capacity rejection"):
            _finalize(repository, job["jobId"], plan)

        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == source_manifest
        )
        assert (
            repository.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
            == source_observed
        )
        assert repository.measure_intent_records().records
        assert (
            repository.read(StateRecordPath.authorization_job(job["jobId"])).document["phase"]
            == "claimed"
        )
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job["jobId"]))
    finally:
        repository.close()


def test_route_validation_rejects_candidate_outside_exact_transform(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    try:
        tampered = deepcopy(plan)
        spec = cast(dict[str, object], tampered.manifest["spec"])
        quotas = cast(dict[str, object], spec["quotas"])
        quotas["storageMiB"] = 99
        stored_job = repository.read(StateRecordPath.authorization_job(job["jobId"]))
        with pytest.raises(RouteCommitError):
            validate_route_transition(stored_job, tampered)
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dispatchSourceObservedState", None),
        ("dispatchSourceRuntimeGenerationId", _LATEST_SOURCE_GENERATION),
        ("dispatchSourceRouteSet", "absent"),
    ],
)
def test_route_validation_rejects_recovery_outside_persisted_dispatch_authority(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    stored_job = repository.read(StateRecordPath.authorization_job(job["jobId"]))
    drifted_job = stored_job.document
    if field == "dispatchSourceObservedState":
        drifted_observed = deepcopy(cast(dict[str, object], drifted_job[field]))
        drifted_observed["reconciledAt"] = "2026-09-02T12:00:02Z"
        drifted_job[field] = drifted_observed
    else:
        drifted_job[field] = value
    try:
        with pytest.raises(RouteCommitError, match="terminal documents disagree"):
            validate_route_transition(
                StoredContract(drifted_job, stored_job.revision),
                plan,
            )
    finally:
        repository.close()


def test_route_activation_selects_reloads_and_commits_terminal_state(
    tmp_path: Path,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _Runtime()
    try:
        result = _activate(
            repository,
            runtime,
            _prepared_activation(repository, job["jobId"], plan),
        )

        assert result == plan.result
        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert runtime.events == [
            "locked",
            f"opened:{_SOURCE_GENERATION}",
            f"opened:{_CANDIDATE_GENERATION}",
            "cleaned-reference-temporaries",
            "read-active",
            f"verified:{_SOURCE_GENERATION}",
            f"selected:{_CANDIDATE_GENERATION}",
            "reloaded",
        ]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_activation_restores_source_when_reload_fails(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _Runtime()
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def fail_reload(
        _source: PinnedCaddyGeneration,
        _candidate: PinnedCaddyGeneration,
    ) -> None:
        runtime.events.append("reload-failed")
        raise RuntimeError("injected reload failure")

    try:
        with pytest.raises(RuntimeError, match="injected reload failure"):
            activate_route_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(PublicationGate, _Gate()),
                prepared,
                reloader=fail_reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-3:] == [
            "reload-failed",
            f"selected:{_SOURCE_GENERATION}",
            "restored",
        ]
        assert repository.measure_intent_records().records
        source = cast(dict[str, object], plan.intent["sourceManifest"])
        assert repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document == source
    finally:
        repository.close()


def test_route_activation_replays_an_interrupted_terminal_commit(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _Runtime()
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def interrupt(boundary: RouteCommitBoundary) -> None:
        if boundary is RouteCommitBoundary.JOB_SYNC:
            raise RuntimeError("interrupted terminal commit")

    try:
        with pytest.raises(RuntimeError, match="interrupted terminal commit"):
            _activate(repository, runtime, prepared, failure_hook=interrupt)

        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert repository.measure_intent_records().records
        runtime.events.clear()
        assert _activate(repository, runtime, prepared) == plan.result
        assert runtime.events[-2:] == [
            "read-active",
            f"verified:{_CANDIDATE_GENERATION}",
        ]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_activation_rejects_capacity_before_runtime_selection(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _Runtime()
    prepared = _prepared_activation(
        repository,
        job["jobId"],
        plan,
        capacity_limits=HostCapacityLimits(maximum_allocated_bytes=0),
    )
    try:
        with pytest.raises(CapacityRejectedError):
            _activate(repository, runtime, prepared)

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert not any(event.startswith("selected:") for event in runtime.events)
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_route_activation_restores_source_when_audit_capacity_is_exhausted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _Runtime()
    runtime.active = runtime.running = _CANDIDATE_GENERATION

    def reject_audit(_transaction: object, _document: object) -> None:
        raise AuditCapacityError("injected audit capacity rejection")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.admit_audit_append",
        reject_audit,
    )
    try:
        with pytest.raises(AuditCapacityError, match="injected audit capacity rejection"):
            _activate(
                repository,
                runtime,
                _prepared_activation(repository, job["jobId"], plan),
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert runtime.events[-2:] == [
            f"selected:{_SOURCE_GENERATION}",
            "restored",
        ]
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_route_recovery_reconstructs_and_activates_durable_preparation(
    tmp_path: Path,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    try:
        result = recover_route_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(PublicationGate, _Gate()),
            plan.intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == plan.result
        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_recovery_reconstructs_an_omitted_archived_tenant(
    tmp_path: Path,
) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        operation="reconcile",
        state="archived",
    )
    runtime = _recovery_runtime(repository, job, plan)
    try:
        result = recover_route_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(PublicationGate, _Gate()),
            plan.intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == plan.result
        assert runtime.snapshots[_SOURCE_GENERATION].tenants == ()
        assert runtime.snapshots[_CANDIDATE_GENERATION].tenants == ()
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_recovery_repairs_drifted_reconcile_authority(tmp_path: Path) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        operation="reconcile",
        state="active",
        source_route_set="absent",
        drift_observed=True,
    )
    runtime = _recovery_runtime(repository, job, plan)
    try:
        result = recover_route_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(PublicationGate, _Gate()),
            plan.intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == plan.result
        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert (
            repository.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
            == plan.observed_state
        )
    finally:
        repository.close()


def test_route_recovery_repairs_archived_reconcile_observed_state_drift(
    tmp_path: Path,
) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        operation="reconcile",
        state="archived",
        drift_observed=True,
    )
    runtime = _recovery_runtime(repository, job, plan)
    try:
        result = recover_route_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(PublicationGate, _Gate()),
            plan.intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == plan.result
        assert runtime.snapshots[_SOURCE_GENERATION].tenants == ()
        assert runtime.snapshots[_CANDIDATE_GENERATION].tenants == ()
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dispatchSourceObservedState", None),
        ("dispatchSourceRuntimeGenerationId", _LATEST_SOURCE_GENERATION),
        ("dispatchSourceRouteSet", "absent"),
    ],
)
def test_route_recovery_rejects_job_source_authority_drift(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    job_path = StateRecordPath.authorization_job(job["jobId"])
    current = repository.read(job_path)
    drifted = current.document
    drifted[field] = value
    repository.close()
    _write(tmp_path / "state", job_path, drifted)
    repository = StateRepository(tmp_path / "state", expected_owner=os.geteuid())
    try:
        with pytest.raises(RouteRecoveryError, match="durable job binding"):
            recover_route_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
    finally:
        repository.close()


def test_route_recovery_rejects_a_candidate_snapshot_outside_authority(
    tmp_path: Path,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    snapshot = runtime.snapshots[_CANDIDATE_GENERATION]
    tampered = deepcopy(snapshot.tenants[0].manifest)
    metadata = cast(dict[str, object], tampered["metadata"])
    metadata["slug"] = "foreign-slug"
    runtime.snapshots[_CANDIDATE_GENERATION] = TenantRouteSnapshot(
        snapshot.platform_namespace,
        (
            TenantRouteInput(
                tampered,
                snapshot.tenants[0].observed_state,
                snapshot.tenants[0].deployment,
            ),
        ),
    )
    try:
        with pytest.raises(RouteRecoveryError, match="generation snapshots"):
            recover_route_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_route_recovery_rejects_platform_authority_drift(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    namespace_path = StateRecordPath.platform_namespace()
    namespace = repository.read(namespace_path)
    drifted = namespace.document
    drifted["initializedAt"] = "2026-09-03T12:00:00Z"
    repository.compare_and_swap(namespace_path, namespace.revision, drifted)
    try:
        with pytest.raises(RouteRecoveryError, match="source authority drifted"):
            recover_route_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_route_recovery_completes_a_partial_desired_state_commit(tmp_path: Path) -> None:
    repository, job, plan = _prepared(tmp_path)
    runtime = _recovery_runtime(repository, job, plan)
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def interrupt(boundary: RouteCommitBoundary) -> None:
        if boundary is RouteCommitBoundary.DESIRED_STATE_SYNC:
            raise RuntimeError("interrupted after desired state")

    try:
        with pytest.raises(RuntimeError, match="interrupted after desired state"):
            _activate(repository, runtime, prepared, failure_hook=interrupt)

        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == plan.manifest
        )
        source_observed = cast(
            dict[str, object],
            cast(dict[str, object], plan.intent["lifecycleRecovery"])["sourceObservedState"],
        )
        assert (
            repository.read(StateRecordPath.tenant_observed(plan.tenant_id)).document
            == source_observed
        )
        assert (
            recover_route_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
            == plan.result
        )
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()
