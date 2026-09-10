from __future__ import annotations

import io
import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from multiprocessing import get_context
from pathlib import Path
from typing import cast

import lowerduckpond_static_host_agent.deployment_prepare as deployment_prepare_module
import pytest
from lowerduckpond_static_contracts import (
    Digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    request_digest,
)
from lowerduckpond_static_host_agent import (
    AdmittedArtifact,
    ArtifactIntake,
    AuditCapacityError,
    AuditState,
    AuthorizationExecutor,
    AuthorizationIssuer,
    CaddyGenerationManifest,
    CaddyRuntime,
    CapacityRejectedError,
    DeploymentCommitBoundary,
    DeploymentCommitError,
    DeploymentReleaseStore,
    FilesystemCapacity,
    HostCapacityLimits,
    InodeAllocation,
    LifecycleArtifact,
    LifecycleJobRejectionError,
    LockManager,
    LockMode,
    LockName,
    PinnedCaddyGeneration,
    PublicationGate,
    ReleaseStoreError,
    StateConflictError,
    StateRecordPath,
    StateRepository,
    TenantRouteInput,
    TenantRouteOverlay,
    VerifiedArtifact,
    build_portable_bundle,
)
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    ReleaseCapacityUsage,
)
from lowerduckpond_static_host_agent.deployment_activate import (
    DeploymentActivationError,
    activate_deployment_transition,
)
from lowerduckpond_static_host_agent.deployment_commit import (
    DeploymentCommitOutcome,
    finalize_deployment_transition_outcome,
    validate_deployment_transition,
)
from lowerduckpond_static_host_agent.deployment_handler import DeploymentLifecycleHandler
from lowerduckpond_static_host_agent.deployment_prepare import (
    PreparedDeploymentTransition,
)
from lowerduckpond_static_host_agent.deployment_recover import (
    DeploymentRecoveryError,
    recover_deployment_transition,
)
from lowerduckpond_static_host_agent.lifecycle_plan import (
    DeploymentTransitionPlan,
    plan_deployment_transition,
)
from lowerduckpond_static_host_agent.release_store import PublishedReleaseInventory
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    RouteSnapshotTransaction,
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_INTERRUPTED_STATUS = 23
_NOW = datetime(2026, 9, 4, 12, 30, tzinfo=UTC)
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000020"
_CANDIDATE_GENERATION = "0198d17f-6f4a-7000-8000-000000000021"
_JOB_ID = "0198d17f-6f4a-7000-8000-000000000022"
_CORRELATION_ID = "0198d17f-6f4a-7000-8000-000000000023"


class _Entropy:
    def __init__(self) -> None:
        self._value = 30

    def __call__(self, length: int) -> bytes:
        self._value += 1
        return self._value.to_bytes(length, byteorder="big")


@dataclass(frozen=True, slots=True)
class _Measurement:
    digest: Digest
    allocations: tuple[InodeAllocation, ...] = ()


@dataclass(frozen=True, slots=True)
class _Staged:
    deployment_id: str
    digest: dict[str, object]


class _ReleaseStore:
    def __init__(self, releases: dict[str, dict[str, object]]) -> None:
        self.releases = deepcopy(releases)
        self.staged: dict[str, dict[str, object]] = {}
        self.removed: list[str] = []
        self.reconciled = False

    def reconcile_staging(
        self,
        protected: dict[str, str],
        *,
        publication_lock: object,
    ) -> None:
        assert protected == {}
        assert publication_lock is not None
        self.reconciled = True

    def stage(  # noqa: PLR0913 - fake mirrors the release-store authority tuple
        self,
        _intake: object,
        _artifact: object,
        *,
        tenant_id: object,
        deployment_id: object,
        expected_release_tree_digest: object,
        retained_usage: object,
        publication_lock: object,
        capacity_limits: object,
        expected_import_manifest_digest: object = None,
    ) -> _Staged:
        assert tenant_id == _tenant_id()
        assert type(deployment_id) is str
        assert type(expected_release_tree_digest) is dict
        assert retained_usage is not None
        assert publication_lock is not None
        assert capacity_limits is not None
        assert (
            expected_import_manifest_digest is None or type(expected_import_manifest_digest) is dict
        )
        return _Staged(deployment_id, deepcopy(expected_release_tree_digest))

    def publish(self, staged: _Staged, *, publication_lock: object) -> None:
        assert publication_lock is not None
        self.releases[staged.deployment_id] = deepcopy(staged.digest)

    def resume_publication(
        self,
        tenant_id: object,
        deployment_id: object,
        *,
        expected_release_tree_digest: object,
        publication_lock: object,
    ) -> object:
        assert tenant_id == _tenant_id()
        assert publication_lock is not None
        deployment = cast(str, deployment_id)
        expected = cast(dict[str, object], expected_release_tree_digest)
        current = self.releases.get(deployment)
        if current is None:
            current = self.staged.pop(deployment)
            self.releases[deployment] = current
        if current != expected:
            raise ReleaseStoreError("published release disagrees with recovery authority")
        return object()

    def measure(
        self,
        tenant_id: object,
        deployment_id: object,
        *,
        publication_lock: object,
    ) -> _Measurement:
        assert tenant_id == _tenant_id()
        assert publication_lock is not None
        try:
            digest = self.releases[cast(str, deployment_id)]
        except KeyError as error:
            raise FileNotFoundError(deployment_id) from error
        return _Measurement(
            Digest(
                cast(str, digest["format"]),
                cast(str, digest["algorithm"]),
                cast(str, digest["value"]),
            )
        )

    def published_inventory(
        self,
        *,
        publication_lock: object,
    ) -> PublishedReleaseInventory:
        assert publication_lock is not None
        releases = tuple(sorted(self.releases))
        return PublishedReleaseInventory(
            ((_tenant_id(), releases),) if releases else (),
            ReleaseCapacityUsage(()),
        )

    def remove_release(
        self,
        tenant_id: object,
        deployment_id: object,
        *,
        expected_release_tree_digest: object,
        publication_lock: object,
    ) -> None:
        assert tenant_id == _tenant_id()
        assert publication_lock is not None
        deployment = cast(str, deployment_id)
        expected = cast(dict[str, object], expected_release_tree_digest)
        current = self.releases.get(deployment)
        if current is not None and current != expected:
            raise AssertionError("test release authority drifted")
        self.releases.pop(deployment, None)
        self.removed.append(deployment)


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
        self.missing_generations: set[str] = set()

    @contextmanager
    def using_held_publication_lock(self, _repository: StateRepository) -> Iterator[None]:
        self.events.append("locked")
        yield

    def open_verified_generation(self, generation_id: object) -> _Generation:
        assert type(generation_id) is str
        self.events.append(f"opened:{generation_id}")
        if generation_id in self.missing_generations:
            raise FileNotFoundError(generation_id)
        return _Generation(generation_id)

    def open_active_verified(self) -> _Selected:
        self.events.append("active")
        return _Selected(self.active, _Generation(self.active))

    def remove_abandoned_reference_temporaries(self) -> None:
        self.events.append("cleaned-reference-temporaries")

    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        self.events.append(f"snapshot:{generation_id}")
        try:
            return deepcopy(self.snapshots[generation_id])
        except KeyError as error:
            raise FileNotFoundError(generation_id) from error

    def prune_unreferenced_generations(
        self,
        _protected: object,
        *,
        keep_newest_unprotected: int,
    ) -> tuple[str, ...]:
        assert keep_newest_unprotected == 1
        self.events.append("pruned-generations")
        return ()

    def publish_candidate(
        self,
        generation_id: str,
        *,
        transaction: object,
        overlay: TenantRouteOverlay,
        gate: object,
        deployment_transition_tenant_id: object,
    ) -> _GenerationManifest:
        assert deployment_transition_tenant_id == _tenant_id()
        assert gate is not None
        self.snapshots[generation_id] = snapshot_tenant_routes(
            cast(RouteSnapshotTransaction, transaction),
            overlay=overlay,
            deployment_transition_tenant_id=deployment_transition_tenant_id,
        )
        self.missing_generations.discard(generation_id)
        self.events.append(f"published:{generation_id}")
        return _GenerationManifest(generation_id)

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


def _tenant_id() -> str:
    manifest = _fixture("site.json")
    metadata = cast(dict[str, object], manifest["metadata"])
    return cast(str, metadata["id"])


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


def _deployment(deployment_id: str, *, value: str) -> dict[str, object]:
    record = _fixture("deployment-record.json")
    record["id"] = deployment_id
    record["tenantId"] = _tenant_id()
    record["archiveSha256"] = value
    record["releaseTreeDigest"] = {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": value,
    }
    record["correlationId"] = _CORRELATION_ID
    return record


def _source(
    deployments: list[dict[str, object]],
    *,
    state: str,
    selected_index: int = -1,
) -> tuple[dict[str, object], dict[str, object], dict[str, object] | None]:
    manifest = _fixture("site.json")
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    spec["desiredState"] = state
    selected = deployments[selected_index] if deployments else None
    if selected is None:
        spec.pop("desiredDeployment")
    else:
        spec["desiredDeployment"] = {
            "id": selected["id"],
            "archiveSha256": selected["archiveSha256"],
        }
    observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": metadata["id"],
        "desiredManifestDigest": manifest_digest(manifest).to_dict(),
        "observedState": state,
        "activeDeploymentId": selected["id"] if selected is not None else None,
        "runtimeGenerationId": _SOURCE_GENERATION if state == "active" else None,
        "reconciledAt": "2026-09-04T12:00:00Z",
    }
    return manifest, observed, selected


def _job(  # noqa: PLR0913 - fixture authority tuple
    operation: str,
    namespace: dict[str, object],
    manifest: dict[str, object],
    observed: dict[str, object],
    deployments: list[dict[str, object]],
    *,
    rollback: dict[str, object] | None,
    release_tree_digest: dict[str, object] | None,
) -> dict[str, object]:
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    desired = spec.get("desiredDeployment")
    selected = (
        next(
            deployment
            for deployment in deployments
            if type(desired) is dict and deployment["id"] == desired.get("id")
        )
        if desired is not None
        else None
    )
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": _CORRELATION_ID,
        "tenantId": metadata["id"],
    }
    if operation in {"deploy", "import"}:
        request["artifact"] = {"size": 32, "sha256": "e" * 64}
    else:
        assert rollback is not None
        request["deploymentId"] = rollback["id"]
    history = [cast(str, deployment["id"]) for deployment in deployments]
    job: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuthorizationJob",
        "compatibilityVersion": "static-job-v2",
        "jobId": _JOB_ID,
        "operatorPrincipal": "operator@example.test",
        "request": request,
        "requestDigest": request_digest(request).to_dict(),
        "artifact": request.get("artifact"),
        "expectedSource": {
            "expectsTenantAbsent": False,
            "lifecycle": spec["desiredState"],
            "manifestDigest": manifest_digest(manifest).to_dict(),
            "deploymentDigest": (
                deployment_record_digest(selected).to_dict() if selected is not None else None
            ),
            "archiveRecordDigest": None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        },
        "sourceAuthority": {"manifest": manifest, "archiveRecord": None},
        "dispatchArchiveDeploymentIds": [],
        "dispatchArtifactReleaseTreeDigest": release_tree_digest,
        "dispatchSourceObservedState": observed,
        "dispatchSourceReleaseTreeDigest": (
            selected["releaseTreeDigest"] if selected is not None else None
        ),
        "dispatchSourceRouteSet": ("both" if spec["desiredState"] == "active" else "absent"),
        "dispatchSourceRuntimeGenerationId": _SOURCE_GENERATION,
        "dispatchDeploymentIds": history,
        "dispatchTenantIds": [metadata["id"]],
        "dispatchTenantRecordHistories": [[metadata["id"], [], history]],
        "acceptedAt": "2026-09-04T12:00:01Z",
        "phase": "claimed",
        "executionValidated": False,
    }
    if operation == "import":
        imported = _fixture("site.json")
        imported_metadata = cast(dict[str, object], imported["metadata"])
        source_id = "0198d17f-6f4a-7000-8000-000000000099"
        imported_metadata["id"] = source_id
        imported_metadata["slug"] = "source-slug"
        imported_metadata["canonicalOrigin"] = f"t-{source_id.replace('-', '')}.lowerduckpond.com"
        cast(dict[str, object], imported["spec"])["desiredState"] = "suspended"
        job["dispatchImportManifest"] = imported
    return job


def _prepared(  # noqa: PLR0913 - fixture authority tuple
    tmp_path: Path,
    *,
    operation: str,
    deployment_count: int,
    state: str,
    selected_index: int = -1,
    rollback_index: int = -2,
    include_other_tenant: bool = False,
    create_intent: bool = True,
) -> tuple[
    StateRepository,
    dict[str, object],
    DeploymentTransitionPlan,
    _ReleaseStore,
]:
    root = _state_root(tmp_path)
    tenant_id = _tenant_id()
    tenant_root = root / "tenants" / tenant_id
    _mkdir(tenant_root)
    _mkdir(tenant_root / "deployments")
    _mkdir(tenant_root / "archives")
    deployments = [
        _deployment(
            f"0198d17f-6f4a-7000-8000-{index:012x}",
            value=f"{index:x}" * 64,
        )
        for index in range(1, deployment_count + 1)
    ]
    manifest, observed, selected = _source(
        deployments,
        state=state,
        selected_index=selected_index,
    )
    namespace = _fixture("platform-namespace.json")
    rollback = deployments[rollback_index] if operation == "rollback" else None
    release_digest: dict[str, object] | None = (
        {
            "format": "lowerduckpond-release-tree-v1",
            "algorithm": "sha256",
            "value": "e" * 64,
        }
        if operation in {"deploy", "import"}
        else None
    )
    job = _job(
        operation,
        namespace,
        manifest,
        observed,
        deployments,
        rollback=rollback,
        release_tree_digest=release_digest,
    )
    if include_other_tenant:
        other_tenant = "0198d17f-6f4a-7000-8000-000000000099"
        tenant_ids = sorted([tenant_id, other_tenant])
        histories = {
            tenant_id: [tenant_id, [], job["dispatchDeploymentIds"]],
            other_tenant: [other_tenant, [], []],
        }
        job["dispatchTenantIds"] = tenant_ids
        job["dispatchTenantRecordHistories"] = [histories[value] for value in tenant_ids]
    plan = plan_deployment_transition(
        job,
        namespace,
        manifest,
        observed,
        selected,
        rollback,
        artifact_release_tree_digest=release_digest,
        source_runtime_generation_id=_SOURCE_GENERATION,
        candidate_runtime_generation_id=_CANDIDATE_GENERATION,
        audit_state=AuditState(0, 0, 0, None),
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(tenant_id), manifest)
    _write(root, StateRecordPath.tenant_observed(tenant_id), observed)
    for deployment in deployments:
        _write(
            root,
            StateRecordPath.tenant_deployment(tenant_id, deployment["id"]),
            deployment,
        )
    _write(root, StateRecordPath.authorization_job(_JOB_ID), job)
    repository = StateRepository(root, expected_owner=os.geteuid())
    if create_intent:
        repository.create_immutable(
            StateRecordPath.transaction_intent(plan.intent_id),
            plan.intent,
        )
    releases = {
        cast(str, deployment["id"]): cast(dict[str, object], deployment["releaseTreeDigest"])
        for deployment in deployments
    }
    if create_intent or operation == "rollback":
        releases[cast(str, plan.deployment["id"])] = cast(
            dict[str, object], plan.deployment["releaseTreeDigest"]
        )
    return repository, job, plan, _ReleaseStore(releases)


def _finalize(
    repository: StateRepository,
    release_store: _ReleaseStore,
    plan: DeploymentTransitionPlan,
    *,
    failure_hook: Callable[[DeploymentCommitBoundary], None] | None = None,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> DeploymentCommitOutcome:
    with repository.publication_transaction() as transaction:
        job = transaction.read(StateRecordPath.authorization_job(_JOB_ID))
        return finalize_deployment_transition_outcome(
            transaction,
            cast(DeploymentReleaseStore, release_store),
            job,
            plan,
            capacity_limits=capacity_limits,
            failure_hook=failure_hook,
        )


def _prepared_activation(
    repository: StateRepository,
    job_id: object,
    plan: DeploymentTransitionPlan,
    *,
    capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
) -> PreparedDeploymentTransition:
    return PreparedDeploymentTransition(
        repository.read(StateRecordPath.authorization_job(job_id)),
        plan,
        cast(CaddyGenerationManifest, _GenerationManifest(_CANDIDATE_GENERATION)),
        capacity_limits,
    )


def _activate(
    repository: StateRepository,
    runtime: _Runtime,
    releases: _ReleaseStore,
    prepared: PreparedDeploymentTransition,
    *,
    failure_hook: Callable[[DeploymentCommitBoundary], None] | None = None,
) -> dict[str, object]:
    return activate_deployment_transition(
        repository,
        cast(CaddyRuntime, runtime),
        cast(DeploymentReleaseStore, releases),
        cast(PublicationGate, _Gate()),
        prepared,
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
        commit_failure_hook=failure_hook,
    )


def _write_correlation(
    repository: StateRepository,
    job: dict[str, object],
) -> None:
    correlation = deepcopy(job)
    correlation["phase"] = "pending"
    repository.create_immutable(
        StateRecordPath.authorization_correlation(
            cast(dict[str, object], job["request"])["correlationId"]
        ),
        correlation,
    )


def _recovery_runtime(
    repository: StateRepository,
    job: dict[str, object],
    plan: DeploymentTransitionPlan,
) -> _Runtime:
    _write_correlation(repository, job)
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    source_observed = cast(dict[str, object], recovery["sourceObservedState"])
    source_spec = cast(dict[str, object], source_manifest["spec"])
    source_selected = source_spec.get("desiredDeployment")
    source_deployment = None
    if type(source_selected) is dict:
        source_deployment = repository.read(
            StateRecordPath.tenant_deployment(plan.tenant_id, source_selected["id"])
        ).document
    source_tenant = TenantRouteInput(
        source_manifest,
        source_observed,
        source_deployment,
    )
    candidate_tenant = TenantRouteInput(
        plan.manifest,
        plan.observed_state,
        plan.deployment,
    )
    with repository.publication_transaction() as transaction:
        source_snapshot = snapshot_tenant_routes(transaction)
        candidate_snapshot = snapshot_tenant_routes(
            transaction,
            overlay=TenantRouteOverlay(
                RouteOverlayMode.REPLACE,
                candidate_tenant,
                source_tenant,
            ),
        )
    runtime = _Runtime()
    runtime.snapshots = {
        _SOURCE_GENERATION: source_snapshot,
        _CANDIDATE_GENERATION: candidate_snapshot,
    }
    return runtime


@pytest.mark.parametrize(
    ("operation", "deployment_count", "state"),
    [
        ("deploy", 0, "undeployed"),
        ("import", 0, "undeployed"),
        ("deploy", 1, "active"),
        ("deploy", 1, "suspended"),
        ("rollback", 2, "active"),
        ("rollback", 2, "suspended"),
    ],
)
def test_deployment_commit_completes_and_replays_exact_state(
    tmp_path: Path,
    operation: str,
    deployment_count: int,
    state: str,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=deployment_count,
        state=state,
    )
    try:
        first = _finalize(repository, releases, plan)
        second = _finalize(repository, releases, plan)

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
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize("boundary", tuple(DeploymentCommitBoundary))
def test_fourth_deploy_replays_every_commit_boundary(
    tmp_path: Path,
    boundary: DeploymentCommitBoundary,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    injected = False

    def fail(selected: DeploymentCommitBoundary) -> None:
        nonlocal injected
        if selected is boundary and not injected:
            injected = True
            raise RuntimeError("injected deployment commit interruption")

    try:
        with pytest.raises(RuntimeError, match="injected"):
            _finalize(repository, releases, plan, failure_hook=fail)
        outcome = _finalize(repository, releases, plan)

        assert injected is True
        assert outcome.result == plan.result
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            retained = transaction.tenant_deployment_ids(plan.tenant_id)
        assert retained == (
            "0198d17f-6f4a-7000-8000-000000000002",
            "0198d17f-6f4a-7000-8000-000000000003",
            plan.deployment["id"],
        )
        assert "0198d17f-6f4a-7000-8000-000000000001" not in releases.releases
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize("boundary", tuple(DeploymentCommitBoundary))
def test_rollback_replays_cleanup_of_every_successor(
    tmp_path: Path,
    boundary: DeploymentCommitBoundary,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="rollback",
        deployment_count=3,
        state="active",
        rollback_index=0,
    )
    injected = False

    def fail(selected: DeploymentCommitBoundary) -> None:
        nonlocal injected
        if selected is boundary and not injected:
            injected = True
            raise RuntimeError("injected rollback commit interruption")

    try:
        with pytest.raises(RuntimeError, match="injected"):
            _finalize(repository, releases, plan, failure_hook=fail)
        outcome = _finalize(repository, releases, plan)

        assert injected is True
        assert outcome.result == plan.result
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            retained = transaction.tenant_deployment_ids(plan.tenant_id)
        assert retained == ("0198d17f-6f4a-7000-8000-000000000001",)
        assert set(releases.releases) == set(retained)
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_deployment_commit_rejects_plan_tampering_before_mutation(
    tmp_path: Path,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    tampered = deepcopy(plan)
    tampered.deployment["archiveSha256"] = "f" * 64
    try:
        job = repository.read(StateRecordPath.authorization_job(_JOB_ID))
        with pytest.raises(DeploymentCommitError, match="documents disagree"):
            validate_deployment_transition(job, tampered)
        assert repository.measure_intent_records().records
        assert not releases.removed
    finally:
        repository.close()


def test_deployment_commit_accepts_global_multi_tenant_dispatch_authority(
    tmp_path: Path,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
        include_other_tenant=True,
    )
    try:
        assert _finalize(repository, releases, plan).result == plan.result
    finally:
        repository.close()


def test_deployment_commit_rejects_capacity_before_release_or_state_mutation(
    tmp_path: Path,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    before_releases = deepcopy(releases.releases)
    try:
        with pytest.raises(CapacityRejectedError):
            _finalize(
                repository,
                releases,
                plan,
                capacity_limits=HostCapacityLimits(maximum_allocated_bytes=0),
            )

        assert releases.releases == before_releases
        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == source_manifest
        )
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_deployment_commit_admits_audit_before_release_or_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    before_releases = deepcopy(releases.releases)

    def reject_audit(_transaction: object, _document: object) -> None:
        raise AuditCapacityError("injected audit capacity rejection")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.repository._StateTransaction.admit_audit_append",
        reject_audit,
    )
    try:
        with pytest.raises(AuditCapacityError, match="injected audit capacity rejection"):
            _finalize(repository, releases, plan)

        assert releases.releases == before_releases
        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == source_manifest
        )
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_deployment_commit_refuses_state_outside_recovery_authority(
    tmp_path: Path,
) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    desired_path = StateRecordPath.tenant_desired(plan.tenant_id)
    try:
        current = repository.read(desired_path)
        drifted = current.document
        cast(dict[str, object], drifted["metadata"])["slug"] = "other-duck"
        repository.compare_and_swap(desired_path, current.revision, drifted)

        with pytest.raises(StateConflictError, match="outside recovery authority"):
            _finalize(repository, releases, plan)
        assert not releases.removed
    finally:
        repository.close()


def test_deployment_commit_refuses_selected_release_drift(tmp_path: Path) -> None:
    repository, _job_document, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    target = cast(str, plan.deployment["id"])
    releases.releases[target] = {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": "f" * 64,
    }
    try:
        with pytest.raises(StateConflictError, match="selected release disagrees"):
            _finalize(repository, releases, plan)
        assert not releases.removed
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_exact_deployment_removal_rejects_a_changed_record(tmp_path: Path) -> None:
    repository, _job_document, plan, _releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    oldest_path = StateRecordPath.tenant_deployment(
        plan.tenant_id,
        "0198d17f-6f4a-7000-8000-000000000001",
    )
    try:
        with repository.publication_transaction() as transaction:
            expected = transaction.read(oldest_path)
            token = transaction.deployment_removal_token(expected)
            changed = expected.document
            changed["archiveSha256"] = "f" * 64
            target = (tmp_path / "state").joinpath(*oldest_path.components)
            target.write_bytes(canonical_json_bytes(changed))
            with pytest.raises(StateConflictError, match="changed before exact removal"):
                transaction.remove_exact_deployment(expected, token)
    finally:
        repository.close()


def test_deployment_activation_selects_reloads_and_commits_terminal_state(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _Runtime()
    try:
        result = _activate(
            repository,
            runtime,
            releases,
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


def test_deployment_activation_restores_source_when_reload_fails(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _Runtime()
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def fail_reload(
        _source: PinnedCaddyGeneration,
        _candidate: PinnedCaddyGeneration,
    ) -> None:
        runtime.events.append("reload-failed")
        raise RuntimeError("injected deployment reload failure")

    try:
        with pytest.raises(RuntimeError, match="injected deployment reload failure"):
            activate_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
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
    finally:
        repository.close()


def test_deployment_activation_replays_an_interrupted_terminal_commit(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _Runtime()
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def interrupt(boundary: DeploymentCommitBoundary) -> None:
        if boundary is DeploymentCommitBoundary.JOB_SYNC:
            raise RuntimeError("interrupted deployment activation commit")

    try:
        with pytest.raises(RuntimeError, match="interrupted deployment activation commit"):
            _activate(repository, runtime, releases, prepared, failure_hook=interrupt)

        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert repository.measure_intent_records().records
        runtime.events.clear()
        assert _activate(repository, runtime, releases, prepared) == plan.result
        assert runtime.events[-2:] == [
            "read-active",
            f"verified:{_CANDIDATE_GENERATION}",
        ]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_deployment_activation_rejects_capacity_before_runtime_selection(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    runtime = _Runtime()
    prepared = _prepared_activation(
        repository,
        job["jobId"],
        plan,
        capacity_limits=HostCapacityLimits(maximum_allocated_bytes=0),
    )
    try:
        with pytest.raises(CapacityRejectedError):
            _activate(repository, runtime, releases, prepared)

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert not any(event.startswith("selected:") for event in runtime.events)
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_deployment_activation_rejects_selected_release_drift_before_selection(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    target = cast(str, plan.deployment["id"])
    releases.releases[target] = {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": "f" * 64,
    }
    runtime = _Runtime()
    try:
        with pytest.raises(DeploymentActivationError, match="selected release disagrees"):
            _activate(
                repository,
                runtime,
                releases,
                _prepared_activation(repository, job["jobId"], plan),
            )

        assert runtime.active == runtime.running == _SOURCE_GENERATION
        assert not any(event.startswith("selected:") for event in runtime.events)
        assert repository.measure_intent_records().records
    finally:
        repository.close()


def test_deployment_activation_rejects_runtime_outside_recovery_authority(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="rollback",
        deployment_count=2,
        state="active",
    )
    runtime = _Runtime()
    runtime.active = runtime.running = "0198d17f-6f4a-7000-8000-000000000099"
    try:
        with pytest.raises(DeploymentActivationError, match="outside deployment recovery"):
            _activate(
                repository,
                runtime,
                releases,
                _prepared_activation(repository, job["jobId"], plan),
            )

        assert repository.measure_intent_records().records
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("operation", "deployment_count"),
    [("deploy", 1), ("rollback", 2)],
)
def test_deployment_recovery_reconstructs_and_activates_durable_preparation(
    tmp_path: Path,
    operation: str,
    deployment_count: int,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=deployment_count,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    try:
        result = recover_deployment_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(DeploymentReleaseStore, releases),
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


def test_deployment_recovery_resumes_release_and_candidate_publication(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=0,
        state="undeployed",
    )
    runtime = _recovery_runtime(repository, job, plan)
    deployment_id = cast(str, plan.deployment["id"])
    releases.staged[deployment_id] = releases.releases.pop(deployment_id)
    runtime.snapshots.pop(_CANDIDATE_GENERATION)
    runtime.missing_generations.add(_CANDIDATE_GENERATION)
    try:
        result = recover_deployment_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(DeploymentReleaseStore, releases),
            cast(PublicationGate, _Gate()),
            plan.intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == plan.result
        assert releases.staged == {}
        assert releases.releases[deployment_id] == plan.deployment["releaseTreeDigest"]
        assert f"published:{_CANDIDATE_GENERATION}" in runtime.events
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_deployment_recovery_accepts_its_fourth_transition_record(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=3,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    repository.create_immutable(
        StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"]),
        plan.deployment,
    )
    try:
        result = recover_deployment_transition(
            repository,
            cast(CaddyRuntime, runtime),
            cast(DeploymentReleaseStore, releases),
            cast(PublicationGate, _Gate()),
            plan.intent_id,
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        assert result == plan.result
        with repository.publication_transaction() as transaction:
            assert transaction.tenant_deployment_ids(plan.tenant_id) == tuple(
                sorted(
                    [
                        "0198d17f-6f4a-7000-8000-000000000002",
                        "0198d17f-6f4a-7000-8000-000000000003",
                        cast(str, plan.deployment["id"]),
                    ]
                )
            )
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize(
    "interruption",
    [DeploymentCommitBoundary.DESIRED_STATE_SYNC, DeploymentCommitBoundary.AUDIT_SYNC],
)
def test_deployment_recovery_repairs_an_interrupted_terminal_commit(
    tmp_path: Path,
    interruption: DeploymentCommitBoundary,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def interrupt(boundary: DeploymentCommitBoundary) -> None:
        if boundary is interruption:
            raise RuntimeError("interrupted deployment terminal commit")

    try:
        with pytest.raises(RuntimeError, match="interrupted deployment terminal commit"):
            _activate(repository, runtime, releases, prepared, failure_hook=interrupt)

        assert (
            repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == plan.manifest
        )
        assert repository.measure_intent_records().records
        assert (
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
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


def test_deployment_recovery_accepts_a_retired_rollback_source_record(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="rollback",
        deployment_count=3,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    prepared = _prepared_activation(repository, job["jobId"], plan)
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    source_spec = cast(dict[str, object], source_manifest["spec"])
    source_selection = cast(dict[str, object], source_spec["desiredDeployment"])

    def interrupt(boundary: DeploymentCommitBoundary) -> None:
        if boundary is DeploymentCommitBoundary.RETIRED_DEPLOYMENT_REMOVED:
            raise RuntimeError("interrupted after rollback source retirement")

    try:
        with pytest.raises(RuntimeError, match="rollback source retirement"):
            _activate(repository, runtime, releases, prepared, failure_hook=interrupt)

        with pytest.raises(FileNotFoundError):
            repository.read(
                StateRecordPath.tenant_deployment(
                    plan.tenant_id,
                    source_selection["id"],
                )
            )
        assert (
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
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


def test_deployment_recovery_never_restores_a_retired_source_release(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="rollback",
        deployment_count=3,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def interrupt(boundary: DeploymentCommitBoundary) -> None:
        if boundary is DeploymentCommitBoundary.RETIRED_RELEASE_REMOVED:
            raise RuntimeError("interrupted after rollback release retirement")

    def reject_candidate(_generation: PinnedCaddyGeneration) -> None:
        raise RuntimeError("candidate verification failed")

    def reject_reload(
        _source: PinnedCaddyGeneration,
        _candidate: PinnedCaddyGeneration,
    ) -> None:
        raise RuntimeError("candidate reload failed")

    try:
        with pytest.raises(RuntimeError, match="rollback release retirement"):
            _activate(repository, runtime, releases, prepared, failure_hook=interrupt)

        runtime.events.clear()
        with pytest.raises(DeploymentActivationError, match="source release retirement"):
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=reject_reload,
                restorer=runtime.restore,
                verifier=reject_candidate,
            )
        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert "restored" not in runtime.events
        assert f"selected:{_SOURCE_GENERATION}" not in runtime.events
        assert repository.measure_intent_records().records

        assert (
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
            == plan.result
        )
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("operation", "deployment_count"),
    [("deploy", 1), ("rollback", 3)],
)
def test_deployment_recovery_rejects_a_source_release_missing_before_retirement(
    tmp_path: Path,
    operation: str,
    deployment_count: int,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=deployment_count,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    source_manifest = cast(dict[str, object], plan.intent["sourceManifest"])
    source_spec = cast(dict[str, object], source_manifest["spec"])
    source_selection = cast(dict[str, object], source_spec["desiredDeployment"])
    releases.releases.pop(cast(str, source_selection["id"]))
    try:
        with pytest.raises(
            DeploymentRecoveryError,
            match="source release disappeared before rollback retirement",
        ):
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
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


def test_deployment_recovery_rejects_archive_history_drift(tmp_path: Path) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    archive = _fixture("archive-record.json")
    archive["tenantId"] = plan.tenant_id
    archive["deploymentId"] = "0198d17f-6f4a-7000-8000-000000000090"
    repository.create_immutable(
        StateRecordPath.tenant_archive(plan.tenant_id, archive["deploymentId"]),
        archive,
    )
    try:
        with pytest.raises(DeploymentRecoveryError, match="archive history drifted"):
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
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


def test_deployment_recovery_rejects_job_source_authority_drift(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    path = StateRecordPath.authorization_job(job["jobId"])
    current = repository.read(path)
    drifted = current.document
    drifted["dispatchSourceRouteSet"] = "absent"
    repository.close()
    _write(tmp_path / "state", path, drifted)
    repository = StateRepository(tmp_path / "state", expected_owner=os.geteuid())
    try:
        with pytest.raises(DeploymentRecoveryError, match="durable job binding"):
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
    finally:
        repository.close()


def test_deployment_recovery_rejects_candidate_generation_snapshot_drift(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    snapshot = deepcopy(runtime.snapshots[_CANDIDATE_GENERATION])
    snapshot.platform_namespace["tenantBaseDomain"] = "other.invalid"
    runtime.snapshots[_CANDIDATE_GENERATION] = snapshot
    try:
        with pytest.raises(DeploymentRecoveryError, match="unrelated tenant authority"):
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
    finally:
        repository.close()


def test_deployment_recovery_rejects_selected_release_drift(
    tmp_path: Path,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation="deploy",
        deployment_count=1,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    releases.releases[cast(str, plan.deployment["id"])] = {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": "f" * 64,
    }
    try:
        with pytest.raises(DeploymentRecoveryError, match="release publication"):
            recover_deployment_transition(
                repository,
                cast(CaddyRuntime, runtime),
                cast(DeploymentReleaseStore, releases),
                cast(PublicationGate, _Gate()),
                plan.intent_id,
                reloader=runtime.reload,
                restorer=runtime.restore,
                verifier=runtime.verify,
            )
        assert runtime.active == runtime.running == _SOURCE_GENERATION
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("operation", "deployment_count"),
    [("deploy", 1), ("rollback", 2)],
)
def test_deployment_handler_completes_and_replays_a_fresh_claimed_job(
    tmp_path: Path,
    operation: str,
    deployment_count: int,
) -> None:
    repository, job, bootstrap_plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=deployment_count,
        state="active",
        create_intent=False,
    )
    runtime = _recovery_runtime(repository, job, bootstrap_plan)
    entropy = _Entropy()
    entropy._value = 50
    handler = DeploymentLifecycleHandler(
        repository,
        cast(CaddyRuntime, runtime),
        cast(ArtifactIntake, object()),
        cast(DeploymentReleaseStore, releases),
        cast(PublicationGate, _Gate()),
        now=lambda: _NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=entropy,
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
    )
    claim = (
        LifecycleArtifact(AdmittedArtifact("deploy.artifact", VerifiedArtifact(32, "e" * 64)))
        if operation in {"deploy", "import"}
        else None
    )
    try:
        first = handler.execute(cast(str, job["jobId"]), claim=claim, blocking=False)
        completed_events = tuple(runtime.events)
        second = handler.execute(cast(str, job["jobId"]), claim=claim, blocking=False)

        assert first.result == second.result
        assert first.created is True
        assert second.created is False
        assert first.result["status"] == "succeeded"
        assert runtime.active == runtime.running
        assert runtime.active != _SOURCE_GENERATION
        assert runtime.events == list(completed_events)
        assert releases.reconciled is True
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("operation", "deployment_count"),
    [("deploy", 1), ("rollback", 2)],
)
def test_deployment_handler_recovers_and_replays_a_durable_intent(
    tmp_path: Path,
    operation: str,
    deployment_count: int,
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=deployment_count,
        state="active",
    )
    runtime = _recovery_runtime(repository, job, plan)
    handler = DeploymentLifecycleHandler(
        repository,
        cast(CaddyRuntime, runtime),
        cast(ArtifactIntake, object()),
        cast(DeploymentReleaseStore, releases),
        cast(PublicationGate, _Gate()),
        reloader=runtime.reload,
        restorer=runtime.restore,
        verifier=runtime.verify,
    )
    try:
        first = handler.execute(cast(str, job["jobId"]), claim=None, blocking=False)
        completed_events = tuple(runtime.events)
        second = handler.execute(cast(str, job["jobId"]), claim=None, blocking=False)

        assert first.result == second.result == plan.result
        assert first.created is True
        assert second.created is False
        assert runtime.active == runtime.running == _CANDIDATE_GENERATION
        assert runtime.events == list(completed_events)
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("operation", "deployment_count", "claim"),
    [
        ("deploy", 1, None),
        (
            "rollback",
            2,
            LifecycleArtifact(
                AdmittedArtifact("unexpected.artifact", VerifiedArtifact(32, "e" * 64))
            ),
        ),
    ],
)
def test_deployment_handler_rejects_fresh_artifact_presence_mismatch(
    tmp_path: Path,
    operation: str,
    deployment_count: int,
    claim: LifecycleArtifact | None,
) -> None:
    repository, job, bootstrap_plan, releases = _prepared(
        tmp_path,
        operation=operation,
        deployment_count=deployment_count,
        state="active",
        create_intent=False,
    )
    runtime = _recovery_runtime(repository, job, bootstrap_plan)
    handler = DeploymentLifecycleHandler(
        repository,
        cast(CaddyRuntime, runtime),
        cast(ArtifactIntake, object()),
        cast(DeploymentReleaseStore, releases),
        cast(PublicationGate, _Gate()),
    )
    try:
        with pytest.raises(LifecycleJobRejectionError) as failure:
            handler.execute(cast(str, job["jobId"]), claim=claim, blocking=False)

        assert failure.value.error_code == "invalid_artifact"
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize(
    "interruption",
    [boundary for boundary in DeploymentCommitBoundary if not boundary.name.startswith("RETIRED_")],
)
def test_import_recovers_every_terminal_boundary_without_borrowing_source_state(
    tmp_path: Path, interruption: DeploymentCommitBoundary
) -> None:
    repository, job, plan, releases = _prepared(
        tmp_path, operation="import", deployment_count=0, state="undeployed"
    )
    runtime = _recovery_runtime(repository, job, plan)
    prepared = _prepared_activation(repository, job["jobId"], plan)

    def interrupt(boundary: DeploymentCommitBoundary) -> None:
        if boundary is interruption:
            raise RuntimeError("interrupted import terminal commit")

    try:
        with pytest.raises(RuntimeError, match="interrupted import terminal commit"):
            _activate(repository, runtime, releases, prepared, failure_hook=interrupt)
        handler = DeploymentLifecycleHandler(
            repository,
            cast(CaddyRuntime, runtime),
            cast(ArtifactIntake, object()),
            cast(DeploymentReleaseStore, releases),
            _Gate(),
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )
        first = handler.execute(str(job["jobId"]), claim=None, blocking=False)
        second = handler.execute(str(job["jobId"]), claim=None, blocking=False)
        assert first.result == second.result == plan.result
        source = cast(dict[str, object], job["sourceAuthority"])["manifest"]
        assert isinstance(source, dict)
        expected = deepcopy(source)
        expected_spec = cast(dict[str, object], expected["spec"])
        expected_spec["desiredState"] = "active"
        expected_spec["desiredDeployment"] = cast(dict[str, object], plan.manifest["spec"])[
            "desiredDeployment"
        ]
        assert plan.manifest == expected
        imported = job["dispatchImportManifest"]
        assert isinstance(imported, dict)
        provenance = plan.deployment["importProvenance"]
        assert provenance == {
            "manifest": imported,
            "manifestDigest": manifest_digest(imported).to_dict(),
        }
        assert cast(dict[str, object], imported["spec"])["desiredState"] == "suspended"
        assert (
            plan.deployment["id"]
            != cast(
                dict[str, object], cast(dict[str, object], imported["spec"])["desiredDeployment"]
            )["id"]
        )
        assert (
            repository.read(
                StateRecordPath.tenant_deployment(plan.tenant_id, plan.deployment["id"])
            ).document
            == plan.deployment
        )
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


@pytest.mark.parametrize("source_state", ["active", "suspended", "archived"])
@pytest.mark.parametrize("interrupt_preparation", [False, True])
def test_import_executor_publishes_only_content_and_preserves_target_policy(  # noqa: PLR0915
    tmp_path: Path,
    source_state: str,
    interrupt_preparation: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for module in ("intake", "portable_bundle", "zip_structure"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.measure_filesystem_capacity_descriptor",
            lambda descriptor: FilesystemCapacity(
                os.fstat(descriptor).st_dev, 4096, 10_000_000, 9_000_000, 1_000_000, 900_000
            ),
        )
    root = _state_root(tmp_path)
    for path in (root / "intake", root / "exports", root / "tenants" / _tenant_id()):
        _mkdir(path)
    for name in ("deployments", "archives"):
        _mkdir(root / "tenants" / _tenant_id() / name)
    target, observed, _selected = _source([], state="undeployed")
    cast(dict[str, object], target["spec"])["quotas"] = {"storageMiB": 1, "entries": 2}
    observed["desiredManifestDigest"] = manifest_digest(target).to_dict()
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(_tenant_id()), target)
    _write(root, StateRecordPath.tenant_observed(_tenant_id()), observed)
    releases = tmp_path / "releases"
    staging = releases / ".staging"
    _mkdir(releases)
    releases.chmod(0o710)
    _mkdir(staging)
    source_content = tmp_path / "source-content"
    _mkdir(source_content)
    source_content.chmod(0o755)
    (source_content / "index.html").write_bytes(b"portable import content\n")
    (source_content / "index.html").chmod(0o644)
    (source_content / "empty").mkdir(mode=0o755)
    source_manifest = _fixture("site.json")
    metadata = cast(dict[str, object], source_manifest["metadata"])
    source_id = "0198d17f-6f4a-7000-8000-000000000099"
    metadata.update(
        id=source_id,
        slug="source-only",
        canonicalOrigin=f"t-{source_id.replace('-', '')}.lowerduckpond.com",
    )
    cast(dict[str, object], source_manifest["spec"])["desiredState"] = source_state
    output = tmp_path / "output"
    _mkdir(output)
    with (
        LockManager(root / "locks", expected_owner=os.geteuid()) as locks,
        locks.acquire(LockName.EXPORT),
    ):
        bundle = build_portable_bundle(
            source_content,
            source_manifest,
            output_parent=output,
            output_name="portable.zip",
            lock_manager=locks,
            expected_owner=os.geteuid(),
        )
    content = (output / "portable.zip").read_bytes()
    artifact = VerifiedArtifact(len(content), bundle.bundle_digest.value)
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "import",
        "tenantId": _tenant_id(),
        "correlationId": _CORRELATION_ID,
        "artifact": {"size": artifact.size, "sha256": artifact.sha256},
    }
    with (
        StateRepository(
            root, expected_owner=os.geteuid(), tenant_release_root=releases
        ) as repository,
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            releases,
            staging,
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store,
    ):
        with intake.admit(
            operation="import",
            correlation_id=_CORRELATION_ID,
            declared=artifact,
            read=io.BytesIO(content).read,
        ) as lease:
            issued = AuthorizationIssuer(repository, gate=_Gate(), entropy=_Entropy()).issue(
                canonical_json_bytes(request),
                operator_principal="operator@example.test",
                now=_NOW,
                artifact=artifact,
            )
            lease.commit()
        runtime = _Runtime()
        with repository.publication_transaction() as transaction:
            runtime.snapshots[_SOURCE_GENERATION] = snapshot_tenant_routes(transaction)
        handler = DeploymentLifecycleHandler(
            repository,
            cast(CaddyRuntime, runtime),
            intake,
            store,
            _Gate(),
            now=lambda: _NOW,
            clock=lambda: 1_777_000_000_000,
            entropy=_Entropy(),
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )
        executor = AuthorizationExecutor(
            repository,
            intake,
            handlers={"import": handler},
            tenant_runtime_validator=lambda *_args: True,
        )
        if interrupt_preparation:
            original = deployment_prepare_module._admit_and_create_intent

            def kill_after_intent(*args: object, **kwargs: object) -> None:
                original(*args, **kwargs)  # type: ignore[arg-type]
                os._exit(_INTERRUPTED_STATUS)

            with monkeypatch.context() as interrupted:
                interrupted.setattr(
                    deployment_prepare_module, "_admit_and_create_intent", kill_after_intent
                )
                child = get_context("fork").Process(target=executor.execute, args=(issued.job_id,))
                child.start()
                child.join(10)
                assert child.exitcode == _INTERRUPTED_STATUS
            intents = repository.measure_intent_records().records
            assert intents
            intent = repository.read(StateRecordPath.transaction_intent(intents[0].intent_id))
            recovery = cast(dict[str, object], intent.document["lifecycleRecovery"])
            runtime.missing_generations.add(str(recovery["candidateRuntimeGenerationId"]))
            assert repository.read(StateRecordPath.tenant_desired(_tenant_id())).document == target
        first = executor.execute(issued.job_id)
        assert first.result["status"] == "succeeded"
        assert executor.execute(issued.job_id).result == first.result
        manifest = cast(dict[str, object], first.result["manifest"])
        expected = deepcopy(target)
        expected_spec = cast(dict[str, object], expected["spec"])
        selected = cast(
            dict[str, object], cast(dict[str, object], manifest["spec"])["desiredDeployment"]
        )
        expected_spec.update(desiredState="active", desiredDeployment=selected)
        assert manifest == expected
        assert (
            selected["id"]
            != cast(
                dict[str, object],
                cast(dict[str, object], source_manifest["spec"])["desiredDeployment"],
            )["id"]
        )
        deployed = repository.read(
            StateRecordPath.tenant_deployment(_tenant_id(), selected["id"])
        ).document
        assert deployed["importProvenance"] == {
            "manifest": source_manifest,
            "manifestDigest": manifest_digest(source_manifest).to_dict(),
        }
        release_path = releases / _tenant_id() / "releases" / str(selected["id"])
        assert sorted(path.name for path in release_path.iterdir()) == ["empty", "index.html"]
        assert (release_path / "index.html").read_bytes() == b"portable import content\n"
        assert (release_path / "empty").is_dir()
        assert list((root / "intake").iterdir()) == []
        assert repository.measure_intent_records().records == ()
        assert (
            repository.read(StateRecordPath.authorization_job(issued.job_id)).document[
                "executionValidated"
            ]
            is True
        )
