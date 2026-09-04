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
    archive_record_digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    request_digest,
)
from lowerduckpond_static_host_agent import (
    CaddyGenerationManifest,
    CaddyRuntime,
    CapacityRejectedError,
    FilesystemCapacity,
    HostCapacityLimits,
    LockManager,
    LockMode,
    PreparedRouteTransition,
    RouteAuthorityDriftError,
    RoutePreparationError,
    StateRecordPath,
    StateRepository,
    StoredContract,
    TenantRouteInput,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    prepare_route_transition,
    snapshot_tenant_routes,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000004"
_LATEST_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000005"
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
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
    def close(self) -> None:
        return


@dataclass(frozen=True)
class _Selected:
    generation_id: str
    generation: _Pinned


@dataclass(frozen=True)
class _Candidate:
    generation_id: str


class _Runtime:
    def __init__(
        self,
        active_generation_id: str = _SOURCE_GENERATION,
        *,
        source_route_set: str | None = None,
    ) -> None:
        self.events: list[str] = []
        self.overlay: TenantRouteOverlay | None = None
        self.candidate: _Candidate | None = None
        self.active_generation_id = active_generation_id
        self.source_snapshot: TenantRouteSnapshot | None = None
        if source_route_set is not None:
            source_state = "active" if source_route_set == "both" else "suspended"
            self.source_snapshot = TenantRouteSnapshot(
                _fixture("platform-namespace.json"),
                (
                    TenantRouteInput(
                        {
                            "metadata": {"id": _TENANT_ID},
                            "spec": {"desiredState": source_state},
                        },
                        {},
                        None,
                    ),
                ),
            )

    @contextmanager
    def using_held_publication_lock(self, _repository: StateRepository) -> Iterator[None]:
        self.events.append("locked")
        yield

    def open_active_verified(self) -> _Selected:
        self.events.append("active")
        return _Selected(self.active_generation_id, _Pinned())

    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        assert generation_id == self.active_generation_id
        assert self.source_snapshot is not None
        return self.source_snapshot

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


def _route_source(
    state: str,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object] | None,
    dict[str, object] | None,
]:
    manifest = _fixture("site.json")
    spec = manifest["spec"]
    metadata = manifest["metadata"]
    assert type(spec) is dict
    assert type(metadata) is dict
    spec["desiredState"] = state
    deployment: dict[str, object] | None = _fixture("deployment-record.json")
    archive: dict[str, object] | None = None
    if state == "undeployed":
        spec.pop("desiredDeployment")
        deployment = None
        active_deployment_id = None
    else:
        reference = spec["desiredDeployment"]
        assert type(reference) is dict
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


def _route_job(  # noqa: PLR0913 - fixture authority tuple
    operation: str,
    namespace: dict[str, object],
    manifest: dict[str, object],
    deployment: dict[str, object] | None,
    archive: dict[str, object] | None,
    *,
    slug: str | None = None,
) -> dict[str, object]:
    metadata = manifest["metadata"]
    spec = manifest["spec"]
    assert type(metadata) is dict
    assert type(spec) is dict
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
        "compatibilityVersion": "static-job-v1",
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
            "archiveRecordDigest": (archive_record_digest(archive).to_dict() if archive else None),
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        },
        "acceptedAt": "2026-09-02T12:00:01Z",
        "phase": "claimed",
    }


def _prepared_repository(
    root: Path,
    operation: str,
    state: str,
    *,
    slug: str | None = None,
) -> tuple[StateRepository, dict[str, object]]:
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _route_source(state)
    job = _route_job(operation, namespace, manifest, deployment, archive, slug=slug)
    metadata = manifest["metadata"]
    assert type(metadata) is dict
    tenant_id = cast(str, metadata["id"])
    tenant_root = root / "tenants" / tenant_id
    _mkdir(tenant_root)
    _mkdir(tenant_root / "deployments")
    _mkdir(tenant_root / "archives")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    _write(root, StateRecordPath.tenant_desired(tenant_id), manifest)
    _write(root, StateRecordPath.tenant_observed(tenant_id), observed)
    if deployment is not None:
        _write(
            root,
            StateRecordPath.tenant_deployment(tenant_id, deployment["id"]),
            deployment,
        )
    if archive is not None:
        _write(
            root,
            StateRecordPath.tenant_archive(tenant_id, archive["deploymentId"]),
            archive,
        )
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    return StateRepository(root, expected_owner=os.geteuid()), job


def _prepare(
    repository: StateRepository,
    runtime: _Runtime,
    job: dict[str, object],
    *,
    limits: HostCapacityLimits | None = None,
    gate: _Gate | None = None,
) -> PreparedRouteTransition:
    if runtime.source_snapshot is None:
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            runtime.source_snapshot = snapshot_tenant_routes(transaction)
    return prepare_route_transition(
        repository,
        cast(CaddyRuntime, runtime),
        _Gate() if gate is None else gate,
        job["jobId"],
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
        capacity_limits=HostCapacityLimits() if limits is None else limits,
    )


@pytest.mark.parametrize(
    ("operation", "state", "slug"),
    [
        ("suspend", "active", None),
        ("rename", "undeployed", "renamed-duck"),
        ("reconcile", "archived", None),
    ],
)
def test_route_preparation_publishes_then_binds_one_exact_intent(
    tmp_path: Path,
    operation: str,
    state: str,
    slug: str | None,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, operation, state, slug=slug)
    runtime = _Runtime(
        source_route_set=("both" if state == "active" else "absent")
        if operation == "reconcile"
        else None
    )
    try:
        prepared = _prepare(repository, runtime, job)

        assert runtime.events == ["locked", "active", "pruned", "published"]
        assert runtime.overlay is not None
        assert runtime.overlay.tenant.manifest == prepared.plan.manifest
        assert runtime.overlay.source is not None
        assert runtime.overlay.source.manifest != prepared.plan.manifest or operation == "reconcile"
        assert (
            repository.read(StateRecordPath.transaction_intent(prepared.plan.intent_id)).document
            == prepared.plan.intent
        )
    finally:
        repository.close()


def test_route_preparation_separates_target_and_complete_source_generations(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    request = job["request"]
    assert type(request) is dict
    tenant_id = cast(str, request["tenantId"])
    observed_path = StateRecordPath.tenant_observed(tenant_id)
    observed = repository.read(observed_path).document
    observed["runtimeGenerationId"] = _SOURCE_GENERATION
    _write(root, observed_path, observed)
    runtime = _Runtime(_LATEST_SOURCE_GENERATION)
    try:
        prepared = _prepare(repository, runtime, job)

        recovery = prepared.plan.intent["lifecycleRecovery"]
        assert type(recovery) is dict
        source_observed = recovery["sourceObservedState"]
        assert type(source_observed) is dict
        assert recovery["sourceRuntimeGenerationId"] == _LATEST_SOURCE_GENERATION
        assert source_observed["runtimeGenerationId"] == _SOURCE_GENERATION
    finally:
        repository.close()


def test_route_preparation_reconciles_drift_from_desired_authority(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "reconcile", "active")
    request = job["request"]
    assert type(request) is dict
    observed_path = StateRecordPath.tenant_observed(request["tenantId"])
    drifted = repository.read(observed_path).document
    drifted["desiredManifestDigest"] = {
        "format": "lowerduckpond-manifest-v1",
        "algorithm": "sha256",
        "value": "f" * 64,
    }
    drifted["observedState"] = "suspended"
    drifted["runtimeGenerationId"] = None
    _write(root, observed_path, drifted)
    runtime = _Runtime(source_route_set="absent")
    try:
        prepared = _prepare(repository, runtime, job)

        recovery = prepared.plan.intent["lifecycleRecovery"]
        assert type(recovery) is dict
        assert recovery["sourceObservedState"] == drifted
        assert recovery["sourceRouteSet"] == "absent"
        assert (
            prepared.plan.observed_state["desiredManifestDigest"]
            == manifest_digest(prepared.plan.manifest).to_dict()
        )
        assert prepared.plan.observed_state["observedState"] == "active"
        assert (
            prepared.plan.observed_state["runtimeGenerationId"]
            == recovery["candidateRuntimeGenerationId"]
        )
    finally:
        repository.close()


def test_route_preparation_rejects_non_target_reconcile_snapshot_drift(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "reconcile", "active")
    runtime = _Runtime(source_route_set="both")
    assert runtime.source_snapshot is not None
    runtime.source_snapshot = TenantRouteSnapshot({}, runtime.source_snapshot.tenants)
    try:
        with pytest.raises(
            RouteAuthorityDriftError,
            match="selected runtime generation disagrees",
        ):
            _prepare(repository, runtime, job)
    finally:
        repository.close()


def test_route_preparation_rejects_archive_retained_by_live_source(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    manifest, _observed, deployment, _archive = _route_source("active")
    assert deployment is not None
    archive = _fixture("archive-record.json")
    archive["manifestDigest"] = manifest_digest(manifest).to_dict()
    _write(
        root,
        StateRecordPath.tenant_archive(_TENANT_ID, deployment["id"]),
        archive,
    )
    try:
        with pytest.raises(
            RouteAuthorityDriftError,
            match="live route source retained an archive record",
        ):
            _prepare(repository, _Runtime(source_route_set="both"), job)
    finally:
        repository.close()


def test_route_preparation_checks_gate_before_generation_cleanup(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    runtime = _Runtime()
    try:
        with pytest.raises(RuntimeError, match="publication_disabled"):
            _prepare(repository, runtime, job, gate=_Gate(enabled=False))

        assert runtime.events == ["locked"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_preparation_rejects_authority_drift_before_publication(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected["lifecycle"] = "suspended"
    _write(root, StateRecordPath.authorization_job(job["jobId"]), job)
    runtime = _Runtime()
    try:
        with pytest.raises(RouteAuthorityDriftError, match="source state drifted"):
            _prepare(repository, runtime, job)

        assert runtime.events == ["locked"]
    finally:
        repository.close()


def test_route_preparation_rejects_stale_selected_snapshot_before_publication(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    runtime = _Runtime(source_route_set="both")
    try:
        with pytest.raises(RouteAuthorityDriftError, match="selected runtime generation"):
            _prepare(repository, runtime, job)

        assert runtime.events == ["locked", "active"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_preparation_rejects_undeployed_source_with_deployment_history(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "rename", "undeployed", slug="renamed-duck")
    request = job["request"]
    assert type(request) is dict
    deployment = _fixture("deployment-record.json")
    deployment["tenantId"] = request["tenantId"]
    _write(
        root,
        StateRecordPath.tenant_deployment(request["tenantId"], deployment["id"]),
        deployment,
    )
    runtime = _Runtime(source_route_set="absent")
    try:
        with pytest.raises(RouteAuthorityDriftError, match="retains deployment history"):
            _prepare(repository, runtime, job)

        assert runtime.events == ["locked"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_preparation_classifies_disappeared_source_as_authority_drift(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    request = job["request"]
    assert type(request) is dict
    tenant_id = cast(str, request["tenantId"])
    root.joinpath(*StateRecordPath.tenant_desired(tenant_id).components).unlink()
    runtime = _Runtime(source_route_set="both")
    try:
        with pytest.raises(RouteAuthorityDriftError, match="disappeared"):
            _prepare(repository, runtime, job)

        assert runtime.events == ["locked"]
    finally:
        repository.close()


def test_route_preparation_discards_candidate_when_intent_admission_fails(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
    runtime = _Runtime()
    limits = HostCapacityLimits(minimum_available_bytes=100 * 1024 * 1024 * 1024)
    try:
        with pytest.raises(CapacityRejectedError):
            _prepare(repository, runtime, job, limits=limits)

        assert runtime.events[-2:] == ["published", "discarded"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_route_preparation_retains_candidate_on_ambiguous_intent_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)
    repository, job = _prepared_repository(root, "suspend", "active")
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
        with pytest.raises(RoutePreparationError, match="ambiguous durable completion"):
            _prepare(repository, runtime, job)

        assert "discarded" not in runtime.events
        assert len(repository.measure_intent_records().records) == 1
    finally:
        repository.close()
