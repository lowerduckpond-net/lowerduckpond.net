from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import lowerduckpond_static_host_agent.repository as repository_module
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
    CaddyGenerationManifest,
    CaddyRuntime,
    CapacityRejectedError,
    DeploymentAuthorityDriftError,
    DeploymentPreparationError,
    DeploymentReleaseStore,
    FilesystemCapacity,
    InodeAllocation,
    LockManager,
    LockMode,
    PreparedDeploymentTransition,
    PublicationGate,
    ReleaseTreeMeasurement,
    StateRecordPath,
    StateRepository,
    TenantRouteInput,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    VerifiedArtifact,
    prepare_deployment_transition,
)
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    ReleaseCapacityUsage,
)
from lowerduckpond_static_host_agent.release_store import (
    PublishedDeploymentRelease,
    PublishedReleaseInventory,
    StagedDeploymentRelease,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_NOW = datetime(2026, 9, 5, 12, 30, tzinfo=UTC)
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000020"
_JOB_ID = "0198d17f-6f4a-7000-8000-000000000022"
_CORRELATION_ID = "0198d17f-6f4a-7000-8000-000000000023"
_OTHER_TENANT_ID = "0198d17f-6f4a-7000-8000-000000000099"


class _Entropy:
    def __init__(self) -> None:
        self._value = 30

    def __call__(self, length: int) -> bytes:
        self._value += 1
        return self._value.to_bytes(length, byteorder="big")


class _Gate:
    def require_enabled(self) -> None:
        return


class _Pinned:
    def close(self) -> None:
        return


@dataclass(frozen=True, slots=True)
class _Selected:
    generation_id: str
    generation: _Pinned


@dataclass(frozen=True, slots=True)
class _Candidate:
    generation_id: str


class _Runtime:
    def __init__(self, source_snapshot: TenantRouteSnapshot) -> None:
        self.source_snapshot = source_snapshot
        self.overlay: TenantRouteOverlay | None = None
        self.events: list[str] = []
        self.fail_publish = False

    @contextmanager
    def using_held_publication_lock(self, _repository: StateRepository) -> Iterator[None]:
        self.events.append("locked")
        yield

    def open_active_verified(self) -> _Selected:
        self.events.append("active")
        return _Selected(_SOURCE_GENERATION, _Pinned())

    def read_generation_route_snapshot(self, generation_id: str) -> TenantRouteSnapshot:
        assert generation_id == _SOURCE_GENERATION
        return deepcopy(self.source_snapshot)

    def prune_unreferenced_generations(
        self,
        protected: tuple[()],
        *,
        keep_newest_unprotected: int,
    ) -> tuple[str, ...]:
        assert protected == ()
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
        del gate
        inventory = transaction.measure_intent_records()  # type: ignore[attr-defined]
        assert len(inventory.records) == 1
        self.events.append("candidate")
        self.overlay = deepcopy(overlay)
        if self.fail_publish:
            raise RuntimeError("injected candidate publication failure")
        return cast(CaddyGenerationManifest, _Candidate(generation_id))


class _ReleaseStore:
    def __init__(
        self,
        releases: dict[tuple[str, str], ReleaseTreeMeasurement],
    ) -> None:
        self.releases = dict(releases)
        self.events: list[str] = []
        self.discarded = False

    def reconcile_staging(
        self,
        protected: dict[str, dict[str, object]],
        *,
        publication_lock: object,
    ) -> int:
        assert protected == {}
        assert publication_lock.measure_intent_records().records == ()  # type: ignore[attr-defined]
        self.events.append("reconciled")
        return 1

    def measure(
        self,
        tenant_id: object,
        deployment_id: object,
        *,
        publication_lock: object,
    ) -> ReleaseTreeMeasurement:
        del publication_lock
        return self.releases[(cast(str, tenant_id), cast(str, deployment_id))]

    def published_inventory(
        self,
        *,
        publication_lock: object,
    ) -> PublishedReleaseInventory:
        del publication_lock
        inventory: dict[str, list[str]] = {}
        for tenant_id, deployment_id in self.releases:
            inventory.setdefault(tenant_id, []).append(deployment_id)
        tenant_releases = tuple(
            (tenant_id, tuple(sorted(deployment_ids)))
            for tenant_id, deployment_ids in sorted(inventory.items())
        )
        namespace_allocations = tuple(
            InodeAllocation(1, 1_000 + index, 4_096) for index in range(len(tenant_releases) * 2)
        )
        return PublishedReleaseInventory(
            tenant_releases,
            ReleaseCapacityUsage(namespace_allocations),
        )

    def stage(  # noqa: PLR0913 - mirrors the release-store boundary
        self,
        intake: object,
        artifact: AdmittedArtifact,
        *,
        tenant_id: object,
        deployment_id: object,
        expected_release_tree_digest: dict[str, object],
        retained_usage: ReleaseCapacityUsage,
        publication_lock: object,
        capacity_limits: object,
    ) -> StagedDeploymentRelease:
        del intake, capacity_limits
        assert artifact.verified.sha256 == "e" * 64
        assert publication_lock.measure_intent_records().records == ()  # type: ignore[attr-defined]
        release_inodes = len(
            {
                (item.device, item.inode)
                for value in self.releases.values()
                for item in value.allocations
            }
        )
        tenant_count = len({tenant_id for tenant_id, _deployment_id in self.releases})
        assert retained_usage.unique_inodes == release_inodes + tenant_count * 2
        self.events.append("staged")
        measurement = _measurement(expected_release_tree_digest, inode=900)
        return StagedDeploymentRelease(
            cast(str, tenant_id),
            cast(str, deployment_id),
            f"{tenant_id}--{deployment_id}",
            measurement,
        )

    def publish(
        self,
        staged: StagedDeploymentRelease,
        *,
        publication_lock: object,
    ) -> PublishedDeploymentRelease:
        assert len(publication_lock.measure_intent_records().records) == 1  # type: ignore[attr-defined]
        self.events.append("published")
        self.releases[(staged.tenant_id, staged.deployment_id)] = staged.measurement
        return PublishedDeploymentRelease(staged.measurement, True)

    def discard_staged(
        self,
        staged: StagedDeploymentRelease,
        *,
        publication_lock: object,
    ) -> None:
        del staged, publication_lock
        self.events.append("discarded")
        self.discarded = True


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
    return cast(str, cast(dict[str, object], manifest["metadata"])["id"])


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
    record["releaseTreeDigest"] = _digest(value)
    record["correlationId"] = _CORRELATION_ID
    return record


def _digest(value: str) -> dict[str, object]:
    return {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": value,
    }


def _measurement(value: dict[str, object], *, inode: int) -> ReleaseTreeMeasurement:
    return ReleaseTreeMeasurement(
        Digest(
            cast(str, value["format"]),
            cast(str, value["algorithm"]),
            cast(str, value["value"]),
        ),
        1,
        1,
        (InodeAllocation(1, inode, 4096),),
    )


def _source(
    deployments: list[dict[str, object]],
    *,
    state: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object] | None]:
    manifest = _fixture("site.json")
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    spec["desiredState"] = state
    selected = deployments[-1] if deployments else None
    if selected is None:
        spec.pop("desiredDeployment", None)
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
        "activeDeploymentId": None if selected is None else selected["id"],
        "runtimeGenerationId": _SOURCE_GENERATION if state == "active" else None,
        "reconciledAt": "2026-09-05T12:00:00Z",
    }
    return manifest, observed, selected


def _job(
    operation: str,
    namespace: dict[str, object],
    manifest: dict[str, object],
    deployments: list[dict[str, object]],
    *,
    rollback: dict[str, object] | None,
) -> dict[str, object]:
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    selected = deployments[-1] if deployments else None
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": _CORRELATION_ID,
        "tenantId": metadata["id"],
    }
    release_digest = None
    if operation == "deploy":
        request["artifact"] = {"size": 32, "sha256": "e" * 64}
        release_digest = _digest("e" * 64)
    else:
        assert rollback is not None
        request["deploymentId"] = rollback["id"]
    history = [cast(str, deployment["id"]) for deployment in deployments]
    return {
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
                None if selected is None else deployment_record_digest(selected).to_dict()
            ),
            "archiveRecordDigest": None,
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        },
        "sourceAuthority": {"manifest": manifest, "archiveRecord": None},
        "dispatchArchiveDeploymentIds": [],
        "dispatchArtifactReleaseTreeDigest": release_digest,
        "dispatchSourceReleaseTreeDigest": (
            None if selected is None else selected["releaseTreeDigest"]
        ),
        "dispatchDeploymentIds": history,
        "dispatchTenantIds": [metadata["id"]],
        "dispatchTenantRecordHistories": [[metadata["id"], [], history]],
        "acceptedAt": "2026-09-05T12:00:01Z",
        "phase": "claimed",
        "executionValidated": False,
    }


def _prepared_state(  # noqa: PLR0915 - fixture constructs complete host authority
    tmp_path: Path,
    *,
    operation: str = "deploy",
    state: str = "active",
    include_other_tenant: bool = False,
) -> tuple[
    StateRepository,
    _Runtime,
    _ReleaseStore,
    AdmittedArtifact | None,
    list[dict[str, object]],
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
        for index in range(1, 3 if operation == "rollback" else 2)
    ]
    manifest, observed, selected = _source(deployments, state=state)
    namespace = _fixture("platform-namespace.json")
    rollback = deployments[0] if operation == "rollback" else None
    job = _job(operation, namespace, manifest, deployments, rollback=rollback)
    other_route: TenantRouteInput | None = None
    other_deployment: dict[str, object] | None = None
    if include_other_tenant:
        other_deployment = _deployment(
            "0198d17f-6f4a-7000-8000-000000000098",
            value="a" * 64,
        )
        other_deployment["tenantId"] = _OTHER_TENANT_ID
        other_manifest = deepcopy(manifest)
        other_metadata = cast(dict[str, object], other_manifest["metadata"])
        other_metadata["id"] = _OTHER_TENANT_ID
        other_metadata["slug"] = "other-tenant"
        other_metadata["canonicalOrigin"] = "t-0198d17f6f4a70008000000000000099.lowerduckpond.com"
        other_spec = cast(dict[str, object], other_manifest["spec"])
        other_spec["desiredDeployment"] = {
            "id": other_deployment["id"],
            "archiveSha256": other_deployment["archiveSha256"],
        }
        other_observed = deepcopy(observed)
        other_observed["tenantId"] = _OTHER_TENANT_ID
        other_observed["desiredManifestDigest"] = manifest_digest(other_manifest).to_dict()
        other_observed["activeDeploymentId"] = other_deployment["id"]
        other_root = root / "tenants" / _OTHER_TENANT_ID
        _mkdir(other_root)
        _mkdir(other_root / "deployments")
        _mkdir(other_root / "archives")
        _write(root, StateRecordPath.tenant_desired(_OTHER_TENANT_ID), other_manifest)
        _write(root, StateRecordPath.tenant_observed(_OTHER_TENANT_ID), other_observed)
        _write(
            root,
            StateRecordPath.tenant_deployment(
                _OTHER_TENANT_ID,
                other_deployment["id"],
            ),
            other_deployment,
        )
        tenant_ids = sorted([tenant_id, _OTHER_TENANT_ID])
        histories = {
            tenant_id: [tenant_id, [], job["dispatchDeploymentIds"]],
            _OTHER_TENANT_ID: [
                _OTHER_TENANT_ID,
                [],
                [other_deployment["id"]],
            ],
        }
        job["dispatchTenantIds"] = tenant_ids
        job["dispatchTenantRecordHistories"] = [histories[value] for value in tenant_ids]
        other_route = TenantRouteInput(other_manifest, other_observed, other_deployment)
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
    routes = [TenantRouteInput(manifest, observed, selected)]
    if other_route is not None:
        routes.append(other_route)
    routes.sort(key=lambda value: cast(str, value.manifest["metadata"]["id"]))  # type: ignore[index]
    snapshot = TenantRouteSnapshot(namespace, tuple(routes))
    releases = {
        (tenant_id, cast(str, deployment["id"])): _measurement(
            cast(dict[str, object], deployment["releaseTreeDigest"]),
            inode=index,
        )
        for index, deployment in enumerate(deployments, start=100)
    }
    if other_deployment is not None:
        releases[(_OTHER_TENANT_ID, cast(str, other_deployment["id"]))] = _measurement(
            cast(dict[str, object], other_deployment["releaseTreeDigest"]),
            inode=200,
        )
    artifact = (
        AdmittedArtifact("artifact", VerifiedArtifact(32, "e" * 64))
        if operation == "deploy"
        else None
    )
    return repository, _Runtime(snapshot), _ReleaseStore(releases), artifact, deployments


def _prepare(
    repository: StateRepository,
    runtime: _Runtime,
    releases: _ReleaseStore,
    artifact: AdmittedArtifact | None,
) -> PreparedDeploymentTransition:
    return prepare_deployment_transition(
        repository,
        cast(CaddyRuntime, runtime),
        cast(ArtifactIntake, object()),
        cast(DeploymentReleaseStore, releases),
        cast(PublicationGate, _Gate()),
        _JOB_ID,
        artifact,
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )


def test_deploy_stages_before_intent_and_publishes_after_it(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    try:
        prepared = _prepare(repository, runtime, releases, artifact)

        assert prepared.plan.creates_deployment is True
        assert releases.events == ["reconciled", "staged", "published"]
        assert runtime.events == ["locked", "active", "pruned", "candidate"]
        assert (
            repository.read(StateRecordPath.transaction_intent(prepared.plan.intent_id)).document
            == prepared.plan.intent
        )
        assert (prepared.plan.tenant_id, prepared.plan.deployment["id"]) in releases.releases
        assert runtime.overlay is not None
        assert runtime.overlay.tenant.deployment == prepared.plan.deployment
        stored_job = repository.read(StateRecordPath.authorization_job(_JOB_ID)).document
        assert stored_job["dispatchSourceRuntimeGenerationId"] == _SOURCE_GENERATION
        assert stored_job["dispatchSourceRouteSet"] == "both"
    finally:
        repository.close()


def test_deploy_capacity_accounts_for_every_tenant_release(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(
        tmp_path,
        include_other_tenant=True,
    )
    try:
        prepared = _prepare(repository, runtime, releases, artifact)

        assert prepared.plan.creates_deployment is True
        assert releases.events == ["reconciled", "staged", "published"]
    finally:
        repository.close()


def test_rollback_reuses_retained_release_without_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, deployments = _prepared_state(
        tmp_path,
        operation="rollback",
    )
    try:
        prepared = _prepare(repository, runtime, releases, artifact)

        assert prepared.plan.creates_deployment is False
        assert prepared.plan.deployment == deployments[0]
        assert releases.events == ["reconciled"]
        assert runtime.overlay is not None
        assert runtime.overlay.tenant.deployment == deployments[0]
        assert len(repository.measure_intent_records().records) == 1
    finally:
        repository.close()


def test_failed_intent_admission_discards_private_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)

    def reject(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected intent admission failure")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.deployment_prepare._admit_and_create_intent",
        reject,
    )
    try:
        with pytest.raises(RuntimeError, match="intent admission"):
            _prepare(repository, runtime, releases, artifact)

        assert releases.events == ["reconciled", "staged", "discarded"]
        assert repository.measure_intent_records().records == ()
        assert "candidate" not in runtime.events
    finally:
        repository.close()


def test_failure_after_intent_preserves_recoverable_release_authority(
    tmp_path: Path,
) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    runtime.fail_publish = True
    try:
        with pytest.raises(RuntimeError, match="candidate publication"):
            _prepare(repository, runtime, releases, artifact)

        assert len(repository.measure_intent_records().records) == 1
        assert releases.events == ["reconciled", "staged", "published"]
        assert releases.discarded is False
    finally:
        repository.close()


def test_terminal_capacity_is_admitted_before_release_or_candidate_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)

    def reject(*_args: object, **_kwargs: object) -> None:
        raise CapacityRejectedError("injected terminal capacity rejection")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.deployment_prepare.admit_deployment_transition",
        reject,
    )
    try:
        with pytest.raises(CapacityRejectedError, match="terminal capacity"):
            _prepare(repository, runtime, releases, artifact)

        assert len(repository.measure_intent_records().records) == 1
        assert releases.events == ["reconciled", "staged"]
        assert "candidate" not in runtime.events
    finally:
        repository.close()


def test_ambiguous_intent_commit_preserves_staging_for_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    original = repository_module._StateTransaction.create_immutable

    def commit_then_interrupt(
        transaction: repository_module._StateTransaction,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> object:
        stored = original(transaction, path, document)
        if path.components[0] == "intents":
            raise RuntimeError("injected ambiguous intent completion")
        return stored

    monkeypatch.setattr(
        repository_module._StateTransaction,
        "create_immutable",
        commit_then_interrupt,
    )
    try:
        with pytest.raises(DeploymentPreparationError, match="ambiguous durable"):
            _prepare(repository, runtime, releases, artifact)

        assert len(repository.measure_intent_records().records) == 1
        assert releases.events == ["reconciled", "staged"]
        assert releases.discarded is False
        assert "candidate" not in runtime.events
    finally:
        repository.close()


def test_pre_intent_source_generation_is_safely_rebound(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    stored = repository.read(StateRecordPath.authorization_job(_JOB_ID))
    changed = stored.document
    changed["dispatchSourceRuntimeGenerationId"] = "0198d17f-6f4a-7000-8000-000000000099"
    changed["dispatchSourceRouteSet"] = "both"
    changed["dispatchSourceObservedState"] = runtime.source_snapshot.tenants[0].observed_state
    with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        transaction.bind_dispatch_authority(
            StateRecordPath.authorization_job(_JOB_ID),
            stored.revision,
            changed,
            capacity_limits=DEFAULT_HOST_CAPACITY_LIMITS,
        )
    try:
        prepared = _prepare(repository, runtime, releases, artifact)
        rebound = repository.read(StateRecordPath.authorization_job(_JOB_ID)).document

        assert rebound["dispatchSourceRuntimeGenerationId"] == _SOURCE_GENERATION
        assert prepared.job.document == rebound
        assert releases.events == ["reconciled", "staged", "published"]
    finally:
        repository.close()


def test_selected_runtime_drift_fails_before_release_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    runtime.source_snapshot = TenantRouteSnapshot(
        runtime.source_snapshot.platform_namespace,
        (),
    )
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="selected runtime"):
            _prepare(repository, runtime, releases, artifact)
        assert releases.events == ["reconciled"]
    finally:
        repository.close()


def test_missing_authorized_source_is_classified_as_authority_drift(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    desired = (tmp_path / "state").joinpath(
        *StateRecordPath.tenant_desired(_tenant_id()).components
    )
    desired.unlink()
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="source state disappeared"):
            _prepare(repository, runtime, releases, artifact)

        assert releases.events == []
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_retained_release_drift_fails_before_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, deployments = _prepared_state(tmp_path)
    deployment_id = cast(str, deployments[-1]["id"])
    releases.releases[(_tenant_id(), deployment_id)] = _measurement(_digest("f" * 64), inode=300)
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="retained release"):
            _prepare(repository, runtime, releases, artifact)
        assert releases.events == ["reconciled"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_unbound_published_release_fails_before_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    unexpected_id = "0198d17f-6f4a-7000-8000-000000000077"
    releases.releases[(_tenant_id(), unexpected_id)] = _measurement(_digest("7" * 64), inode=300)
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="release inventory"):
            _prepare(repository, runtime, releases, artifact)

        assert releases.events == ["reconciled"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_unexpected_target_archive_history_fails_before_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, deployments = _prepared_state(tmp_path)
    tenant_id = _tenant_id()
    deployment = deployments[-1]
    manifest = repository.read(StateRecordPath.tenant_desired(tenant_id)).document
    archive = _fixture("archive-record.json")
    archive["tenantId"] = tenant_id
    archive["deploymentId"] = deployment["id"]
    archive["releaseTreeDigest"] = deployment["releaseTreeDigest"]
    archive["manifestDigest"] = manifest_digest(manifest).to_dict()
    _write(
        tmp_path / "state",
        StateRecordPath.tenant_archive(tenant_id, deployment["id"]),
        archive,
    )
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="archive history"):
            _prepare(repository, runtime, releases, artifact)

        assert releases.events == ["reconciled"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_bound_archive_history_is_rejected_before_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, deployments = _prepared_state(tmp_path)
    tenant_id = _tenant_id()
    deployment = deployments[-1]
    deployment_id = cast(str, deployment["id"])
    manifest = repository.read(StateRecordPath.tenant_desired(tenant_id)).document
    archive = _fixture("archive-record.json")
    archive["tenantId"] = tenant_id
    archive["deploymentId"] = deployment_id
    archive["releaseTreeDigest"] = deployment["releaseTreeDigest"]
    archive["manifestDigest"] = manifest_digest(manifest).to_dict()
    _write(
        tmp_path / "state",
        StateRecordPath.tenant_archive(tenant_id, deployment_id),
        archive,
    )
    job = repository.read(StateRecordPath.authorization_job(_JOB_ID)).document
    job["dispatchArchiveDeploymentIds"] = [deployment_id]
    job["dispatchTenantRecordHistories"] = [
        [tenant_id, [deployment_id], job["dispatchDeploymentIds"]]
    ]
    _write(tmp_path / "state", StateRecordPath.authorization_job(_JOB_ID), job)
    try:
        with pytest.raises(DeploymentPreparationError, match="empty archive history"):
            _prepare(repository, runtime, releases, artifact)

        assert releases.events == ["reconciled"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_global_retained_history_drift_fails_before_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(
        tmp_path,
        include_other_tenant=True,
    )
    deployment_id = "0198d17f-6f4a-7000-8000-000000000097"
    deployment = _deployment(deployment_id, value="9" * 64)
    deployment["tenantId"] = _OTHER_TENANT_ID
    _write(
        tmp_path / "state",
        StateRecordPath.tenant_deployment(_OTHER_TENANT_ID, deployment_id),
        deployment,
    )
    releases.releases[(_OTHER_TENANT_ID, deployment_id)] = _measurement(
        cast(dict[str, object], deployment["releaseTreeDigest"]),
        inode=300,
    )
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="global tenant retained"):
            _prepare(repository, runtime, releases, artifact)

        assert releases.events == ["reconciled"]
        assert repository.measure_intent_records().records == ()
    finally:
        repository.close()


def test_bound_source_release_drift_fails_before_staging(tmp_path: Path) -> None:
    repository, runtime, releases, artifact, _deployments = _prepared_state(tmp_path)
    stored = repository.read(StateRecordPath.authorization_job(_JOB_ID))
    changed = stored.document
    changed["dispatchSourceReleaseTreeDigest"] = _digest("f" * 64)
    _write(tmp_path / "state", StateRecordPath.authorization_job(_JOB_ID), changed)
    try:
        with pytest.raises(DeploymentAuthorityDriftError, match="source release"):
            _prepare(repository, runtime, releases, artifact)
        assert releases.events == ["reconciled"]
    finally:
        repository.close()


def test_claimed_artifact_drift_is_rejected(tmp_path: Path) -> None:
    repository, runtime, releases, _artifact, _deployments = _prepared_state(tmp_path)
    changed = AdmittedArtifact("artifact", VerifiedArtifact(32, "f" * 64))
    try:
        with pytest.raises(DeploymentPreparationError, match="artifact changed"):
            _prepare(repository, runtime, releases, changed)
        assert releases.events == ["reconciled"]
    finally:
        repository.close()
