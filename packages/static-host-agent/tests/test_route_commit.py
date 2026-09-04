from __future__ import annotations

import json
import os
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

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
    CapacityRejectedError,
    FilesystemCapacity,
    HostCapacityLimits,
    LockManager,
    StateConflictError,
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.lifecycle_plan import (
    RouteTransitionPlan,
    plan_route_transition,
)
from lowerduckpond_static_host_agent.route_commit import (
    RouteCommitBoundary,
    RouteCommitError,
    RouteCommitOutcome,
    finalize_route_transition_outcome,
    validate_route_transition,
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
    repository.create_immutable(
        StateRecordPath.transaction_intent(plan.intent_id),
        plan.intent,
    )
    return repository, job, plan


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
