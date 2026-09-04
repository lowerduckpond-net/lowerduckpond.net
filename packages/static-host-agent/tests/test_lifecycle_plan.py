from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    audit_entry_digest,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    request_digest,
    result_digest,
    validate_contract,
)
from lowerduckpond_static_host_agent import AuditState
from lowerduckpond_static_host_agent.lifecycle_plan import (
    CreateTransitionPlan,
    LifecyclePlanError,
    RouteTransitionPlan,
    plan_create_transition,
    plan_route_transition,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_NOW = datetime(2026, 9, 2, 12, 30, tzinfo=UTC)
_SOURCE_GENERATION = "0198d17f-6f4a-7000-8000-000000000004"
_CANDIDATE_GENERATION = "0198d17f-6f4a-7000-8000-000000000006"
_AUDIT_SEQUENCE = 3


class _Entropy:
    def __init__(self) -> None:
        self._value = 0

    def __call__(self, length: int) -> bytes:
        self._value += 1
        return self._value.to_bytes(length, byteorder="big")


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _claimed_job(namespace: dict[str, object]) -> dict[str, object]:
    job = _fixture("authorization-job.json")
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected["platformStateDigest"] = platform_state_digest(namespace).to_dict()
    job["phase"] = "claimed"
    return job


def _plan(
    *,
    job: dict[str, object] | None = None,
    namespace: dict[str, object] | None = None,
    source_generation: str = _SOURCE_GENERATION,
    candidate_generation: str = _CANDIDATE_GENERATION,
) -> CreateTransitionPlan:
    selected_namespace = _fixture("platform-namespace.json") if namespace is None else namespace
    selected_job = _claimed_job(selected_namespace) if job is None else job
    return plan_create_transition(
        selected_job,
        selected_namespace,
        source_runtime_generation_id=source_generation,
        candidate_runtime_generation_id=candidate_generation,
        audit_state=AuditState(
            _AUDIT_SEQUENCE,
            1,
            4096,
            audit_entry_digest(_fixture("audit-entry.json")).to_dict(),
        ),
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )


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
        desired_deployment = spec["desiredDeployment"]
        assert type(desired_deployment) is dict
        active_deployment_id = desired_deployment["id"] if state != "archived" else None
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
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
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
    job: dict[str, object] = {
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
                deployment_record_digest(deployment).to_dict() if deployment is not None else None
            ),
            "archiveRecordDigest": (
                archive_record_digest(archive).to_dict() if archive is not None else None
            ),
            "platformStateDigest": platform_state_digest(namespace).to_dict(),
        },
        "acceptedAt": "2026-09-02T12:00:01Z",
        "phase": "claimed",
    }
    validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
    return job


def _route_plan(
    operation: str,
    state: str,
    *,
    slug: str | None = None,
    candidate_generation: str = _CANDIDATE_GENERATION,
) -> RouteTransitionPlan:
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _route_source(state)
    return plan_route_transition(
        _route_job(operation, namespace, manifest, deployment, archive, slug=slug),
        namespace,
        manifest,
        observed,
        deployment,
        archive,
        source_runtime_generation_id=_SOURCE_GENERATION,
        candidate_runtime_generation_id=candidate_generation,
        audit_state=AuditState(
            _AUDIT_SEQUENCE,
            1,
            4096,
            audit_entry_digest(_fixture("audit-entry.json")).to_dict(),
        ),
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )


def test_create_plan_is_one_complete_absent_to_undeployed_transaction() -> None:
    plan = _plan()
    manifest = plan.manifest
    observed = plan.observed_state
    intent = plan.intent
    result = plan.result
    audit = plan.audit_entry

    assert validate_contract(manifest) is ContractKind.SITE
    assert validate_contract(observed) is ContractKind.TENANT_OBSERVED_STATE
    assert validate_contract(intent) is ContractKind.TRANSACTION_INTENT
    assert validate_contract(result) is ContractKind.OPERATION_RESULT
    assert validate_contract(audit) is ContractKind.AUDIT_ENTRY
    spec = manifest["spec"]
    metadata = manifest["metadata"]
    assert type(spec) is dict
    assert type(metadata) is dict
    assert spec["desiredState"] == "undeployed"
    assert observed["observedState"] == "undeployed"
    assert observed["runtimeGenerationId"] is None
    assert observed["desiredManifestDigest"] == manifest_digest(manifest).to_dict()
    assert intent["sourceManifestDigest"] is None
    assert intent["candidateManifest"] == manifest
    assert intent["candidateManifestDigest"] == manifest_digest(manifest).to_dict()
    recovery = intent["lifecycleRecovery"]
    assert type(recovery) is dict
    assert recovery["sourceRouteSet"] == recovery["candidateRouteSet"] == "absent"
    assert recovery["sourceRuntimeGenerationId"] == _SOURCE_GENERATION
    assert recovery["candidateRuntimeGenerationId"] == _CANDIDATE_GENERATION
    assert result["tenantId"] == metadata["id"] == plan.tenant_id
    assert audit["resultDigest"] == result_digest(result).to_dict()
    assert audit["sequence"] == _AUDIT_SEQUENCE


def test_create_plan_does_not_mutate_validated_authority_inputs() -> None:
    namespace = _fixture("platform-namespace.json")
    job = _claimed_job(namespace)
    before_namespace = deepcopy(namespace)
    before_job = deepcopy(job)

    _plan(job=job, namespace=namespace)

    assert namespace == before_namespace
    assert job == before_job


def test_create_plan_rejects_an_unclaimed_job() -> None:
    namespace = _fixture("platform-namespace.json")
    job = _claimed_job(namespace)
    job["phase"] = "pending"

    with pytest.raises(LifecyclePlanError, match="claimed"):
        _plan(job=job, namespace=namespace)


def test_create_plan_rejects_namespace_binding_drift() -> None:
    namespace = _fixture("platform-namespace.json")
    job = _claimed_job(namespace)
    expected = job["expectedSource"]
    assert type(expected) is dict
    digest = expected["platformStateDigest"]
    assert type(digest) is dict
    digest["value"] = "a" * 64

    with pytest.raises(LifecyclePlanError, match="namespace"):
        _plan(job=job, namespace=namespace)


def test_create_plan_rejects_reusing_the_active_runtime_generation() -> None:
    with pytest.raises(LifecyclePlanError, match="distinct complete runtime"):
        _plan(candidate_generation=_SOURCE_GENERATION)


def test_create_plan_rejects_a_naive_wall_clock() -> None:
    namespace = _fixture("platform-namespace.json")
    job = _claimed_job(namespace)

    with pytest.raises(LifecyclePlanError, match="timezone-aware"):
        plan_create_transition(
            job,
            namespace,
            source_runtime_generation_id=_SOURCE_GENERATION,
            candidate_runtime_generation_id=_CANDIDATE_GENERATION,
            audit_state=AuditState(0, 0, 0, None),
            now=datetime(2026, 9, 2, 12, 30),
            clock=lambda: 1_777_000_000_000,
            entropy=_Entropy(),
        )


@pytest.mark.parametrize(
    ("operation", "source_state", "target_state", "source_routes", "candidate_routes"),
    [
        ("suspend", "active", "suspended", "both", "absent"),
        ("suspend", "suspended", "suspended", "absent", "absent"),
        ("resume", "suspended", "active", "absent", "both"),
        ("resume", "active", "active", "both", "both"),
        ("rename", "undeployed", "undeployed", "absent", "absent"),
        ("rename", "active", "active", "both", "both"),
        ("rename", "suspended", "suspended", "absent", "absent"),
        ("reconcile", "undeployed", "undeployed", "absent", "absent"),
        ("reconcile", "active", "active", "both", "both"),
        ("reconcile", "suspended", "suspended", "absent", "absent"),
        ("reconcile", "archived", "archived", "absent", "absent"),
    ],
)
def test_route_plan_materializes_the_complete_lifecycle_matrix_entry(
    operation: str,
    source_state: str,
    target_state: str,
    source_routes: str,
    candidate_routes: str,
) -> None:
    slug = "renamed-duck" if operation == "rename" else None
    plan = _route_plan(operation, source_state, slug=slug)

    assert validate_contract(plan.manifest) is ContractKind.SITE
    assert validate_contract(plan.observed_state) is ContractKind.TENANT_OBSERVED_STATE
    assert validate_contract(plan.intent) is ContractKind.TRANSACTION_INTENT
    assert validate_contract(plan.result) is ContractKind.OPERATION_RESULT
    assert validate_contract(plan.audit_entry) is ContractKind.AUDIT_ENTRY
    spec = plan.manifest["spec"]
    metadata = plan.manifest["metadata"]
    recovery = plan.intent["lifecycleRecovery"]
    assert type(spec) is dict
    assert type(metadata) is dict
    assert type(recovery) is dict
    assert spec["desiredState"] == target_state
    if slug is not None:
        assert metadata["slug"] == slug
    assert recovery["sourceRouteSet"] == source_routes
    assert recovery["candidateRouteSet"] == candidate_routes
    assert recovery["sourceRuntimeGenerationId"] == _SOURCE_GENERATION
    assert recovery["candidateRuntimeGenerationId"] == _CANDIDATE_GENERATION
    assert plan.intent["compatibilityVersion"] == "static-intent-v2"
    assert plan.intent["sourceManifest"] == _route_source(source_state)[0]
    assert plan.intent["candidateManifest"] == plan.manifest
    assert plan.observed_state["runtimeGenerationId"] == (
        _CANDIDATE_GENERATION if target_state == "active" else None
    )
    assert plan.audit_entry["resultDigest"] == result_digest(plan.result).to_dict()


@pytest.mark.parametrize(
    ("operation", "state"),
    [("suspend", "suspended"), ("resume", "active"), ("reconcile", "active")],
)
def test_route_plan_preserves_manifest_generation_for_no_op_transitions(
    operation: str,
    state: str,
) -> None:
    plan = _route_plan(operation, state)

    assert plan.intent["sourceManifestDigest"] == plan.intent["candidateManifestDigest"]


def test_route_plan_does_not_mutate_authority_or_source_inputs() -> None:
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _route_source("active")
    job = _route_job("rename", namespace, manifest, deployment, archive, slug="renamed-duck")
    before = deepcopy((job, namespace, manifest, observed, deployment, archive))

    plan_route_transition(
        job,
        namespace,
        manifest,
        observed,
        deployment,
        archive,
        source_runtime_generation_id=_SOURCE_GENERATION,
        candidate_runtime_generation_id=_CANDIDATE_GENERATION,
        audit_state=AuditState(0, 0, 0, None),
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )

    assert (job, namespace, manifest, observed, deployment, archive) == before


def test_route_plan_rejects_a_transition_outside_the_lifecycle_matrix() -> None:
    with pytest.raises(LifecyclePlanError, match="not valid"):
        _route_plan("suspend", "undeployed")


def test_route_plan_rejects_authority_source_drift() -> None:
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _route_source("active")
    job = _route_job("suspend", namespace, manifest, deployment, archive)
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected["manifestDigest"] = {
        "format": "lowerduckpond-manifest-v1",
        "algorithm": "sha256",
        "value": "a" * 64,
    }

    with pytest.raises(LifecyclePlanError, match="not bound"):
        plan_route_transition(
            job,
            namespace,
            manifest,
            observed,
            deployment,
            archive,
            source_runtime_generation_id=_SOURCE_GENERATION,
            candidate_runtime_generation_id=_CANDIDATE_GENERATION,
            audit_state=AuditState(0, 0, 0, None),
            now=_NOW,
            clock=lambda: 1_777_000_000_000,
            entropy=_Entropy(),
        )


def test_route_plan_retains_an_older_target_generation_than_the_selected_source() -> None:
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _route_source("active")
    target_generation = "0198d17f-6f4a-7000-8000-000000000003"
    observed["runtimeGenerationId"] = target_generation

    plan = plan_route_transition(
        _route_job("suspend", namespace, manifest, deployment, archive),
        namespace,
        manifest,
        observed,
        deployment,
        archive,
        source_runtime_generation_id=_SOURCE_GENERATION,
        candidate_runtime_generation_id=_CANDIDATE_GENERATION,
        audit_state=AuditState(0, 0, 0, None),
        now=_NOW,
        clock=lambda: 1_777_000_000_000,
        entropy=_Entropy(),
    )

    recovery = plan.intent["lifecycleRecovery"]
    assert type(recovery) is dict
    source_observed = recovery["sourceObservedState"]
    assert type(source_observed) is dict
    assert recovery["sourceRuntimeGenerationId"] == _SOURCE_GENERATION
    assert source_observed["runtimeGenerationId"] == target_generation


def test_route_plan_rejects_an_archived_source_without_its_archive_record() -> None:
    namespace = _fixture("platform-namespace.json")
    manifest, observed, deployment, archive = _route_source("archived")
    assert archive is not None

    with pytest.raises(LifecyclePlanError, match="omitted its archive"):
        plan_route_transition(
            _route_job("reconcile", namespace, manifest, deployment, archive),
            namespace,
            manifest,
            observed,
            deployment,
            None,
            source_runtime_generation_id=_SOURCE_GENERATION,
            candidate_runtime_generation_id=_CANDIDATE_GENERATION,
            audit_state=AuditState(0, 0, 0, None),
            now=_NOW,
            clock=lambda: 1_777_000_000_000,
            entropy=_Entropy(),
        )


def test_route_plan_rejects_reusing_the_runtime_generation() -> None:
    with pytest.raises(LifecyclePlanError, match="distinct runtime"):
        _route_plan("reconcile", "active", candidate_generation=_SOURCE_GENERATION)


def test_route_plan_rejects_a_rename_to_the_current_slug() -> None:
    with pytest.raises(LifecyclePlanError, match="different slug"):
        _route_plan("rename", "active", slug="duck-repair")
