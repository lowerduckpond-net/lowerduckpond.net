from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ContractKind,
    audit_entry_digest,
    manifest_digest,
    platform_state_digest,
    result_digest,
    validate_contract,
)
from lowerduckpond_static_host_agent import AuditState
from lowerduckpond_static_host_agent.lifecycle_plan import (
    CreateTransitionPlan,
    LifecyclePlanError,
    plan_create_transition,
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
