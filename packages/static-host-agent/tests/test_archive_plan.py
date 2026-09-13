from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import ContractError, manifest_digest, result_digest
from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.lifecycle_plan import (
    ArchiveTransitionPlan,
    LifecyclePlanError,
    plan_archive_transition,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_journal import (
    _NOW,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)

_CANDIDATE_GENERATION = "0198d17f-6f4a-7000-8000-000000000006"


def _inputs(tmp_path: Path, state: str = "active") -> list[dict[str, object]]:
    with prepared_source(tmp_path, MemoryRemote()) as (journal, job_id, snapshot, _quarantine):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        source = snapshot.source_manifest
        assert source is not None
        values = [
            journal.repository.read(StateRecordPath.authorization_job(job_id)).document,
            journal.repository.read(StateRecordPath.platform_namespace()).document,
            deepcopy(source),
            journal.repository.read(StateRecordPath.tenant_observed(_TENANT)).document,
            deepcopy(snapshot.deployment),
            uploaded.construction.document,
            deepcopy(uploaded.record),
        ]
    if state == "suspended":
        job, _namespace, source, observed, _deployment, construction, _archive = values
        cast(dict[str, object], source["spec"])["desiredState"] = state
        source_digest = manifest_digest(source).to_dict()
        cast(dict[str, object], job["expectedSource"]).update(
            lifecycle=state,
            manifestDigest=source_digest,
        )
        job["sourceAuthority"] = {"manifest": deepcopy(source), "archiveRecord": None}
        observed.update(
            observedState=state, runtimeGenerationId=None, desiredManifestDigest=source_digest
        )
        construction["sourceManifestDigest"] = source_digest
    return values


def _plan(values: list[dict[str, object]], *, routes: str | None = None) -> ArchiveTransitionPlan:
    state = cast(dict[str, object], values[2]["spec"])["desiredState"]
    return plan_archive_transition(
        *values,
        source_runtime_generation_id=(
            values[3]["runtimeGenerationId"] or "0198d17f-6f4a-7000-8000-000000000004"
        ),
        candidate_runtime_generation_id=_CANDIDATE_GENERATION,
        source_route_set=routes or ("both" if state == "active" else "absent"),
        audit_state=AuditState(0, 0, 0, None),
        now=_NOW,
        clock=lambda: 1_789_000_000_000,
        entropy=lambda length: b"\x07" * length,
    )


@pytest.mark.parametrize("state", ["active", "suspended"])
def test_archive_plan_preserves_exact_rollback_source_and_verified_remote_authority(
    tmp_path: Path, state: str
) -> None:
    values = _inputs(tmp_path, state)
    originals = deepcopy(values)
    plan = _plan(values)
    recovery = cast(dict[str, object], plan.intent["archiveRecovery"])
    assert recovery["sourceManifest"] == values[2]
    assert recovery["sourceObservedState"] == values[3]
    assert recovery["sourceRouteSet"] == ("both" if state == "active" else "absent")
    assert recovery["candidateRouteSet"] == "absent"
    expected = deepcopy(values[2])
    cast(dict[str, object], expected["spec"])["desiredState"] = "archived"
    assert plan.manifest == expected
    assert plan.archive_record == values[6]
    assert plan.result["archiveRecord"] == values[6]
    assert plan.construction_intent_id == values[5]["intentId"]
    assert plan.observed_state["activeDeploymentId"] is None
    assert plan.observed_state["runtimeGenerationId"] is None
    assert plan.audit_entry["resultDigest"] == result_digest(plan.result).to_dict()
    assert values == originals
    cast(dict[str, object], plan.manifest["spec"])["desiredState"] = "suspended"
    assert recovery["candidateManifest"] == expected
    assert plan.result["manifest"] == expected


@pytest.mark.parametrize(
    "defect",
    [
        "prepared",
        "source-digest",
        "candidate-digest",
        "deployment-digest",
        "tree-digest",
        "record-version",
        "record-bucket",
        "record-size",
        "other-job",
        "other-key",
        "issued",
    ],
)
def test_archive_plan_rejects_unverified_or_unbound_construction(
    tmp_path: Path, defect: str
) -> None:
    values = _inputs(tmp_path)
    job, _namespace, _source, _observed, _deployment, construction, archive = values
    if defect == "prepared":
        construction.update(phase="prepared", versionId=None)
    elif defect in {"source-digest", "candidate-digest", "deployment-digest", "tree-digest"}:
        field = {
            "source-digest": "sourceManifestDigest",
            "candidate-digest": "candidateManifestDigest",
            "deployment-digest": "deploymentRecordDigest",
            "tree-digest": "releaseTreeDigest",
        }[defect]
        cast(dict[str, object], construction[field])["value"] = "a" * 64
    elif defect == "record-version":
        archive["versionId"] = "another-version"
    elif defect == "record-bucket":
        archive["bucket"] = "another-archive-bucket"
    elif defect == "record-size":
        archive["bundleSize"] = cast(int, archive["bundleSize"]) + 1
    elif defect == "other-job":
        construction["jobId"] = "0198d17f-6f4a-7000-8000-000000000004"
    elif defect == "other-key":
        construction["key"] = archive["key"] = "archives/arbitrary.zip"
    else:
        job["phase"] = "issued"
    with pytest.raises((ContractError, LifecyclePlanError)):
        _plan(values)


@pytest.mark.parametrize("state", ["active", "suspended"])
def test_archive_plan_rejects_source_route_disagreement(tmp_path: Path, state: str) -> None:
    values = _inputs(tmp_path, state)
    with pytest.raises(ContractError):
        _plan(values, routes="absent" if state == "active" else "both")
