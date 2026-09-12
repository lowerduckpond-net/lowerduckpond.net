from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import ContractError, canonical_json_bytes
from lowerduckpond_static_host_agent.audit import AuditState
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.lifecycle_plan import (
    DeploymentTransitionPlan,
    LifecyclePlanError,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.restore_plan import plan_restore_transition
from test_archive_activate import _activate, _prepared
from test_archive_journal import (
    _NOW,
    _TENANT,
    OpenGate,
    capacity,  # noqa: F401 - shared capacity fixture
)
from test_route_commit import _Entropy


def _inputs(tmp_path: Path) -> list[dict[str, object]]:
    with _prepared(tmp_path, "active") as (journal, store, prepared, runtime):
        _activate(journal, store, prepared, runtime)
        journal.finish(prepared.plan.construction_intent_id)
        issued = AuthorizationIssuer(journal.repository, gate=OpenGate(), entropy=_Entropy()).issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": "restore",
                    "tenantId": _TENANT,
                    "correlationId": "0198d17f-6f4a-7000-8000-000000000010",
                }
            ),
            operator_principal="operator@example.test",
            now=_NOW,
            artifact=None,
        )
        with journal.repository.publication_transaction() as transaction:
            path = StateRecordPath.authorization_job(issued.job_id)
            job = transaction.read(path)
            claimed = job.document
            claimed["phase"] = "claimed"
            stored = transaction.compare_and_swap(path, job.revision, claimed)
            archive = prepared.plan.archive_record
            claimed.update(
                dispatchDeploymentIds=list(transaction.tenant_deployment_ids(_TENANT)),
                dispatchArchiveDeploymentIds=[archive["deploymentId"]],
                dispatchSourceReleaseTreeDigest=archive["releaseTreeDigest"],
            )
            transaction.bind_dispatch_authority(path, stored.revision, claimed)
        retirement = journal.prepare_retirement(issued.job_id, now=_NOW)
        return [
            claimed,
            journal.repository.read(StateRecordPath.platform_namespace()).document,
            prepared.plan.manifest,
            prepared.plan.observed_state,
            journal.repository.read(
                StateRecordPath.tenant_deployment(_TENANT, archive["deploymentId"])
            ).document,
            retirement.document,
        ]


def _plan(values: list[dict[str, object]]) -> DeploymentTransitionPlan:
    return plan_restore_transition(
        *values,
        source_runtime_generation_id="0198d17f-6f4a-7000-8000-000000000005",
        candidate_runtime_generation_id="0198d17f-6f4a-7000-8000-000000000006",
        audit_state=AuditState(0, 0, 0, None),
        now=_NOW,
        clock=lambda: 1_789_000_000_000,
        entropy=_Entropy(),
    )


def test_restore_plan_preserves_identity_and_policy_with_a_fresh_deployment(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    originals = deepcopy(values)
    plan = _plan(values)
    archive = cast(dict[str, object], values[-1]["archiveRecord"])
    expected = deepcopy(values[2])
    cast(dict[str, object], expected["spec"]).update(
        desiredState="active",
        desiredDeployment={
            "id": plan.deployment["id"],
            "archiveSha256": plan.deployment["archiveSha256"],
        },
    )
    assert plan.manifest == expected
    assert plan.deployment["id"] != archive["deploymentId"]
    assert plan.deployment["releaseTreeDigest"] == archive["releaseTreeDigest"]
    assert (
        plan.deployment["archiveSha256"]
        == cast(dict[str, object], archive["bundleDigest"])["value"]
    )
    assert plan.observed_state["activeDeploymentId"] == plan.deployment["id"]
    assert plan.result["operation"] == "restore"
    assert values == originals


@pytest.mark.parametrize("defect", ["job", "tenant", "object", "deployment", "history", "observed"])
def test_restore_plan_rejects_changed_retirement_authority(tmp_path: Path, defect: str) -> None:
    values = _inputs(tmp_path)
    job, _namespace, _source, observed, deployment, retirement = values
    if defect == "job":
        cast(dict[str, object], retirement["provenance"])["jobId"] = _TENANT
    elif defect == "tenant":
        retirement["tenantId"] = "0198d17f-6f4a-7000-8000-000000000020"
    elif defect == "object":
        cast(dict[str, object], retirement["archiveRecord"])["versionId"] = "other-version"
    elif defect == "deployment":
        deployment["archiveSha256"] = "0" * 64
    elif defect == "history":
        job["dispatchArchiveDeploymentIds"] = []
    else:
        observed["activeDeploymentId"] = deployment["id"]
    with pytest.raises((ContractError, LifecyclePlanError)):
        _plan(values)
