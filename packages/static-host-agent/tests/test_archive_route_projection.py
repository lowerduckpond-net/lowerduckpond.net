from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    RouteSnapshotError,
    TenantRouteOverlay,
    snapshot_tenant_routes,
)
from test_archive_commit import _prepared
from test_archive_journal import (
    _DEPLOYMENT,
    _TENANT,
    capacity,  # noqa: F401 - shared autouse capacity fixture
)


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_archive_candidate_removes_routes_without_prematurely_binding_archive_state(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, _store, _job, plan):
        recovery = cast(dict[str, object], plan.intent["archiveRecovery"])
        with journal.repository.publication_transaction() as transaction:
            deployment = transaction.read(
                StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT)
            ).document
            source = TenantRouteInput(
                cast(dict[str, object], recovery["sourceManifest"]),
                cast(dict[str, object], recovery["sourceObservedState"]),
                deployment,
            )
            before = snapshot_tenant_routes(transaction)
            overlay = TenantRouteOverlay(
                RouteOverlayMode.REPLACE,
                TenantRouteInput(plan.manifest, plan.observed_state, deployment),
                source,
                archive_record=plan.archive_record,
            )
            projected = snapshot_tenant_routes(transaction, overlay=overlay)
            assert projected.platform_namespace == before.platform_namespace
            assert projected.tenants == ()
            assert before.tenants == (source,)
            assert snapshot_tenant_routes(transaction) == before
            with pytest.raises(FileNotFoundError):
                transaction.read(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT))


@pytest.mark.parametrize("defect", ["tenant", "deployment", "manifest", "tree", "already-bound"])
def test_archive_projection_rejects_wrong_evidence_and_existing_live_archive_binding(
    tmp_path: Path,
    defect: str,
) -> None:
    with _prepared(tmp_path) as (journal, _store, _job, plan):
        recovery = cast(dict[str, object], plan.intent["archiveRecovery"])
        with journal.repository.publication_transaction() as transaction:
            deployment = transaction.read(
                StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT)
            ).document
            source = TenantRouteInput(
                cast(dict[str, object], recovery["sourceManifest"]),
                cast(dict[str, object], recovery["sourceObservedState"]),
                deployment,
            )
            archive = deepcopy(plan.archive_record)
            if defect == "already-bound":
                transaction.create_immutable(
                    StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT), archive
                )
            elif defect in {"tenant", "deployment"}:
                archive["tenantId" if defect == "tenant" else "deploymentId"] = (
                    "0198d17f-6f4a-7000-8000-000000000004"
                )
            else:
                field = "manifestDigest" if defect == "manifest" else "releaseTreeDigest"
                cast(dict[str, object], archive[field])["value"] = "a" * 64
            overlay = TenantRouteOverlay(
                RouteOverlayMode.REPLACE,
                TenantRouteInput(plan.manifest, plan.observed_state, deployment),
                source,
                archive_record=archive,
            )
            with pytest.raises(RouteSnapshotError):
                snapshot_tenant_routes(transaction, overlay=overlay)


def test_archive_projection_cannot_change_tenant_policy(tmp_path: Path) -> None:
    with _prepared(tmp_path) as (journal, _store, _job, plan):
        recovery = cast(dict[str, object], plan.intent["archiveRecovery"])
        deployment = journal.repository.read(
            StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT)
        ).document
        candidate = deepcopy(plan.manifest)
        cast(dict[str, object], candidate["metadata"])["slug"] = "changed-slug"
        with pytest.raises(ValueError, match="outside its transition"):
            TenantRouteOverlay(
                RouteOverlayMode.REPLACE,
                TenantRouteInput(candidate, plan.observed_state, deployment),
                TenantRouteInput(
                    cast(dict[str, object], recovery["sourceManifest"]),
                    cast(dict[str, object], recovery["sourceObservedState"]),
                    deployment,
                ),
                archive_record=plan.archive_record,
            )
