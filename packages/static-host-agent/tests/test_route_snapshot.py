from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, manifest_digest
from lowerduckpond_static_host_agent import (
    LockManager,
    LockMode,
    RouteOverlayMode,
    RouteSnapshotError,
    StateRecordPath,
    StateRepository,
    TenantRouteInput,
    TenantRouteOverlay,
    snapshot_tenant_routes,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_SECOND_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2101"


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
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    LockManager.initialize(root / "locks", expected_owner=os.geteuid()).close()
    return root


def _write(root: Path, path: StateRecordPath, document: dict[str, object]) -> None:
    target = root.joinpath(*path.components)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(0o600)


def _active_tenant(root: Path) -> TenantRouteInput:
    manifest = _fixture("site.json")
    observed = _fixture("tenant-observed-state.json")
    deployment = _fixture("deployment-record.json")
    observed["desiredManifestDigest"] = manifest_digest(manifest).to_dict()
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)
    _write(root, StateRecordPath.tenant_observed(_TENANT_ID), observed)
    _write(
        root,
        StateRecordPath.tenant_deployment(_TENANT_ID, deployment["id"]),
        deployment,
    )
    return TenantRouteInput(manifest, observed, deployment)


def _undeployed_tenant(tenant_id: str, *, slug: str) -> TenantRouteInput:
    manifest = _fixture("operation-result.json")["manifest"]
    assert type(manifest) is dict
    manifest = deepcopy(manifest)
    metadata = manifest["metadata"]
    assert type(metadata) is dict
    metadata["id"] = tenant_id
    metadata["slug"] = slug
    metadata["canonicalOrigin"] = f"t-{tenant_id.replace('-', '')}.lowerduckpond.com"
    observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": tenant_id,
        "desiredManifestDigest": manifest_digest(manifest).to_dict(),
        "observedState": "undeployed",
        "activeDeploymentId": None,
        "runtimeGenerationId": None,
        "reconciledAt": "2026-09-02T12:30:00Z",
    }
    return TenantRouteInput(manifest, observed, None)


def _archived_tenant(tenant_id: str, *, slug: str) -> TenantRouteInput:
    tenant = _undeployed_tenant(tenant_id, slug=slug)
    deployment = _fixture("deployment-record.json")
    deployment["tenantId"] = tenant_id
    spec = tenant.manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "archived"
    spec["desiredDeployment"] = {
        "id": deployment["id"],
        "archiveSha256": deployment["archiveSha256"],
    }
    tenant.observed_state["desiredManifestDigest"] = manifest_digest(tenant.manifest).to_dict()
    tenant.observed_state["observedState"] = "archived"
    return TenantRouteInput(tenant.manifest, tenant.observed_state, deployment)


def test_snapshot_reads_every_tenant_and_selected_deployment(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    namespace = _fixture("platform-namespace.json")
    _write(root, StateRecordPath.platform_namespace(), namespace)
    active = _active_tenant(root)
    second = _undeployed_tenant(_SECOND_TENANT_ID, slug="second-duck")
    _write(root, StateRecordPath.tenant_desired(_SECOND_TENANT_ID), second.manifest)
    _write(root, StateRecordPath.tenant_observed(_SECOND_TENANT_ID), second.observed_state)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        snapshot = snapshot_tenant_routes(transaction)

    assert snapshot.platform_namespace == namespace
    assert snapshot.tenants == (active, second)


def test_snapshot_omits_archived_tenants_from_the_complete_runtime_input(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    active = _active_tenant(root)
    archived = _archived_tenant(_SECOND_TENANT_ID, slug="archived-duck")
    _write(root, StateRecordPath.tenant_desired(_SECOND_TENANT_ID), archived.manifest)
    _write(root, StateRecordPath.tenant_observed(_SECOND_TENANT_ID), archived.observed_state)
    assert archived.deployment is not None
    _write(
        root,
        StateRecordPath.tenant_deployment(_SECOND_TENANT_ID, archived.deployment["id"]),
        archived.deployment,
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        snapshot = snapshot_tenant_routes(transaction)
        replaced = snapshot_tenant_routes(
            transaction,
            overlay=TenantRouteOverlay(RouteOverlayMode.REPLACE, archived, archived),
        )

    assert snapshot.tenants == (active,)
    assert replaced.tenants == (active,)


def test_add_overlay_extends_the_complete_snapshot_without_persisting(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    active = _active_tenant(root)
    candidate = _undeployed_tenant(_SECOND_TENANT_ID, slug="second-duck")

    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            snapshot = snapshot_tenant_routes(
                transaction,
                overlay=TenantRouteOverlay(RouteOverlayMode.ADD, candidate),
            )
        inventory = repository.measure_inventory()

    assert snapshot.tenants == (active, candidate)
    assert inventory.tenant_ids == (_TENANT_ID,)


def test_replace_overlay_substitutes_exactly_one_existing_tenant(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    source = _active_tenant(root)
    candidate = _undeployed_tenant(_TENANT_ID, slug="duck-repair")

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        snapshot = snapshot_tenant_routes(
            transaction,
            overlay=TenantRouteOverlay(RouteOverlayMode.REPLACE, candidate, source),
        )

    assert snapshot.tenants == (candidate,)


@pytest.mark.parametrize(
    ("mode", "candidate_id", "message"),
    [
        (RouteOverlayMode.ADD, _TENANT_ID, "already exists"),
        (RouteOverlayMode.REPLACE, _SECOND_TENANT_ID, "is absent"),
    ],
)
def test_overlay_disposition_must_match_the_inventory(
    tmp_path: Path,
    mode: RouteOverlayMode,
    candidate_id: str,
    message: str,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    _active_tenant(root)
    candidate = _undeployed_tenant(candidate_id, slug="candidate")
    overlay_source = (
        _undeployed_tenant(candidate_id, slug="source")
        if mode is RouteOverlayMode.REPLACE
        else None
    )

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
        pytest.raises(RouteSnapshotError, match=message),
    ):
        snapshot_tenant_routes(
            transaction,
            overlay=TenantRouteOverlay(mode, candidate, overlay_source),
        )


def test_replace_overlay_rejects_source_state_that_changed_before_the_lock(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    source = _active_tenant(root)
    candidate = _undeployed_tenant(_TENANT_ID, slug="duck-repair")
    changed = deepcopy(source.observed_state)
    changed["reconciledAt"] = "2026-09-02T12:31:00Z"
    _write(root, StateRecordPath.tenant_observed(_TENANT_ID), changed)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
        pytest.raises(RouteSnapshotError, match="source changed"),
    ):
        snapshot_tenant_routes(
            transaction,
            overlay=TenantRouteOverlay(RouteOverlayMode.REPLACE, candidate, source),
        )


def test_snapshot_fails_closed_when_one_inventory_tenant_is_incomplete(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _write(root, StateRecordPath.platform_namespace(), _fixture("platform-namespace.json"))
    manifest = _undeployed_tenant(_TENANT_ID, slug="duck-repair").manifest
    _write(root, StateRecordPath.tenant_desired(_TENANT_ID), manifest)

    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
        pytest.raises(FileNotFoundError),
    ):
        snapshot_tenant_routes(transaction)
