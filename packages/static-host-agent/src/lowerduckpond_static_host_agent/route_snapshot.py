"""Complete tenant route inputs captured under the authoritative-state lock."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from lowerduckpond_static_contracts import ContractKind, validate_contract, validate_uuid7

from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventory


class RouteSnapshotError(RuntimeError):
    """Authoritative tenant state cannot produce one complete route snapshot."""


class RouteOverlayMode(StrEnum):
    """Whether a proposed tenant is new or replaces an existing tenant."""

    ADD = "add"
    REPLACE = "replace"


@dataclass(frozen=True, slots=True)
class TenantRouteOverlay:
    """One lifecycle candidate overlaid on the complete persisted tenant set."""

    mode: RouteOverlayMode
    tenant: TenantRouteInput
    source: TenantRouteInput | None = None

    def __post_init__(self) -> None:
        if type(self.mode) is not RouteOverlayMode:
            raise TypeError("route overlay mode must be explicit")
        if type(self.tenant) is not TenantRouteInput:
            raise TypeError("route overlay tenant must be one immutable route input")
        if self.source is not None and type(self.source) is not TenantRouteInput:
            raise TypeError("route overlay source must be one immutable route input")
        if self.mode is RouteOverlayMode.ADD and self.source is not None:
            raise ValueError("add route overlay cannot have a source tenant")
        if self.mode is RouteOverlayMode.REPLACE:
            if self.source is None:
                raise ValueError("replace route overlay requires a source tenant")
            if _tenant_id(self.source) != _tenant_id(self.tenant):
                raise ValueError("route overlay source and candidate tenants differ")


@dataclass(frozen=True, slots=True)
class TenantRouteSnapshot:
    """The namespace and every tenant input for one complete Caddy generation."""

    platform_namespace: dict[str, object]
    tenants: tuple[TenantRouteInput, ...]


class RouteSnapshotTransaction(Protocol):
    """The exclusive repository surface needed for one stable snapshot."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def measure_inventory(self) -> StateInventory: ...


def snapshot_tenant_routes(
    transaction: RouteSnapshotTransaction,
    *,
    overlay: TenantRouteOverlay | None = None,
) -> TenantRouteSnapshot:
    """Read every tenant or substitute one explicit lifecycle candidate."""

    namespace = transaction.read(StateRecordPath.platform_namespace()).document
    validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    inventory = transaction.measure_inventory()
    candidate = None if overlay is None else _copy_tenant(overlay.tenant)
    source = None if overlay is None or overlay.source is None else _copy_tenant(overlay.source)
    overlay_id = None if candidate is None else _tenant_id(candidate)
    if overlay is not None:
        exists = overlay_id in inventory.tenant_ids
        if (overlay.mode is RouteOverlayMode.ADD) == exists:
            disposition = "already exists" if exists else "is absent"
            raise RouteSnapshotError(f"{overlay.mode.value} route overlay tenant {disposition}")

    tenants = []
    for tenant_id in inventory.tenant_ids:
        if tenant_id == overlay_id:
            if candidate is None:  # pragma: no cover - equality proves otherwise
                raise RouteSnapshotError("route overlay identity was lost")
            current = _read_tenant(transaction, tenant_id)
            if source is None or current != source:
                raise RouteSnapshotError(
                    "replace route overlay source changed before the locked snapshot"
                )
            tenants.append(candidate)
        else:
            tenants.append(_read_tenant(transaction, tenant_id))
    if overlay is not None and overlay.mode is RouteOverlayMode.ADD:
        if candidate is None:  # pragma: no cover - the add mode proves otherwise
            raise RouteSnapshotError("route overlay candidate was lost")
        tenants.append(candidate)
    tenants.sort(key=_tenant_id)
    return TenantRouteSnapshot(namespace, tuple(tenants))


def _read_tenant(
    transaction: RouteSnapshotTransaction,
    tenant_id: str,
) -> TenantRouteInput:
    manifest = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
    observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    if _manifest_tenant_id(manifest) != tenant_id:
        raise RouteSnapshotError("tenant desired-state identity disagrees with inventory")
    spec = cast(dict[str, object], manifest["spec"])
    desired = spec.get("desiredDeployment")
    if desired is None:
        deployment = None
    else:
        if type(desired) is not dict:  # pragma: no cover - schema validation proves this
            raise RouteSnapshotError("tenant desired deployment is malformed")
        deployment_id = validate_uuid7(desired["id"])
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, deployment_id)
        ).document
        validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    return _copy_tenant(TenantRouteInput(manifest, observed, deployment))


def _tenant_id(tenant: TenantRouteInput) -> str:
    return _manifest_tenant_id(tenant.manifest)


def _manifest_tenant_id(manifest: dict[str, object]) -> str:
    if type(manifest) is not dict:
        raise RouteSnapshotError("tenant route manifest is not an object")
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    metadata = cast(dict[str, object], manifest["metadata"])
    return validate_uuid7(metadata["id"])


def _copy_tenant(tenant: TenantRouteInput) -> TenantRouteInput:
    manifest = deepcopy(tenant.manifest)
    observed = deepcopy(tenant.observed_state)
    deployment = deepcopy(tenant.deployment)
    if type(manifest) is not dict or type(observed) is not dict:
        raise RouteSnapshotError("tenant route state is not a contract object")
    if deployment is not None and type(deployment) is not dict:
        raise RouteSnapshotError("tenant route deployment is not a contract object")
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    if deployment is not None:
        validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    return TenantRouteInput(manifest, observed, deployment)
