"""Complete tenant route inputs captured under the authoritative-state lock."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    manifest_digest,
    validate_contract,
    validate_uuid7,
)

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
    """The namespace and every runtime-relevant input for one Caddy generation."""

    platform_namespace: dict[str, object]
    tenants: tuple[TenantRouteInput, ...]


class RouteSnapshotTransaction(Protocol):
    """The exclusive repository surface needed for one stable snapshot."""

    def read(self, path: StateRecordPath) -> StoredContract: ...

    def deployment_history_tenant_ids(
        self,
        tenant_ids: tuple[str, ...],
    ) -> frozenset[str]: ...

    def measure_inventory(self) -> StateInventory: ...


def snapshot_tenant_routes(
    transaction: RouteSnapshotTransaction,
    *,
    overlay: TenantRouteOverlay | None = None,
    observed_drift_tenant_id: object | None = None,
    deployment_transition_tenant_id: object | None = None,
) -> TenantRouteSnapshot:
    """Read every runtime tenant or substitute one explicit lifecycle candidate."""

    drift_tenant_id = (
        None if observed_drift_tenant_id is None else validate_uuid7(observed_drift_tenant_id)
    )
    transition_tenant_id = (
        None
        if deployment_transition_tenant_id is None
        else validate_uuid7(deployment_transition_tenant_id)
    )
    return _snapshot_tenants(
        transaction,
        overlay=overlay,
        include_archived=False,
        observed_drift_tenant_id=drift_tenant_id,
        deployment_transition_tenant_id=transition_tenant_id,
    )


def snapshot_tenant_authority(
    transaction: RouteSnapshotTransaction,
    *,
    observed_drift_tenant_id: object | None = None,
) -> TenantRouteSnapshot:
    """Read every validated tenant, including archived durable authority."""

    drift_tenant_id = (
        None if observed_drift_tenant_id is None else validate_uuid7(observed_drift_tenant_id)
    )
    return _snapshot_tenants(
        transaction,
        overlay=None,
        include_archived=True,
        observed_drift_tenant_id=drift_tenant_id,
        deployment_transition_tenant_id=None,
    )


def _snapshot_tenants(
    transaction: RouteSnapshotTransaction,
    *,
    overlay: TenantRouteOverlay | None,
    include_archived: bool,
    observed_drift_tenant_id: str | None,
    deployment_transition_tenant_id: str | None,
) -> TenantRouteSnapshot:
    """Capture one complete tenant view under the caller's exclusive lock."""

    namespace = transaction.read(StateRecordPath.platform_namespace()).document
    validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    inventory = transaction.measure_inventory()
    history_candidates = set(inventory.tenant_ids)
    if deployment_transition_tenant_id is not None:
        if deployment_transition_tenant_id not in history_candidates:
            raise RouteSnapshotError("deployment transition tenant is absent")
        # A durable deploy intent authorizes one candidate release and, during
        # terminal replay, one extra deployment record. Neither is historical
        # authority for deciding whether the still-undeployed source is valid.
        # The deployment commit path separately validates the exact candidate
        # and bounded transition history before either can become terminal.
        history_candidates.remove(deployment_transition_tenant_id)
    if overlay is not None and overlay.mode is RouteOverlayMode.ADD:
        history_candidates.add(_tenant_id(overlay.tenant))
    deployment_history = transaction.deployment_history_tenant_ids(
        tuple(sorted(history_candidates))
    )
    candidate, source = _prepare_overlay(overlay, inventory, deployment_history)
    overlay_id = None if candidate is None else _tenant_id(candidate)

    tenants: list[tuple[TenantRouteInput, bool]] = []
    for tenant_id in inventory.tenant_ids:
        if tenant_id == overlay_id:
            if candidate is None:  # pragma: no cover - equality proves otherwise
                raise RouteSnapshotError("route overlay identity was lost")
            current = _read_tenant(transaction, tenant_id, deployment_history)
            if source is None or current != source:
                raise RouteSnapshotError(
                    "replace route overlay source changed before the locked snapshot"
                )
            tenants.append(
                (
                    candidate,
                    _is_archived(
                        transaction,
                        candidate,
                        allow_observed_drift=(tenant_id == observed_drift_tenant_id),
                    ),
                )
            )
        else:
            current = _read_tenant(transaction, tenant_id, deployment_history)
            tenants.append(
                (
                    current,
                    _is_archived(
                        transaction,
                        current,
                        allow_observed_drift=(tenant_id == observed_drift_tenant_id),
                    ),
                )
            )
    if overlay is not None and overlay.mode is RouteOverlayMode.ADD:
        if candidate is None:  # pragma: no cover - the add mode proves otherwise
            raise RouteSnapshotError("route overlay candidate was lost")
        tenants.append(
            (
                candidate,
                _is_archived(
                    transaction,
                    candidate,
                    allow_observed_drift=(_tenant_id(candidate) == observed_drift_tenant_id),
                ),
            )
        )
    tenants.sort(key=lambda item: _tenant_id(item[0]))
    _require_unique_slugs(tuple(tenant for tenant, _archived in tenants))
    selected = (
        tuple(tenant for tenant, _archived in tenants)
        if include_archived
        else tuple(tenant for tenant, archived in tenants if not archived)
    )
    return TenantRouteSnapshot(namespace, selected)


def _prepare_overlay(
    overlay: TenantRouteOverlay | None,
    inventory: StateInventory,
    deployment_history: frozenset[str],
) -> tuple[TenantRouteInput | None, TenantRouteInput | None]:
    if overlay is None:
        return None, None
    candidate = _copy_tenant(overlay.tenant)
    source = None if overlay.source is None else _copy_tenant(overlay.source)
    exists = _tenant_id(candidate) in inventory.tenant_ids
    if (overlay.mode is RouteOverlayMode.ADD) == exists:
        disposition = "already exists" if exists else "is absent"
        raise RouteSnapshotError(f"{overlay.mode.value} route overlay tenant {disposition}")
    _reject_undeployed_history(candidate, deployment_history)
    return candidate, source


def _read_tenant(
    transaction: RouteSnapshotTransaction,
    tenant_id: str,
    deployment_history: frozenset[str],
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
    tenant = _copy_tenant(TenantRouteInput(manifest, observed, deployment))
    _reject_undeployed_history(tenant, deployment_history)
    return tenant


def _reject_undeployed_history(
    tenant: TenantRouteInput,
    deployment_history: frozenset[str],
) -> None:
    spec = cast(dict[str, object], tenant.manifest["spec"])
    if spec["desiredState"] == "undeployed" and _tenant_id(tenant) in deployment_history:
        raise RouteSnapshotError("undeployed tenant retains deployment history")


def _tenant_id(tenant: TenantRouteInput) -> str:
    return _manifest_tenant_id(tenant.manifest)


def _require_unique_slugs(tenants: tuple[TenantRouteInput, ...]) -> None:
    slugs: set[str] = set()
    for tenant in tenants:
        metadata = tenant.manifest.get("metadata")
        if type(metadata) is not dict:  # pragma: no cover - route input was validated
            raise RouteSnapshotError("tenant route metadata is malformed")
        slug = cast(str, metadata["slug"])
        if slug in slugs:
            raise RouteSnapshotError("tenant slug namespace is ambiguous")
        slugs.add(slug)


def _is_archived(
    transaction: RouteSnapshotTransaction,
    tenant: TenantRouteInput,
    *,
    allow_observed_drift: bool,
) -> bool:
    spec = tenant.manifest.get("spec")
    if type(spec) is not dict:  # pragma: no cover - copied route input was validated
        raise RouteSnapshotError("tenant route manifest spec is malformed")
    if spec.get("desiredState") != "archived":
        _reject_live_archive_binding(transaction, tenant)
        return False
    _validate_archived_bindings(
        transaction,
        tenant,
        spec,
        allow_observed_drift=allow_observed_drift,
    )
    return True


def _reject_live_archive_binding(
    transaction: RouteSnapshotTransaction,
    tenant: TenantRouteInput,
) -> None:
    deployment = tenant.deployment
    if deployment is None:
        return
    tenant_id = _tenant_id(tenant)
    deployment_id = validate_uuid7(deployment["id"])
    try:
        transaction.read(StateRecordPath.tenant_archive(tenant_id, deployment_id))
    except FileNotFoundError:
        return
    raise RouteSnapshotError("live tenant retained an archive record")


def _validate_archived_bindings(
    transaction: RouteSnapshotTransaction,
    tenant: TenantRouteInput,
    spec: dict[str, object],
    *,
    allow_observed_drift: bool,
) -> None:
    tenant_id = _tenant_id(tenant)
    observed = tenant.observed_state
    deployment = tenant.deployment
    if observed["tenantId"] != tenant_id:
        raise RouteSnapshotError("archived tenant observed-state identity drifted")
    if not allow_observed_drift and (
        observed["desiredManifestDigest"] != manifest_digest(tenant.manifest).to_dict()
        or observed["observedState"] != "archived"
        or observed["activeDeploymentId"] is not None
        or observed["runtimeGenerationId"] is not None
    ):
        raise RouteSnapshotError("archived tenant desired and observed state disagree")
    desired = spec.get("desiredDeployment")
    if deployment is None or type(desired) is not dict:
        raise RouteSnapshotError("archived tenant omitted its selected deployment")
    if (
        deployment["tenantId"] != tenant_id
        or deployment["id"] != desired["id"]
        or deployment["archiveSha256"] != desired["archiveSha256"]
    ):
        raise RouteSnapshotError("archived tenant deployment binding drifted")
    deployment_id = validate_uuid7(deployment["id"])
    try:
        archive = transaction.read(
            StateRecordPath.tenant_archive(tenant_id, deployment_id)
        ).document
    except FileNotFoundError as error:
        raise RouteSnapshotError("archived tenant omitted its archive record") from error
    validate_contract(archive, expected_kind=ContractKind.ARCHIVE_RECORD)
    if (
        archive["tenantId"] != tenant_id
        or archive["deploymentId"] != deployment_id
        or archive["releaseTreeDigest"] != deployment["releaseTreeDigest"]
        or archive["manifestDigest"] != manifest_digest(tenant.manifest).to_dict()
    ):
        raise RouteSnapshotError("archived tenant archive binding drifted")


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
