"""Prove captured Caddy selection from complete non-secret tenant route inputs."""

from __future__ import annotations

from collections.abc import Mapping

from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.caddy_routes import (
    build_platform_only_caddy_routes,
    build_tenant_caddy_routes,
)
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.route_snapshot import TenantRouteSnapshot


def require_captured_selection(
    evidence: CaddyBackupEvidence,
    choices: Mapping[str, tuple[str, TenantRouteSnapshot]],
    original_origin_pull_ca_der: tuple[bytes, ...],
) -> str:
    """No restored adapted config or newly generated manifest impersonates an old one."""
    matches = [
        (name, state)
        for name, (identifier, state) in choices.items()
        if identifier == evidence.selected_target.generation_id
    ]
    if len(matches) != 1:
        raise HostRestoreError("restore_lifecycle_selection_unavailable")
    name, state = matches[0]
    selected = next(row for row in evidence.generations if row.target == evidence.selected_target)
    routes = build_tenant_caddy_routes(
        platform_namespace=state.platform_namespace,
        tenants=state.tenants,
        runtime_generation_id=selected.target.generation_id,
        origin_pull_ca_der=original_origin_pull_ca_der,
        origin_pull_required=True,
    )
    if routes.route_metadata["routeStateDigest"] != selected.route_state_digest:
        if (
            not state.tenants
            and build_platform_only_caddy_routes(
                origin_pull_ca_der=original_origin_pull_ca_der,
                origin_pull_required=True,
            ).route_metadata["routeStateDigest"]
            == selected.route_state_digest
        ):
            return name
        raise HostRestoreError("restore_lifecycle_route_proof_mismatch")
    return name
