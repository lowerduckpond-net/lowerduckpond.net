"""Derive one complete tenant Caddy generation from pinned runtime inputs."""

from __future__ import annotations

import os

from lowerduckpond_static_contracts import ContractError, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_CONFIGURATION_NAME,
    MAX_CADDY_CONFIGURATION_BYTES,
    CaddyDerivedGenerationPayload,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.caddy_routes import (
    CaddyRouteError,
    build_tenant_caddy_routes,
    configured_origin_pull_policy,
)
from lowerduckpond_static_host_agent.route_snapshot import TenantRouteSnapshot


class TenantGenerationError(RuntimeError):
    """A complete tenant snapshot cannot become one safe runtime generation."""


def derive_tenant_generation_payload(
    source: PinnedCaddyGeneration,
    snapshot: TenantRouteSnapshot,
    *,
    candidate_generation_id: object,
) -> CaddyDerivedGenerationPayload:
    """Replace routes while retaining the exact pinned host binary and environment."""

    if type(source) is not PinnedCaddyGeneration:
        raise TypeError("tenant generation source must be one pinned Caddy generation")
    if type(snapshot) is not TenantRouteSnapshot:
        raise TypeError("tenant generation snapshot must be one complete route snapshot")
    try:
        candidate_id = validate_uuid7(candidate_generation_id)
    except ContractError as error:
        raise TenantGenerationError("candidate generation ID is not a canonical UUIDv7") from error
    if source.manifest.generation_id == candidate_id:
        raise TenantGenerationError("candidate generation must differ from its source")

    descriptor = source.duplicate_payload_descriptor(CADDY_CONFIGURATION_NAME)
    try:
        configuration = decode_json_object(
            os.pread(descriptor, MAX_CADDY_CONFIGURATION_BYTES + 1, 0),
            maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES,
        )
    except ContractError as error:
        raise TenantGenerationError("source Caddy configuration is malformed") from error
    finally:
        os.close(descriptor)

    try:
        origin_pull_ca_der, origin_pull_required = configured_origin_pull_policy(configuration)
        routes = build_tenant_caddy_routes(
            platform_namespace=snapshot.platform_namespace,
            tenants=snapshot.tenants,
            runtime_generation_id=candidate_id,
            origin_pull_ca_der=origin_pull_ca_der,
            origin_pull_required=origin_pull_required,
        )
    except CaddyRouteError as error:
        raise TenantGenerationError("tenant Caddy route derivation failed") from error
    return CaddyDerivedGenerationPayload(
        source=source,
        configuration=routes.configuration,
        route_metadata=routes.route_metadata,
    )
