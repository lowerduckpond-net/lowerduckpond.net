"""The pure root-owned create operation's identity and manifest constructor."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Final, cast

from lowerduckpond_static_contracts import (
    ContractError,
    ContractKind,
    ErrorCode,
    validate_contract,
)
from lowerduckpond_static_contracts.identifiers import (
    MAX_DNS_HOSTNAME_BYTES,
    validate_tenant_origin_suffix,
)

from lowerduckpond_static_domain.identity import EntropySource, MillisecondClock, generate_uuid7

TENANT_ORIGIN_LABEL_PREFIX: Final = "t-"


@dataclass(frozen=True, slots=True)
class CreatedTenant:
    """One generated identity and its complete undeployed desired manifest."""

    tenant_id: str
    canonical_origin: str
    manifest: dict[str, object]


def _canonical_origin(tenant_id: str, suffix: str) -> str:
    origin = f"{TENANT_ORIGIN_LABEL_PREFIX}{tenant_id.replace('-', '')}.{suffix}"
    try:
        encoded = origin.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise ContractError(
            ErrorCode.INVALID_CANONICAL_ORIGIN,
            "canonical origin is not ASCII",
        ) from error
    if len(encoded) > MAX_DNS_HOSTNAME_BYTES:
        raise ContractError(
            ErrorCode.INVALID_CANONICAL_ORIGIN,
            "canonical origin exceeds the DNS hostname limit",
        )
    return origin


def construct_create_manifest(
    request: dict[str, object],
    namespace: dict[str, object],
    *,
    clock: MillisecondClock,
    entropy: EntropySource,
) -> CreatedTenant:
    """Generate identity and desired state from validated choices and pinned namespace."""

    if any(field in request for field in ("id", "tenantId", "canonicalOrigin", "manifest")):
        raise ContractError(
            ErrorCode.CALLER_SELECTED_IDENTITY,
            "create cannot select identity, origin, or desired state",
        )
    validate_contract(request, expected_kind=ContractKind.OPERATION_REQUEST)
    if request["operation"] != "create":
        raise ContractError(ErrorCode.SCHEMA_INVALID, "request is not a create operation")
    validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    suffix = validate_tenant_origin_suffix(namespace["tenantOriginSuffix"])
    tenant_id = generate_uuid7(clock=clock, entropy=entropy)
    origin = _canonical_origin(tenant_id, suffix)
    quotas = deepcopy(cast(dict[str, object], request["quotas"]))
    manifest: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "Site",
        "metadata": {
            "id": tenant_id,
            "slug": request["slug"],
            "canonicalOrigin": origin,
        },
        "spec": {
            "runtime": "static",
            "desiredState": "undeployed",
            "quotas": quotas,
        },
    }
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    return CreatedTenant(tenant_id=tenant_id, canonical_origin=origin, manifest=manifest)
