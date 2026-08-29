"""The pure root-owned create operation's identity and manifest constructor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts import (
    ContractError,
    ErrorCode,
    ValidatedCreateRequest,
    ValidatedPlatformNamespace,
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
    request: ValidatedCreateRequest,
    namespace: ValidatedPlatformNamespace,
    *,
    clock: MillisecondClock,
    entropy: EntropySource,
) -> CreatedTenant:
    """Generate identity and desired state from validated choices and pinned namespace."""

    suffix = validate_tenant_origin_suffix(namespace.tenant_origin_suffix)
    tenant_id = generate_uuid7(clock=clock, entropy=entropy)
    origin = _canonical_origin(tenant_id, suffix)
    quotas: dict[str, object] = {
        "storageMiB": request.storage_mib,
        "entries": request.entries,
    }
    manifest: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "Site",
        "metadata": {
            "id": tenant_id,
            "slug": request.slug,
            "canonicalOrigin": origin,
        },
        "spec": {
            "runtime": "static",
            "desiredState": "undeployed",
            "quotas": quotas,
        },
    }
    return CreatedTenant(tenant_id=tenant_id, canonical_origin=origin, manifest=manifest)
