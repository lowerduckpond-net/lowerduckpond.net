"""Immutable values projected from schema-validated contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts.errors import ContractError, ErrorCode
from lowerduckpond_static_contracts.identifiers import TENANT_ORIGIN_SUFFIX, validate_slug

MINIMUM_QUOTA: Final = 1
MAXIMUM_STORAGE_MIB: Final = 100
MAXIMUM_ENTRIES: Final = 5000


@dataclass(frozen=True, slots=True)
class ValidatedCreateRequest:
    """Caller choices from one schema-validated create request."""

    slug: str
    storage_mib: int
    entries: int

    def __post_init__(self) -> None:
        validate_slug(self.slug)
        if type(self.storage_mib) is not int or not (
            MINIMUM_QUOTA <= self.storage_mib <= MAXIMUM_STORAGE_MIB
        ):
            raise ContractError(ErrorCode.SCHEMA_INVALID, "storage quota is invalid")
        if type(self.entries) is not int or not (MINIMUM_QUOTA <= self.entries <= MAXIMUM_ENTRIES):
            raise ContractError(ErrorCode.SCHEMA_INVALID, "entry quota is invalid")


@dataclass(frozen=True, slots=True)
class ValidatedPlatformNamespace:
    """Origin input from one schema-validated platform namespace."""

    tenant_origin_suffix: str

    def __post_init__(self) -> None:
        if self.tenant_origin_suffix != TENANT_ORIGIN_SUFFIX:
            raise ContractError(ErrorCode.INVALID_NAMESPACE, "tenant-origin suffix is not pinned")
