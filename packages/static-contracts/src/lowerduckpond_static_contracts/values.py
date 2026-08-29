"""Immutable values projected from schema-validated contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ValidatedCreateRequest:
    """Caller choices from one schema-validated create request."""

    slug: str
    storage_mib: int
    entries: int


@dataclass(frozen=True, slots=True)
class ValidatedPlatformNamespace:
    """Origin input from one schema-validated platform namespace."""

    tenant_origin_suffix: str
