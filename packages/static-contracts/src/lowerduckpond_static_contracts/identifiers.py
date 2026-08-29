"""Canonical UUID, slug, namespace, and hostname validation."""

from __future__ import annotations

import re
import uuid
from typing import Final

from lowerduckpond_static_contracts.errors import ContractError, ErrorCode

UUID7_PATTERN: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    flags=re.ASCII,
)
SLUG_PATTERN: Final = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    flags=re.ASCII,
)
CANONICAL_ORIGIN_SLUG_PATTERN: Final = re.compile(r"t-[0-9a-f]{32}", flags=re.ASCII)
DNS_LABEL_PATTERN: Final = SLUG_PATTERN
RESERVED_SLUGS: Final = frozenset({"hosting", "secure", "www"})
MAX_DNS_HOSTNAME_BYTES: Final = 253
MAX_DNS_LABEL_BYTES: Final = 63
MINIMUM_SUFFIX_LABELS: Final = 2
UUID_VERSION: Final = 7


def validate_uuid7(value: object) -> str:
    """Require the one lowercase, hyphenated UUIDv7 representation."""

    if type(value) is not str or UUID7_PATTERN.fullmatch(value) is None:
        raise ContractError(ErrorCode.INVALID_IDENTIFIER, "identifier is not a canonical UUIDv7")
    parsed = uuid.UUID(value)
    if parsed.version != UUID_VERSION or str(parsed) != value:
        raise ContractError(ErrorCode.INVALID_IDENTIFIER, "identifier is not a canonical UUIDv7")
    return value


def validate_slug(value: object) -> str:
    """Validate a caller-selectable slug and its committed reservations."""

    if type(value) is not str:
        raise ContractError(ErrorCode.INVALID_SLUG, "slug must be an ASCII string")
    try:
        length = len(value.encode("ascii", errors="strict"))
    except UnicodeEncodeError as error:
        raise ContractError(ErrorCode.INVALID_SLUG, "slug must contain only ASCII") from error
    if not 1 <= length <= MAX_DNS_LABEL_BYTES or SLUG_PATTERN.fullmatch(value) is None:
        raise ContractError(ErrorCode.INVALID_SLUG, "slug is not one canonical DNS label")
    if value in RESERVED_SLUGS or CANONICAL_ORIGIN_SLUG_PATTERN.fullmatch(value) is not None:
        raise ContractError(ErrorCode.RESERVED_SLUG, "slug is reserved by the platform")
    return value


def validate_tenant_origin_suffix(value: object) -> str:
    """Require a normalized multi-label DNS suffix within the full hostname limit."""

    if type(value) is not str or len(value.encode("utf-8")) > MAX_DNS_HOSTNAME_BYTES:
        raise ContractError(ErrorCode.INVALID_NAMESPACE, "tenant-origin suffix is invalid")
    labels = value.split(".")
    if len(labels) < MINIMUM_SUFFIX_LABELS or any(
        DNS_LABEL_PATTERN.fullmatch(label) is None for label in labels
    ):
        raise ContractError(ErrorCode.INVALID_NAMESPACE, "tenant-origin suffix is invalid")
    return value
