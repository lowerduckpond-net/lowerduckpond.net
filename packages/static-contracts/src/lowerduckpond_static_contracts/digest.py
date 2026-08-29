"""Versioned digest representations for canonical contract bytes."""

from __future__ import annotations

from lowerduckpond_static_contracts._digest import (
    MANIFEST_DIGEST_FORMAT,
    REQUEST_DIGEST_FORMAT,
    RESULT_DIGEST_FORMAT,
    Digest,
    digest_bytes,
)
from lowerduckpond_static_contracts.canonical import canonical_json_bytes
from lowerduckpond_static_contracts.errors import ContractError, ErrorCode
from lowerduckpond_static_contracts.schema import ContractKind, validate_contract

__all__ = ["Digest", "manifest_digest", "request_digest", "result_digest"]


def manifest_digest(manifest: object) -> Digest:
    """Compute the accepted v1 desired-manifest digest."""

    if type(manifest) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "manifest must be a contract object")
    validate_contract(manifest, expected_kind=ContractKind.SITE)

    return digest_bytes(
        canonical_json_bytes(manifest),
        format_identifier=MANIFEST_DIGEST_FORMAT,
    )


def request_digest(request: object) -> Digest:
    """Compute the accepted v1 canonical operation-request digest."""

    if type(request) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "request must be a contract object")
    validate_contract(request, expected_kind=ContractKind.OPERATION_REQUEST)
    return digest_bytes(canonical_json_bytes(request), format_identifier=REQUEST_DIGEST_FORMAT)


def result_digest(result: object) -> Digest:
    """Compute the accepted v1 canonical operation-result digest."""

    if type(result) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "result must be a contract object")
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    return digest_bytes(canonical_json_bytes(result), format_identifier=RESULT_DIGEST_FORMAT)
