"""Versioned digest representations for canonical contract bytes."""

from __future__ import annotations

from lowerduckpond_static_contracts._digest import (
    ARCHIVE_RECORD_DIGEST_FORMAT,
    AUDIT_ENTRY_DIGEST_FORMAT,
    DEPLOYMENT_RECORD_DIGEST_FORMAT,
    MANIFEST_DIGEST_FORMAT,
    PLATFORM_STATE_DIGEST_FORMAT,
    REQUEST_DIGEST_FORMAT,
    RESULT_DIGEST_FORMAT,
    Digest,
    digest_bytes,
)
from lowerduckpond_static_contracts.canonical import canonical_json_bytes
from lowerduckpond_static_contracts.errors import ContractError, ErrorCode
from lowerduckpond_static_contracts.schema import ContractKind, validate_contract

__all__ = [
    "Digest",
    "archive_record_digest",
    "audit_entry_digest",
    "deployment_record_digest",
    "manifest_digest",
    "platform_state_digest",
    "request_digest",
    "result_digest",
]


def _contract_digest(
    document: object,
    *,
    kind: ContractKind,
    format_identifier: str,
    label: str,
) -> Digest:
    if type(document) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, f"{label} must be a contract object")
    validate_contract(document, expected_kind=kind)
    return digest_bytes(canonical_json_bytes(document), format_identifier=format_identifier)


def platform_state_digest(namespace: object) -> Digest:
    """Bind one exact canonical platform-namespace generation."""

    return _contract_digest(
        namespace,
        kind=ContractKind.PLATFORM_NAMESPACE,
        format_identifier=PLATFORM_STATE_DIGEST_FORMAT,
        label="platform namespace",
    )


def deployment_record_digest(deployment: object) -> Digest:
    """Bind one exact canonical deployment-record generation."""

    return _contract_digest(
        deployment,
        kind=ContractKind.DEPLOYMENT_RECORD,
        format_identifier=DEPLOYMENT_RECORD_DIGEST_FORMAT,
        label="deployment record",
    )


def archive_record_digest(archive: object) -> Digest:
    """Bind one exact canonical archive-record generation."""

    return _contract_digest(
        archive,
        kind=ContractKind.ARCHIVE_RECORD,
        format_identifier=ARCHIVE_RECORD_DIGEST_FORMAT,
        label="archive record",
    )


def audit_entry_digest(entry: object) -> Digest:
    """Compute the accepted v1 canonical audit-entry digest."""

    if type(entry) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "audit entry must be a contract object")
    validate_contract(entry, expected_kind=ContractKind.AUDIT_ENTRY)
    return digest_bytes(
        canonical_json_bytes(entry),
        format_identifier=AUDIT_ENTRY_DIGEST_FORMAT,
    )


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
