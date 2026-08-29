"""Strict, transport-independent static-publication contracts."""

from lowerduckpond_static_contracts.canonical import (
    MAX_CANONICAL_BYTES,
    MAX_RAW_REQUEST_BYTES,
    canonical_json_bytes,
    decode_json_object,
)
from lowerduckpond_static_contracts.digest import (
    Digest,
    manifest_digest,
    request_digest,
    result_digest,
)
from lowerduckpond_static_contracts.errors import ContractError, ErrorCode, ResultErrorCode
from lowerduckpond_static_contracts.identifiers import (
    RESERVED_SLUGS,
    validate_slug,
    validate_uuid7,
)
from lowerduckpond_static_contracts.lifecycle import (
    LIFECYCLE_MATRIX,
    TRANSACTION_PHASE_TRANSITIONS,
    LifecycleState,
    Operation,
    TransactionPhase,
)
from lowerduckpond_static_contracts.schema import (
    ContractKind,
    decode_contract,
    decode_request,
    decode_result,
    materialize_create_request,
    materialize_platform_namespace,
    validate_contract,
)
from lowerduckpond_static_contracts.values import (
    ValidatedCreateRequest,
    ValidatedPlatformNamespace,
)

__all__ = [
    "LIFECYCLE_MATRIX",
    "MAX_CANONICAL_BYTES",
    "MAX_RAW_REQUEST_BYTES",
    "RESERVED_SLUGS",
    "TRANSACTION_PHASE_TRANSITIONS",
    "ContractError",
    "ContractKind",
    "Digest",
    "ErrorCode",
    "LifecycleState",
    "Operation",
    "ResultErrorCode",
    "TransactionPhase",
    "ValidatedCreateRequest",
    "ValidatedPlatformNamespace",
    "canonical_json_bytes",
    "decode_contract",
    "decode_json_object",
    "decode_request",
    "decode_result",
    "manifest_digest",
    "materialize_create_request",
    "materialize_platform_namespace",
    "request_digest",
    "result_digest",
    "validate_contract",
    "validate_slug",
    "validate_uuid7",
]
