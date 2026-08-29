"""Stable error identifiers shared by static-publication peers."""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    """Version-one errors safe to return without reflecting submitted input."""

    CANONICAL_TOO_LARGE = "contract.canonical_too_large"
    CALLER_SELECTED_IDENTITY = "contract.caller_selected_identity"
    DUPLICATE_JSON_MEMBER = "contract.duplicate_json_member"
    DUPLICATE_YAML_KEY = "client.duplicate_yaml_key"
    INVALID_CANONICAL_ORIGIN = "contract.invalid_canonical_origin"
    INVALID_CLOCK = "contract.invalid_clock"
    INVALID_ENTROPY = "contract.invalid_entropy"
    INVALID_IDENTIFIER = "contract.invalid_identifier"
    INVALID_JSON = "contract.invalid_json"
    INVALID_NAMESPACE = "contract.invalid_namespace"
    INVALID_SLUG = "contract.invalid_slug"
    INVALID_UTF8 = "contract.invalid_utf8"
    INVALID_YAML = "client.invalid_yaml"
    LIFECYCLE_DENIED = "contract.lifecycle_denied"
    RAW_REQUEST_TOO_LARGE = "contract.raw_request_too_large"
    RESERVED_SLUG = "contract.reserved_slug"
    SCHEMA_INVALID = "contract.schema_invalid"
    STANDALONE_MANIFEST_FRAME = "contract.standalone_manifest_frame"
    UNKNOWN_FIELD = "contract.unknown_field"
    UNKNOWN_KIND = "contract.unknown_kind"
    UNSUPPORTED_VERSION = "contract.unsupported_version"


class ResultErrorCode(StrEnum):
    """Bounded operation failures that may appear in an immutable result."""

    ARCHIVE_UNAVAILABLE = "archive_unavailable"
    BUSY = "busy"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    CONFLICT = "conflict"
    DENIED = "denied"
    INVALID_ARTIFACT = "invalid_artifact"
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    NOT_IMPLEMENTED = "not_implemented"
    PUBLICATION_DISABLED = "publication_disabled"
    STATE_DRIFT = "state_drift"
    UNAVAILABLE = "unavailable"


class ContractError(ValueError):
    """A deterministic contract rejection with a non-reflective explanation."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
