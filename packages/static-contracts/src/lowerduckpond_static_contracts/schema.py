"""Strict schema registry and semantic contract validation."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from enum import StrEnum
from functools import cache
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Final, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from lowerduckpond_static_contracts._digest import REQUEST_DIGEST_FORMAT, digest_bytes
from lowerduckpond_static_contracts.canonical import (
    MAX_CANONICAL_BYTES,
    MAX_RAW_REQUEST_BYTES,
    canonical_json_bytes,
    decode_json_object,
)
from lowerduckpond_static_contracts.errors import ContractError, ErrorCode
from lowerduckpond_static_contracts.identifiers import (
    validate_canonical_origin,
    validate_slug,
    validate_uuid7,
)

API_VERSION: Final = "hosting.lowerduckpond.net/v1alpha1"
SCHEMA_DIRECTORY: Final = files("lowerduckpond_static_contracts").joinpath("schemas")


class ContractKind(StrEnum):
    """Every persisted or transported v1alpha1 contract kind."""

    PLATFORM_NAMESPACE = "PlatformNamespace"
    LAUNCH_RECORD = "LaunchRecord"
    SITE = "Site"
    TENANT_OBSERVED_STATE = "TenantObservedState"
    DEPLOYMENT_RECORD = "DeploymentRecord"
    ARCHIVE_RECORD = "ArchiveRecord"
    OPERATION_REQUEST = "OperationRequest"
    AUTHORIZATION_JOB = "AuthorizationJob"
    TRANSACTION_INTENT = "TransactionIntent"
    AUDIT_ENTRY = "AuditEntry"
    OPERATION_RESULT = "OperationResult"


SCHEMA_FILE_BY_KIND: Final = {
    ContractKind.PLATFORM_NAMESPACE: "platform-namespace.schema.json",
    ContractKind.LAUNCH_RECORD: "launch-record.schema.json",
    ContractKind.SITE: "site.schema.json",
    ContractKind.TENANT_OBSERVED_STATE: "tenant-observed-state.schema.json",
    ContractKind.DEPLOYMENT_RECORD: "deployment-record.schema.json",
    ContractKind.ARCHIVE_RECORD: "archive-record.schema.json",
    ContractKind.OPERATION_REQUEST: "operation-request.schema.json",
    ContractKind.AUTHORIZATION_JOB: "authorization-job.schema.json",
    ContractKind.TRANSACTION_INTENT: "transaction-intent.schema.json",
    ContractKind.AUDIT_ENTRY: "audit-entry.schema.json",
    ContractKind.OPERATION_RESULT: "operation-result.schema.json",
}


def _read_schema(path: Traversable) -> dict[str, object]:
    try:
        return decode_json_object(path.read_bytes(), maximum_bytes=128 * 1024)
    except ContractError as error:
        raise RuntimeError(f"schema is not strict JSON: {path.name}") from error


@cache
def _schema_documents() -> dict[str, dict[str, object]]:
    documents: dict[str, dict[str, object]] = {}
    paths = sorted(
        (path for path in SCHEMA_DIRECTORY.iterdir() if path.name.endswith(".schema.json")),
        key=lambda path: path.name,
    )
    for path in paths:
        document = _read_schema(path)
        identifier = document.get("$id")
        if type(identifier) is not str or identifier in documents:
            raise RuntimeError(f"schema has an invalid identifier: {path.name}")
        Draft202012Validator.check_schema(document)
        documents[identifier] = document
    expected = len(SCHEMA_FILE_BY_KIND) + 1
    if len(documents) != expected:
        raise RuntimeError(f"expected {expected} static-publication schemas")
    return documents


@cache
def _registry() -> Registry[dict[str, object]]:
    resources = [
        (identifier, Resource.from_contents(document))
        for identifier, document in _schema_documents().items()
    ]
    return Registry().with_resources(resources)


@cache
def _cached_schema(kind: ContractKind) -> dict[str, object]:
    path = SCHEMA_DIRECTORY / SCHEMA_FILE_BY_KIND[kind]
    return _read_schema(path)


def schema_for(kind: ContractKind) -> dict[str, object]:
    """Load an independently schema-checked contract without exposing cached state."""

    return deepcopy(_cached_schema(kind))


@cache
def _validator(kind: ContractKind) -> Draft202012Validator:
    schema = _cached_schema(kind)
    return Draft202012Validator(
        schema,
        registry=_registry(),  # type: ignore[arg-type]  # jsonschema stub is wider
        format_checker=FormatChecker(),
    )


def _validation_error_code(error: ValidationError) -> ErrorCode:
    if error.validator == "additionalProperties":
        return ErrorCode.UNKNOWN_FIELD
    return ErrorCode.SCHEMA_INVALID


def _require_supported_identity(document: dict[str, object]) -> ContractKind:
    version = document.get("apiVersion")
    if version != API_VERSION:
        raise ContractError(
            ErrorCode.UNSUPPORTED_VERSION,
            "contract version is not supported",
        )
    kind_value = document.get("kind")
    if type(kind_value) is not str:
        raise ContractError(ErrorCode.UNKNOWN_KIND, "contract kind is not supported")
    try:
        return ContractKind(kind_value)
    except (TypeError, ValueError) as error:
        raise ContractError(ErrorCode.UNKNOWN_KIND, "contract kind is not supported") from error


def _validate_namespace(document: dict[str, object]) -> None:
    if document["tenantOriginSuffix"] != "lowerduckpond.com":
        raise ContractError(ErrorCode.INVALID_NAMESPACE, "tenant namespace is not accepted")


def _validate_site(document: dict[str, object]) -> None:
    metadata = cast(dict[str, object], document["metadata"])
    tenant_id = validate_uuid7(metadata["id"])
    validate_slug(metadata["slug"])
    validate_canonical_origin(tenant_id, metadata["canonicalOrigin"])


def _validate_request(document: dict[str, object]) -> None:
    validate_uuid7(document["correlationId"])
    operation = cast(str, document["operation"])
    if operation == "create":
        validate_slug(document["slug"])
    else:
        validate_uuid7(document["tenantId"])
    if operation == "rename":
        validate_slug(document["slug"])
    if operation == "rollback":
        validate_uuid7(document["deploymentId"])


def _validate_job(document: dict[str, object]) -> None:
    request = cast(dict[str, object], document["request"])
    _validate_request(request)
    expected_request_digest = digest_bytes(
        canonical_json_bytes(request),
        format_identifier=REQUEST_DIGEST_FORMAT,
    ).to_dict()
    if document["requestDigest"] != expected_request_digest:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "job request digest binding does not match")
    if document["artifact"] != request.get("artifact"):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "job artifact binding does not match")
    expected = cast(dict[str, object], document["expectedSource"])
    if request["operation"] == "create":
        if expected != {
            "expectsTenantAbsent": True,
            "lifecycle": None,
            "manifestDigest": None,
            "deploymentDigest": None,
            "archiveRecordDigest": None,
            "platformStateDigest": expected["platformStateDigest"],
        }:
            raise ContractError(ErrorCode.SCHEMA_INVALID, "create job source binding is invalid")
        return
    if expected["expectsTenantAbsent"] is not False or expected["manifestDigest"] is None:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "tenant job source binding is invalid")
    lifecycle = expected["lifecycle"]
    deployment = expected["deploymentDigest"]
    archive = expected["archiveRecordDigest"]
    if lifecycle not in {"undeployed", "active", "suspended", "archived"}:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "tenant source lifecycle is absent")
    if lifecycle == "undeployed" and (deployment is not None or archive is not None):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "undeployed source binding is invalid")
    if lifecycle in {"active", "suspended"} and (deployment is None or archive is not None):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "deployed source binding is invalid")
    if lifecycle == "archived" and (deployment is None or archive is None):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archived source binding is invalid")


def _validate_result(document: dict[str, object]) -> None:
    if "manifest" not in document:
        return
    manifest = cast(dict[str, object], document["manifest"])
    _validate_site(manifest)
    metadata = cast(dict[str, object], manifest["metadata"])
    if document["tenantId"] != metadata["id"]:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "result tenant identity does not match")
    if document.get("canonicalOrigin") != metadata["canonicalOrigin"]:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "result tenant origin does not match")


_SEMANTIC_VALIDATORS: Final[dict[ContractKind, Callable[[dict[str, object]], None]]] = {
    ContractKind.PLATFORM_NAMESPACE: _validate_namespace,
    ContractKind.SITE: _validate_site,
    ContractKind.OPERATION_REQUEST: _validate_request,
    ContractKind.AUTHORIZATION_JOB: _validate_job,
    ContractKind.OPERATION_RESULT: _validate_result,
}


def _semantic_validation(document: dict[str, object], kind: ContractKind) -> None:
    validator = _SEMANTIC_VALIDATORS.get(kind)
    if validator is not None:
        validator(document)
    for field in ("id", "tenantId", "deploymentId", "jobId", "intentId", "correlationId"):
        value = document.get(field)
        if value is not None:
            validate_uuid7(value)


def validate_contract(
    document: dict[str, object],
    *,
    expected_kind: ContractKind | None = None,
) -> ContractKind:
    """Validate shape, types, identifiers, reservations, and canonical size."""

    kind = _require_supported_identity(document)
    if expected_kind is not None and kind is not expected_kind:
        raise ContractError(ErrorCode.UNKNOWN_KIND, "contract kind is not the expected kind")
    errors = sorted(_validator(kind).iter_errors(document), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        raise ContractError(_validation_error_code(error), "contract does not match its schema")
    _semantic_validation(document, kind)
    canonical_json_bytes(document)
    return kind


def decode_contract(
    raw: bytes,
    *,
    expected_kind: ContractKind | None = None,
    maximum_raw_bytes: int = MAX_RAW_REQUEST_BYTES,
) -> dict[str, object]:
    """Decode and strictly validate one v1alpha1 contract."""

    document = decode_json_object(raw, maximum_bytes=maximum_raw_bytes)
    validate_contract(document, expected_kind=expected_kind)
    return document


def decode_request(raw: bytes) -> dict[str, object]:
    """Decode a host request and explicitly reject the retired manifest frame."""

    document = decode_json_object(raw, maximum_bytes=MAX_RAW_REQUEST_BYTES)
    if document.get("kind") == ContractKind.SITE:
        raise ContractError(
            ErrorCode.STANDALONE_MANIFEST_FRAME,
            "a desired manifest is not an operation request",
        )
    if document.get("operation") == "create" and any(
        field in document for field in ("id", "tenantId", "canonicalOrigin")
    ):
        raise ContractError(
            ErrorCode.CALLER_SELECTED_IDENTITY,
            "create cannot select tenant identity or origin",
        )
    validate_contract(document, expected_kind=ContractKind.OPERATION_REQUEST)
    return document


def decode_result(raw: bytes) -> dict[str, object]:
    """Decode a canonical-size operation result."""

    return decode_contract(
        raw,
        expected_kind=ContractKind.OPERATION_RESULT,
        maximum_raw_bytes=MAX_CANONICAL_BYTES,
    )
