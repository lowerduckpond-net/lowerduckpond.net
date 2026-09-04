"""Strict schema registry and semantic contract validation."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from enum import StrEnum
from functools import cache
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Final, cast

from jsonschema import Draft202012Validator, FormatChecker, validators
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from lowerduckpond_static_contracts._digest import (
    ARCHIVE_RECORD_DIGEST_FORMAT,
    MANIFEST_DIGEST_FORMAT,
    REQUEST_DIGEST_FORMAT,
    digest_bytes,
)
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
from lowerduckpond_static_contracts.lifecycle import (
    LIFECYCLE_MATRIX,
    LifecycleState,
    Operation,
    TransactionPhase,
)
from lowerduckpond_static_contracts.values import (
    ValidatedCreateRequest,
    ValidatedPlatformNamespace,
)

API_VERSION: Final = "hosting.lowerduckpond.net/v1alpha1"
SCHEMA_DIRECTORY: Final = files("lowerduckpond_static_contracts").joinpath("schemas")
STRICT_DRAFT_202012_VALIDATOR: Final[type[Draft202012Validator]] = cast(
    type[Draft202012Validator],
    validators.extend(  # type: ignore[no-untyped-call]
        Draft202012Validator,
        type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
            "integer",
            lambda _checker, value: type(value) is int,
        ),
    ),
)


class ContractKind(StrEnum):
    """Every persisted or transported v1alpha1 contract kind."""

    PLATFORM_NAMESPACE = "PlatformNamespace"
    LAUNCH_RECORD = "LaunchRecord"
    SITE = "Site"
    TENANT_OBSERVED_STATE = "TenantObservedState"
    DEPLOYMENT_RECORD = "DeploymentRecord"
    ARCHIVE_RECORD = "ArchiveRecord"
    ARCHIVE_CONSTRUCTION_INTENT = "ArchiveConstructionIntent"
    ARCHIVE_RETIREMENT_INTENT = "ArchiveRetirementIntent"
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
    ContractKind.ARCHIVE_CONSTRUCTION_INTENT: "archive-construction-intent.schema.json",
    ContractKind.ARCHIVE_RETIREMENT_INTENT: "archive-retirement-intent.schema.json",
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
    return STRICT_DRAFT_202012_VALIDATOR(
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
    _validate_job_source_authority(document, request, expected)
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
    _validate_job_deletion_authority(
        document,
        request,
        expected,
        lifecycle,
        archive,
    )


def _validate_job_source_authority(
    document: dict[str, object],
    request: dict[str, object],
    expected: dict[str, object],
) -> None:
    if document["compatibilityVersion"] == "static-job-v1":
        if "sourceAuthority" in document:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "legacy job carries current source authority",
            )
        return
    authority = document["sourceAuthority"]
    if request["operation"] == "create":
        if authority is not None:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "create job carries tenant source authority",
            )
        return
    if type(authority) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "tenant job source authority is absent")
    manifest = cast(dict[str, object], authority["manifest"])
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    manifest_binding = digest_bytes(
        canonical_json_bytes(manifest),
        format_identifier=MANIFEST_DIGEST_FORMAT,
    ).to_dict()
    archive = authority["archiveRecord"]
    if (
        metadata["id"] != request["tenantId"]
        or spec["desiredState"] != expected["lifecycle"]
        or manifest_binding != expected["manifestDigest"]
    ):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "tenant job source authority disagrees")
    if expected["lifecycle"] != "archived":
        if archive is not None:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "non-archived job carries archive source authority",
            )
        return
    reference = cast(dict[str, object], spec["desiredDeployment"])
    if type(archive) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archived job source authority is absent")
    archive_binding = digest_bytes(
        canonical_json_bytes(archive),
        format_identifier=ARCHIVE_RECORD_DIGEST_FORMAT,
    ).to_dict()
    if (
        archive_binding != expected["archiveRecordDigest"]
        or archive["tenantId"] != request["tenantId"]
        or archive["deploymentId"] != reference["id"]
        or archive["manifestDigest"] != manifest_binding
    ):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archived job source authority disagrees")


def _validate_job_deletion_authority(
    document: dict[str, object],
    request: dict[str, object],
    expected: dict[str, object],
    lifecycle: object,
    archive_digest: object,
) -> None:
    operation = request["operation"]
    if operation != "delete":
        if "deletionEvidence" in expected:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "non-delete job carries deletion evidence",
            )
        return
    if "deletionEvidence" not in expected:
        if document["compatibilityVersion"] == "static-job-v1":
            return
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "delete job has no durable deletion authority",
        )
    deletion = expected["deletionEvidence"]
    if lifecycle in {"active", "suspended"}:
        if deletion is not None:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "ineligible delete source carries deletion evidence",
            )
        return
    if type(deletion) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "delete source evidence is absent")
    if document["compatibilityVersion"] == "static-job-v1":
        _validate_legacy_job_deletion_authority(deletion, lifecycle, archive_digest)
        return
    expected_deletion = _current_job_deletion_authority(
        document.get("sourceAuthority"),
        lifecycle,
        archive_digest,
    )
    if deletion != expected_deletion:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "delete source evidence disagrees with its durable authority",
        )


def _validate_legacy_job_deletion_authority(
    deletion: dict[str, object],
    lifecycle: object,
    archive_digest: object,
) -> None:
    if lifecycle == "undeployed" and deletion["mode"] != "never-deployed":
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "undeployed delete source evidence is invalid",
        )
    if lifecycle == "archived" and (
        deletion["mode"] != "archived" or deletion["archiveRecordDigest"] != archive_digest
    ):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archived delete source evidence is invalid",
        )


def _current_job_deletion_authority(
    source_authority: object,
    lifecycle: object,
    archive_digest: object,
) -> dict[str, object]:
    if type(source_authority) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "delete source authority is absent")
    manifest = cast(dict[str, object], source_authority["manifest"])
    metadata = cast(dict[str, object], manifest["metadata"])
    expected_deletion: dict[str, object] = {
        "mode": "never-deployed",
        "releasedSlugs": [metadata["slug"]],
        "archiveRecordDigest": None,
        "bucket": None,
        "key": None,
        "versionId": None,
        "emergencyReason": None,
    }
    if lifecycle == "archived":
        archive_record = source_authority["archiveRecord"]
        if type(archive_record) is not dict:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "archived delete source authority is absent",
            )
        expected_deletion.update(
            {
                "mode": "archived",
                "archiveRecordDigest": archive_digest,
                "bucket": archive_record["bucket"],
                "key": archive_record["key"],
                "versionId": archive_record["versionId"],
            }
        )
    return expected_deletion


def _validate_result(document: dict[str, object]) -> None:
    canonical_origin = document.get("canonicalOrigin")
    if canonical_origin is not None:
        validate_canonical_origin(document["tenantId"], canonical_origin)
    raw_manifest = document.get("manifest")
    manifest: dict[str, object] | None = None
    if type(raw_manifest) is dict:
        manifest = raw_manifest
        _validate_site(manifest)
        metadata = cast(dict[str, object], manifest["metadata"])
        if document["tenantId"] != metadata["id"]:
            raise ContractError(ErrorCode.SCHEMA_INVALID, "result tenant identity does not match")
        if canonical_origin != metadata["canonicalOrigin"]:
            raise ContractError(ErrorCode.SCHEMA_INVALID, "result tenant origin does not match")
    if document["operation"] != "archive" or document["status"] != "succeeded":
        return
    archive = document.get("archiveRecord")
    if manifest is None or type(archive) is not dict:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "successful archive result lacks durable archive authority",
        )
    spec = cast(dict[str, object], manifest["spec"])
    deployment = spec.get("desiredDeployment")
    if type(deployment) is not dict or (
        archive["tenantId"] != document["tenantId"]
        or archive["correlationId"] != document["correlationId"]
        or archive["manifestDigest"] != _manifest_digest(manifest)
        or archive["deploymentId"] != deployment["id"]
    ):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "successful archive record disagrees with its result",
        )


def _validate_archive_construction_intent(document: dict[str, object]) -> None:
    upload_attempt_id = validate_uuid7(document["uploadAttemptId"])
    if document["key"] != f"archives/{upload_attempt_id}.zip":
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archive key does not match its upload attempt identity",
        )
    if document["sourceManifestDigest"] == document["candidateManifestDigest"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archive construction did not change the manifest generation",
        )


def _validate_archive_retirement_intent(document: dict[str, object]) -> None:
    if document.get("compatibilityVersion") != "static-retirement-v2":
        return
    archive = cast(dict[str, object], document["archiveRecord"])
    archive_digest = digest_bytes(
        canonical_json_bytes(archive),
        format_identifier=ARCHIVE_RECORD_DIGEST_FORMAT,
    ).to_dict()
    if document["archiveRecordDigest"] != archive_digest:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archive retirement record digest binding is invalid",
        )
    if (
        document["tenantId"] != archive["tenantId"]
        or document["sourceManifestDigest"] != archive["manifestDigest"]
        or document["bundleDigest"] != archive["bundleDigest"]
        or document["bundleSize"] != archive["bundleSize"]
        or document["bucket"] != archive["bucket"]
        or document["key"] != archive["key"]
        or document["versionId"] != archive["versionId"]
    ):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archive retirement object authority disagrees with its record",
        )


def _manifest_digest(document: dict[str, object]) -> dict[str, str]:
    return digest_bytes(
        canonical_json_bytes(document),
        format_identifier=MANIFEST_DIGEST_FORMAT,
    ).to_dict()


def _validated_transaction_candidate(
    document: dict[str, object],
    operation: str,
) -> dict[str, object] | None:
    candidate = document["candidateManifest"]
    if operation == "delete":
        return None
    candidate_manifest = cast(dict[str, object], candidate)
    _validate_site(candidate_manifest)
    candidate_metadata = cast(dict[str, object], candidate_manifest["metadata"])
    if candidate_metadata["id"] != document["tenantId"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "transaction candidate tenant identity drifted",
        )
    if _manifest_digest(candidate_manifest) != document["candidateManifestDigest"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "transaction candidate manifest binding is invalid",
        )
    return candidate_manifest


def _validated_transaction_source(
    document: dict[str, object],
    operation: str,
) -> dict[str, object] | None:
    source = document["sourceManifest"]
    if operation == "create":
        return None
    source_manifest = cast(dict[str, object], source)
    _validate_site(source_manifest)
    source_metadata = cast(dict[str, object], source_manifest["metadata"])
    if source_metadata["id"] != document["tenantId"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "transaction source tenant identity drifted",
        )
    if _manifest_digest(source_manifest) != document["sourceManifestDigest"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "transaction source manifest binding is invalid",
        )
    return source_manifest


def _validate_archive_source_manifest_binding(
    document: dict[str, object],
    source_manifest: dict[str, object],
) -> None:
    if _manifest_digest(source_manifest) != document["sourceManifestDigest"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archive source manifest binding is invalid",
        )


def _validate_transaction_manifest_transform(
    operation: str,
    source: dict[str, object] | None,
    candidate: dict[str, object] | None,
) -> None:
    if operation in {"create", "delete", "archive"}:
        return
    source_manifest = cast(dict[str, object], source)
    candidate_manifest = cast(dict[str, object], candidate)
    expected = deepcopy(source_manifest)
    candidate_metadata = cast(dict[str, object], candidate_manifest["metadata"])
    candidate_spec = cast(dict[str, object], candidate_manifest["spec"])
    expected_metadata = cast(dict[str, object], expected["metadata"])
    expected_spec = cast(dict[str, object], expected["spec"])
    if operation == "rename":
        expected_metadata["slug"] = candidate_metadata["slug"]
    elif operation in {"suspend", "resume"}:
        expected_spec["desiredState"] = candidate_spec["desiredState"]
    elif operation in {"deploy", "rollback", "import", "restore"}:
        expected_spec["desiredState"] = candidate_spec["desiredState"]
        expected_spec["desiredDeployment"] = candidate_spec["desiredDeployment"]
    if candidate_manifest != expected:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "transaction candidate changed fields outside its operation",
        )


def _validate_transaction_intent(document: dict[str, object]) -> None:
    _validate_restart_fence(document)
    operation = cast(str, document["operation"])
    current = document.get("compatibilityVersion") == "static-intent-v2"
    source_manifest: dict[str, object] | None = None
    candidate_manifest: dict[str, object] | None = None
    if current:
        source_manifest = _validated_transaction_source(document, operation)
        candidate_manifest = _validated_transaction_candidate(document, operation)
        _validate_transaction_manifest_transform(
            operation,
            source_manifest,
            candidate_manifest,
        )
    if operation != "archive":
        _validate_nonarchive_transaction_intent(document, operation, current=current)
        return
    recovery = cast(dict[str, object], document["archiveRecovery"])
    source = cast(dict[str, object], recovery["sourceManifest"])
    archive_candidate = cast(dict[str, object], recovery["candidateManifest"])
    observed = cast(dict[str, object], recovery["sourceObservedState"])
    archive = cast(dict[str, object], recovery["candidateArchiveRecord"])
    _validate_site(source)
    _validate_site(archive_candidate)

    tenant_id = document["tenantId"]
    source_metadata = cast(dict[str, object], source["metadata"])
    candidate_metadata = cast(dict[str, object], archive_candidate["metadata"])
    if source_metadata["id"] != tenant_id or candidate_metadata != source_metadata:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive intent tenant identity drifted")
    _validate_archive_source_manifest_binding(document, source)
    if current and source != source_manifest:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive source manifest copies drifted")
    if current and candidate_manifest != archive_candidate:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "archive candidate manifest copies drifted",
        )
    if document["candidateManifestDigest"] != _manifest_digest(archive_candidate):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID, "archive candidate manifest binding is invalid"
        )

    source_spec = cast(dict[str, object], source["spec"])
    candidate_spec = cast(dict[str, object], archive_candidate["spec"])
    source_state = source_spec["desiredState"]
    expected_candidate_spec = deepcopy(source_spec)
    expected_candidate_spec["desiredState"] = "archived"
    if source_state not in {"active", "suspended"} or candidate_spec != expected_candidate_spec:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive candidate state is invalid")

    source_deployment = cast(dict[str, object], source_spec["desiredDeployment"])
    if (
        observed["tenantId"] != tenant_id
        or observed["desiredManifestDigest"] != document["sourceManifestDigest"]
        or observed["observedState"] != source_state
        or observed["activeDeploymentId"] != source_deployment["id"]
    ):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive observed-state binding is invalid")
    expected_routes = "both" if source_state == "active" else "absent"
    if recovery["sourceRouteSet"] != expected_routes:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive source route binding is invalid")
    if source_state == "active" and (
        observed["runtimeGenerationId"] != recovery["sourceRuntimeGenerationId"]
    ):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive source runtime binding is invalid")

    if (
        archive["tenantId"] != tenant_id
        or archive["deploymentId"] != source_deployment["id"]
        or archive["manifestDigest"] != document["candidateManifestDigest"]
        or archive["correlationId"] != document["correlationId"]
    ):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "archive record binding is invalid")
    if recovery["candidateRuntimeGenerationId"] == recovery["sourceRuntimeGenerationId"]:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID, "archive runtime generations are not distinct"
        )


def _validate_nonarchive_transaction_intent(
    document: dict[str, object],
    operation: str,
    *,
    current: bool,
) -> None:
    if operation == "export":
        if document["sourceManifestDigest"] != document["candidateManifestDigest"]:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "export intent manifest generation drifted",
            )
        return
    if operation == "reconcile" and (
        document["sourceManifestDigest"] != document["candidateManifestDigest"]
    ):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "reconcile intent manifest generation drifted",
        )
    _validate_lifecycle_recovery(document, current=current)


def _validate_lifecycle_recovery(
    document: dict[str, object],
    *,
    current: bool,
) -> None:
    operation = cast(str, document["operation"])
    recovery = cast(dict[str, object], document["lifecycleRecovery"])
    source = recovery["sourceObservedState"]
    candidate = recovery["candidateObservedState"]
    if (operation == "create") != (source is None):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "source recovery state is invalid")
    if (operation == "delete") != (candidate is None):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "candidate recovery state is invalid")

    source_state = LifecycleState.ABSENT
    source_observed: dict[str, object] | None = None
    if source is not None:
        source_observed = cast(dict[str, object], source)
        source_state = LifecycleState(cast(str, source_observed["observedState"]))
        _validate_observed_recovery_binding(
            document,
            source_observed,
            digest_field="sourceManifestDigest",
            route_set=recovery["sourceRouteSet"],
            runtime_generation=recovery["sourceRuntimeGenerationId"],
        )
        if current:
            _validate_observed_manifest_binding(
                cast(dict[str, object], document["sourceManifest"]),
                source_observed,
            )
    elif recovery["sourceRouteSet"] != "absent":
        raise ContractError(ErrorCode.SCHEMA_INVALID, "absent source retained tenant routes")

    candidate_state = LifecycleState.ABSENT
    candidate_observed: dict[str, object] | None = None
    if candidate is not None:
        candidate_observed = cast(dict[str, object], candidate)
        candidate_state = LifecycleState(cast(str, candidate_observed["observedState"]))
        _validate_observed_recovery_binding(
            document,
            candidate_observed,
            digest_field="candidateManifestDigest",
            route_set=recovery["candidateRouteSet"],
            runtime_generation=recovery["candidateRuntimeGenerationId"],
        )
        if current:
            _validate_observed_manifest_binding(
                cast(dict[str, object], document["candidateManifest"]),
                candidate_observed,
            )
    elif recovery["candidateRouteSet"] != "absent":
        raise ContractError(ErrorCode.SCHEMA_INVALID, "absent candidate retained tenant routes")

    expected = LIFECYCLE_MATRIX.get((Operation(operation), source_state))
    if expected != candidate_state:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "recovery states violate lifecycle matrix")
    _validate_manifest_transition_binding(document, operation, source_state, candidate_state)
    deployment_operations = {"deploy", "rollback", "restore"} if current else {"deploy", "rollback"}
    if operation in deployment_operations and (
        source_observed is None
        or candidate_observed is None
        or source_observed["activeDeploymentId"] == candidate_observed["activeDeploymentId"]
        or document["sourceManifestDigest"] == document["candidateManifestDigest"]
    ):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "deployment-selecting transition did not select a distinct generation",
        )
    if operation in {"suspend", "resume", "rename", "reconcile"} and (
        source_observed is None
        or candidate_observed is None
        or source_observed["activeDeploymentId"] != candidate_observed["activeDeploymentId"]
    ):
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "route-only transition changed the remembered deployment",
        )
    if recovery["candidateRuntimeGenerationId"] == recovery["sourceRuntimeGenerationId"]:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "runtime generations are not distinct")


def _validate_observed_manifest_binding(
    manifest: dict[str, object],
    observed: dict[str, object],
) -> None:
    spec = cast(dict[str, object], manifest["spec"])
    state = observed["observedState"]
    deployment = spec.get("desiredDeployment")
    deployment_id = None
    if state in {"active", "suspended"}:
        deployment_id = cast(dict[str, object], deployment)["id"]
    if spec["desiredState"] != state or observed["activeDeploymentId"] != deployment_id:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "observed recovery state disagrees with its manifest",
        )


def _restart_fence_matches(
    fence: object,
    *,
    target: str,
    candidate_attempts: range,
    recovery_attempts: range,
    invocation_required: bool,
) -> bool:
    if type(fence) is not dict:
        return False
    candidate_count = fence["candidateAttemptCount"]
    recovery_count = fence["recoveryAttemptCount"]
    invocation = fence["systemdInvocationId"]
    return (
        fence["selectedTarget"] == target
        and candidate_count in candidate_attempts
        and recovery_count in recovery_attempts
        and (invocation is not None) == invocation_required
    )


def _validate_restart_fence(document: dict[str, object]) -> None:
    phase = TransactionPhase(cast(str, document["phase"]))
    fence = document["restartFence"]
    valid = False
    if phase in {TransactionPhase.PREPARED, TransactionPhase.RUNTIME_SELECTED}:
        valid = fence is None
    elif phase is TransactionPhase.RESTART_REQUIRED:
        valid = _restart_fence_matches(
            fence,
            target="candidate",
            candidate_attempts=range(1),
            recovery_attempts=range(1),
            invocation_required=False,
        )
    elif phase is TransactionPhase.CANDIDATE_STARTING:
        valid = _restart_fence_matches(
            fence,
            target="candidate",
            candidate_attempts=range(1, 4),
            recovery_attempts=range(1),
            invocation_required=True,
        )
    elif phase is TransactionPhase.ROLLBACK_RESTART_REQUIRED:
        valid = _restart_fence_matches(
            fence,
            target="previous",
            candidate_attempts=range(1, 4),
            recovery_attempts=range(1),
            invocation_required=False,
        )
    elif phase is TransactionPhase.RECOVERY_STARTING:
        valid = _restart_fence_matches(
            fence,
            target="previous",
            candidate_attempts=range(1, 4),
            recovery_attempts=range(1, 4),
            invocation_required=True,
        )
    elif phase is TransactionPhase.STATE_COMMITTED:
        valid = (
            fence is None
            or _restart_fence_matches(
                fence,
                target="candidate",
                candidate_attempts=range(1, 4),
                recovery_attempts=range(1),
                invocation_required=True,
            )
            or _restart_fence_matches(
                fence,
                target="previous",
                candidate_attempts=range(1, 4),
                recovery_attempts=range(1, 4),
                invocation_required=True,
            )
        )
    if not valid:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "restart attempt fence does not match the durable transaction phase",
        )


def _validate_manifest_transition_binding(
    document: dict[str, object],
    operation: str,
    source_state: LifecycleState,
    candidate_state: LifecycleState,
) -> None:
    same_digest = document["sourceManifestDigest"] == document["candidateManifestDigest"]
    if source_state != candidate_state:
        if same_digest:
            raise ContractError(
                ErrorCode.SCHEMA_INVALID,
                "lifecycle transition did not change the manifest generation",
            )
        return
    if operation in {"suspend", "resume"} and not same_digest:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "no-op route transition changed the manifest generation",
        )
    if operation == "rename" and same_digest:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID,
            "rename transition did not change the manifest generation",
        )


def _validate_observed_recovery_binding(
    document: dict[str, object],
    observed: dict[str, object],
    *,
    digest_field: str,
    route_set: object,
    runtime_generation: object,
) -> None:
    if (
        observed["tenantId"] != document["tenantId"]
        or observed["desiredManifestDigest"] != document[digest_field]
    ):
        raise ContractError(ErrorCode.SCHEMA_INVALID, "observed recovery binding is invalid")
    state = observed["observedState"]
    expected_routes = "both" if state == "active" else "absent"
    if route_set != expected_routes:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "observed route binding is invalid")
    if state == "active" and observed["runtimeGenerationId"] != runtime_generation:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "observed runtime binding is invalid")


def _validate_audit_entry(document: dict[str, object]) -> None:
    evidence = document.get("deletionEvidence")
    if evidence is None:
        return
    deletion = cast(dict[str, object], evidence)
    for slug in cast(list[object], deletion["releasedSlugs"]):
        validate_slug(slug)


_SEMANTIC_VALIDATORS: Final[dict[ContractKind, Callable[[dict[str, object]], None]]] = {
    ContractKind.PLATFORM_NAMESPACE: _validate_namespace,
    ContractKind.SITE: _validate_site,
    ContractKind.OPERATION_REQUEST: _validate_request,
    ContractKind.AUTHORIZATION_JOB: _validate_job,
    ContractKind.OPERATION_RESULT: _validate_result,
    ContractKind.ARCHIVE_CONSTRUCTION_INTENT: _validate_archive_construction_intent,
    ContractKind.ARCHIVE_RETIREMENT_INTENT: _validate_archive_retirement_intent,
    ContractKind.TRANSACTION_INTENT: _validate_transaction_intent,
    ContractKind.AUDIT_ENTRY: _validate_audit_entry,
}


def _semantic_validation(document: dict[str, object], kind: ContractKind) -> None:
    validator = _SEMANTIC_VALIDATORS.get(kind)
    if validator is not None:
        validator(document)
    for field in (
        "id",
        "tenantId",
        "deploymentId",
        "jobId",
        "intentId",
        "uploadAttemptId",
        "correlationId",
    ):
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


def _reject_create_authority_fields(document: dict[str, object]) -> None:
    if document.get("operation") == "create" and any(
        field in document for field in ("id", "tenantId", "canonicalOrigin", "manifest")
    ):
        raise ContractError(
            ErrorCode.CALLER_SELECTED_IDENTITY,
            "create cannot select identity, origin, or desired state",
        )


def materialize_create_request(document: dict[str, object]) -> ValidatedCreateRequest:
    """Validate and project the caller choices needed by pure create construction."""

    _reject_create_authority_fields(document)
    validate_contract(document, expected_kind=ContractKind.OPERATION_REQUEST)
    if document["operation"] != "create":
        raise ContractError(ErrorCode.SCHEMA_INVALID, "request is not a create operation")
    quotas = cast(dict[str, object], document["quotas"])
    return ValidatedCreateRequest(
        slug=cast(str, document["slug"]),
        storage_mib=cast(int, quotas["storageMiB"]),
        entries=cast(int, quotas["entries"]),
    )


def materialize_platform_namespace(
    document: dict[str, object],
) -> ValidatedPlatformNamespace:
    """Validate and project the pinned input needed by pure create construction."""

    validate_contract(document, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    return ValidatedPlatformNamespace(
        tenant_origin_suffix=cast(str, document["tenantOriginSuffix"]),
    )


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
    _reject_create_authority_fields(document)
    validate_contract(document, expected_kind=ContractKind.OPERATION_REQUEST)
    return document


def decode_result(raw: bytes) -> dict[str, object]:
    """Decode a canonical-size operation result."""

    return decode_contract(
        raw,
        expected_kind=ContractKind.OPERATION_RESULT,
        maximum_raw_bytes=MAX_CANONICAL_BYTES,
    )
