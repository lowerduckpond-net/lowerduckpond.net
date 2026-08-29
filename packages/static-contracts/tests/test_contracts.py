from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from conftest import FIXTURE_ROOT
from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    MAX_RAW_REQUEST_BYTES,
    ContractError,
    ContractKind,
    Digest,
    ErrorCode,
    Operation,
    canonical_json_bytes,
    decode_contract,
    decode_request,
    request_digest,
    validate_contract,
)
from lowerduckpond_static_contracts.schema import SCHEMA_FILE_BY_KIND, schema_for

PUBLIC_SCHEMA_ROOT = Path(__file__).parents[3] / "schemas/static-publication/v1alpha1"
PACKAGED_SCHEMA_ROOT = Path(__file__).parents[1] / "src/lowerduckpond_static_contracts/schemas"


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def test_every_committed_schema_has_one_accepted_golden_fixture() -> None:
    paths = sorted((FIXTURE_ROOT / "accepted").glob("*.json"))

    decoded = [decode_contract(path.read_bytes()) for path in paths]

    assert {document["kind"] for document in decoded} == {kind.value for kind in ContractKind}
    assert len(paths) == len(SCHEMA_FILE_BY_KIND)


@pytest.mark.parametrize(
    "path",
    sorted((FIXTURE_ROOT / "accepted").glob("*.json")),
    ids=lambda path: path.name,
)
def test_accepted_fixtures_round_trip_through_canonical_bytes(path: Path) -> None:
    first = decode_contract(path.read_bytes())
    encoded = canonical_json_bytes(first)

    assert encoded.endswith(b"\n") and not encoded.endswith(b"\n\n")
    assert canonical_json_bytes(decode_contract(encoded)) == encoded


def test_schema_loader_returns_a_copy_not_mutable_cached_state() -> None:
    schema = schema_for(ContractKind.SITE)
    schema["type"] = "array"

    assert schema_for(ContractKind.SITE)["type"] == "object"


def test_public_and_packaged_schema_snapshots_are_byte_identical() -> None:
    public = {path.name: path.read_bytes() for path in PUBLIC_SCHEMA_ROOT.glob("*.schema.json")}
    packaged = {path.name: path.read_bytes() for path in PACKAGED_SCHEMA_ROOT.glob("*.schema.json")}

    assert public == packaged


def test_hostile_golden_fixtures_have_stable_error_codes() -> None:
    hostile = FIXTURE_ROOT / "hostile"
    expected = _load_object(hostile / "index.json")
    observed: dict[str, str] = {}
    for filename in expected:
        assert type(filename) is str
        path = hostile / filename
        decoder = decode_request
        with pytest.raises(ContractError) as captured:
            decoder(path.read_bytes())
        observed[filename] = captured.value.code.value

    assert observed == expected


def test_validation_failure_does_not_mutate_the_supplied_document() -> None:
    document = _load_object(FIXTURE_ROOT / "accepted/operation-request.json")
    document["unknown"] = {"nested": [1, 2, 3]}
    before = deepcopy(document)

    with pytest.raises(ContractError, match="schema") as captured:
        validate_contract(document)

    assert captured.value.code is ErrorCode.UNKNOWN_FIELD
    assert document == before


def test_duplicate_members_are_rejected_before_schema_or_correlation_work() -> None:
    raw = (FIXTURE_ROOT / "hostile/duplicate-json-member.json.raw").read_bytes()

    with pytest.raises(ContractError) as captured:
        decode_request(raw)

    assert captured.value.code is ErrorCode.DUPLICATE_JSON_MEMBER


def test_raw_request_limit_reads_at_most_the_detection_byte() -> None:
    with pytest.raises(ContractError) as captured:
        decode_request(b" " * (MAX_RAW_REQUEST_BYTES + 1))

    assert captured.value.code is ErrorCode.RAW_REQUEST_TOO_LARGE


def test_canonical_limit_includes_exactly_one_trailing_lf() -> None:
    framing_bytes = len(b'{"x":""}\n')
    value = {"x": "a" * (MAX_CANONICAL_BYTES - framing_bytes)}

    assert len(canonical_json_bytes(value)) == MAX_CANONICAL_BYTES
    value["x"] = str(value["x"]) + "a"
    with pytest.raises(ContractError) as captured:
        canonical_json_bytes(value)
    assert captured.value.code is ErrorCode.CANONICAL_TOO_LARGE


def test_request_cannot_carry_a_standalone_desired_manifest() -> None:
    raw = (FIXTURE_ROOT / "hostile/standalone-manifest.json").read_bytes()

    with pytest.raises(ContractError) as captured:
        decode_request(raw)

    assert captured.value.code is ErrorCode.STANDALONE_MANIFEST_FRAME


@pytest.mark.parametrize(
    ("operation", "fields"),
    [
        ("create", {"slug": "duck-repair", "quotas": {"storageMiB": 100, "entries": 5000}}),
        (
            "deploy",
            {
                "tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100",
                "artifact": {"size": 104857600, "sha256": "a" * 64},
            },
        ),
        (
            "rollback",
            {
                "tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100",
                "deploymentId": "0191e2ca-49f2-7608-8cf3-f80ab2cab151",
            },
        ),
        ("suspend", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
        ("resume", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
        (
            "rename",
            {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100", "slug": "new-duck"},
        ),
        ("export", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
        (
            "import",
            {
                "tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100",
                "artifact": {"size": 125829120, "sha256": "b" * 64},
            },
        ),
        ("archive", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
        ("restore", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
        ("delete", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
        ("reconcile", {"tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"}),
    ],
)
def test_every_operation_has_one_strict_request_shape(
    operation: str, fields: dict[str, object]
) -> None:
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        **fields,
    }

    assert decode_request(canonical_json_bytes(request)) == request


def test_deploy_and_import_keep_their_distinct_artifact_ceilings() -> None:
    request: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "deploy",
        "correlationId": "0198d17f-6f4a-7000-8000-000000000001",
        "tenantId": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100",
        "artifact": {"size": 104857601, "sha256": "a" * 64},
    }

    with pytest.raises(ContractError) as captured:
        validate_contract(request)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_authorization_job_expected_source_bindings_are_not_optional_conventions() -> None:
    job = _load_object(FIXTURE_ROOT / "accepted/authorization-job.json")
    expected = job["expectedSource"]
    assert type(expected) is dict
    expected["expectsTenantAbsent"] = False

    with pytest.raises(ContractError) as captured:
        validate_contract(job)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_authorization_job_request_digest_binds_the_embedded_request() -> None:
    job = _load_object(FIXTURE_ROOT / "accepted/authorization-job.json")
    request = job["request"]
    assert type(request) is dict

    assert job["requestDigest"] == request_digest(request).to_dict()
    digest = job["requestDigest"]
    assert type(digest) is dict
    digest["value"] = "e" * 64

    with pytest.raises(ContractError) as captured:
        validate_contract(job)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


@pytest.mark.parametrize("field", ["tenantId", "canonicalOrigin", "manifest"])
def test_successful_create_result_requires_generated_identity_fields(field: str) -> None:
    result = _load_object(FIXTURE_ROOT / "accepted/operation-result.json")
    del result[field]

    with pytest.raises(ContractError) as captured:
        validate_contract(result)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_successful_create_result_rejects_a_null_tenant_identity() -> None:
    result = _load_object(FIXTURE_ROOT / "accepted/operation-result.json")
    result["tenantId"] = None

    with pytest.raises(ContractError) as captured:
        validate_contract(result)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


@pytest.mark.parametrize("desired_state", ["active", "suspended", "archived"])
def test_successful_create_result_requires_an_undeployed_manifest(desired_state: str) -> None:
    result = _load_object(FIXTURE_ROOT / "accepted/operation-result.json")
    manifest = result["manifest"]
    assert type(manifest) is dict
    spec = manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = desired_state
    spec["desiredDeployment"] = {
        "id": "0191e2ca-49f2-7608-8cf3-f80ab2cab151",
        "archiveSha256": "a" * 64,
    }

    with pytest.raises(ContractError) as captured:
        validate_contract(result)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


@pytest.mark.parametrize("status", ["succeeded", "failed"])
@pytest.mark.parametrize(
    "operation",
    [operation.value for operation in Operation if operation is not Operation.CREATE],
)
def test_existing_tenant_results_require_a_tenant_identity(operation: str, status: str) -> None:
    result = _load_object(FIXTURE_ROOT / "accepted/operation-result.json")
    del result["canonicalOrigin"]
    del result["manifest"]
    result["operation"] = operation
    result["status"] = status
    result["tenantId"] = None
    if status == "failed":
        result["errorCode"] = "unavailable"

    with pytest.raises(ContractError) as captured:
        validate_contract(result)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_failed_create_result_may_precede_tenant_identity_generation() -> None:
    result = _load_object(FIXTURE_ROOT / "accepted/operation-result.json")
    del result["canonicalOrigin"]
    del result["manifest"]
    result["status"] = "failed"
    result["tenantId"] = None
    result["errorCode"] = "capacity_exceeded"

    assert validate_contract(result) is ContractKind.OPERATION_RESULT


def test_existing_tenant_intent_requires_a_source_manifest_digest() -> None:
    intent = _load_object(FIXTURE_ROOT / "accepted/transaction-intent.json")
    intent["sourceManifestDigest"] = None

    with pytest.raises(ContractError) as captured:
        validate_contract(intent)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_create_intent_requires_an_absent_source_manifest() -> None:
    intent = _load_object(FIXTURE_ROOT / "accepted/transaction-intent.json")
    source_digest = intent["sourceManifestDigest"]
    intent["operation"] = "create"
    intent["sourceManifestDigest"] = None

    assert validate_contract(intent) is ContractKind.TRANSACTION_INTENT

    intent["sourceManifestDigest"] = source_digest
    with pytest.raises(ContractError) as captured:
        validate_contract(intent)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_timestamp_format_validation_is_not_an_optional_environment_feature() -> None:
    namespace = _load_object(FIXTURE_ROOT / "accepted/platform-namespace.json")
    namespace["initializedAt"] = "not-a-dateZ"

    with pytest.raises(ContractError) as captured:
        validate_contract(namespace)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


@pytest.mark.parametrize("bucket", ["ab", "a" * 64])
def test_archive_bucket_uses_the_provisioned_spaces_length_bounds(bucket: str) -> None:
    archive = _load_object(FIXTURE_ROOT / "accepted/archive-record.json")
    archive["bucket"] = bucket

    with pytest.raises(ContractError) as captured:
        validate_contract(archive)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_site_canonical_origin_is_bound_to_its_tenant_identity() -> None:
    site = _load_object(FIXTURE_ROOT / "accepted/site.json")
    metadata = site["metadata"]
    assert type(metadata) is dict
    metadata["canonicalOrigin"] = "t-0198d17f6f4a70008000000000000001.lowerduckpond.com"

    with pytest.raises(ContractError) as captured:
        validate_contract(site)

    assert captured.value.code is ErrorCode.INVALID_CANONICAL_ORIGIN


def test_audit_genesis_entry_cannot_claim_a_predecessor() -> None:
    entry = _load_object(FIXTURE_ROOT / "accepted/audit-entry.json")
    entry["previousEntryDigest"] = {
        "format": "lowerduckpond-audit-entry-v1",
        "algorithm": "sha256",
        "value": "a" * 64,
    }

    with pytest.raises(ContractError) as captured:
        validate_contract(entry)

    assert captured.value.code is ErrorCode.SCHEMA_INVALID


def test_later_audit_entries_require_a_predecessor() -> None:
    entry = _load_object(FIXTURE_ROOT / "accepted/audit-entry.json")
    entry["sequence"] = 1

    with pytest.raises(ContractError) as captured:
        validate_contract(entry)
    assert captured.value.code is ErrorCode.SCHEMA_INVALID

    entry["previousEntryDigest"] = {
        "format": "lowerduckpond-audit-entry-v1",
        "algorithm": "sha256",
        "value": "a" * 64,
    }
    assert validate_contract(entry) is ContractKind.AUDIT_ENTRY


def test_manifestless_result_origin_is_bound_to_its_tenant_identity() -> None:
    result = _load_object(FIXTURE_ROOT / "accepted/operation-result.json")
    del result["manifest"]
    result["operation"] = "deploy"
    result["canonicalOrigin"] = "t-0198d17f6f4a70008000000000000001.lowerduckpond.com"

    with pytest.raises(ContractError) as captured:
        validate_contract(result)
    assert captured.value.code is ErrorCode.INVALID_CANONICAL_ORIGIN

    result["canonicalOrigin"] = "t-0191e2c48f7a7c3b8d1e5f62047a2100.lowerduckpond.com"
    assert validate_contract(result) is ContractKind.OPERATION_RESULT


@pytest.mark.parametrize(
    "format_identifier",
    ["lowerduckpond--v1", "lowerduckpond-state--v1", "lowerduckpond--state-v1"],
)
def test_schema_and_digest_value_reject_empty_format_segments(format_identifier: str) -> None:
    job = _load_object(FIXTURE_ROOT / "accepted/authorization-job.json")
    expected = job["expectedSource"]
    assert type(expected) is dict
    platform_digest = expected["platformStateDigest"]
    assert type(platform_digest) is dict
    platform_digest["format"] = format_identifier

    with pytest.raises(ContractError) as schema_error:
        validate_contract(job)
    with pytest.raises(ContractError) as value_error:
        Digest(format_identifier, "sha256", "f" * 64)

    assert schema_error.value.code is ErrorCode.SCHEMA_INVALID
    assert value_error.value.code is ErrorCode.INVALID_IDENTIFIER
