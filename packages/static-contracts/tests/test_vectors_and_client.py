from __future__ import annotations

import hashlib
import json

import pytest
from conftest import FIXTURE_ROOT, VECTOR_ROOT
from lowerduckpond_static_contracts import (
    ContractError,
    ErrorCode,
    ResultErrorCode,
    canonical_json_bytes,
    decode_request,
    manifest_digest,
    request_digest,
    result_digest,
)
from lowerduckpond_static_contracts.client_yaml import parse_create_spec

CORRELATION_ID = "0198d17f-6f4a-7000-8000-000000000001"


def test_rfc8785_canonical_byte_vectors_are_exact() -> None:
    document = json.loads((VECTOR_ROOT / "canonical-json-v1.json").read_text(encoding="utf-8"))
    for vector in document["vectors"]:
        canonical = canonical_json_bytes(vector["input"])
        assert canonical.hex() == vector["canonicalHex"]
        assert hashlib.sha256(canonical).hexdigest() == vector["canonicalSha256"]


def test_versioned_manifest_digest_vector_is_exact() -> None:
    vector = json.loads((VECTOR_ROOT / "manifest-digest-v1.json").read_text(encoding="utf-8"))
    manifest = json.loads((FIXTURE_ROOT / vector["fixture"]).read_text(encoding="utf-8"))
    canonical = canonical_json_bytes(manifest)

    assert len(canonical) == vector["canonicalBytes"]
    assert hashlib.sha256(canonical).hexdigest() == vector["canonicalSha256"]
    assert manifest_digest(manifest).to_dict() == vector["digest"]


def test_versioned_request_and_result_digest_vectors_are_exact() -> None:
    document = json.loads((VECTOR_ROOT / "contract-digests-v1.json").read_text(encoding="utf-8"))
    functions = [request_digest, result_digest]
    for vector, digest_function in zip(document["vectors"], functions, strict=True):
        value = json.loads((FIXTURE_ROOT / vector["fixture"]).read_text(encoding="utf-8"))
        canonical = canonical_json_bytes(value)
        assert len(canonical) == vector["canonicalBytes"]
        assert hashlib.sha256(canonical).hexdigest() == vector["canonicalSha256"]
        assert digest_function(value).to_dict() == vector["digest"]


def test_error_code_vector_is_complete_and_stable() -> None:
    vector = json.loads((VECTOR_ROOT / "error-codes-v1.json").read_text(encoding="utf-8"))

    assert sorted(code.value for code in ErrorCode) == vector["codes"]
    assert sorted(code.value for code in ResultErrorCode) == vector["resultCodes"]


def test_client_yaml_translates_only_caller_controlled_create_fields() -> None:
    raw = b"slug: duck-repair\nquotas:\n  storageMiB: 100\n  entries: 5000\n"

    request = parse_create_spec(raw, correlation_id=CORRELATION_ID)

    assert decode_request(canonical_json_bytes(request)) == request
    assert set(request) == {
        "apiVersion",
        "kind",
        "operation",
        "correlationId",
        "slug",
        "quotas",
    }


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (
            b"slug: first\nslug: second\nquotas: {storageMiB: 100, entries: 5000}\n",
            ErrorCode.DUPLICATE_YAML_KEY,
        ),
        (
            b"slug: duck\nquotas: {storageMiB: 100, entries: 5000, burst: 1}\n",
            ErrorCode.UNKNOWN_FIELD,
        ),
        (
            b"slug: duck\nquotas: {storageMiB: 100, entries: 5000}\nid: chosen\n",
            ErrorCode.UNKNOWN_FIELD,
        ),
    ],
)
def test_client_yaml_rejects_duplicate_or_unknown_fields(raw: bytes, code: ErrorCode) -> None:
    with pytest.raises(ContractError) as captured:
        parse_create_spec(raw, correlation_id=CORRELATION_ID)

    assert captured.value.code is code
