from __future__ import annotations

import hashlib
import inspect
import json
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ContractError,
    ErrorCode,
    ValidatedCreateRequest,
    ValidatedPlatformNamespace,
    canonical_json_bytes,
    manifest_digest,
    materialize_create_request,
    materialize_platform_namespace,
)
from lowerduckpond_static_contracts import schema as contract_schema
from lowerduckpond_static_contracts.identifiers import MAX_DNS_HOSTNAME_BYTES
from lowerduckpond_static_domain import construct_create_manifest

FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures"
VECTOR_ROOT = Path(__file__).parents[3] / "tests/static-publication/vectors"


def _zero_entropy(length: int) -> bytes:
    return bytes(length)


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    return (
        _load_object(FIXTURE_ROOT / "accepted/operation-request.json"),
        _load_object(FIXTURE_ROOT / "accepted/platform-namespace.json"),
    )


def _inputs() -> tuple[ValidatedCreateRequest, ValidatedPlatformNamespace]:
    request, namespace = _documents()
    return materialize_create_request(request), materialize_platform_namespace(namespace)


def test_create_constructor_matches_the_committed_real_producer_vector() -> None:
    vector = _load_object(VECTOR_ROOT / "root-domain-v1.json")["create"]
    assert type(vector) is dict
    request = materialize_create_request(_load_object(FIXTURE_ROOT / vector["requestFixture"]))
    namespace = materialize_platform_namespace(
        _load_object(FIXTURE_ROOT / vector["namespaceFixture"])
    )
    entropy = bytes.fromhex(str(vector["entropyHex"]))

    created = construct_create_manifest(
        request,
        namespace,
        clock=lambda: int(vector["unixMilliseconds"]),
        entropy=lambda _length: entropy,
    )
    canonical = canonical_json_bytes(created.manifest)

    assert created.tenant_id == vector["tenantId"]
    assert created.canonical_origin == vector["canonicalOrigin"]
    assert len(canonical) == vector["canonicalBytes"]
    assert hashlib.sha256(canonical).hexdigest() == vector["canonicalSha256"]
    assert manifest_digest(created.manifest).value == vector["manifestDigest"]


def test_create_constructor_accepts_no_identity_or_origin_parameter() -> None:
    signature = inspect.signature(construct_create_manifest)

    assert set(signature.parameters) == {"request", "namespace", "clock", "entropy"}
    assert signature.parameters["clock"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["entropy"].kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.parametrize("field", ["id", "tenantId", "canonicalOrigin", "manifest"])
def test_caller_selected_identity_origin_or_manifest_is_rejected_before_generation(
    field: str,
) -> None:
    request, _namespace = _documents()
    request[field] = "caller-selected"
    calls: list[str] = []

    def clock() -> int:
        calls.append("clock")
        return 0

    def entropy(length: int) -> bytes:
        calls.append("entropy")
        return bytes(length)

    with pytest.raises(ContractError) as captured:
        materialize_create_request(request)

    assert captured.value.code is ErrorCode.CALLER_SELECTED_IDENTITY
    assert calls == []


@pytest.mark.parametrize("invalid_input", ["request", "namespace"])
def test_invalid_authoritative_inputs_are_rejected_before_generation(
    invalid_input: str,
) -> None:
    request, namespace = _documents()
    if invalid_input == "request":
        request["unexpected"] = True
    else:
        namespace["tenantOriginSuffix"] = "example.com"
    calls: list[str] = []

    def clock() -> int:
        calls.append("clock")
        return 0

    def entropy(length: int) -> bytes:
        calls.append("entropy")
        return bytes(length)

    with pytest.raises(ContractError):
        if invalid_input == "request":
            materialize_create_request(request)
        else:
            materialize_platform_namespace(namespace)

    assert calls == []


def test_rejection_and_success_do_not_mutate_authoritative_inputs() -> None:
    request_document, namespace_document = _documents()
    request_document_before = deepcopy(request_document)
    namespace_document_before = deepcopy(namespace_document)
    request = materialize_create_request(request_document)
    namespace = materialize_platform_namespace(namespace_document)
    request_before = deepcopy(request)
    namespace_before = deepcopy(namespace)

    created = construct_create_manifest(
        request,
        namespace,
        clock=lambda: 0,
        entropy=_zero_entropy,
    )
    manifest_quotas = created.manifest["spec"]
    assert type(manifest_quotas) is dict
    quotas = manifest_quotas["quotas"]
    assert type(quotas) is dict
    quotas["entries"] = 1

    assert request == request_before
    assert namespace == namespace_before
    assert request_document == request_document_before
    assert namespace_document == namespace_document_before

    request_document["slug"] = "secure"
    rejected_before = deepcopy(request_document)
    with pytest.raises(ContractError):
        materialize_create_request(request_document)
    assert request_document == rejected_before
    assert namespace_document == namespace_document_before


def test_create_constructor_cannot_read_schemas_with_cold_contract_caches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, namespace = _inputs()
    contract_schema._validator.cache_clear()
    contract_schema._registry.cache_clear()
    contract_schema._schema_documents.cache_clear()
    contract_schema._cached_schema.cache_clear()

    def reject_schema_read(_path: object) -> dict[str, object]:
        raise AssertionError("pure create construction attempted to read a schema")

    monkeypatch.setattr(contract_schema, "_read_schema", reject_schema_read)

    construct_create_manifest(
        request,
        namespace,
        clock=lambda: 0,
        entropy=_zero_entropy,
    )


def test_generated_manifest_is_always_undeployed_without_a_deployment_reference() -> None:
    request, namespace = _inputs()

    created = construct_create_manifest(
        request,
        namespace,
        clock=lambda: 0,
        entropy=_zero_entropy,
    )

    spec = created.manifest["spec"]
    assert type(spec) is dict
    assert spec["desiredState"] == "undeployed"
    assert "desiredDeployment" not in spec
    assert created.canonical_origin == (f"t-{created.tenant_id.replace('-', '')}.lowerduckpond.com")
    assert len(created.canonical_origin.encode("ascii")) <= MAX_DNS_HOSTNAME_BYTES
