"""Optional trusted-workstation-only YAML create-spec translation."""

from __future__ import annotations

from typing import Final, cast

from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import YAMLError

from lowerduckpond_static_contracts.errors import ContractError, ErrorCode
from lowerduckpond_static_contracts.schema import API_VERSION, ContractKind, validate_contract

MAX_CREATE_SPEC_BYTES: Final = 64 * 1024


def parse_create_spec(raw: bytes, *, correlation_id: str) -> dict[str, object]:
    """Translate bounded safe YAML into the strict structured create request."""

    if len(raw) > MAX_CREATE_SPEC_BYTES:
        raise ContractError(
            ErrorCode.RAW_REQUEST_TOO_LARGE, "local create specification is too large"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(
            ErrorCode.INVALID_UTF8, "local create specification is not UTF-8"
        ) from error

    yaml = YAML(typ="safe", pure=True)
    yaml.allow_duplicate_keys = False
    try:
        value = yaml.load(text)
    except DuplicateKeyError as error:
        raise ContractError(
            ErrorCode.DUPLICATE_YAML_KEY, "create specification has a duplicate key"
        ) from error
    except YAMLError as error:
        raise ContractError(
            ErrorCode.INVALID_YAML, "create specification is not safe YAML"
        ) from error
    if type(value) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "create specification must be a mapping")
    specification = cast(dict[object, object], value)
    if set(specification) != {"slug", "quotas"}:
        raise ContractError(ErrorCode.UNKNOWN_FIELD, "create specification fields are not accepted")
    quotas = specification["quotas"]
    if type(quotas) is not dict or set(quotas) != {"storageMiB", "entries"}:
        raise ContractError(ErrorCode.UNKNOWN_FIELD, "create quota fields are not accepted")
    request: dict[str, object] = {
        "apiVersion": API_VERSION,
        "kind": ContractKind.OPERATION_REQUEST.value,
        "operation": "create",
        "correlationId": correlation_id,
        "slug": specification["slug"],
        "quotas": quotas,
    }
    validate_contract(request, expected_kind=ContractKind.OPERATION_REQUEST)
    return request
