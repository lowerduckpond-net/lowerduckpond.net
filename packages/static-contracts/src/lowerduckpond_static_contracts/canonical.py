"""Bounded JSON decoding and RFC 8785 canonical serialization."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Final, cast

import rfc8785

from lowerduckpond_static_contracts.errors import ContractError, ErrorCode

MAX_RAW_REQUEST_BYTES: Final = 32 * 1024
MAX_CANONICAL_BYTES: Final = 16 * 1024
type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


def _reject_constant(_value: str) -> object:
    raise ContractError(ErrorCode.INVALID_JSON, "JSON contains a non-finite number")


def _unique_object(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(
                ErrorCode.DUPLICATE_JSON_MEMBER,
                "JSON contains a duplicate object member",
            )
        result[key] = value
    return result


def decode_json_object(
    raw: bytes,
    *,
    maximum_bytes: int = MAX_RAW_REQUEST_BYTES,
) -> dict[str, object]:
    """Decode one bounded UTF-8 JSON object while rejecting duplicate members."""

    if len(raw) > maximum_bytes:
        raise ContractError(ErrorCode.RAW_REQUEST_TOO_LARGE, "raw JSON exceeds its limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(ErrorCode.INVALID_UTF8, "raw JSON is not valid UTF-8") from error
    if text.startswith("\ufeff"):
        raise ContractError(ErrorCode.INVALID_UTF8, "raw JSON must not contain a byte-order mark")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ContractError(ErrorCode.INVALID_JSON, "raw JSON is not one valid document") from error
    if type(value) is not dict:
        raise ContractError(ErrorCode.SCHEMA_INVALID, "contract document must be an object")
    return value


def canonical_json_bytes(
    value: object,
    *,
    maximum_bytes: int = MAX_CANONICAL_BYTES,
) -> bytes:
    """Return RFC 8785 UTF-8 followed by exactly one LF."""

    try:
        canonical = rfc8785.dumps(cast(JsonValue, value)) + b"\n"
    except (rfc8785.CanonicalizationError, TypeError, ValueError) as error:
        raise ContractError(
            ErrorCode.SCHEMA_INVALID, "value is not canonicalizable JSON"
        ) from error
    if len(canonical) > maximum_bytes:
        raise ContractError(
            ErrorCode.CANONICAL_TOO_LARGE,
            "canonical JSON exceeds its limit",
        )
    return canonical
