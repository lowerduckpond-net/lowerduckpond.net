from __future__ import annotations

import json

import pytest
from conftest import VECTOR_ROOT
from hypothesis import given
from hypothesis import strategies as st
from lowerduckpond_static_contracts import ContractError, ErrorCode
from lowerduckpond_static_contracts.identifiers import (
    MAX_DNS_LABEL_BYTES,
    SLUG_PATTERN,
    validate_slug,
    validate_uuid7,
)


def _identifier_vectors() -> dict[str, object]:
    value = json.loads((VECTOR_ROOT / "identifiers-v1.json").read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def test_committed_uuidv7_vectors() -> None:
    vectors = _identifier_vectors()["uuidv7"]
    assert type(vectors) is dict
    for value in vectors["accepted"]:
        assert validate_uuid7(value) == value
    for value in vectors["rejected"]:
        with pytest.raises(ContractError) as captured:
            validate_uuid7(value)
        assert captured.value.code is ErrorCode.INVALID_IDENTIFIER


def test_committed_slug_vectors_and_reservations() -> None:
    vectors = _identifier_vectors()["slug"]
    assert type(vectors) is dict
    for value in vectors["accepted"]:
        assert validate_slug(value) == value
    for value in vectors["rejected"]:
        with pytest.raises(ContractError) as captured:
            validate_slug(value)
        assert captured.value.code is ErrorCode.INVALID_SLUG
    for value in vectors["reserved"]:
        with pytest.raises(ContractError) as captured:
            validate_slug(value)
        assert captured.value.code is ErrorCode.RESERVED_SLUG


@given(
    st.from_regex(SLUG_PATTERN, fullmatch=True).filter(
        lambda value: len(value) <= MAX_DNS_LABEL_BYTES
    )
)
def test_every_grammar_generated_nonreserved_slug_is_ascii_or_reserved(value: str) -> None:
    try:
        validated = validate_slug(value)
    except ContractError as error:
        assert error.code is ErrorCode.RESERVED_SLUG
    else:
        assert validated.encode("ascii").decode("ascii") == value
