from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from lowerduckpond_static_contracts import ContractError, ErrorCode, validate_uuid7
from lowerduckpond_static_domain import generate_uuid7
from lowerduckpond_static_domain.identity import (
    MAX_TIMESTAMP_MILLISECONDS,
    UUID_ENTROPY_BYTES,
    UUID_VERSION,
    EntropySource,
    MillisecondClock,
)

VECTOR_ROOT = Path(__file__).parents[3] / "tests/static-publication/vectors"


def _zero_entropy(length: int) -> bytes:
    return bytes(length)


def test_uuidv7_generator_matches_committed_vectors() -> None:
    vectors = json.loads((VECTOR_ROOT / "root-domain-v1.json").read_text(encoding="utf-8"))
    for vector in vectors["uuidv7"]:
        entropy = bytes.fromhex(vector["entropyHex"])
        generated = generate_uuid7(
            clock=lambda vector=vector: vector["unixMilliseconds"],
            entropy=lambda length, entropy=entropy: entropy,
        )
        assert generated == vector["id"]
        assert validate_uuid7(generated) == generated


@given(
    timestamp=st.integers(min_value=0, max_value=MAX_TIMESTAMP_MILLISECONDS),
    entropy=st.binary(min_size=UUID_ENTROPY_BYTES, max_size=UUID_ENTROPY_BYTES),
)
def test_uuidv7_preserves_timestamp_version_variant_and_canonical_form(
    timestamp: int, entropy: bytes
) -> None:
    generated = generate_uuid7(
        clock=lambda: timestamp,
        entropy=lambda _length: entropy,
    )
    parsed = uuid.UUID(generated)

    assert parsed.version == UUID_VERSION
    assert parsed.variant == uuid.RFC_4122
    assert parsed.int >> 80 == timestamp
    assert str(parsed) == generated


@pytest.mark.parametrize("timestamp", [-1, MAX_TIMESTAMP_MILLISECONDS + 1, True, 1.5])
def test_uuidv7_rejects_clock_values_outside_the_exact_integer_domain(
    timestamp: object,
) -> None:
    with pytest.raises(ContractError) as captured:
        generate_uuid7(
            clock=cast(MillisecondClock, lambda: timestamp),
            entropy=_zero_entropy,
        )

    assert captured.value.code is ErrorCode.INVALID_CLOCK


@pytest.mark.parametrize("entropy", [b"", b"a" * 9, b"a" * 11, bytearray(10)])
def test_uuidv7_rejects_nonexact_entropy(entropy: object) -> None:
    with pytest.raises(ContractError) as captured:
        generate_uuid7(
            clock=lambda: 0,
            entropy=cast(EntropySource, lambda _length: entropy),
        )

    assert captured.value.code is ErrorCode.INVALID_ENTROPY


def test_uuidv7_requests_exactly_ten_entropy_bytes() -> None:
    requested: list[int] = []

    def entropy(length: int) -> bytes:
        requested.append(length)
        return bytes(length)

    generate_uuid7(clock=lambda: 0, entropy=entropy)

    assert requested == [UUID_ENTROPY_BYTES]
