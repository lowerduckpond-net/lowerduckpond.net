"""UUIDv7 generation from explicit root-provided time and entropy sources."""

from __future__ import annotations

import uuid
from typing import Final, Protocol

from lowerduckpond_static_contracts import ContractError, ErrorCode

UUID_VERSION: Final = 7
UUID_VARIANT: Final = 0b10
UUID_TIMESTAMP_BITS: Final = 48
UUID_RANDOM_BITS: Final = 74
UUID_ENTROPY_BYTES: Final = 10
MAX_TIMESTAMP_MILLISECONDS: Final = (1 << UUID_TIMESTAMP_BITS) - 1
RANDOM_MASK: Final = (1 << UUID_RANDOM_BITS) - 1
RAND_B_MASK: Final = (1 << 62) - 1


class MillisecondClock(Protocol):
    """One explicitly injected Unix-millisecond clock."""

    def __call__(self) -> int: ...


class EntropySource(Protocol):
    """One explicitly injected exact-length byte source."""

    def __call__(self, length: int) -> bytes: ...


def generate_uuid7(*, clock: MillisecondClock, entropy: EntropySource) -> str:
    """Generate one canonical lowercase UUIDv7 without ambient dependencies."""

    timestamp = clock()
    if type(timestamp) is not int or not 0 <= timestamp <= MAX_TIMESTAMP_MILLISECONDS:
        raise ContractError(ErrorCode.INVALID_CLOCK, "UUIDv7 clock value is outside its domain")
    random_bytes = entropy(UUID_ENTROPY_BYTES)
    if type(random_bytes) is not bytes or len(random_bytes) != UUID_ENTROPY_BYTES:
        raise ContractError(ErrorCode.INVALID_ENTROPY, "UUIDv7 entropy length is invalid")
    random_bits = int.from_bytes(random_bytes, byteorder="big") & RANDOM_MASK
    rand_a = random_bits >> 62
    rand_b = random_bits & RAND_B_MASK
    value = (
        (timestamp << 80) | (UUID_VERSION << 76) | (rand_a << 64) | (UUID_VARIANT << 62) | rand_b
    )
    return str(uuid.UUID(int=value))
