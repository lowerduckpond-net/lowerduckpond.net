"""Schema-independent versioned digest values and byte framing."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts.errors import ContractError, ErrorCode

MANIFEST_DIGEST_FORMAT: Final = "lowerduckpond-manifest-v1"
REQUEST_DIGEST_FORMAT: Final = "lowerduckpond-request-v1"
RESULT_DIGEST_FORMAT: Final = "lowerduckpond-result-v1"
AUDIT_ENTRY_DIGEST_FORMAT: Final = "lowerduckpond-audit-entry-v1"
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
FORMAT_PATTERN: Final = re.compile(
    r"lowerduckpond-[a-z0-9]+(?:-[a-z0-9]+)*-v1",
    flags=re.ASCII,
)
MAX_U32: Final = (1 << 32) - 1


@dataclass(frozen=True, slots=True)
class Digest:
    """One non-ambiguous versioned digest value."""

    format: str
    algorithm: str
    value: str

    def __post_init__(self) -> None:
        if (
            self.algorithm != "sha256"
            or type(self.value) is not str
            or SHA256_PATTERN.fullmatch(self.value) is None
        ):
            raise ContractError(ErrorCode.INVALID_IDENTIFIER, "digest is not canonical SHA-256")
        if type(self.format) is not str or FORMAT_PATTERN.fullmatch(self.format) is None:
            raise ContractError(ErrorCode.INVALID_IDENTIFIER, "digest format is not recognized")

    def to_dict(self) -> dict[str, str]:
        """Return the strict JSON representation."""

        return {"format": self.format, "algorithm": self.algorithm, "value": self.value}


def digest_bytes(payload: bytes, *, format_identifier: str) -> Digest:
    """Digest length-bound bytes with the format's domain separator."""

    digest = Digest(format_identifier, "sha256", "0" * 64)
    if len(payload) > MAX_U32:
        raise ContractError(ErrorCode.CANONICAL_TOO_LARGE, "digest payload length is unsupported")
    framed = digest.format.encode("ascii") + b"\0" + len(payload).to_bytes(4, "big") + payload
    return Digest(digest.format, "sha256", hashlib.sha256(framed).hexdigest())
