"""An encrypted read cache, never an alternative to the live obligation inventory."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.model import LifecycleError
from scripts.m3_11_unattended.state import replace_private

FORMAT = "lowerduckpond-m3-11-journal-cache-v1"
MAX_CACHE_BYTES = 32 * 1024 * 1024
NONCE_BYTES = 12


class JournalCache:
    """Only encrypted journal records may enter the GitHub Actions cache.

    The dedicated service-account token supplies the key. No bootstrap provider
    secret, production input, or runtime credential is included in the payload.
    Cache hits still require current 1Password inventory metadata and title hashes.
    """

    def __init__(self, path: Path, *, token: str, vault: str) -> None:
        self.path = path
        self.context = (FORMAT + ":" + vault).encode()
        self.cipher = AESGCM(hashlib.sha256(self.context + b"\0" + token.encode()).digest())

    def read(self) -> dict[str, object]:
        if not self.path.exists() and not self.path.is_symlink():
            return {}
        try:
            value = fields(read_private(self.path, maximum=MAX_CACHE_BYTES), {"ciphertext"})
            if not isinstance(value["ciphertext"], str):
                raise ValueError
            raw = base64.b64decode(value["ciphertext"], validate=True)
            plain = self.cipher.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], self.context)
            result = json.loads(plain)
            if not isinstance(result, dict) or canonical_bytes(result) != plain:
                raise ValueError
            return result
        except InvalidTag, OSError, ValueError, TypeError:
            raise LifecycleError(
                "encrypted journal cache is invalid; preserve obligations"
            ) from None

    def write(self, records: dict[str, object]) -> None:
        nonce = os.urandom(NONCE_BYTES)
        raw = nonce + self.cipher.encrypt(nonce, canonical_bytes(records), self.context)
        value: dict[str, object] = {"ciphertext": base64.b64encode(raw).decode()}
        if len(canonical_bytes(value)) > MAX_CACHE_BYTES:
            raise LifecycleError("encrypted journal cache exceeds its bound")
        replace_private(self.path, value)
