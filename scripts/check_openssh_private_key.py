#!/usr/bin/env python3
"""Validate the bounded, encrypted container metadata of one OpenSSH private key."""

from __future__ import annotations

import base64
import binascii
import sys
from pathlib import Path
from typing import Final

MAXIMUM_PRIVATE_KEY_BYTES: Final = 65_536
MINIMUM_PEM_LINES: Final = 3
OPENSSH_MAGIC: Final = b"openssh-key-v1\0"
PEM_BEGIN_PREFIX: Final = b"-----BEGIN OPENSSH"
PEM_END_PREFIX: Final = b"-----END OPENSSH"
PEM_PRIVATE_SUFFIX: Final = b"PRIVATE KEY-----"
PEM_BEGIN: Final = PEM_BEGIN_PREFIX + b" " + PEM_PRIVATE_SUFFIX
PEM_END: Final = PEM_END_PREFIX + b" " + PEM_PRIVATE_SUFFIX
UINT32_BYTES: Final = 4


class OpenSSHPrivateKeyError(RuntimeError):
    """Raised when an administrative private-key container is unsafe."""


def _read_string(value: bytes, offset: int) -> tuple[bytes, int]:
    if len(value) - offset < UINT32_BYTES:
        raise OpenSSHPrivateKeyError("the private-key container is malformed")
    length = int.from_bytes(value[offset : offset + UINT32_BYTES], byteorder="big")
    offset += UINT32_BYTES
    if length > len(value) - offset:
        raise OpenSSHPrivateKeyError("the private-key container is malformed")
    return value[offset : offset + length], offset + length


def validate(path: Path) -> None:
    """Require one structurally valid, encrypted OpenSSH private-key container."""
    try:
        with path.open("rb") as private_key:
            raw = private_key.read(MAXIMUM_PRIVATE_KEY_BYTES + 1)
    except OSError as error:
        raise OpenSSHPrivateKeyError("the administrative SSH identity could not be read") from error
    if len(raw) > MAXIMUM_PRIVATE_KEY_BYTES:
        raise OpenSSHPrivateKeyError("the administrative SSH identity is oversized")
    lines = raw.splitlines()
    if len(lines) < MINIMUM_PEM_LINES or lines[0] != PEM_BEGIN or lines[-1] != PEM_END:
        raise OpenSSHPrivateKeyError(
            "the administrative SSH identity does not contain private-key material"
        )
    try:
        container = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError) as error:
        raise OpenSSHPrivateKeyError("the private-key container is malformed") from error
    if not container.startswith(OPENSSH_MAGIC):
        raise OpenSSHPrivateKeyError("the private-key container is malformed")

    offset = len(OPENSSH_MAGIC)
    cipher_name, offset = _read_string(container, offset)
    kdf_name, offset = _read_string(container, offset)
    kdf_options, offset = _read_string(container, offset)
    if len(container) - offset < UINT32_BYTES:
        raise OpenSSHPrivateKeyError("the private-key container is malformed")
    key_count = int.from_bytes(container[offset : offset + UINT32_BYTES], byteorder="big")
    offset += UINT32_BYTES
    if key_count != 1:
        raise OpenSSHPrivateKeyError("the private-key container is malformed")
    public_key, offset = _read_string(container, offset)
    private_section, offset = _read_string(container, offset)
    if offset != len(container) or not public_key or not private_section:
        raise OpenSSHPrivateKeyError("the private-key container is malformed")

    if cipher_name == b"none" and kdf_name == b"none" and not kdf_options:
        raise OpenSSHPrivateKeyError("the administrative SSH identity must be passphrase-protected")
    if (
        not cipher_name
        or cipher_name == b"none"
        or not kdf_name
        or kdf_name == b"none"
        or not kdf_options
    ):
        raise OpenSSHPrivateKeyError("the private-key encryption metadata is malformed")


def main(arguments: list[str] | None = None) -> int:
    """Validate one path without displaying key material or its location."""
    args = sys.argv[1:] if arguments is None else arguments
    if len(args) != 1:
        print("usage: check_openssh_private_key.py PRIVATE_KEY", file=sys.stderr)
        return 64
    try:
        validate(Path(args[0]))
    except OpenSSHPrivateKeyError as error:
        print(f"{error}.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
