#!/usr/bin/env python3
"""Validate non-secret production convergence inputs without mutating state."""

from __future__ import annotations

import ipaddress
import json
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from scripts.check_m3_7_production_edge import (
    MAXIMUM_CERTIFICATE_BYTES,
    ProductionEdgePreflightError,
    certificate_public_key_identity,
    validate_ca_certificate,
)

MAXIMUM_INPUT_BYTES: Final = 16_384
EXPECTED_KEYS: Final = {"adminSourceCidrs", "originPullCaPaths"}


class ProductionEnvironmentInputError(RuntimeError):
    """Raised when a local production convergence input is unsafe."""


def _validate_admin_source_cidrs(raw: object) -> None:
    if not isinstance(raw, list) or not raw or any(not isinstance(item, str) for item in raw):
        raise ProductionEnvironmentInputError(
            "administrative source CIDRs must be one non-empty string array"
        )
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw:
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as error:
            raise ProductionEnvironmentInputError(
                "an administrative source CIDR is malformed or noncanonical"
            ) from error
        if network.prefixlen == 0:
            raise ProductionEnvironmentInputError(
                "administrative source CIDRs must not admit an entire address family"
            )
        networks.append(network)
    if len(set(networks)) != len(networks):
        raise ProductionEnvironmentInputError("administrative source CIDRs contain a duplicate")


def _validate_origin_pull_cas(raw: object) -> None:
    if (
        not isinstance(raw, list)
        or len(raw) not in {1, 2}
        or any(not isinstance(item, str) for item in raw)
        or len(set(raw)) != len(raw)
    ):
        raise ProductionEnvironmentInputError(
            "origin-pull CA paths must be one or two distinct strings"
        )
    now = datetime.now(UTC)
    seen_certificate_identities: set[bytes] = set()
    seen_public_key_identities: set[bytes] = set()
    for item in raw:
        path = Path(item)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ProductionEnvironmentInputError("an origin-pull CA path is unsafe")
        try:
            if path.stat().st_size > MAXIMUM_CERTIFICATE_BYTES:
                raise ProductionEnvironmentInputError("an origin-pull CA is oversized")
            pem = path.read_bytes()
            validate_ca_certificate(path, pem, now=now)
            identity = ssl.PEM_cert_to_DER_cert(pem.decode("ascii", errors="strict"))
            if identity in seen_certificate_identities:
                raise ProductionEnvironmentInputError(
                    "origin-pull CA certificates must be distinct"
                )
            public_key_identity = certificate_public_key_identity(pem)
            if public_key_identity in seen_public_key_identities:
                raise ProductionEnvironmentInputError("origin-pull CA public keys must be distinct")
            seen_certificate_identities.add(identity)
            seen_public_key_identities.add(public_key_identity)
        except OSError as error:
            raise ProductionEnvironmentInputError("an origin-pull CA is unreadable") from error
        except (ProductionEdgePreflightError, UnicodeError, ValueError) as error:
            raise ProductionEnvironmentInputError(
                "an origin-pull CA failed the production certificate policy"
            ) from error


def validate(payload: object) -> None:
    """Validate the exact local input payload used by the Bash loader."""
    if not isinstance(payload, dict) or set(payload) != EXPECTED_KEYS:
        raise ProductionEnvironmentInputError("the validation input has an unexpected shape")
    _validate_admin_source_cidrs(payload["adminSourceCidrs"])
    _validate_origin_pull_cas(payload["originPullCaPaths"])


def main() -> int:
    """Read and validate one bounded JSON value from standard input."""
    raw = sys.stdin.buffer.read(MAXIMUM_INPUT_BYTES + 1)
    if len(raw) > MAXIMUM_INPUT_BYTES:
        print("Production environment input validation failed: input is oversized", file=sys.stderr)
        return 2
    try:
        payload = json.loads(raw)
        validate(payload)
    except (json.JSONDecodeError, UnicodeError, ProductionEnvironmentInputError) as error:
        print(f"Production environment input validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
