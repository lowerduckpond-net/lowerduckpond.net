"""Authenticate Connect clients and compare signed grants with native setup metadata."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import cast

from scripts.m3_11_unattended.connect_api import Connect, _object
from scripts.m3_11_unattended.model import LifecycleError, instant, stamp

IDENTITY = re.compile(r"[A-Za-z0-9]{26}")
# Native op 2.33.0 metadata calls these allow_viewing and allow_editing.
# These exact signed ACL values were observed for the corresponding issued
# read-only/read-write clients. Reject unknown bits rather than infer access.
READ = 48
READ_WRITE = 496
CLAIM_PREFIX = "1password.com/"
SKEW = timedelta(minutes=5)
MAX_LIFETIME = timedelta(days=7)
MAX_TOKEN_BYTES = 65536


def identity(value: object) -> str:
    if not isinstance(value, str) or IDENTITY.fullmatch(value) is None:
        raise LifecycleError("Connect identity is invalid")
    return value


def _part(value: str) -> dict[str, object]:
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        result = json.loads(raw, object_pairs_hook=_object)
    except ValueError, UnicodeError:
        raise LifecycleError("Connect token claims are invalid") from None
    if not isinstance(result, dict):
        raise LifecycleError("Connect token claims are unavailable")
    return cast(dict[str, object], result)


def claims(token: str) -> dict[str, object]:
    """Private only: payload includes key material, not just public JWT claims."""
    if (
        len(token) > MAX_TOKEN_BYTES
        or re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token) is None
    ):
        raise LifecycleError("Connect client credential is invalid")
    header, payload, _signature = token.split(".")
    details = _part(header)
    if details.get("alg") != "ES256" or details.get("typ") != "JWT":
        raise LifecycleError("Connect client signing algorithm is unexpected")
    return _part(payload)


def _grants(value: object, *, native: bool) -> dict[str, int]:
    if not isinstance(value, list):
        raise LifecycleError("Connect vault policy is unavailable")
    grants: dict[str, int] = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise LifecycleError("Connect vault policy is malformed")
        vault = identity(entry.get("id" if native else "u")).lower()
        permission = entry.get("acl" if native else "a")
        if native:
            if permission == ["allow_viewing"]:
                permission = READ
            elif permission in (
                ["allow_viewing", "allow_editing"],
                ["allow_editing", "allow_viewing"],
            ):
                permission = READ_WRITE
            else:
                raise LifecycleError("Connect native policy contains an unexpected permission")
        if type(permission) is not int or permission not in {READ, READ_WRITE} or vault in grants:
            raise LifecycleError("Connect signed policy contains unknown or ambiguous grants")
        grants[vault] = permission
    return grants


@dataclass(frozen=True)
class Access:
    server_id: str
    token_id: str
    account_id: str
    expires_at: datetime
    grants: dict[str, int]
    token: str = field(repr=False)

    def receipt(self) -> dict[str, object]:
        return {
            "server_sha256": hashlib.sha256(self.server_id.encode()).hexdigest(),
            "token_id_sha256": hashlib.sha256(self.token_id.encode()).hexdigest(),
            "expires_at": stamp(self.expires_at),
            "exact_native_and_signed_policy": True,
            "authenticated": False,
        }


def inspect(
    entry: dict[str, object],
    metadata: dict[str, object],
    *,
    expected: dict[str, int],
    now: datetime,
) -> Access:
    """Parse policy privately. Endpoint authentication must follow before use."""
    token = entry.get("token")
    if not isinstance(token, str):
        raise LifecycleError("Connect client is unavailable")
    payload = claims(token)
    server, records = metadata.get("server"), metadata.get("tokens")
    if not isinstance(server, dict) or not isinstance(records, list):
        raise LifecycleError("Connect native metadata is unavailable")
    server_id = identity(entry.get("server"))
    token_id, account = identity(payload.get("jti")), identity(payload.get(CLAIM_PREFIX + "auuid"))
    matches = [row for row in records if isinstance(row, dict) and row.get("id") == token_id]
    if len(matches) != 1:
        raise LifecycleError("Connect native token identity is ambiguous")
    native = matches[0]
    if (
        server.get("id") != server_id
        or server.get("state") != "ACTIVE"
        or payload.get("sub") != server_id
        or native.get("integration_id") != server_id
        or native.get("state") != "ACTIVE"
        or native.get("name") != entry.get("name")
        or not isinstance(native.get("issuer"), str)
        or not isinstance(native.get("audience"), str)
        or native.get("issuer") != payload.get("iss")
        or native.get("audience") != payload.get("aud")
        or native.get("features") != ["vaultaccess"]
        or payload.get(CLAIM_PREFIX + "fts") != ["vaultaccess"]
        or _grants(native.get("vaults"), native=True) != expected
        or _grants(payload.get(CLAIM_PREFIX + "vts"), native=False) != expected
    ):
        raise LifecycleError("Connect client identity, activity or exact policy differs")
    issued, expiry = payload.get("iat"), payload.get("exp")
    if type(issued) is not int or type(expiry) is not int:
        raise LifecycleError("Connect client lifetime is unavailable")
    try:
        issued_at, expires_at = (
            datetime.fromtimestamp(issued, UTC),
            datetime.fromtimestamp(expiry, UTC),
        )
    except OverflowError, OSError, ValueError:
        raise LifecycleError("Connect client lifetime is invalid") from None
    if (
        issued_at > now + SKEW
        or not now < expires_at <= issued_at + MAX_LIFETIME + SKEW
        or abs(instant(native.get("created_at")) - issued_at) > SKEW
        or instant(native.get("expires_at")) != expires_at
        or instant(entry.get("expires_at")) != expires_at
    ):
        raise LifecycleError("Connect native and signed lifetimes differ or have expired")
    return Access(server_id, token_id, account, expires_at, dict(expected), token)


def authenticate(client: Connect, access: Access, *, forbidden: set[str]) -> dict[str, object]:
    """Server acceptance verifies the signed token; native metadata supplies exact ACLs."""
    if client.credential_sha256 != hashlib.sha256(access.token.encode()).hexdigest():
        raise LifecycleError("Connect authentication client differs from the inspected token")
    if {vault["id"] for vault in client.vaults()} != set(access.grants):
        raise LifecycleError("Connect authenticated vault visibility differs from its policy")
    if forbidden & access.grants.keys():
        raise LifecycleError("Connect approved and forbidden vaults overlap")
    for vault in sorted(forbidden):
        identity(vault)
        response = client.request("GET", "/v1/vaults/" + vault.lower())
        if response.status not in {403, 404}:
            raise LifecycleError("Connect access to a forbidden vault was not denied")
    return {**access.receipt(), "authenticated": True, "forbidden_vaults_denied": len(forbidden)}
