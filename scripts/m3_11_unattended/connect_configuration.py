"""Explicit Connect role inputs; mixed or incomplete backends never fall back."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import READ, READ_WRITE, Access, authenticate, inspect
from scripts.m3_11_unattended.model import LifecycleError, instant, strings

PROVIDER_REFERENCES = {
    "digitalocean",
    "digitalocean_metadata",
    "cloudflare_account",
    "cloudflare_user",
}
READER_FIELDS = {"url", "role", "vaults", "entry", "metadata"}


def reader_access(
    value: object, *, allow_expired: bool = False
) -> tuple[dict[str, object], Access]:
    # Version two removes the implicit seven-day client limit only when setup
    # supplied an exact approved expiry. It does not change the vault grants.
    explicit = isinstance(value, dict) and value.get("format") == "lowerduckpond-connect-reader-v2"
    selected = fields(
        value, READER_FIELDS | ({"format", "approved_expires_at"} if explicit else set())
    )
    role, url = selected["role"], selected["url"]
    vaults = strings(fields(selected["vaults"], {"provision", "cleanup", "production", "journal"}))
    if (
        role not in {"provision", "cleanup", "production"}
        or not isinstance(role, str)
        or not isinstance(url, str)
        or len(set(vaults.values())) != len(vaults)
        or any(re.fullmatch(r"[a-z0-9]{26}", vault) is None for vault in vaults.values())
        or not isinstance(selected["entry"], dict)
        or not isinstance(selected["metadata"], dict)
    ):
        raise LifecycleError("Connect reader role or isolated vault identities are invalid")
    expected = {vaults[role]: READ}
    if role != "production":
        expected[vaults["journal"]] = READ_WRITE
    access = inspect(
        selected["entry"],
        selected["metadata"],
        expected=expected,
        now=datetime.now(UTC),
        approved_expires_at=instant(selected["approved_expires_at"]) if explicit else None,
        allow_expired=allow_expired,
    )
    Connect(url, access.token)  # Validate the bare HTTPS origin without contacting it.
    return selected, access


def reader(value: object) -> Connect:
    selected, access = reader_access(value)
    url = selected["url"]
    if not isinstance(url, str):
        raise LifecycleError("Connect reader endpoint is invalid")
    client = Connect(url, access.token)
    vaults = strings(selected["vaults"])
    authenticate(client, access, forbidden=set(vaults.values()) - access.grants.keys())
    return client
