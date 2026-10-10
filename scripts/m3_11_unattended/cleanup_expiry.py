"""Read-only reconciliation of exact historical cleanup-expiry update intents."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from pathlib import Path

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.audit_policy_recovery import body
from scripts.m3_11_unattended.cloudflare import Cloudflare, result
from scripts.m3_11_unattended.lifecycle import identifier as credential_id
from scripts.m3_11_unattended.model import LifecycleError, Targets, digest, instant

FORMAT = "lowerduckpond-m3-11-cleanup-bootstrap-expiry-v1"


def inspect(client: Cloudflare, identifier: str) -> dict[str, object]:
    response = client.api.request("GET", client.path + "/" + identifier)
    value = result(response.status, response.body)
    if not isinstance(value, dict) or value.get("id") != identifier:
        raise LifecycleError("cleanup bootstrap identity changed")
    return body(value)


def apply(config: object, raw: object, *, directory: Path, expected: str) -> None:
    raise LifecycleError("obsolete cleanup expiry updates are permanently disabled")


def reconcile_imported(
    raw: object, *, targets: Targets, expected: str, providers: Mapping[str, Cloudflare]
) -> str:
    """Observe a historical update; never replay or renew its old mutation.

    The import binds the original approval and intent files. Its elapsed window
    cannot erase a lost-response obligation or authorize another expiry update.
    """
    approved = fields(raw, {"format", "targets_sha256", "expires_at", "observed_at", "providers"})
    if (
        approved["format"] != FORMAT
        or digest(approved) != expected
        or approved["targets_sha256"] != digest(dataclasses.asdict(targets))
    ):
        raise LifecycleError("imported cleanup expiry approval differs")
    instant(approved["expires_at"])
    instant(approved["observed_at"])
    rows = fields(approved["providers"], {"cloudflare-account", "cloudflare-user"})
    for kind, raw_row in rows.items():
        row = fields(raw_row, {"id", "authority_sha256", "before", "after"})
        client = providers[kind]
        before, after = body(row["before"]), body(row["after"])
        if (
            client.kind != kind
            or client.authority_sha256 != row["authority_sha256"]
            or after != {**before, "expires_on": approved["expires_at"]}
            or instant(before["expires_on"]) >= instant(approved["expires_at"])
            or (
                kind == "cloudflare-account"
                and client.path != f"/accounts/{targets.account_id}/tokens"
            )
        ):
            raise LifecycleError("imported cleanup expiry identity or policy differs")
        if inspect(client, credential_id(row["id"])) != after:
            raise LifecycleError("historical cleanup expiry update remains unresolved")
    return "verified"
