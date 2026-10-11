"""Read-only reconciliation of exact historical cleanup-expiry update intents."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.audit_policy_recovery import body
from scripts.m3_11_unattended.cloudflare import Cloudflare, result
from scripts.m3_11_unattended.journal import validate
from scripts.m3_11_unattended.lifecycle import identifier as credential_id
from scripts.m3_11_unattended.model import (
    LifecycleError,
    Targets,
    digest,
    fingerprint,
    instant,
    strings,
)

FORMAT = "lowerduckpond-m3-11-cleanup-bootstrap-expiry-v1"
PROOF_FORMAT = "lowerduckpond-m3-11-imported-expiry-readback-v1"


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
    approved = imported_plan(raw, expected=expected)
    if approved["targets_sha256"] != digest(dataclasses.asdict(targets)):
        raise LifecycleError("imported cleanup expiry approval differs")
    rows = fields(approved["providers"], {"cloudflare-account", "cloudflare-user"})
    for kind, raw_row in rows.items():
        row = fields(raw_row, {"id", "authority_sha256", "before", "after"})
        client = providers[kind]
        if (
            client.kind != kind
            or client.authority_sha256 != row["authority_sha256"]
            or (
                kind == "cloudflare-account"
                and client.path != f"/accounts/{targets.account_id}/tokens"
            )
        ):
            raise LifecycleError("imported cleanup expiry identity or policy differs")
        if inspect(client, credential_id(row["id"])) != body(row["after"]):
            raise LifecycleError("historical cleanup expiry update remains unresolved")
    return "verified"


def imported_plan(raw: object, *, expected: str) -> dict[str, object]:
    """Validate the immutable update independently of historical provider access."""
    approved = fields(raw, {"format", "targets_sha256", "expires_at", "observed_at", "providers"})
    if approved["format"] != FORMAT or digest(approved) != expected:
        raise LifecycleError("imported cleanup expiry approval differs")
    fingerprint(approved["targets_sha256"])
    instant(approved["expires_at"])
    instant(approved["observed_at"])
    rows = fields(approved["providers"], {"cloudflare-account", "cloudflare-user"})
    for raw_row in rows.values():
        row = fields(raw_row, {"id", "authority_sha256", "before", "after"})
        credential_id(row["id"])
        fingerprint(row["authority_sha256"])
        before, after = body(row["before"]), body(row["after"])
        if after != {**before, "expires_on": approved["expires_at"]} or instant(
            before["expires_on"]
        ) >= instant(approved["expires_at"]):
            raise LifecycleError("imported cleanup expiry identity or policy differs")
    return approved


def imported_update(raw: object) -> dict[str, object]:
    """Optionally retain exact nonsecret result-file contents in the approved import.

    File hashes alone cannot establish completion after the original host is
    gone. Embedded bytes retain that evidence without generating a new result.
    Older imports remain valid and require live reconciliation when needed.
    """
    row = fields(
        raw,
        {"plan", "plan_sha256", "generation_id", "result_files"}
        | ({"result_contents"} if isinstance(raw, dict) and "result_contents" in raw else set()),
    )
    approved = imported_plan(row["plan"], expected=str(row["plan_sha256"]))
    files = strings(row["result_files"])
    contents = strings(row.get("result_contents", {}))
    if contents and set(contents) != set(files):
        raise LifecycleError("legacy expiry result contents do not cover the retained files")
    providers = fields(approved["providers"], {"cloudflare-account", "cloudflare-user"})
    for filename, content in contents.items():
        if hashlib.sha256(content.encode()).hexdigest() != files[filename]:
            raise LifecycleError("legacy expiry result bytes differ from the retained evidence")
        result = fields(
            json.loads(content),
            {"plan_sha256", "identity_sha256", "expires_at", "status", "observed_at"},
        )
        matches = [
            item
            for item in providers.values()
            if isinstance(item, dict) and item["authority_sha256"] == result["identity_sha256"]
        ]
        if (
            len(matches) != 1
            or result["plan_sha256"] != row["plan_sha256"]
            or result["expires_at"] != approved["expires_at"]
            or result["status"] != "verified"
            or not instant(approved["observed_at"])
            <= instant(result["observed_at"])
            < instant(approved["expires_at"])
        ):
            raise LifecycleError("legacy expiry result lacks its original identity and readback")
    return row


def readback_proof(raw: object) -> dict[str, object]:
    """Exact expected readbacks, published only after live reconciliation succeeds."""
    row = imported_update(raw)
    plan = imported_plan(row["plan"], expected=str(row["plan_sha256"]))
    providers = fields(plan["providers"], {"cloudflare-account", "cloudflare-user"})
    return {
        "format": PROOF_FORMAT,
        "plan_sha256": row["plan_sha256"],
        "generation_id": row["generation_id"],
        "targets_sha256": plan["targets_sha256"],
        "readbacks": {
            kind: {
                "credential_id": value["id"],
                "authority_sha256": value["authority_sha256"],
                "body": body(value["after"]),
            }
            for kind, raw_value in providers.items()
            for value in [fields(raw_value, {"id", "authority_sha256", "before", "after"})]
        },
    }


def terminal_update(
    raw: object, *, targets: Targets | None = None, records: list[dict[str, object]] | None = None
) -> bool:
    row = imported_update(raw)
    approved = imported_plan(row["plan"], expected=str(row["plan_sha256"]))
    if targets is not None and approved["targets_sha256"] != digest(dataclasses.asdict(targets)):
        raise LifecycleError("imported cleanup expiry target differs")
    proven = False
    for record in records or []:
        value = record["payload"]
        if (
            isinstance(value, dict)
            and value.get("format") == PROOF_FORMAT
            and value.get("plan_sha256") == row["plan_sha256"]
        ):
            validate(record)
            if (
                record["kind"] != "heartbeat"
                or record["run_id"] != row["generation_id"]
                or value != readback_proof(row)
                or instant(record["recorded_at"]) < instant(approved["observed_at"])
            ):
                raise LifecycleError("legacy expiry readback conflicts with its original update")
            proven = True
    identities = {
        fields(
            json.loads(value),
            {"plan_sha256", "identity_sha256", "expires_at", "status", "observed_at"},
        )["identity_sha256"]
        for value in strings(row.get("result_contents", {})).values()
    }
    expected = {
        fields(value, {"id", "authority_sha256", "before", "after"})["authority_sha256"]
        for value in fields(
            approved["providers"], {"cloudflare-account", "cloudflare-user"}
        ).values()
    }
    return proven or identities == expected
