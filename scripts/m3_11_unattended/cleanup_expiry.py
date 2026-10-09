"""Explicitly approved expiry-only updates of the two existing cleanup bootstraps."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.audit_policy_recovery import body
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare, result
from scripts.m3_11_unattended.config import Configuration, _cloudflare_authority
from scripts.m3_11_unattended.connect_diagnostics import failure
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.model import (
    CLEANUP_MARGIN,
    LIFETIME,
    LifecycleError,
    digest,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import private_directory, replace_private
from scripts.production_qualification_inputs import current_candidate

FORMAT = "lowerduckpond-m3-11-cleanup-bootstrap-expiry-v1"


def clients(config: Configuration) -> dict[str, Cloudflare]:
    reader = config.cleanup.reader()
    return {
        kind: Cloudflare(Api(ORIGIN, reader.read(config.cleanup.values[key])), account=account)
        for kind, key, account in (
            ("cloudflare-account", "cloudflare_account", config.targets.account_id),
            ("cloudflare-user", "cloudflare_user", None),
        )
    }


def inspect(client: Cloudflare, identifier: str) -> dict[str, object]:
    response = client.api.request("GET", client.path + "/" + identifier)
    value = result(response.status, response.body)
    if not isinstance(value, dict) or value.get("id") != identifier:
        raise LifecycleError("cleanup bootstrap identity changed")
    return body(value)


def plan(config: Configuration, *, expires_at: str, now: datetime) -> dict[str, object]:
    expiry = instant(expires_at)
    if not now + LIFETIME + CLEANUP_MARGIN < expiry <= now + timedelta(days=8):
        raise LifecycleError("cleanup renewal expiry is outside its bounded approval window")
    rows = {}
    for kind, client in clients(config).items():
        identifier, previous_expiry = _cloudflare_authority(client, target=config.targets, now=now)
        before = inspect(client, identifier)
        if expiry <= previous_expiry:
            raise LifecycleError("cleanup expiry proposal does not extend the existing deadline")
        rows[kind] = {
            "id": identifier,
            "authority_sha256": client.authority_sha256,
            "before": before,
            "after": {**copy.deepcopy(before), "expires_on": expires_at},
        }
    return {
        "format": FORMAT,
        "targets_sha256": digest(dataclasses.asdict(config.targets)),
        "expires_at": expires_at,
        "observed_at": stamp(now),
        "providers": rows,
    }


def apply(config: Configuration, raw: object, *, directory: Path, expected: str) -> None:
    approved = fields(raw, {"format", "targets_sha256", "expires_at", "observed_at", "providers"})
    expiry, observed, now = (
        instant(approved["expires_at"]),
        instant(approved["observed_at"]),
        datetime.now(UTC),
    )
    rows = fields(approved["providers"], {"cloudflare-account", "cloudflare-user"})
    if (
        digest(approved) != expected
        or approved["format"] != FORMAT
        or approved["targets_sha256"] != digest(dataclasses.asdict(config.targets))
        or not observed <= now < observed + timedelta(days=1)
        or not now + LIFETIME + CLEANUP_MARGIN < expiry <= observed + timedelta(days=8)
    ):
        raise LifecycleError("cleanup expiry approval is stale or mismatched")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(directory)
    intent = directory / "intent.json"
    if intent.exists():
        if read_private(intent) != approved:
            raise LifecycleError("another cleanup expiry intent already exists")
    else:
        write_private(intent, approved)
    for kind, client in clients(config).items():
        row = fields(rows[kind], {"id", "authority_sha256", "before", "after"})
        identifier, _expiry = _cloudflare_authority(client, target=config.targets, now=now)
        before, after = body(row["before"]), body(row["after"])
        if (
            identifier != row["id"]
            or client.authority_sha256 != row["authority_sha256"]
            or after != {**before, "expires_on": approved["expires_at"]}
        ):
            raise LifecycleError("cleanup expiry cannot change identity, policy or token value")
        current = inspect(client, identifier)
        if current not in (before, after):
            raise LifecycleError("cleanup bootstrap changed outside the approved expiry operation")
        if current == before:
            try:
                response = client.api.request(
                    "PUT", client.path + "/" + identifier, cast(dict[str, object], row["after"])
                )
                result(response.status, response.body)
            except RuntimeError, OSError, ValueError:
                pass  # Lost replies reconcile this exact identity; readback still decides.
        if inspect(client, identifier) != after:
            raise LifecycleError(
                "cleanup expiry update remains unverified; original intent retained"
            )
        verified_id, verified_expiry = _cloudflare_authority(
            client, target=config.targets, now=datetime.now(UTC)
        )
        if verified_id != identifier or verified_expiry != expiry:
            raise LifecycleError("cleanup expiry activity or lifetime readback differs")
        replace_private(
            directory / (kind + ".json"),
            {
                "plan_sha256": expected,
                "identity_sha256": row["authority_sha256"],
                "expires_at": approved["expires_at"],
                "status": "verified",
                "observed_at": stamp(datetime.now(UTC)),
            },
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--expires-at")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    stage = "validate-revision-and-configuration"
    try:
        current_candidate(Path(__file__).resolve().parents[2], args.revision)
        config = Configuration.load(args.config)
        if args.apply:
            if not args.plan_sha256 or args.directory is None or args.expires_at:
                raise LifecycleError(
                    "expiry update needs its exact approved plan and private evidence"
                )
            stage = "apply-expiry-and-verify-readback"
            apply(
                config, read_private(args.plan), directory=args.directory, expected=args.plan_sha256
            )
            print(
                "Both cleanup bootstrap expiries verified; "
                "credential values and policies unchanged."
            )
        else:
            if not args.expires_at or args.plan_sha256 or args.directory:
                raise LifecycleError("expiry preview needs one explicit deadline")
            stage = "inspect-current-cleanup-authority"
            value = plan(config, expires_at=args.expires_at, now=datetime.now(UTC))
            write_private(args.plan, value)
            print("Read-only cleanup expiry proposal saved; SHA-256 " + digest(value))
    except (LifecycleError, OSError, ValueError, TypeError, KeyError) as error:
        print(
            json.dumps(
                {
                    "status": "unresolved",
                    "stage": stage,
                    "failure": failure(error),
                    "message": "Retained obligations and evidence remain authoritative.",
                }
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
