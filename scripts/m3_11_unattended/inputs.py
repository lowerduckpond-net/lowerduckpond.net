"""Explicit managed fixture inputs: complete, private, bound, and never state-derived."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import (
    ROLES,
    LifecycleError,
    Targets,
    digest,
    identity,
    instant,
    strings,
)
from scripts.production_qualification_inputs import current_candidate, fingerprint, revision

MANAGED_ENV = "LDP_M3_11_MANAGED_INPUTS"
FORMAT = "lowerduckpond-m3-11-managed-inputs-v1"
PRODUCTION_FORMAT = "lowerduckpond-m3-11-production-credentials-v1"
FIXTURE_FORMAT = "lowerduckpond-m3-11-fixture-credentials-v1"
BINDING = {
    "managed_run_id",
    "source_revision",
    "helper_revision",
    "qualification_inputs_sha256",
    "storage_target_sha256",
    "artifact_sha256",
}
SECRET_ENV = frozenset(
    {
        "SPACES_ARCHIVE_ACCESS_KEY_ID",
        "SPACES_ARCHIVE_SECRET_ACCESS_KEY",
        "SPACES_BACKUP_ACCESS_KEY_ID",
        "SPACES_BACKUP_SECRET_ACCESS_KEY",
        "SPACES_ACCESS_KEY_ID",
        "SPACES_SECRET_ACCESS_KEY",
        "CADDY_CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_TOKEN",
        "M3_10_TOKEN_AUDIT_TOKEN",
        "M3_10_PAGE_RULES_TOKEN",
    }
)
FORBIDDEN_PREFIXES = (
    "GH_",
    "GITHUB_",
    "OP_",
    "OPENTOFU_",
    "TF_VAR_",
    "AWS_",
    "DIGITALOCEAN_",
    "CF_BOOTSTRAP_",
    "LDP_BOOTSTRAP_",
)
PRODUCTION_RESULT = {
    "caddy": "active-exact-policy-non-expiring",
    "storage": "version-capabilities-mutual-denial-cleanup",
    "separation": "production-and-fixture-distinct",
}
FIXTURE_RESULT = dict.fromkeys(ROLES, "active-exact-policy-expiry-verified")
FIXTURE_RESULT.update(
    dict.fromkeys(("archive", "backup", "operator"), "active-exact-grants-deletion-deadline")
)
MAX_PRODUCTION_CHECK = timedelta(minutes=30)


def validate_receipt(
    value: object,
    *,
    binding: Mapping[str, object],
    kind: str,
    now: datetime,
    maximum_age: timedelta = timedelta(hours=24),
) -> dict[str, object]:
    expected = PRODUCTION_RESULT if kind == "production" else FIXTURE_RESULT
    extra = {"deadline"} if kind == "fixture" else set()
    receipt = fields(
        value,
        BINDING | {"format", "started_at", "completed_at", "checks", "identities_sha256"} | extra,
    )
    if (
        receipt["format"] != (PRODUCTION_FORMAT if kind == "production" else FIXTURE_FORMAT)
        or any(receipt[key] != binding[key] for key in BINDING)
        or receipt["checks"] != expected
    ):
        raise LifecycleError("credential receipt belongs to different inputs or incomplete checks")
    identity(receipt["managed_run_id"])
    revision(receipt["source_revision"])
    revision(receipt["helper_revision"])
    if any(
        re.fullmatch(r"[0-9a-f]{64}", str(receipt[key])) is None
        for key in (
            "artifact_sha256",
            "qualification_inputs_sha256",
            "storage_target_sha256",
        )
    ):
        raise LifecycleError("credential receipt has invalid artifact or input digests")
    ids = strings(receipt["identities_sha256"])
    roles = {"archive", "backup", "caddy"} if kind == "production" else ROLES
    if (
        set(ids) != roles
        or len(set(ids.values())) != len(roles)
        or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in ids.values())
    ):
        raise LifecycleError("credential receipt identities are incomplete or not separated")
    started, completed = instant(receipt["started_at"]), instant(receipt["completed_at"])
    if (
        not now - maximum_age <= started <= completed <= now + timedelta(minutes=5)
        or completed - started > MAX_PRODUCTION_CHECK
    ):
        raise LifecycleError("credential receipt is stale or has invalid chronology")
    if kind == "fixture" and not completed < instant(receipt["deadline"]) <= started + timedelta(
        hours=14
    ):
        raise LifecycleError("fixture receipt exceeded its approved lifetime")
    return receipt


def receipt_pair(
    value: object,
    *,
    binding: Mapping[str, object],
    now: datetime,
    maximum_age: timedelta = timedelta(hours=24),
) -> dict[str, dict[str, object]]:
    pair = fields(value, {"production", "fixture"})
    checked = {
        kind: validate_receipt(
            pair[kind], binding=binding, kind=kind, now=now, maximum_age=maximum_age
        )
        for kind in ("production", "fixture")
    }
    production = strings(checked["production"]["identities_sha256"])
    fixture = strings(checked["fixture"]["identities_sha256"])
    if set(production.values()) & set(fixture.values()):
        raise LifecycleError("fixture credentials cannot validate production credentials")
    return checked


def load(
    path: Path, *, repository: Path, now: datetime
) -> tuple[dict[str, str], dict[str, object]]:
    if (
        not path.is_absolute()
        or path.resolve(strict=True) != path
        or path.is_relative_to(repository)
    ):
        raise LifecycleError("managed inputs require a canonical private path outside the checkout")
    document = fields(
        read_private(path), {"format", "binding", "targets", "credentials", "receipts"}
    )
    binding = fields(document["binding"], BINDING)
    targets = Targets.parse(document["targets"])
    credentials = strings(document["credentials"])
    source = revision(binding["source_revision"])
    current_candidate(repository, source)
    if (
        document["format"] != FORMAT
        or set(credentials) != SECRET_ENV
        or any(not item or any(char.isspace() for char in item) for item in credentials.values())
        or binding["qualification_inputs_sha256"] != fingerprint(repository, source)
        or binding["storage_target_sha256"] != targets.storage_digest
    ):
        raise LifecycleError(
            "managed inputs are incomplete or differ from the approved source and target"
        )
    pair = receipt_pair(document["receipts"], binding=binding, now=now)
    issued_ids = strings(pair["fixture"]["identities_sha256"])
    import hashlib  # noqa: PLC0415 - kept local to private input validation

    for role, variable in (
        ("archive", "SPACES_ARCHIVE_ACCESS_KEY_ID"),
        ("backup", "SPACES_BACKUP_ACCESS_KEY_ID"),
        ("operator", "SPACES_ACCESS_KEY_ID"),
    ):
        if hashlib.sha256(credentials[variable].encode()).hexdigest() != issued_ids[role]:
            raise LifecycleError("delivered Spaces credential differs from its creation receipt")
    fixture = fields(
        pair["fixture"],
        BINDING
        | {"format", "started_at", "completed_at", "checks", "identities_sha256", "deadline"},
    )
    if now >= instant(fixture["deadline"]):
        raise LifecycleError("managed runtime credential delivery has expired")
    for names in (
        ("SPACES_ACCESS_KEY_ID", "SPACES_ARCHIVE_ACCESS_KEY_ID", "SPACES_BACKUP_ACCESS_KEY_ID"),
        (
            "CLOUDFLARE_API_TOKEN",
            "CADDY_CLOUDFLARE_API_TOKEN",
            "M3_10_TOKEN_AUDIT_TOKEN",
            "M3_10_PAGE_RULES_TOKEN",
        ),
    ):
        if len({credentials[key] for key in names}) != len(names):
            raise LifecycleError("managed runtime credential roles are not distinct")
    return {**targets.environment(), **credentials, MANAGED_ENV: str(path)}, document


def require_environment(environment: Mapping[str, str], expected: Mapping[str, str]) -> None:
    if any(name.startswith(FORBIDDEN_PREFIXES) for name in environment):
        raise LifecycleError("bootstrap or production-state inputs entered qualification")
    if any(environment.get(key) != value for key, value in expected.items()):
        raise LifecycleError("managed inputs are missing or overwritten by ambient values")
    allowed = set(expected) | {"SPACES_ENDPOINT_URL"}
    if environment.get("SPACES_ENDPOINT_URL") or any(
        key.startswith(("SPACES_", "CLOUDFLARE_", "CADDY_CLOUDFLARE_")) and key not in allowed
        for key in environment
    ):
        raise LifecycleError("managed inputs contain ambiguous provider coordinates")


def capture(path: Path, directory: Path, *, repository: Path, now: datetime) -> None:
    expected, document = load(path, repository=repository, now=now)
    require_environment(os.environ, expected)
    binding = fields(document["binding"], BINDING)
    write_private(
        directory / "managed-credentials.json",
        {
            "format": "lowerduckpond-m3-11-managed-credentials-v1",
            **binding,
            "receipts": document["receipts"],
            "receipts_sha256": digest(document["receipts"]),
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "capture"))
    parser.add_argument("directory", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        repository = Path(__file__).resolve().parents[2]
        path = Path(os.environ[MANAGED_ENV])
        if args.action == "capture":
            if args.directory is None:
                raise LifecycleError("managed capture needs its original run directory")
            capture(path, args.directory, repository=repository, now=datetime.now(UTC))
        else:
            expected, _ = load(path, repository=repository, now=datetime.now(UTC))
            require_environment(os.environ, expected)
    except RuntimeError, ValueError, OSError, KeyError, TypeError:
        print(
            "Managed qualification inputs are incomplete, ambiguous or unverified.", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
