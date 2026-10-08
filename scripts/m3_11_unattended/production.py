"""Short, isolated use of actual production credentials; emit only a bound receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from scripts.check_m3_7_production_edge import CloudflareClient, verify_active_account_token
from scripts.check_m3_10_provider import check_caddy_token
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_diagnostics import retain_failure
from scripts.m3_11_unattended.inputs import BINDING, PRODUCTION_FORMAT, PRODUCTION_RESULT
from scripts.m3_11_unattended.journal import OnePassword
from scripts.m3_11_unattended.model import LifecycleError, Targets, stamp, strings
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import current_candidate, fingerprint, revision

REFERENCES = frozenset(
    {
        "OPENTOFU_STATE_ACCESS_KEY_ID",
        "OPENTOFU_STATE_SECRET_ACCESS_KEY",
        "OPENTOFU_STATE_BUCKET",
        "OPENTOFU_ENCRYPTION_PASSPHRASE",
        "CADDY_CLOUDFLARE_API_TOKEN",
    }
)
MAX_INPUT_BYTES = 256 * 1024
CHECK_SECONDS = 25 * 60


def _output(request: dict[str, object], repository: Path) -> Path:
    output = request["output"]
    if not isinstance(output, str):
        raise LifecycleError("production-check output path is invalid")
    path = Path(output)
    if not path.is_absolute() or path.is_relative_to(repository):
        raise LifecycleError("production-check output must be private and outside source")
    private_directory(path.parent)
    return path


@contextmanager
def _log(request: dict[str, object], repository: Path, name: str) -> Iterator[BinaryIO]:
    # Child output can contain durable secrets. It is retained privately and
    # never read by the sanitized exporter; only a static failure and exit code
    # cross that boundary.
    path = _output(request, repository).with_name(name)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        yield stream


def _failure(request: object, *, stage: str, error: Exception, repository: Path) -> None:
    try:
        if not isinstance(request, dict) or not isinstance(request.get("output"), str):
            return
        output = Path(request["output"])
        if not output.is_absolute() or output.is_relative_to(repository):
            return
        private_directory(output.parent)
        retain_failure(
            output.with_name("production-failure.json"),
            binding=fields(request["binding"], BINDING),
            stage=stage,
            error=error,
        )
    except Exception:
        return  # Preserve the failed result even when private diagnostics cannot be written.


def _request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise LifecycleError("production-check input exceeds its bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise LifecycleError("production-check input is invalid")
    return value


def bootstrap(request: dict[str, object], repository: Path) -> int:
    """Provisioning credentials are not accepted here; only the production reader."""
    authority = "connect" if "connect" in request else "service_account"
    value = fields(request, {authority, "references", "targets", "binding", "fixture", "output"})
    references = strings(value["references"])
    if set(references) != REFERENCES:
        raise LifecycleError("production-check references are incomplete")
    targets = Targets.parse(value["targets"])
    fixture = strings(
        fields(value["fixture"], {"audit", "observer", "archive_id", "backup_id", "caddy_id"})
    )
    op: OnePassword | Connect
    if authority == "connect":
        from scripts.m3_11_unattended.connect_configuration import (  # noqa: PLC0415
            reader,
            reader_access,
        )

        configured, _access = reader_access(value["connect"])
        if configured["role"] != "production":
            raise LifecycleError("production checking requires its isolated Connect reader")
        op = reader(value["connect"])
    else:
        token = value["service_account"]
        if not isinstance(token, str):
            raise LifecycleError("production-check reader is unavailable")
        op = OnePassword(token)
    environment = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "SSL_CERT_FILE")
        if key in os.environ
    }
    environment.update({key: op.read(reference) for key, reference in references.items()})
    environment.update(targets.environment())
    environment.update(
        M3_10_TOKEN_AUDIT_TOKEN=fixture["audit"], CLOUDFLARE_API_TOKEN=fixture["observer"]
    )
    # Do not forward the service account or any bootstrap reference to the state
    # reader. The pipe holds only the non-secret binding/identities/output path.
    safe = {key: value[key] for key in ("targets", "binding", "output")}
    safe["fixture_ids"] = {role: fixture[role + "_id"] for role in ("archive", "backup", "caddy")}
    safe["started_at"] = stamp(datetime.now(UTC))
    command = (
        'set +xv; set -euo pipefail; umask 077; repository_root="$PWD"; '
        'source "$repository_root/scripts/lib/m3-10-production-state"; '
        "exec uv run --quiet --no-sync --frozen python "
        "-m scripts.m3_11_unattended.production validate"
    )
    with _log(value, repository, "production-state.log") as stream:
        result = subprocess.run(  # noqa: S603 - fixed shell program, no interpolated input
            ["/bin/bash", "--noprofile", "--norc", "-c", command],
            input=canonical_bytes(safe),
            env=environment,
            cwd=repository,
            timeout=CHECK_SECONDS,
            check=True,
            stdout=stream,
            stderr=stream,
        )
    return result.returncode


def validate(request: dict[str, object], repository: Path) -> None:
    value = fields(request, {"targets", "binding", "output", "fixture_ids", "started_at"})
    targets = Targets.parse(value["targets"])
    path = _output(value, repository)
    binding = fields(value["binding"], BINDING)
    source = revision(binding["source_revision"])
    current_candidate(repository, source)
    if (
        binding["qualification_inputs_sha256"] != fingerprint(repository, source)
        or binding["storage_target_sha256"] != targets.storage_digest
        or any(os.environ.get(key) != item for key, item in targets.environment().items())
    ):
        raise LifecycleError("production state and approved qualification targets differ")
    fixture = strings(fields(value["fixture_ids"], {"archive", "backup", "caddy"}))
    now = datetime.now(UTC)
    check_caddy_token(os.environ, account_id=targets.account_id, now=now)
    caddy_id = verify_active_account_token(
        CloudflareClient(os.environ["CADDY_CLOUDFLARE_API_TOKEN"]),
        account_id=targets.account_id,
        label="production Caddy",
    )
    identities = {
        "caddy": caddy_id,
        "archive": os.environ["SPACES_ARCHIVE_ACCESS_KEY_ID"],
        "backup": os.environ["SPACES_BACKUP_ACCESS_KEY_ID"],
    }
    if len(set(identities.values())) != len(identities) or set(identities.values()) & set(
        fixture.values()
    ):
        raise LifecycleError("production credentials are not separated from fixture credentials")
    # Decryption inputs do not enter even this short capability probe. Its only
    # mutation is the existing owned disposable-prefix check and mutual denial.
    environment = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "SSL_CERT_FILE")
        if key in os.environ
    }
    environment.update(
        {
            key: os.environ[key]
            for key in (
                "SPACES_ARCHIVE_ACCESS_KEY_ID",
                "SPACES_ARCHIVE_SECRET_ACCESS_KEY",
                "SPACES_BACKUP_ACCESS_KEY_ID",
                "SPACES_BACKUP_SECRET_ACCESS_KEY",
            )
        }
    )
    uv = shutil.which("uv")
    if uv is None:
        raise LifecycleError("production-check runtime is unavailable")
    with _log(value, repository, "production-storage.log") as stream:
        subprocess.run(  # noqa: S603 - fixed existing capability probe
            [
                uv,
                "run",
                "--quiet",
                "--no-sync",
                "--frozen",
                "ldp-m3-archive",
                "credential-check",
                "--backup-bucket",
                targets.backup_bucket,
                "--archive-bucket",
                targets.archive_bucket,
                "--region",
                targets.region,
                "--probe-record",
                str(path.with_name("production-storage-ownership.json")),
                "--source-revision",
                source,
                "--run-id",
                str(binding["managed_run_id"]),
            ],
            env=environment,
            cwd=repository,
            timeout=CHECK_SECONDS,
            check=True,
            stdout=stream,
            stderr=stream,
        )
    write_private(
        path,
        {
            "format": PRODUCTION_FORMAT,
            **binding,
            "started_at": value["started_at"],
            "completed_at": stamp(datetime.now(UTC)),
            "checks": PRODUCTION_RESULT,
            "identities_sha256": {
                role: hashlib.sha256(item.encode()).hexdigest() for role, item in identities.items()
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("bootstrap", "validate"))
    args = parser.parse_args()
    request: object = None
    repository = Path(__file__).resolve().parents[2]
    try:
        request = _request()
        if args.action == "bootstrap":
            return bootstrap(request, repository)
        validate(request, repository)
    except (
        RuntimeError,
        ValueError,
        OSError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        _failure(request, stage=args.action, error=error, repository=repository)
        print(
            "Actual production credential validation failed; no receipt was issued.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
