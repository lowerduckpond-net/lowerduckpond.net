"""Operator delivery of public-image pull access; never provider or fixture authority."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.m3_11_unattended.connect_delivery import ENVIRONMENT, REPOSITORY
from scripts.m3_11_unattended.connect_setup import Operator
from scripts.m3_11_unattended.model import LifecycleError, instant
from scripts.production_qualification_inputs import current_candidate

SECRET = "DOCKERHUB_PUBLIC_READ_TOKEN"  # noqa: S105 - name, not a credential


def command(
    executable: str, *arguments: str, stdin: bytes | None = None, environment: dict[str, str]
) -> None:
    """Native output can contain credentials; return fixed diagnostics only."""
    path = shutil.which(executable, path=environment.get("PATH"))
    if path is None:
        raise LifecycleError(f"Registry setup needs {executable} on the secure workstation")
    try:
        result = subprocess.run(  # noqa: S603 - fixed tools; credential only on stdin
            [path, *arguments],
            input=stdin,
            env=environment,
            capture_output=True,
            timeout=90,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        raise LifecycleError(f"Registry setup: {executable} unavailable or timed out") from None
    if result.returncode:
        raise LifecycleError(
            f"Registry setup: {executable} rejected the operation; "
            "check its login and connectivity, then repeat the same setup"
        )


def install(*, username: str, reference: str, expires_at: str) -> None:
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,29}", username) is None:
        raise LifecycleError("Use the Docker ID, not an email address")
    if re.fullmatch(r"op://[^/\r\n]+/[^/\r\n]+/[^/\r\n]+", reference) is None:
        raise LifecycleError("Use the dedicated 1Password token field reference")
    if instant(expires_at) < datetime.now(UTC) + timedelta(days=1):
        raise LifecycleError("The operator-confirmed native expiry must leave at least one day")
    operator = Operator()
    # Normal operator login: no extra service-account quota or Connect vault grant.
    token = operator.command("read", reference).strip()
    if re.fullmatch(rb"[\x21-\x7e]{1,4096}", token) is None:
        raise LifecycleError("The selected 1Password field is not a single token")
    environment = {**operator.environment, "GH_HOST": "github.com"}
    # These override stored gh credentials, including an inherited automation
    # identity. Delivery must use the operator's normal workstation login.
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
        environment.pop(key, None)
    # Do not alter the workstation's Docker login or retain another bearer copy.
    with tempfile.TemporaryDirectory(prefix="ldp-registry-login-") as temporary:
        command(
            "docker",
            "login",
            "docker.io",
            "--username",
            username,
            "--password-stdin",
            stdin=token + b"\n",
            environment={**environment, "DOCKER_CONFIG": temporary},
        )
    for scope in ((), ("--env", ENVIRONMENT)):
        command(
            "gh",
            "secret",
            "set",
            SECRET,
            "--repo",
            REPOSITORY,
            *scope,
            stdin=token,
            environment=environment,
        )
        command(
            "gh",
            "variable",
            "set",
            "DOCKERHUB_EXPIRES_AT",
            "--repo",
            REPOSITORY,
            *scope,
            "--body",
            expires_at,
            environment=environment,
        )
        # Publish the login selector only after its credential is installed.
        command(
            "gh",
            "variable",
            "set",
            "DOCKERHUB_USERNAME",
            "--repo",
            REPOSITORY,
            *scope,
            "--body",
            username,
            environment=environment,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--token-reference", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--confirm-public-read-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        current_candidate(Path(__file__).resolve().parents[2], args.revision)
        if not args.confirm_public_read_only:
            raise LifecycleError("Confirm the token's Repo Public Read-only policy in Docker Hub")
        if args.apply:
            install(
                username=args.username, reference=args.token_reference, expires_at=args.expires_at
            )
            print("Docker Hub login verified and public-pull access installed in GitHub.")
            print("Native CI and independent cleanup still require verification.")
        else:
            print(f"Target repository: {REPOSITORY}; cleanup environment: {ENVIRONMENT}.")
            print("Preview only. No secret read, login, or GitHub changes; add --apply to deliver.")
    except LifecycleError as error:
        print(str(error))
        return 1
    except OSError, ValueError:
        # Neither a CLI response nor a token/reference is safe to echo here.
        print(
            "Registry setup incomplete; check the pinned clean checkout, inputs and normal logins."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
