"""Stage explicit versioned lease access using already approved Connect readers.

This setup boundary never supplies a lifetime default or creates provider children.
The separate readers carry signed grants and native operator metadata.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_action import FORMAT, INDEPENDENT_ORIGIN, bootstrap
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.model import LifecycleError, digest

MAXIMUM = 1024 * 1024


def operation(arguments: tuple[str, ...]) -> str:
    """Expose only a fixed operation label, never an argument or CLI response."""
    names = {
        ("whoami",): "operator sign-in check",
        ("read",): "setup manifest read",
        ("connect", "server", "get"): "Connect server inspection",
        ("connect", "server", "list"): "Connect server inventory",
        ("connect", "server", "create"): "independent Connect server creation",
        ("connect", "vault", "grant"): "Connect vault grant",
        ("connect", "token", "create"): "Connect client creation",
        ("connect", "token", "list"): "Connect client inventory",
    }
    return next(
        (name for prefix, name in names.items() if arguments[: len(prefix)] == prefix),
        "1Password operation",
    )


def failure_reason(stderr: bytes) -> str:
    """Allowlisted hints only; unrecognized native diagnostics remain private."""
    message = stderr[:MAXIMUM].lower()
    for markers, reason in (
        ((b"not signed in", b"not currently signed in", b"session expired"), "sign-in required"),
        ((b"more than one account", b"multiple accounts"), "account selection required"),
        ((b"rate limit", b"too many requests"), "request allowance unavailable"),
        ((b"unknown flag", b"unknown command"), "unsupported CLI operation"),
        ((b"not found", b"couldn't be found", b"could not be found"), "requested object not found"),
    ):
        if any(marker in message for marker in markers):
            return reason
    return "native command rejected"


def directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    stat = path.lstat()
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.st_uid != os.geteuid()
        or stat.st_mode & 0o077
    ):
        raise LifecycleError("Connect bootstrap needs an owned private directory")


class Operator:
    """Only the operator's normal login can grant vault access or issue clients."""

    def __init__(self, *, environment: Mapping[str, str] | None = None) -> None:
        self.environment = dict(os.environ if environment is None else environment)
        for key in ("OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_DEBUG"):
            self.environment.pop(key, None)
        self.executable = shutil.which("op", path=self.environment.get("PATH"))
        if self.executable is None:
            raise LifecycleError("the operator's 1Password CLI is unavailable")

    def command(
        self, *arguments: str, cwd: Path | None = None, stdin: bytes | None = None
    ) -> bytes:
        action = operation(arguments)
        if stdin is not None and len(stdin) > MAXIMUM:
            raise LifecycleError("private operator input exceeds its bound")
        try:
            response = subprocess.run(  # noqa: S603 - fixed op calls; no secret arguments
                [cast(str, self.executable), *arguments],
                cwd=cwd,
                env=self.environment,
                input=stdin,
                capture_output=True,
                check=False,
                timeout=90,
            )
        except subprocess.TimeoutExpired:
            raise LifecycleError(
                f"Connect setup failed during {action}: timed out; retain private setup files"
            ) from None
        except OSError, subprocess.SubprocessError:
            raise LifecycleError(
                f"Connect setup failed during {action}: process unavailable; "
                "retain private setup files"
            ) from None
        if response.returncode:
            raise LifecycleError(
                f"Connect setup failed during {action}: exit {response.returncode}, "
                f"{failure_reason(response.stderr)}; retain private setup files"
            )
        if len(response.stdout) > MAXIMUM:
            raise LifecycleError(
                f"Connect setup failed during {action}: response too large; "
                "retain private setup files"
            )
        return response.stdout


def assemble(
    configuration: object, independent_reader: object, server_credentials: object
) -> tuple[dict[str, object], dict[str, object]]:
    config = LeaseConfiguration.parse(configuration)
    if config.mode != "controller":
        raise LifecycleError("setup requires an explicit controller configuration")
    config.require_issuance(now=datetime.now(UTC))
    reader, access = reader_access(independent_reader)
    shared, shared_access = reader_access(
        config.generations[config.active_generation]["cleanup"].reader_settings
    )
    if (
        reader["role"] != "cleanup"
        or access.server_id != config.independent_server_id
        or reader["vaults"] != shared["vaults"]
        or access.token_id == shared_access.token_id
        or access.token == shared_access.token
        or reader["url"] != INDEPENDENT_ORIGIN
    ):
        raise LifecycleError("independent cleanup reader differs from its isolated identity")
    document = config.document(cleanup_only=True)
    generations = cast(dict[str, dict[str, dict[str, object]]], document["generations"])
    for roles in generations.values():
        roles["cleanup"]["reader"] = reader
    independent = {
        "format": FORMAT,
        "configuration": document,
        "server_credentials": server_credentials,
    }
    bootstrap(independent, helper=config.helper_revision)
    return config.document(), independent


def prepare(
    configuration: object,
    independent_reader: object,
    server_credentials: object,
    *,
    output: Path,
) -> dict[str, object]:
    controller, independent = assemble(configuration, independent_reader, server_credentials)
    directory(output)
    for name, value in (
        ("controller-connect.json", controller),
        ("github-connect.json", independent),
    ):
        path = output / name
        if not path.exists():
            write_private(path, value)
        if read_private(path) != value:
            raise LifecycleError("staged lease configuration differs; retain the original bundle")
    return {"controller_sha256": digest(controller), "independent_sha256": digest(independent)}


def prepare_controller(
    configuration: object, profile: object, *, output: Path
) -> dict[str, object]:
    """Stage shared readers only; independent secrets remain in GitHub."""
    from scripts.m3_11_unattended.connect_profile import require_controller  # noqa: PLC0415

    config = LeaseConfiguration.parse(configuration)
    selected = require_controller(config, profile)
    config.require_issuance(now=datetime.now(UTC))
    directory(output)
    for name in ("github-connect.json", "activation.json"):
        if (output / name).exists() or (output / name).is_symlink():
            raise LifecycleError("controller-only setup cannot replace a staged joint bundle")
    for name, value in (("controller-connect.json", config.document()), ("profile.json", selected)):
        path = output / name
        if not path.exists():
            write_private(path, value)
        if read_private(path) != value:
            raise LifecycleError("controller-only staging differs; preserve original inputs")
    return {
        "controller_sha256": digest(config.document()),
        "profile_sha256": digest(selected),
        "independent_confirmation": "pending-exact-manifest",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--independent-reader", type=Path)
    parser.add_argument("--server-credentials", type=Path)
    parser.add_argument("--existing-profile", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.existing_profile is not None:
            if args.independent_reader is not None or args.server_credentials is not None:
                raise LifecycleError("controller-only setup excludes independent material")
            prepare_controller(
                read_private(args.configuration),
                read_private(args.existing_profile),
                output=args.output,
            )
        else:
            if args.independent_reader is None or args.server_credentials is None:
                raise LifecycleError("joint setup needs complete independent material")
            prepare(
                read_private(args.configuration),
                read_private(args.independent_reader),
                read_private(args.server_credentials),
                output=args.output,
            )
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Lease setup is incomplete; retain private inputs.\n")
    print("Versioned private bundles staged; activation requires verified migration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
