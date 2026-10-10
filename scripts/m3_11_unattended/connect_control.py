"""Dispatch the one protected manifest-confirmation/cleanup workflow."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.connect_action import REPOSITORY, WORKFLOW
from scripts.m3_11_unattended.model import LifecycleError

ENVIRONMENT = "m3-11-credential-cleanup"
PREFIX = f"repos/{REPOSITORY}"
MAX_BYTES = 1024 * 1024


class GitHub:
    def __init__(self) -> None:
        executable = shutil.which("gh")
        if executable is None:
            raise LifecycleError("GitHub control CLI is unavailable")
        self.executable = executable

    def api(self, path: str, *, method: str = "GET", body: object = None) -> object:
        if not path.startswith(PREFIX + "/") or method not in {"GET", "POST"}:
            raise LifecycleError("GitHub control escaped the dedicated repository")
        arguments = [self.executable, "api", "--hostname", "github.com", "--method", method, path]
        if body is not None:
            arguments.extend(["--input", "-"])
        try:
            result = subprocess.run(  # noqa: S603 - fixed repository and private JSON stdin
                arguments,
                input=canonical_bytes(body) if body is not None else None,
                capture_output=True,
                check=False,
                timeout=30,
            )
            if result.returncode or len(result.stdout) > MAX_BYTES:
                raise LifecycleError("GitHub dispatch remains unresolved")
            return json.loads(result.stdout) if result.stdout else None
        except OSError, subprocess.SubprocessError, ValueError:
            raise LifecycleError("GitHub dispatch remains unresolved") from None

    def protection(self) -> None:
        path = f"{PREFIX}/environments/{ENVIRONMENT}"
        value, policies = self.api(path), self.api(path + "/deployment-branch-policies")
        if not isinstance(value, dict) or not isinstance(policies, dict):
            raise LifecycleError("protected cleanup environment is unavailable")
        rules, branches = value.get("protection_rules"), policies.get("branch_policies")
        if (
            not isinstance(rules, list)
            or any(not isinstance(row, dict) or row.get("type") != "branch_policy" for row in rules)
            or value.get("deployment_branch_policy")
            != {"protected_branches": False, "custom_branch_policies": True}
            or not isinstance(branches, list)
            or len(branches) != 1
            or not isinstance(branches[0], dict)
            or branches[0].get("name") != "main"
            or branches[0].get("type") != "branch"
        ):
            raise LifecycleError(
                "cleanup requires its main-only environment without approval waits"
            )

    def dispatch(self, operation: str) -> None:
        if operation not in {"confirm", "cleanup"}:
            raise LifecycleError("independent operation is invalid")
        self.protection()
        self.api(
            f"{PREFIX}/actions/workflows/{WORKFLOW}/dispatches",
            method="POST",
            body={"ref": "main", "inputs": {"operation": operation}},
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("confirm", "cleanup"))
    args = parser.parse_args()
    try:
        GitHub().dispatch(args.operation)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(
            1, "Independent dispatch is unresolved; no issuance is authorized by dispatch.\n"
        )
    print("Independent operation requested; issuance waits for the exact inventory confirmation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
