"""Operator-only delivery of staged Connect bootstrap, without activating a runner."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import connect_renewal
from scripts.m3_11_unattended.model import LifecycleError

REPOSITORY = "lowerduckpond-net/lowerduckpond.net"
ENVIRONMENT = "m3-11-credential-cleanup"
SECRET_NAME = "M3_11_CONNECT_BOOTSTRAP"  # noqa: S105 - GitHub secret name, never a value
DESTINATION = "/home/coder/.config/lowerduckpond/m3-11/connect-bootstrap.json"
PARENT_DOCKER = [
    "docker",
    "exec",
    "coder_dind",
    "docker",
    "--host",
    "unix:///docker-sock/docker.sock",
]
MAX_SECRET_BYTES = 48 * 1024

# Executed as the workspace user; the secret travels on stdin, never in this
# program, its arguments, a shell substitution, or Docker's container log.
RECEIVER = r"""
import hashlib, json, os, stat, sys, tempfile
from pathlib import Path

def receive():
    os.umask(0o077)
    path = Path(sys.argv[1])
    expected = sys.argv[2]
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if not 0 < len(raw) <= 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError()
    value = json.loads(raw)
    fields = {"format", "manifest", "url", "tokens", "provider_metadata"}
    if isinstance(value, dict) and "renewal" in value:
        fields.add("renewal")
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError()
    if value["format"] != "lowerduckpond-m3-11-connect-bootstrap-v1":
        raise ValueError()
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.parent.lstat()
    if path.parent.resolve() != path.parent or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, "rb") as existing:
            info = os.fstat(existing.fileno())
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or existing.read(len(raw) + 1) != raw):
                raise ValueError()
    else:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".connect-incoming-", delete=False
        ) as pending:
            pending.write(raw)
            pending.flush()
            os.fsync(pending.fileno())
        try:
            os.link(pending.name, path, follow_symlinks=False)
        finally:
            os.unlink(pending.name)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(expected)

try:
    receive()
except (OSError, ValueError, TypeError):
    raise SystemExit("Private Connect delivery failed; original files retained.") from None
"""


def bundles(output: Path) -> tuple[bytes, bytes]:
    raw_controller = read_private(output / "controller-connect.json")
    raw_cleanup = read_private(output / "github-connect.json")
    controller = fields(
        raw_controller,
        {
            "format",
            "manifest",
            "url",
            "tokens",
            "provider_metadata",
        }
        | ({"renewal"} if "renewal" in raw_controller else set()),
    )
    cleanup = fields(
        raw_cleanup,
        {
            "format",
            "targets",
            "journal_vault",
            "cleanup",
            "token",
            "server_credentials",
            "provider_metadata",
        }
        | ({"checkpoint_token"} if "checkpoint_token" in raw_cleanup else set()),
    )
    value = controller["manifest"]
    if (
        controller["format"] != "lowerduckpond-m3-11-connect-bootstrap-v1"
        or cleanup["format"] != controller["format"]
        or not isinstance(value, dict)
        or any(cleanup[key] != value.get(key) for key in ("targets", "journal_vault", "cleanup"))
        or not isinstance(controller["tokens"], dict)
        or set(controller["tokens"]) != {"provision", "cleanup", "production"}
    ):
        raise LifecycleError("Connect delivery bundles have mismatched roles or targets")
    if ("renewal" in controller) != ("checkpoint_token" in cleanup):
        raise LifecycleError("cleanup renewal must preserve the original checkpoint key")
    if "renewal" in controller:
        receipt = connect_renewal.receipt(controller["renewal"])
        key = cleanup["checkpoint_token"]
        if (
            not isinstance(key, str)
            or hashlib.sha256(key.encode()).hexdigest() != receipt["checkpoint_token_sha256"]
        ):
            raise LifecycleError("cleanup delivery checkpoint key differs from its renewal")
    return canonical_bytes(controller), canonical_bytes(cleanup)


class Delivery:
    def __init__(self, destination: str, workspace: str, workspace_id: str) -> None:
        if (
            re.fullmatch(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+", destination) is None
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]+", workspace) is None
            or re.fullmatch(r"[a-f0-9-]{36}", workspace_id) is None
        ):
            raise LifecycleError("Connect delivery needs explicit SSH and workspace identities")
        self.destination, self.workspace, self.workspace_id = destination, workspace, workspace_id

    def command(self, program: str, *arguments: str, stdin: bytes | None = None) -> bytes:
        executable = shutil.which(program)
        if executable is None:
            raise LifecycleError("Connect delivery needs SSH and GitHub CLI on the workstation")
        try:
            result = subprocess.run(  # noqa: S603 - argv contains identities; secrets only on stdin
                [executable, *arguments], input=stdin, capture_output=True, check=False, timeout=90
            )
        except OSError, subprocess.SubprocessError:
            raise LifecycleError("Connect delivery failed; private setup files retained") from None
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise LifecycleError("Connect delivery failed; private setup files retained")
        return result.stdout

    def ssh(self, arguments: list[str], stdin: bytes | None = None) -> bytes:
        return self.command(
            "ssh",
            "-T",
            "-o",
            "ConnectTimeout=10",
            "--",
            self.destination,
            shlex.join(arguments),
            stdin=stdin,
        )

    def workspace_identity(self) -> str:
        # Inspect only the fields we need, never Config.Env or a full container.
        template = (
            "{{json .Id}}|{{json .Name}}|{{json .State.Running}}|"
            '{{json (index .Config.Labels "coder.workspace_id")}}|'
            '{{range .Mounts}}{{if eq .Destination "/home/coder"}}{{json .Name}}{{end}}{{end}}'
        )
        response = self.ssh([*PARENT_DOCKER, "inspect", "--format", template, self.workspace])
        try:
            parts = [json.loads(part) for part in response.decode().strip().split("|")]
        except ValueError, UnicodeError:
            raise LifecycleError(
                "the destination workspace identity could not be verified"
            ) from None
        if (
            len(parts) != 5  # noqa: PLR2004 - exact inspected fields
            or not isinstance(parts[0], str)
            or re.fullmatch(r"[a-f0-9]{64}", parts[0]) is None
            or parts[1:]
            != [
                "/" + self.workspace,
                True,
                self.workspace_id,
                "coder-" + self.workspace_id + "-home",
            ]
        ):
            raise LifecycleError("Connect destination differs from the approved LDP workspace")
        return parts[0]

    def github_protection(self) -> None:
        path = "repos/" + REPOSITORY + "/environments/" + ENVIRONMENT
        rules = json.loads(self.command("gh", "api", "--hostname", "github.com", path))
        policies = json.loads(
            self.command(
                "gh", "api", "--hostname", "github.com", path + "/deployment-branch-policies"
            )
        )
        if not isinstance(rules, dict) or not isinstance(policies, dict):
            raise LifecycleError("GitHub cleanup environment policy is unavailable")
        protection = rules.get("protection_rules")
        branches = policies.get("branch_policies")
        if (
            not isinstance(protection, list)
            or any(
                not isinstance(rule, dict) or rule.get("type") != "branch_policy"
                for rule in protection
            )
            or rules.get("deployment_branch_policy")
            != {"protected_branches": False, "custom_branch_policies": True}
            or not isinstance(branches, list)
            or len(branches) != 1
            or not isinstance(branches[0], dict)
            or branches[0].get("name") != "main"
            or branches[0].get("type") != "branch"
        ):
            raise LifecycleError(
                "GitHub cleanup needs the existing main-only, unattended environment"
            )

    def preflight(self) -> None:
        self.workspace_identity()
        self.github_protection()

    def install(self, output: Path, *, renewal_id: str | None = None) -> None:
        controller, cleanup = bundles(output)
        destination = DESTINATION
        renewal = json.loads(controller).get("renewal")
        if (renewal_id is None) != (renewal is None):
            raise LifecycleError("cleanup renewal must use its separate staging destination")
        if renewal_id is not None:
            from scripts.m3_11_unattended.model import identity as run_identity  # noqa: PLC0415

            destination = (
                DESTINATION.removesuffix("connect-bootstrap.json")
                + "connect-renewal-"
                + run_identity(renewal_id)
                + ".json"
            )
            request = connect_renewal.request(connect_renewal.receipt(renewal)["request"])
            if request["renewal_id"] != renewal_id:
                raise LifecycleError("cleanup renewal delivery identity differs")
        if len(cleanup) > MAX_SECRET_BYTES:
            raise LifecycleError("independent Connect bootstrap exceeds GitHub's secret limit")
        identity = self.workspace_identity()
        self.github_protection()
        expected = hashlib.sha256(controller).hexdigest()
        # Pin the immutable container ID after checking its name, workspace ID,
        # and persistent home. Transfer does not depend on its agent process.
        command = PARENT_DOCKER.copy()
        command.insert(2, "-i")
        response = self.ssh(
            [
                *command,
                "exec",
                "--user",
                "1000",
                "-i",
                identity,
                "python3",
                "-c",
                RECEIVER,
                destination,
                expected,
            ],
            stdin=controller,
        )
        if response.decode().strip() != expected:
            raise LifecycleError("private Connect delivery has no matching readback receipt")
        self.command(
            "gh",
            "secret",
            "set",
            SECRET_NAME,
            "--repo",
            "github.com/" + REPOSITORY,
            "--env",
            ENVIRONMENT,
            stdin=cleanup,
        )
        # This is a new, inactive secret. Existing cleanup configuration and
        # the approved helper revision stay under the implementation merge gate.
