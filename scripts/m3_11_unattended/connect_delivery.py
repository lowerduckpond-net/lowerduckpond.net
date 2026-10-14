"""Operator-only delivery of staged Connect bootstrap, without activating a runner."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_action import bootstrap
from scripts.m3_11_unattended.journal import MAX_OUTPUT
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
    if (not isinstance(value, dict)
            or value.get("format") != "lowerduckpond-m3-11-lease-config-v1"
            or value.get("mode") != "controller"):
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
    controller = LeaseConfiguration.load(output / "controller-connect.json")
    raw_cleanup = read_private(output / "github-connect.json")
    cleanup, _credentials = bootstrap(raw_cleanup, helper=controller.helper_revision)
    shared = controller.document(cleanup_only=True)
    independent = cleanup.document()
    for document in (shared, independent):
        generations = document["generations"]
        if not isinstance(generations, dict):
            raise LifecycleError("lease generation projection is unavailable")
        for roles in generations.values():
            roles["cleanup"].pop("reader")
    if shared != independent or controller.mode != "controller":
        raise LifecycleError("Connect delivery bundles have mismatched policy or generations")
    return canonical_bytes(controller.document()), canonical_bytes(raw_cleanup)


class Delivery:
    def __init__(self, destination: str, workspace: str, workspace_id: str) -> None:
        if (
            re.fullmatch(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+", destination) is None
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]+", workspace) is None
            or re.fullmatch(r"[a-f0-9-]{36}", workspace_id) is None
        ):
            raise LifecycleError("Connect delivery needs explicit SSH and workspace identities")
        self.destination, self.workspace, self.workspace_id = destination, workspace, workspace_id

    def command(
        self, program: str, *arguments: str, stdin: bytes | None = None, timeout: int = 90
    ) -> bytes:
        executable = shutil.which(program)
        if executable is None:
            raise LifecycleError("Connect delivery needs SSH and GitHub CLI on the workstation")
        try:
            result = subprocess.run(  # noqa: S603 - argv contains identities; secrets only on stdin
                [executable, *arguments],
                input=stdin,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except OSError, subprocess.SubprocessError:
            raise LifecycleError("Connect delivery failed; private setup files retained") from None
        if result.returncode or len(result.stdout) > MAX_OUTPUT:
            raise LifecycleError("Connect delivery failed; private setup files retained")
        return result.stdout

    def ssh(self, arguments: list[str], stdin: bytes | None = None, *, timeout: int = 90) -> bytes:
        return self.command(
            "ssh",
            "-T",
            "-o",
            "ConnectTimeout=10",
            "--",
            self.destination,
            shlex.join(arguments),
            stdin=stdin,
            timeout=timeout,
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

    def remote_docker(self, arguments: list[str], stdin: bytes) -> bytes:
        return self.ssh([*PARENT_DOCKER, *arguments], stdin=stdin, timeout=1200)

    def receive(self, identity: str, destination: str, expected: str, controller: bytes) -> bytes:
        command = PARENT_DOCKER.copy()
        command.insert(2, "-i")
        return self.ssh(
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

    def migration_utility(
        self, *, prepared: object, operation: str, payload: dict[str, object], daemon_socket: str
    ) -> dict[str, object]:
        from scripts.m3_11_unattended.docker import (  # noqa: PLC0415
            utility_arguments,
            utility_result,
        )

        original = self.workspace_identity()
        envelope = {
            "format": "lowerduckpond-m3-11-daemon-utility-v1",
            "operation": operation,
            "prepared": prepared,
            "payload": payload,
        }
        arguments = utility_arguments(prepared, operation=operation, daemon_socket=daemon_socket)
        raw = self.remote_docker(arguments, canonical_bytes(envelope))
        if self.workspace_identity() != original:
            raise LifecycleError("migration utility destination workspace changed")
        return utility_result(raw, envelope)

    def install(self, output: Path) -> None:
        controller, cleanup = bundles(output)
        activation = read_private(output / "activation.json")
        if (
            activation.get("format") != "lowerduckpond-m3-11-lease-activation-v1"
            or activation.get("status") != "ready"
            or activation.get("controller_sha256") != hashlib.sha256(controller).hexdigest()
            or activation.get("independent_sha256") != hashlib.sha256(cleanup).hexdigest()
        ):
            raise LifecycleError("private delivery requires exact verified migration preflight")
        # Every staged revision has its own immutable destination, including rotation.
        destination = DESTINATION.removesuffix("connect-bootstrap.json") + (
            "lease-" + hashlib.sha256(controller).hexdigest() + ".json"
        )
        if len(cleanup) > MAX_SECRET_BYTES:
            raise LifecycleError("independent Connect bootstrap exceeds GitHub's secret limit")
        identity = self.workspace_identity()
        self.github_protection()
        expected = hashlib.sha256(controller).hexdigest()
        # Pin the immutable container ID after checking its name, workspace ID,
        # and persistent home. Transfer does not depend on its agent process.
        response = self.receive(identity, destination, expected, controller)
        if response.decode().strip() != expected or self.workspace_identity() != identity:
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
        # Delivery is an explicit operational action after migration and approval;
        # scheduled cleanup reads this single versioned bundle on its next execution.


def main() -> int:  # noqa: PLR0912, PLR0915 - explicit transport and operation CLI boundaries
    import argparse  # noqa: PLC0415 - operator-only entry point

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transport", choices=("ssh", "coder"), default="ssh")
    parser.add_argument("--destination")
    parser.add_argument("--workspace")
    parser.add_argument("--coder-workspace")
    parser.add_argument("--daemon-id")
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--operation",
        choices=("deliver", "discover-import", "inspect-import", "import"),
        default="deliver",
    )
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--daemon-socket")
    parser.add_argument("--historical-reader", type=Path)
    parser.add_argument("--journal-vault")
    parser.add_argument("--declarations", type=Path)
    parser.add_argument("--approved-import", type=Path)
    args = parser.parse_args()
    try:
        delivery: Delivery
        if args.transport == "coder":
            from scripts.m3_11_unattended.coder_delivery import CoderDelivery  # noqa: PLC0415

            if not args.coder_workspace or not args.daemon_id or args.destination or args.workspace:
                parser.error(
                    "Coder delivery needs --coder-workspace and --daemon-id, "
                    "without SSH destination flags"
                )
            delivery = CoderDelivery(args.coder_workspace, args.workspace_id, args.daemon_id)
        else:
            if not args.destination or not args.workspace or args.coder_workspace or args.daemon_id:
                parser.error("SSH delivery needs --destination and --workspace")
            delivery = Delivery(args.destination, args.workspace, args.workspace_id)
        if args.operation != "deliver":
            if args.prepared is None or args.daemon_socket is None:
                parser.error(
                    "migration operations need the exact prepared output and daemon socket"
                )
            if args.operation in {"discover-import", "inspect-import"}:
                if (
                    args.historical_reader is None
                    or args.journal_vault is None
                    or args.declarations is None
                ):
                    parser.error(
                        "inspection needs historical reader access, journal vault and declarations"
                    )
                payload = {
                    "historical_reader": read_private(args.historical_reader),
                    "journal_vault": args.journal_vault,
                    "declarations": read_private(args.declarations, maximum=MAX_OUTPUT),
                }
            else:
                if not args.apply or args.approved_import is None:
                    parser.error("import requires --apply and the exact approved mapping")
                config = LeaseConfiguration.load(args.output / "controller-connect.json")
                payload = {
                    "configuration": config.document(cleanup_only=True),
                    "mapping": read_private(args.approved_import, maximum=MAX_OUTPUT),
                }
            observed = delivery.migration_utility(
                prepared=read_private(args.prepared),
                operation=args.operation,
                payload=payload,
                daemon_socket=args.daemon_socket,
            )
            if args.operation in {"discover-import", "inspect-import"}:
                write_private(args.output, observed, maximum=MAX_OUTPUT)
            else:
                from scripts.m3_11_unattended.connect_activate import retain  # noqa: PLC0415

                retain(args.output / "host-import.json", observed)
            print("Daemon migration evidence verified and retained.")
            return 0
        bundles(args.output)
        delivery.preflight()
        if args.apply:
            delivery.install(args.output)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(
            1, "Private delivery is unresolved; retain staged bundles and original access.\n"
        )
    print(
        "Versioned bundles delivered."
        if args.apply
        else "Destination checked; no bundle delivered."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
