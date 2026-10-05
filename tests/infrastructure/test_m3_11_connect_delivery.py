"""Exercise real private delivery and reject foreign workspaces or cleanup authority."""

# ruff: noqa: PLR2004 - explicit boundary sizes, modes and provider statuses

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from infrastructure.test_m3_11_connect_setup import CANARY, Operator, run
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended.connect_delivery import PARENT_DOCKER, RECEIVER, Delivery
from scripts.m3_11_unattended.model import LifecycleError

WORKSPACE = "coder-test-ldp"
WORKSPACE_ID = "01234567-0123-4567-89ab-0123456789ab"
CONTAINER = "a" * 64


class Client(Delivery):
    def __init__(self) -> None:
        super().__init__("root@unraid.test", WORKSPACE, WORKSPACE_ID)
        self.calls: list[tuple[str, tuple[str, ...], bytes | None]] = []
        self.foreign = False
        self.approver = False
        self.branch = "main"

    def command(self, program: str, *arguments: str, stdin: bytes | None = None) -> bytes:
        self.calls.append((program, arguments, stdin))
        assert CANARY not in json.dumps(arguments)
        if program == "ssh":
            remote = shlex.split(arguments[-1])
            if "inspect" in remote:
                identity = WORKSPACE_ID if not self.foreign else "other-workspace"
                values = [
                    CONTAINER,
                    "/" + WORKSPACE,
                    True,
                    identity,
                    "coder-" + WORKSPACE_ID + "-home",
                ]
                return "|".join(json.dumps(value) for value in values).encode()
            assert remote[:7] == [*PARENT_DOCKER[:2], "-i", *PARENT_DOCKER[2:]]
            assert stdin is not None
            return hashlib.sha256(stdin).hexdigest().encode() + b"\n"
        if arguments[0] == "api":
            value = (
                {"branch_policies": [{"name": self.branch, "type": "branch"}]}
                if arguments[-1].endswith("/deployment-branch-policies")
                else {
                    "protection_rules": [{"type": "required_reviewers"}]
                    if self.approver
                    else [{"type": "branch_policy"}],
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                }
            )
            return json.dumps(value).encode()
        assert arguments[:3] == ("secret", "set", "M3_11_CONNECT_BOOTSTRAP")
        assert stdin is not None
        return b""


def test_delivery_sends_only_controller_to_exact_workspace_and_only_cleanup_to_github(
    tmp_path: Path,
) -> None:
    run(Operator(), tmp_path)
    client = Client()
    client.preflight()
    client.install(tmp_path)
    delivered = [(program, arguments, data) for program, arguments, data in client.calls if data]
    assert len(delivered) == 2
    assert delivered[0][0] == "ssh"
    assert delivered[0][2] == (tmp_path / "controller-connect.json").read_bytes()
    assert delivered[1][0] == "gh"
    assert delivered[1][2] == (tmp_path / "github-connect.json").read_bytes()
    assert "server_credentials" not in json.loads(delivered[0][2])
    assert "OPENTOFU_ENCRYPTION_PASSPHRASE" not in delivered[1][2].decode()
    assert "M3_11_CLEANUP_REVISION" not in str(client.calls)
    assert "M3_11_CLEANUP_CONFIG" not in str(client.calls)


@pytest.mark.parametrize("setting,value", [("foreign", True), ("approver", True), ("branch", "*")])
def test_wrong_workspace_or_cleanup_policy_blocks_all_delivery(
    tmp_path: Path, setting: str, value: object
) -> None:
    run(Operator(), tmp_path)
    client = Client()
    setattr(client, setting, value)
    with pytest.raises(LifecycleError):
        client.install(tmp_path)
    assert all(data is None for _, _, data in client.calls)


def test_swapped_bundles_cannot_export_production_authority_to_github(tmp_path: Path) -> None:
    run(Operator(), tmp_path)
    controller = tmp_path / "controller-connect.json"
    cleanup = tmp_path / "github-connect.json"
    cleanup.write_bytes(controller.read_bytes())
    client = Client()
    with pytest.raises(ValueError):
        client.install(tmp_path)
    assert client.calls == []


def receive(
    path: Path, raw: bytes, *, expected: str | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - local exact receiver program and test canaries
        [sys.executable, "-c", RECEIVER, str(path), expected or hashlib.sha256(raw).hexdigest()],
        input=raw,
        capture_output=True,
        timeout=5,
        check=False,
    )


def test_actual_receiver_private_atomic_idempotent_and_never_overwrites(tmp_path: Path) -> None:
    source, destination = tmp_path / "source", tmp_path / "workspace" / "connect.json"
    run(Operator(), source)
    raw = (source / "controller-connect.json").read_bytes()
    result = receive(destination, raw)
    assert result.returncode == 0
    assert destination.read_bytes() == raw
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert CANARY.encode() not in result.stdout + result.stderr
    assert receive(destination, raw).returncode == 0
    changed = json.loads(raw)
    changed["url"] = "https://different.test"
    result = receive(destination, json.dumps(changed).encode())
    assert result.returncode != 0
    assert destination.read_bytes() == raw
    assert CANARY.encode() not in result.stdout + result.stderr


def test_delivery_failure_can_retry_original_tokens_without_issuance(tmp_path: Path) -> None:
    operator = Operator()
    source, destination = tmp_path / "source", tmp_path / "workspace" / "connect.json"
    run(operator, source)
    raw = (source / "controller-connect.json").read_bytes()
    assert receive(destination, raw, expected="f" * 64).returncode != 0
    assert not destination.exists()
    run(operator, source)
    assert operator.tokens == 4
    assert receive(destination, raw).returncode == 0


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "public", "cleanup-bundle"])
def test_actual_receiver_rejects_unsafe_or_wrong_material(tmp_path: Path, unsafe: str) -> None:
    source, destination = tmp_path / "source", tmp_path / "destination.json"
    run(Operator(), source)
    raw = (source / "controller-connect.json").read_bytes()
    original = tmp_path / "original.json"
    write_private(original, {"preserve": CANARY})
    if unsafe == "symlink":
        destination.symlink_to(original)
    elif unsafe == "hardlink":
        destination.hardlink_to(original)
    elif unsafe == "public":
        destination.write_bytes(raw)
        destination.chmod(0o644)
    else:
        raw = (source / "github-connect.json").read_bytes()
    result = receive(destination, raw)
    assert result.returncode != 0
    assert CANARY.encode() not in result.stdout + result.stderr
    assert json.loads(original.read_bytes())["preserve"] == CANARY
