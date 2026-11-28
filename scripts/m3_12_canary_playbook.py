"""Drive exactly one pending dark pass with the original leased production transport."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from scripts.m3_11_production_converge import HOST, recap
from scripts.m3_11_production_preflight import save
from scripts.m3_11_production_session import Logs
from scripts.m3_12_contracts import MAX_RECORD_BYTES, Document, decode, digest, encode, require
from scripts.m3_12_successor import stage_configuration

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/ansible"
SSH_TARGET = "157.230.203.161"
INPUTS = frozenset(
    {
        "ADMIN_SOURCE_CIDRS_JSON",
        "BACKUP_REPOSITORY",
        "CADDY_CLOUDFLARE_API_TOKEN",
        "CADDY_ORIGIN_PULL_CA_PATHS_JSON",
        "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED",
        "M3_DARK_HOST_ROLLBACK_ARTIFACT_PATH",
        "RESTIC_PASSWORD",
        "SPACES_ARCHIVE_ACCESS_KEY_ID",
        "SPACES_ARCHIVE_BUCKET",
        "SPACES_ARCHIVE_SECRET_ACCESS_KEY",
        "SPACES_BACKUP_ACCESS_KEY_ID",
        "SPACES_BACKUP_SECRET_ACCESS_KEY",
        "SPACES_REGION",
        "STATIC_OPERATOR_PRINCIPAL",
        "STATIC_OPERATOR_PUBLIC_KEY",
    }
)


@dataclass(frozen=True)
class DarkPass:
    """Construct only from independently checked exact candidate and live pinned owner."""

    transaction_sha256: str
    invocation: str
    lease: str = field(repr=False)
    artifact: Path
    artifact_sha256: str
    identity: Path
    signer: Path
    known_hosts: Path
    ansible_playbook: Path

    def pending(self, raw: bytes) -> Document:
        row = decode(raw, "phase-receipt")
        phase = row["phase"]
        require(
            re.fullmatch(r"[0-9a-f]{64}", self.lease) is not None
            and self.lease != "0" * 64
            and row["transactionSha256"] == self.transaction_sha256
            and row["transition"] == "started"
            and phase in {"dark-staging", "dark-repeat"}
            and row["publicationView"] == "dark"
            and row["invocationId"] == self.invocation
            and row["leaseSha256"] == hashlib.sha256(self.lease.encode()).hexdigest()
            and row["stageConfigurationSha256"]
            == digest(stage_configuration(phase, self.artifact_sha256)),
            "first-canary-playbook-intent-changed",
        )
        return row

    def ssh_options(self) -> list[str]:
        return [
            "-F",
            "/dev/null",
            "-o",
            "HostKeyAlias=lowerduckpond.net",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"IdentityAgent={self.signer}",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
        ]

    def inventory(self) -> Document:
        return {
            "all": {
                "children": {
                    "hosting_nodes": {
                        "hosts": {
                            HOST: {
                                "ansible_host": SSH_TARGET,
                                "ansible_user": "ldp-admin",
                                "ansible_private_key_file": str(self.identity),
                                "ansible_connection": "ldp_m3_12",
                                "ansible_ssh_args": "-C",
                                "ansible_ssh_common_args": shlex.join(self.ssh_options()),
                                "ansible_ssh_transfer_method": "piped",
                                "ansible_ssh_use_tty": False,
                                "ansible_ssh_retries": 0,
                            }
                        }
                    }
                }
            }
        }


def run(
    action: DarkPass,
    intent: bytes,
    directory: Path,
    inputs: Mapping[str, str],
    observe_pending: Callable[[], bytes],
) -> bytes:
    """Retain controller evidence; the host separately verifies it before committing."""
    row = action.pending(intent)
    require(observe_pending() == intent, "first-canary-playbook-not-current")
    artifact = action.artifact
    require(
        artifact.is_absolute() and artifact.is_file() and artifact.resolve(strict=True) == artifact,
        "first-canary-playbook-artifact-path",
    )
    with artifact.open("rb") as stream:
        require(
            hashlib.file_digest(stream, "sha256").hexdigest() == action.artifact_sha256,
            "first-canary-playbook-artifact-changed",
        )
    require(
        action.ansible_playbook.is_absolute()
        and action.ansible_playbook.resolve(strict=False) == action.ansible_playbook
        and action.ansible_playbook.is_file()
        and os.access(action.ansible_playbook, os.X_OK),
        "first-canary-playbook-runtime-unavailable",
    )
    require(set(inputs) <= INPUTS, "first-canary-playbook-unexpected-environment")
    logs = Logs(directory)
    attempt = Path(tempfile.mkdtemp(prefix=row["phase"] + "-", dir=logs.directory))
    inventory, variables, receipt = (
        attempt / name for name in ("inventory.json", "variables.json", "recap.json")
    )
    save(inventory, encode(action.inventory()))
    save(
        variables,
        encode(
            {
                "static_host_agent_artifact_path": str(artifact),
                "static_host_agent_artifact_sha256": action.artifact_sha256,
                "static_host_agent_verified_completed_candidate": False,
                "backup_static_recovery_enabled": True,
                "backup_audit_rotation_enabled": True,
                "static_publication_enabled": False,
                "host_recovery_bootstrap_enabled": False,
                "static_host_agent_archive_lifecycle_enabled": True,
                "caddy_generation_enabled": True,
            }
        ),
    )
    context = hashlib.sha256(intent).hexdigest()
    result = Logs(attempt).run(
        "ansible-site",
        [
            str(action.ansible_playbook),
            "--inventory",
            str(CONFIG / "inventories/production/hosts.yml"),
            "--inventory",
            str(inventory),
            "--limit",
            HOST,
            "--extra-vars",
            "@" + str(variables),
            str(CONFIG / "playbooks/site.yml"),
        ],
        environment={
            **inputs,
            "PRODUCTION_ORIGIN_IPV4": SSH_TARGET,
            "PATH": "/usr/bin:/bin",
            "HOME": str(attempt),
            "LANG": "C.UTF-8",
            "ANSIBLE_CONFIG": str(CONFIG / "ansible.cfg"),
            "ANSIBLE_COLLECTIONS_PATH": str(Path.home() / ".ansible/collections"),
            "ANSIBLE_CONNECTION_PLUGINS": str(CONFIG / "plugins/connection"),
            "ANSIBLE_CALLBACK_PLUGINS": str(CONFIG / "plugins/callback"),
            "ANSIBLE_CALLBACKS_ENABLED": "ldp_m3_11_receipt",
            "ANSIBLE_LOCAL_TEMP": str(attempt),
            "ANSIBLE_HOST_KEY_CHECKING": "true",
            "LDP_M3_12_LEASE_TOKEN": action.lease,
            "LDP_M3_11_PLAYBOOK_CONTEXT": context,
            "LDP_M3_11_PLAYBOOK_RECEIPT": str(receipt),
        },
    )
    require(result.status == 0, "first-canary-playbook-failed")
    require(observe_pending() == intent, "first-canary-playbook-not-current")
    raw, _ = recap(receipt, context, idempotent=row["phase"] == "dark-repeat")
    return raw


def complete_pending(action: DarkPass, directory: Path, inputs: Mapping[str, str]) -> Document:
    """Complete a caller-owned original lease's pending pass; never start or retry it."""
    logs = Logs(directory)

    def dispatch(operation: str, data: bytes = b"") -> bytes:
        result = logs.run(
            operation,
            [
                "/usr/bin/ssh",
                "-T",
                *action.ssh_options(),
                "-i",
                str(action.identity),
                f"ldp-admin@{SSH_TARGET}",
                shlex.join(
                    [
                        "sudo",
                        "--non-interactive",
                        "/usr/bin/systemd-run",
                        "--quiet",
                        "--wait",
                        "--pipe",
                        "--collect",
                        "--expand-environment=no",
                        "--unit=lowerduckpond-m3-12-action.service",
                        "--service-type=exec",
                        "--property=ExitType=cgroup",
                        "--property=KillMode=control-group",
                        "--property=UMask=0077",
                        "/usr/local/libexec/lowerduckpond/m3-12-successor-action",
                        operation,
                        action.lease,
                    ]
                ),
            ],
            data=data,
            environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        require(result.status == 0, "first-canary-playbook-native-" + operation)
        return result.read(MAX_RECORD_BYTES)

    def observe() -> bytes:
        return dispatch("first-canary-pending-dark")

    intent = observe()
    original = action.pending(intent)
    receipt = run(action, intent, directory, inputs, observe)
    result = decode(dispatch("first-canary-finish-dark", receipt), "phase-receipt")
    require(
        result["transition"] == "committed"
        and result["previousSha256"] == hashlib.sha256(intent).hexdigest()
        and all(
            result[key] == original[key]
            for key in (
                "transactionSha256",
                "phase",
                "invocationId",
                "leaseSha256",
                "publicationView",
                "stageConfigurationSha256",
            )
        ),
        "first-canary-playbook-commit-changed",
    )
    return result
