"""Fixed read-only SSH transport to the independently approved disposable host."""

from __future__ import annotations

import os
import shlex
import stat
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory

from lowerduckpond_static_contracts import ContractError, decode_json_object

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    decode,
    encode,
    require,
)
from scripts.m3_12_droplet_inventory import ApprovedAllocation, ProviderIdentity
from scripts.m3_12_droplet_observe import ed25519_key
from scripts.qualification_probe import bounded_command

PROBE = Path(__file__).with_name("m3_12_droplet_observe.py")
REMOTE_PROBE = "/usr/bin/sudo --non-interactive /usr/bin/python3 -I -B -"
REMOTE_RESTORE = "/usr/bin/sudo --non-interactive /usr/local/sbin/restore-static-host"
SSH_TRANSPORT_EXIT = 255


@dataclass(frozen=True)
class Endpoint:
    allocation: ApprovedAllocation
    provider: ProviderIdentity
    host_public_key: bytes = field(repr=False)
    identity_file: Path = field(repr=False)

    def validate(self) -> tuple[bytes, str]:
        try:
            address = IPv4Address(self.provider.ipv4)
        except ValueError:
            raise ValidationError("droplet-ssh-scope-changed") from None
        require(
            self.provider == self.allocation.identity
            and str(address) == self.provider.ipv4
            and address.is_global
            and not address.is_multicast,
            "droplet-ssh-scope-changed",
        )
        try:
            metadata = self.identity_file.lstat()
            resolved = self.identity_file.resolve(strict=True)
        except OSError, RuntimeError:
            raise ValidationError("droplet-ssh-identity-file-unsafe") from None
        require(
            self.identity_file.is_absolute()
            and resolved == self.identity_file
            and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and not metadata.st_mode & 0o077,
            "droplet-ssh-identity-file-unsafe",
        )
        return ed25519_key(self.host_public_key.strip())


def _options(endpoint: Endpoint, known_hosts: Path) -> list[str]:
    return [
        "-F",
        "/dev/null",
        "-T",
        "-x",
        "-o",
        "AddressFamily=inet",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
        "-o",
        f"UserKnownHostsFile={shlex.quote(str(known_hosts))}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ControlMaster=no",
        "-S",
        "none",
        "-i",
        str(endpoint.identity_file),
    ]


def _arguments(endpoint: Endpoint, known_hosts: Path, command: str = REMOTE_PROBE) -> list[str]:
    return [
        "/usr/bin/ssh",
        *_options(endpoint, known_hosts),
        "--",
        f"ldp-admin@{endpoint.provider.ipv4}",
        command,
    ]


def installation_inventory(endpoint: Endpoint, known_hosts: Path) -> Document:
    """Use the same single-host pin for native Ansible bootstrap."""
    endpoint.validate()
    return {
        "hosting_nodes": {
            "hosts": {
                f"m312-{endpoint.allocation.role}": {
                    "ansible_host": endpoint.provider.ipv4,
                    "ansible_user": "ldp-admin",
                    "ansible_connection": "ssh",
                    "ansible_ssh_args": shlex.join(_options(endpoint, known_hosts)),
                    "ansible_ssh_common_args": "",
                    "ansible_ssh_extra_args": "",
                    "ansible_ssh_transfer_method": "piped",
                    "ansible_ssh_host_key_checking": True,
                }
            }
        }
    }


def _call(endpoint: Endpoint, command: str, *, stdin: bytes = b"") -> bytes:
    public_key, _ = endpoint.validate()
    with TemporaryDirectory(prefix="ldp-m3-12-known-host-") as directory:
        known_hosts = Path(directory) / "known_hosts"
        fd = os.open(known_hosts, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(endpoint.provider.ipv4.encode("ascii") + b" " + public_key + b"\n")
        try:
            raw = bounded_command(
                _arguments(endpoint, known_hosts, command),
                stdin=stdin,
                check=True,
                timeout=None,
                maximum=MAX_RECORD_BYTES,
            )
        except CalledProcessError as error:
            if error.returncode == SSH_TRANSPORT_EXIT:
                raise ConnectionError("droplet-ssh-transport-failed") from None
            raise ValidationError("droplet-ssh-probe-failed") from None
        except OSError:
            raise ConnectionError("droplet-ssh-transport-failed") from None
    if raw is None:
        raise ValidationError("droplet-ssh-observation-missing")

    return raw


def require_observation(endpoint: Endpoint, doc: Document) -> None:
    _, fingerprint = endpoint.validate()
    require(
        doc["metadata"]
        == {"dropletId": endpoint.provider.droplet_id, "ipv4": endpoint.provider.ipv4}
        and doc["hostIdentity"]["hostKeySha256"] == fingerprint,
        "droplet-ssh-observation-changed",
    )


def observe(endpoint: Endpoint) -> Document:
    """Run the fixed probe over a fresh connection with only this host key trusted."""
    raw = _call(endpoint, REMOTE_PROBE, stdin=PROBE.read_bytes())
    doc = decode(raw, "droplet-observation")
    require_observation(endpoint, doc)
    return doc


def capacity_sample(endpoint: Endpoint, *, allocation: bool) -> Document:
    operation = "--capacity-allocation" if allocation else "--capacity"
    raw = _call(endpoint, f"{REMOTE_PROBE} {operation}", stdin=PROBE.read_bytes())
    sample = decode(raw, "droplet-capacity-sample")
    require_observation(endpoint, sample["observation"])
    disk = sample["filesystem"]
    memory = sample["memoryBytes"]
    require(
        (sample["releaseAllocation"] is not None) == allocation
        and sample["sampleStartedUsec"] <= sample["sampleFinishedUsec"]
        and memory["MemAvailable"] <= memory["MemTotal"]
        and memory["SwapFree"] <= memory["SwapTotal"]
        and disk["availableBytes"] <= disk["freeBytes"] <= disk["totalBytes"]
        and disk["availableInodes"] <= disk["freeInodes"] <= disk["totalInodes"],
        "droplet-capacity-sample-inconsistent",
    )
    return sample


def restore_delivery(endpoint: Endpoint) -> Document:
    return _restore_read(endpoint, "--verify-delivery")


def restore_status(endpoint: Endpoint) -> Document:
    return _restore_read(endpoint, "--status")


def _restore_read(endpoint: Endpoint, operation: str) -> Document:
    require(endpoint.allocation.role == "restore", "droplet-restore-readback-role-changed")
    raw = _call(endpoint, f"{REMOTE_RESTORE} {operation}")
    try:
        value = decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError:
        raise ValidationError("droplet-restore-response-invalid") from None
    require(encode(value) == raw, "droplet-restore-response-invalid")
    return value
