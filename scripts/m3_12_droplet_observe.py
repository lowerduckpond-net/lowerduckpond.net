"""Read only allowlisted guest facts over pinned SSH before candidate installation.

This standard-library file also runs on the cold restore host over Python stdin.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from hashlib import sha256
from http import HTTPStatus
from http.client import HTTPConnection, HTTPException
from ipaddress import IPv4Address
from pathlib import Path
from uuid import UUID

MACHINE_ID = Path("/etc/machine-id")
SYSTEM_UUID = Path("/sys/devices/virtual/dmi/id/product_uuid")
HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SELECTION = Path("/opt/lowerduckpond/static-host-agent/current")
LAUNCH = Path("/var/lib/lowerduckpond/static/platform/launch.json")
PUBLICATION = Path("/etc/lowerduckpond/static-publication.json")
RELEASES = Path("/srv/lowerduckpond/sites")
CGROUP = Path("/sys/fs/cgroup")
CAPACITY_UNITS = {
    "caddy": "system.slice/caddy.service",
    "workers": "lowerduckpond.slice/lowerduckpond-static.slice/lowerduckpond-static-workers.slice",
    "backup": "system.slice/lowerduckpond-backup.service",
    "restore": "system.slice/lowerduckpond-host-restore.service",
}
MEMORY_FIELDS = ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")
VM_FIELDS = ("oom_kill", "pswpin", "pswpout")
REQUIRED_PACKAGES = ("systemd", "openssh-server", "sudo", "python3", "e2fsprogs")
CPU_QUOTA_FIELDS = 2
RESOURCE_FORMAT = "lowerduckpond-m3-12-droplet-capacity-sample-v1"
IDENTITY_LIMIT = 4096
METADATA_LIMIT = 64
ED25519_WIRE_HEADER = b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
FORMAT = "lowerduckpond-m3-12-droplet-observation-v1"


def require(condition: bool, error: str) -> None:
    if not condition:
        raise ValueError(error)


def ed25519_key(raw: bytes) -> tuple[bytes, str]:
    """Return the canonical public line and fingerprint of one Ed25519 key."""
    require(
        0 < len(raw) <= IDENTITY_LIMIT and b"\r" not in raw and b"\n" not in raw,
        "droplet-host-key-invalid",
    )
    try:
        key_type, key, *_ = raw.split(maxsplit=2)
        wire_key = base64.b64decode(key, validate=True)
    except ValueError:
        raise ValueError("droplet-host-key-invalid") from None
    require(
        key_type == b"ssh-ed25519"
        and wire_key.startswith(ED25519_WIRE_HEADER)
        and len(wire_key) == len(ED25519_WIRE_HEADER) + 32
        and base64.b64encode(wire_key) == key,
        "droplet-host-key-invalid",
    )
    return b"ssh-ed25519 " + key, sha256(wire_key).hexdigest()


def _system_file(path: Path, owner: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        status = os.fstat(source.fileno())
        require(
            stat.S_ISREG(status.st_mode)
            and status.st_uid == owner
            and status.st_nlink == 1
            and not status.st_mode & 0o022,
            "droplet-host-identity-unsafe",
        )
        value = source.read(IDENTITY_LIMIT + 1)
    require(0 < len(value) <= IDENTITY_LIMIT, "droplet-host-identity-unsafe")
    return value.strip()


def host_identity(owner: int = 0) -> dict[str, str]:
    """Reobserve host-local facts without network access from publication workers."""
    machine = _system_file(MACHINE_ID, owner)
    require(
        re.fullmatch(rb"[0-9a-f]{32}", machine) is not None and machine != b"0" * 32,
        "droplet-machine-id-invalid",
    )
    try:
        system_uuid = UUID(_system_file(SYSTEM_UUID, owner).decode("ascii"))
    except ValueError:
        raise ValueError("droplet-system-uuid-invalid") from None
    require(
        system_uuid not in {UUID(int=0), UUID(int=(1 << 128) - 1)}, "droplet-system-uuid-invalid"
    )
    _, host_key_sha256 = ed25519_key(_system_file(HOST_KEY, owner))
    return {
        "machineSha256": sha256(machine).hexdigest(),
        "systemUuidSha256": sha256(system_uuid.bytes).hexdigest(),
        "hostKeySha256": host_key_sha256,
    }


def _metadata_value(path: str) -> str:
    connection = HTTPConnection("169.254.169.254")
    try:
        connection.request("GET", path)
        with connection.getresponse() as response:
            require(response.status == HTTPStatus.OK, "droplet-metadata-unavailable")
            raw = response.read(METADATA_LIMIT + 1)
        require(0 < len(raw) <= METADATA_LIMIT, "droplet-metadata-invalid")
        return raw.decode("ascii").strip()
    except (OSError, HTTPException) as error:
        raise ValueError("droplet-metadata-unavailable") from error
    except UnicodeDecodeError:
        raise ValueError("droplet-metadata-invalid") from None
    finally:
        connection.close()


def metadata_identity() -> tuple[int, str]:
    """Read only the two non-secret fields required to bind this public IPv4 Droplet."""
    droplet_id = _metadata_value("/metadata/v1/id")
    require(re.fullmatch(r"[1-9][0-9]*", droplet_id) is not None, "droplet-metadata-invalid")
    ipv4 = _metadata_value("/metadata/v1/interfaces/public/0/ipv4/address")
    try:
        return int(droplet_id), str(IPv4Address(ipv4))
    except ValueError:
        raise ValueError("droplet-metadata-invalid") from None


def publication_state(owner: int) -> str:
    try:
        raw = _system_file(PUBLICATION, owner)
    except FileNotFoundError:
        return "absent"
    doc = json.loads(raw)
    require(
        isinstance(doc, dict)
        and set(doc) == {"format", "static_publication_enabled"}
        and doc["format"] == "lowerduckpond-static-publication-gate-v1"
        and type(doc["static_publication_enabled"]) is bool,
        "droplet-publication-state-invalid",
    )
    return "enabled" if doc["static_publication_enabled"] else "dark"


def selected_artifact(owner: int) -> str | None:
    """Read the selector's content-addressed target, without importing it."""
    try:
        selector = SELECTION.lstat()
    except FileNotFoundError:
        return None
    require(
        stat.S_ISLNK(selector.st_mode) and selector.st_uid == owner and selector.st_nlink == 1,
        "droplet-artifact-selector-invalid",
    )
    target = SELECTION.readlink()
    require(
        target.parent == SELECTION.parent
        and re.fullmatch(r"[0-9a-f]{64}", target.name) is not None,
        "droplet-artifact-selector-invalid",
    )
    status = target.lstat()
    require(
        stat.S_ISDIR(status.st_mode) and status.st_uid == owner and not status.st_mode & 0o022,
        "droplet-artifact-selector-invalid",
    )
    return target.name


def observe(owner: int = 0) -> dict[str, object]:
    droplet_id, ipv4 = metadata_identity()
    boot = UUID(_system_file(BOOT_ID, owner).decode("ascii"))
    require(boot.int != 0, "droplet-boot-id-invalid")
    return {
        "format": FORMAT,
        "metadata": {"dropletId": droplet_id, "ipv4": ipv4},
        "hostIdentity": host_identity(owner),
        "bootSha256": sha256(boot.bytes).hexdigest(),
        "state": {
            "artifactSha256": selected_artifact(owner),
            "launchPresent": os.path.lexists(LAUNCH),
            "publication": publication_state(owner),
        },
    }


def _counters(
    path: Path, names: tuple[str, ...], *, memory: bool = False, optional: tuple[str, ...] = ()
) -> dict[str, int]:
    result = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        key = fields[0].removesuffix(":") if fields else ""
        if key in names or key in optional:
            require(key not in result, "droplet-capacity-counter-duplicate")
            require(
                len(fields) == (3 if memory else 2)
                and fields[1].isascii()
                and fields[1].isdigit()
                and (not memory or fields[2] == "kB"),
                "droplet-capacity-counter-invalid",
            )
            result[key] = int(fields[1]) * (1024 if memory else 1)
    require(set(names) <= result.keys(), "droplet-capacity-counter-missing")
    return result


def _cpu_pressure() -> int:
    raw = Path("/proc/pressure/cpu").read_text(encoding="ascii")
    match = re.search(r"^some [^\n]* total=([0-9]+)$", raw, re.MULTILINE)
    if match is None:
        raise ValueError("droplet-capacity-pressure-missing")
    return int(match[1])


def _cgroup(path: Path) -> dict[str, object] | None:
    # An already stopped transient service has no readable cgroup. Its missing
    # kernel peak must stay missing in the original sample.
    try:
        values: dict[str, int | None] = {}
        for field in (
            "memory.peak",
            "memory.swap.peak",
            "memory.max",
            "memory.swap.max",
            "pids.max",
        ):
            value = (path / field).read_text(encoding="ascii").strip()
            unlimited = field.endswith(".max") and value == "max"
            require(
                unlimited or re.fullmatch(r"[0-9]+", value) is not None, "invalid-cgroup-counter"
            )
            values[field] = None if unlimited else int(value)
        cpu = (path / "cpu.max").read_text(encoding="ascii").split()
        require(
            len(cpu) == CPU_QUOTA_FIELDS
            and (cpu[0] == "max" or cpu[0].isdigit())
            and cpu[1].isdigit(),
            "invalid-cgroup-cpu-quota",
        )
        usage = _counters(path / "cpu.stat", ("usage_usec",), optional=("throttled_usec",))
        return {
            **values,
            "residentAnonBytes": _counters(path / "memory.stat", ("anon",))["anon"],
            "cpuQuotaUsec": None if cpu[0] == "max" else int(cpu[0]),
            "cpuPeriodUsec": int(cpu[1]),
            "cpu": {"throttled_usec": None, **usage},
            "memoryEvents": _counters(path / "memory.events", ("oom", "oom_kill")),
        }
    except FileNotFoundError:
        return None


def _command(*args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed read-only capacity commands
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        env={"LANG": "C", "PATH": "/usr/bin:/bin"},
    )
    require(result.returncode == 0, "droplet-capacity-command-failed")
    return result.stdout.strip()


def _package_versions() -> dict[str, str]:
    rows = _command(
        "/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\n", *REQUIRED_PACKAGES
    )
    result = dict(line.split("\t", 1) for line in rows.splitlines())
    require(set(result) == set(REQUIRED_PACKAGES), "droplet-capacity-packages-missing")
    return result


def _allocation(path: Path) -> dict[str, int]:
    # GNU du counts each hard-linked inode once across this one traversal.
    blocks = _command(
        "/usr/bin/du", "--one-file-system", "--summarize", "--block-size=1", "--", str(path)
    )
    inodes = _command(
        "/usr/bin/du", "--one-file-system", "--summarize", "--inodes", "--", str(path)
    )
    return {
        "allocatedBytes": int(blocks.split("\t", 1)[0]),
        "uniqueInodes": int(inodes.split("\t", 1)[0]),
    }


def capacity(owner: int = 0, *, allocation: bool = False) -> dict[str, object]:
    """Sample the host with no workload, cgroup reset, or policy/state writes."""
    start = time.monotonic_ns() // 1000
    host = observe(owner)
    require(stat.S_ISDIR(RELEASES.lstat().st_mode), "droplet-capacity-release-root-invalid")
    disk = os.statvfs(RELEASES)
    fragment = disk.f_frsize or disk.f_bsize
    os_release = platform.freedesktop_os_release()
    measured = {
        "format": RESOURCE_FORMAT,
        "observation": host,
        "sampleStartedUsec": start,
        "platform": {
            "os": os_release["ID"],
            "release": os_release["VERSION_ID"],
            "kernel": os.uname().release,
            "machine": os.uname().machine,
            "filesystem": _command(
                "/usr/bin/findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(RELEASES)
            ),
        },
        "packages": _package_versions(),
        "memoryBytes": _counters(Path("/proc/meminfo"), MEMORY_FIELDS, memory=True),
        "vmEvents": _counters(Path("/proc/vmstat"), VM_FIELDS),
        "cpuOnline": os.sysconf("SC_NPROCESSORS_ONLN"),
        "cpuPressureSomeUsec": _cpu_pressure(),
        "filesystem": {
            "totalBytes": fragment * disk.f_blocks,
            "freeBytes": fragment * disk.f_bfree,
            "availableBytes": fragment * disk.f_bavail,
            "totalInodes": disk.f_files,
            "freeInodes": disk.f_ffree,
            "availableInodes": disk.f_favail,
        },
        "cgroups": {name: _cgroup(CGROUP / group) for name, group in CAPACITY_UNITS.items()},
        "releaseAllocation": _allocation(RELEASES) if allocation else None,
    }
    # The two potentially slow tree walks are optional and belong at workload
    # boundaries. A changed installed selection cannot label the same sample.
    require(observe(owner) == host, "droplet-capacity-observation-changed")
    return {**measured, "sampleFinishedUsec": time.monotonic_ns() // 1000}


def main() -> int:
    try:
        require(os.geteuid() == 0 and not os.path.lexists("/.dockerenv"), "droplet-guest-required")
        arguments = sys.argv[1:]
        if arguments == []:
            document = observe()
        elif arguments in (["--capacity"], ["--capacity-allocation"]):
            document = capacity(allocation=arguments == ["--capacity-allocation"])
        else:
            raise ValueError("droplet-observation-operation-invalid")
        sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    except OSError, ValueError, HTTPException:
        print("M3.12 disposable guest observation unavailable.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
