"""Fixed read-only predecessor probe, sent over verified SSH before installation.

Only the standard library is available on the predecessor. Host integrity,
empty history and provider policy are separate checks in the caller; this probe
adds original completion, dark publication, actual repository identity and
capacity. It never initializes a repository or a rollout record.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

COMPLETION = Path("/var/lib/lowerduckpond/convergence/m3-10")
TRANSACTION = Path("/var/lib/lowerduckpond/convergence/m3-11")
SELECTION = Path("/opt/lowerduckpond/static-host-agent/current")
BACKUP = Path("/etc/lowerduckpond/backup.env")
PUBLICATION = Path("/etc/lowerduckpond/static-publication.json")
CAPACITY_PATHS = (
    Path("/var/lib/lowerduckpond/static"),
    Path("/srv/lowerduckpond/sites"),
    Path("/var/cache/lowerduckpond-backup"),
    Path("/opt/lowerduckpond/static-host-agent"),
)
NODE = "lowerduckpond-production-01"
MAX_BYTES = 16 * 1024
PRIVATE_DIRECTORY_MODE = 0o700
MINIMUM_BYTES = 5 * 1024**3
MINIMUM_INODES = 100_000
MINIMUM_PERCENT = 10
PERCENT = 100
RESTIC_VERSION = 2
# The existing repository metadata discovery bound; this is not a retry budget.
METADATA_SECONDS = 300
RESTIC = ("/usr/bin/restic", "--no-cache", "--no-lock", "cat", "config")
ENVIRONMENT = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_DEFAULT_REGION",
        "RESTIC_PASSWORD",
        "RESTIC_REPOSITORY",
    }
)
CONFIGURATION = ENVIRONMENT | {
    "RESTIC_CACHE_DIR",
    "LOWERDUCKPOND_BACKUP_NODE_NAME",
    "LOWERDUCKPOND_BACKUP_STATUS_SCOPE",
    "LOWERDUCKPOND_BACKUP_MAINTENANCE_STATUS_SCOPE",
    "LOWERDUCKPOND_BACKUP_KEEP_DAILY",
    "LOWERDUCKPOND_BACKUP_KEEP_WEEKLY",
    "LOWERDUCKPOND_BACKUP_KEEP_MONTHLY",
    "LOWERDUCKPOND_BACKUP_ACTIVATION_SCOPE",
    "LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED",
    "LOWERDUCKPOND_AUDIT_ROTATION_ENABLED",
}


def read(path: Path, *, owner: int, mode: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or before.st_size > MAX_BYTES
        ):
            raise ValueError("production predecessor file metadata is unsafe")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        after = path.stat(follow_symlinks=False)
        if len(raw) != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise ValueError("production predecessor changed while reading")
        return raw
    finally:
        os.close(fd)


def configuration(raw: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    # Parse literal shell assignments without evaluating expansions or commands.
    for assignment in shlex.split(raw.decode("utf-8"), comments=True, posix=True):
        key, separator, value = assignment.partition("=")
        if not separator or key not in CONFIGURATION or key in result or "\0" in value:
            raise ValueError("production backup configuration is not a literal environment")
        result[key] = value
    return result


def environment(raw: bytes, *, region: str, locator: str) -> dict[str, str]:
    result = configuration(raw)
    if (
        any(not result.get(key) for key in ENVIRONMENT)
        or result.get("RESTIC_REPOSITORY") != locator
        or result.get("AWS_DEFAULT_REGION") != region
        or result.get("LOWERDUCKPOND_BACKUP_NODE_NAME") != NODE
        or result.get("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED", "false") != "false"
        or result.get("LOWERDUCKPOND_AUDIT_ROTATION_ENABLED", "false") != "false"
    ):
        raise ValueError("production predecessor backup target or migration mode changed")
    return {key: result[key] for key in ENVIRONMENT}


def repository_config(environment: dict[str, str]) -> bytes:
    with subprocess.Popen(  # noqa: S603 - fixed read-only Restic command, explicit credential environment
        RESTIC,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", **environment},
    ) as process:
        assert process.stdout is not None  # noqa: S101 - PIPE supplied above
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        output = bytearray()
        deadline = time.monotonic() + METADATA_SECONDS
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(descriptor, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError("production repository observation exceeded its deadline")
                    try:
                        block = os.read(descriptor, MAX_BYTES + 1 - len(output))
                    except BlockingIOError:
                        continue
                    if not block:
                        break
                    output.extend(block)
                    if len(output) > MAX_BYTES:
                        raise ValueError("production repository observation exceeds its bound")
            if process.wait(timeout=max(0.0, deadline - time.monotonic())):
                raise ValueError("production repository observation failed")
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("production observation contains duplicate fields")
    return value


def capacity(path: Path, *, owner: int) -> dict[str, object]:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if before.st_uid != owner or before.st_mode & 0o022:
            raise ValueError("production capacity path is unsafe")
        usage = os.fstatvfs(fd)
        available = usage.f_bavail * usage.f_frsize
        if (
            usage.f_blocks <= 0
            or usage.f_files <= 0
            or available < MINIMUM_BYTES
            or usage.f_favail < MINIMUM_INODES
            or usage.f_bavail * PERCENT < usage.f_blocks * MINIMUM_PERCENT
            or usage.f_favail * PERCENT < usage.f_files * MINIMUM_PERCENT
        ):
            raise ValueError("production capacity is below the committed reserve")
        named = path.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("production capacity path changed")
        return {"path": str(path), "available_bytes": available, "available_inodes": usage.f_favail}
    finally:
        os.close(fd)


def observe(region: str, bucket: str, *, owner: int = 0) -> dict[str, object]:
    if (
        re.fullmatch(r"[a-z]{3}[1-9][0-9]?", region) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
    ):
        raise ValueError("production storage coordinates are invalid")
    for directory in (COMPLETION.parent, BACKUP.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE:
                raise ValueError("production predecessor directory metadata is unsafe")
        finally:
            os.close(fd)
    if os.path.lexists(TRANSACTION):
        raise ValueError("an existing M3.11 transaction requires its original resume or acceptance")
    predecessor = read(COMPLETION, owner=owner, mode=0o400)
    if re.fullmatch(rb"[0-9a-f]{64} [0-9a-f]{40}( [0-9a-f]{64})?\n", predecessor) is None:
        raise ValueError("production requires original M3.10 completion")
    expected = SELECTION.parent / predecessor.split()[0].decode("ascii")
    if not SELECTION.is_symlink() or SELECTION.resolve(strict=True) != expected:
        raise ValueError("production selected artifact differs from original completion")
    publication = read(PUBLICATION, owner=owner, mode=0o400)
    gate = json.loads(publication, object_pairs_hook=unique_object)
    if (
        not isinstance(gate, dict)
        or set(gate) != {"format", "static_publication_enabled"}
        or gate["format"] != "lowerduckpond-static-publication-gate-v1"
        or gate["static_publication_enabled"] is not False
    ):
        raise ValueError("production publication must remain disabled")
    locator = f"s3:https://{region}.digitaloceanspaces.com/{bucket}/backups/{NODE}"
    configuration = read(BACKUP, owner=owner, mode=0o600)
    config = json.loads(
        repository_config(environment(configuration, region=region, locator=locator)),
        object_pairs_hook=unique_object,
    )
    if (
        not isinstance(config, dict)
        or type(config.get("version")) is not int
        or config["version"] != RESTIC_VERSION
        or not isinstance(config.get("id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", config["id"]) is None
    ):
        raise ValueError("production repository identity is invalid")
    capacities = [capacity(path, owner=owner) for path in CAPACITY_PATHS]
    if (
        read(COMPLETION, owner=owner, mode=0o400) != predecessor
        or read(PUBLICATION, owner=owner, mode=0o400) != publication
        or read(BACKUP, owner=owner, mode=0o600) != configuration
        or SELECTION.resolve(strict=True) != expected
        or os.path.lexists(TRANSACTION)
    ):
        raise ValueError("production predecessor changed during observation")
    return {
        "format": "lowerduckpond-m3-11-predecessor-observation-v1",
        "predecessor": predecessor.decode("ascii"),
        "repository_config_id": config["id"],
        "repository_node": NODE,
        "repository_locator": locator,
        "backup_configuration_sha256": hashlib.sha256(configuration).hexdigest(),
        "publication_configuration_sha256": hashlib.sha256(publication).hexdigest(),
        "capacity": capacities,
    }


def main() -> int:
    try:
        if len(sys.argv) != 3 or os.geteuid() != 0:  # noqa: PLR2004 - fixed root-only stdin protocol
            raise ValueError("invalid production predecessor probe invocation")
        result = observe(sys.argv[1], sys.argv[2])
    except ValueError, OSError, TypeError, RecursionError, subprocess.TimeoutExpired:
        print("M3.11 predecessor observation failed; no production state changed.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
