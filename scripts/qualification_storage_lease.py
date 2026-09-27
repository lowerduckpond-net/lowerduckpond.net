"""One workstation lease per archive target, shared by live runs and retirement."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from scripts.m3_11_qualification_evidence import canonical_bytes

FD_ENV = "LDP_QUALIFICATION_STORAGE_LEASE_FD"


def lease_path(environment: Mapping[str, str]) -> Path:
    region, bucket = (
        environment.get("SPACES_REGION", ""),
        environment.get("SPACES_ARCHIVE_BUCKET", ""),
    )
    if (
        re.fullmatch(r"[a-z]{3}[1-9][0-9]?", region) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
    ):
        raise ValueError("storage lease requires a bound archive target")
    identity = hashlib.sha256(
        canonical_bytes({"region": region, "archive_bucket": bucket})
    ).hexdigest()
    root = Path.home() / ".local/share/lowerduckpond.net/storage-leases"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        root.resolve() != root
        or root.stat().st_uid != os.geteuid()
        or stat.S_IMODE(root.stat().st_mode) != 0o700  # noqa: PLR2004
    ):
        raise ValueError("storage lease directory is unsafe")
    return root / (identity + ".lock")


def require_inherited(environment: Mapping[str, str]) -> int:
    value = environment.get(FD_ENV, "")
    if not value.isascii() or not value.isdecimal() or not 3 <= int(value) <= 1024:  # noqa: PLR2004
        raise ValueError("storage lease descriptor is unavailable")
    fd = int(value)
    actual, expected = os.fstat(fd), lease_path(environment).lstat()
    if (
        (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
        or not stat.S_ISREG(actual.st_mode)
        or actual.st_uid != os.geteuid()
        or actual.st_nlink != 1
        or stat.S_IMODE(actual.st_mode) != 0o600  # noqa: PLR2004
    ):
        raise ValueError("storage lease descriptor differs from its target")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


@contextmanager
def storage_lease(environment: Mapping[str, str]) -> Iterator[int]:
    if FD_ENV in environment:
        yield require_inherited(environment)
        return
    path = lease_path(environment)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        value = os.fstat(fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
            or stat.S_IMODE(value.st_mode) != 0o600  # noqa: PLR2004
        ):
            raise ValueError("storage lease file is unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.check:
            require_inherited(os.environ)
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise ValueError("a leased command is required")
        with storage_lease(os.environ) as fd:
            os.set_inheritable(fd, True)
            environment = {**os.environ, FD_ENV: str(fd)}
            os.execvpe(command[0], command, environment)  # noqa: S606 - explicit operator command
    except OSError, ValueError:
        print("Archive target is busy or its workstation lease is unavailable.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
