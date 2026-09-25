"""Fence rollout commands to one live controller, independently of its journal.

This standard-library component runs on the verified predecessor. A caller must
drain the fixed systemd action unit before a new owner is admitted. Every action
must check its token *inside* that unit, so a delayed launch cannot execute after
takeover. The unit tracks descendants with ExitType=cgroup; this lock alone does
not establish that children of a killed command have exited.
"""

from __future__ import annotations

import fcntl
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

REVOKED = b"0" * 64 + b"\n"
NAMES = frozenset({"owner", "action", "token"})


def _metadata(value: os.stat_result, owner: int, *, directory: bool = False) -> None:
    if (
        value.st_uid != owner
        or stat.S_IMODE(value.st_mode) != (0o700 if directory else 0o600)
        or (not stat.S_ISDIR(value.st_mode) if directory else not stat.S_ISREG(value.st_mode))
        or (not directory and value.st_nlink != 1)
    ):
        raise ValueError("production lease metadata is unsafe")


class Lease:
    def __init__(self, path: Path, directory: int, owner: int) -> None:
        self.path, self.directory, self.owner = path, directory, owner
        self.files: dict[str, int] = {}

    def guard(self) -> None:
        opened, named = os.fstat(self.directory), self.path.stat(follow_symlinks=False)
        _metadata(opened, self.owner, directory=True)
        _metadata(named, self.owner, directory=True)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("production lease directory changed")
        for name, fd in self.files.items():
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            _metadata(opened, self.owner)
            _metadata(named, self.owner)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise ValueError("production lease file changed")
            if opened.st_size > (len(REVOKED) if name == "token" else 0):
                raise ValueError("production lease file has invalid contents")

    def write_token(self, token: bytes) -> None:
        self.guard()
        # The action lock excludes every reader. A killed writer may leave a
        # partial token: actions reject it, and a later owner revokes it before
        # draining. Operational lease tokens are not qualification evidence.
        fd = self.files["token"]
        os.ftruncate(fd, 0)
        remaining = memoryview(token)
        offset = 0
        while remaining:
            count = os.pwrite(fd, remaining, offset)
            if count <= 0:
                raise OSError("production lease token short write")
            remaining = remaining[count:]
            offset += count
        os.fsync(fd)
        self.guard()

    def require_token(self, token: str) -> None:
        self.guard()
        if re.fullmatch(r"[0-9a-f]{64}", token) is None or token == "0" * 64:
            raise ValueError("production lease token is invalid")
        if os.pread(self.files["token"], len(REVOKED) + 1, 0) != token.encode() + b"\n":
            raise ValueError("production controller was superseded")
        try:
            fcntl.flock(self.files["owner"], fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(self.files["owner"], fcntl.LOCK_UN)
            raise ValueError("production controller is no longer present")
        self.guard()


@contextmanager
def _open(path: Path, *, owner: int, initialize: bool = False) -> Iterator[Lease]:
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lease = Lease(path, directory, owner)
    try:
        lease.guard()
        with os.scandir(directory) as entries:
            names = set()
            for entry in entries:
                if entry.name not in NAMES:
                    raise ValueError("production lease directory contains unknown files")
                names.add(entry.name)
        if initialize and (
            ("owner" not in names and names) or ("action" not in names and "token" in names)
        ):
            raise ValueError("production lease lock disappeared")
        for name in ("owner", "action", "token"):
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if initialize:
                try:
                    fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
                except FileExistsError:
                    pass
                else:
                    os.fsync(fd)
                    os.close(fd)
                    os.fsync(directory)
            lease.files[name] = os.open(name, flags, dir_fd=directory)
            lease.guard()
            if initialize and name != "token":
                # Pin ownership before completing a partial initialization;
                # never recreate or alter files beneath a live controller.
                fcntl.flock(lease.files[name], fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield lease
    finally:
        for fd in lease.files.values():
            os.close(fd)
        os.close(directory)


@contextmanager
def controller(path: Path, *, owner: int, drain: Callable[[], None]) -> Iterator[str]:
    """Acquire a fresh owner only after fencing and draining previous actions.

    ``drain`` must prove the fixed action unit and its cgroup are empty. It runs
    with the action lock held and the old token revoked; delayed action-unit
    launches must acquire that same lock and check their token before execution.
    A busy owner/action is refused, never timed out or stolen.
    """
    with _open(path, owner=owner, initialize=True) as lease:
        try:
            lease.write_token(REVOKED)
            drain()
            token = secrets.token_hex(32)
            lease.write_token(token.encode() + b"\n")
        finally:
            fcntl.flock(lease.files["action"], fcntl.LOCK_UN)
        try:
            yield token
        finally:
            # Wait for a currently executing guarded command before revoking;
            # the controller still holds its owner lock throughout this drain.
            fcntl.flock(lease.files["action"], fcntl.LOCK_EX)
            lease.write_token(REVOKED)
            drain()


@contextmanager
def action(path: Path, *, owner: int, token: str) -> Iterator[None]:
    """Guard one command inside the fixed, descendant-tracking systemd unit."""
    with _open(path, owner=owner) as lease:
        fcntl.flock(lease.files["action"], fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease.require_token(token)
        yield
        lease.guard()
