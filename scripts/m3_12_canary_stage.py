"""Stage a reviewed artifact without selecting it on the accepted predecessor."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

INSTALL = Path("/opt/lowerduckpond/static-host-agent")
STATE = Path("/var/lib/lowerduckpond/static")
VERIFIER = Path("/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact")
SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class ReviewedStage:
    # Supplied by the independently verified candidate review, never calculated
    # from the incoming files in the operation that consumes them.
    predecessor: str
    artifact: str
    installer: str
    verifier: str

    def check(self) -> None:
        if (
            any(SHA256.fullmatch(value) is None for value in vars(self).values())
            or self.predecessor == self.artifact
        ):
            raise ValueError("canary-stage-review-invalid")


@contextmanager
def protected(
    path: Path, *, owner: int, directory: bool = False, private: bool = False
) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != owner
            or path.resolve(strict=True) != path
            or not (stat.S_ISDIR if directory else stat.S_ISREG)(metadata.st_mode)
            or (not directory and metadata.st_nlink != 1)
            or metadata.st_mode & 0o022
            or (private and stat.S_IMODE(metadata.st_mode) != (0o700 if directory else 0o600))
        ):
            raise ValueError("canary-stage-custody-invalid")
        yield descriptor
    finally:
        os.close(descriptor)


def check_digest(descriptor: int, expected: str) -> None:
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise ValueError("canary-stage-digest-changed")
        # file_digest can bypass buffering; reset the shared descriptor directly.
        os.lseek(descriptor, 0, os.SEEK_SET)


def run(  # noqa: PLR0913 - isolated roots supplied only by tests
    reviewed: ReviewedStage,
    transfer: Path,
    *,
    owner: int = 0,
    install: Path = INSTALL,
    state: Path = STATE,
    verifier: Path = VERIFIER,
) -> bool:
    """Consume exact reviewed bytes from an already protected transfer directory.

    This cannot start a service, select the successor, or create enrollment.
    The caller must independently check real identity and original authority.
    """
    reviewed.check()
    if os.geteuid() != owner:
        raise ValueError("canary-stage-owner-invalid")
    with (
        protected(transfer, owner=owner, directory=True, private=True),
        protected(install, owner=owner, directory=True) as root_fd,
        protected(install / "selection.lock", owner=owner, private=True) as lock_fd,
        protected(transfer / "installer.py", owner=owner, private=True) as installer_fd,
        protected(transfer / "artifact.tar", owner=owner, private=True) as archive_fd,
        protected(verifier, owner=owner) as verifier_fd,
    ):
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        _selected(install, reviewed.predecessor, root_fd, lock_fd)
        check_digest(installer_fd, reviewed.installer)
        check_digest(archive_fd, reviewed.artifact)
        check_digest(verifier_fd, reviewed.verifier)
        # The verifier name is required by the existing installer; use a private
        # copy of the exact open bytes so replacement cannot change execution.
        with tempfile.TemporaryDirectory(prefix="verification-", dir=transfer) as temporary:
            verify = Path(temporary) / "verify"
            with verify.open("xb") as output, os.fdopen(os.dup(verifier_fd), "rb") as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    output.write(chunk)
                os.fchmod(output.fileno(), 0o500)
            result = subprocess.run(  # noqa: S603 - reviewed bytes/descriptors and fixed stage flag
                [
                    sys.executable,
                    "-I",
                    "-B",
                    f"/proc/self/fd/{installer_fd}",
                    f"/proc/self/fd/{archive_fd}",
                    reviewed.artifact,
                    str(install),
                    str(verify),
                    str(state),
                    "--stage-only",
                ],
                pass_fds=(installer_fd, archive_fd),
                cwd=transfer,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
        _selected(install, reviewed.predecessor, root_fd, lock_fd)
        if result.returncode or result.stdout not in {b"changed\n", b"unchanged\n"}:
            raise ValueError("canary-stage-installer-failed")
        return result.stdout == b"changed\n"


def _selected(install: Path, predecessor: str, root_fd: int, lock_fd: int) -> None:
    for path, fd in ((install, root_fd), (install / "selection.lock", lock_fd)):
        named, opened = path.lstat(), os.fstat(fd)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("canary-stage-selection-authority-changed")
    selected = install / "current"
    if not selected.is_symlink() or selected.resolve(strict=True) != install / predecessor:
        raise ValueError("canary-stage-predecessor-changed")
