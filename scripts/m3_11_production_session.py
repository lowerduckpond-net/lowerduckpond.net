"""One verified SSH owner for the complete production controller transaction."""

from __future__ import annotations

import os
import re
import select
import shlex
import stat
import subprocess
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from scripts import m3_11_production_stage as stage
from scripts import m3_11_production_transport as transport

OWNER_READY_SECONDS = 15
OWNER_RELEASE_SECONDS = 30
TOKEN_BYTES = 65
DIRECTORY_MODE = 0o700


@dataclass(frozen=True)
class Result:
    status: int
    stdout: Path
    stderr: Path

    def read(self, maximum: int = 16 * 1024) -> bytes:
        with self.stdout.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("production observation exceeds its bound")
        return raw


class Logs:
    """Exclusive files retain original failed and successful observations alike."""

    def __init__(self, directory: Path) -> None:
        metadata = directory.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != DIRECTORY_MODE
        ):
            raise ValueError("production diagnostics require a private owned directory")
        self.directory = directory
        self.identity = metadata.st_dev, metadata.st_ino
        self.number = 0

    def paths(self, name: str) -> tuple[Path, Path]:
        metadata = self.directory.stat(follow_symlinks=False)
        if (
            (metadata.st_dev, metadata.st_ino) != self.identity
            or stat.S_IMODE(metadata.st_mode) != DIRECTORY_MODE
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("production diagnostics directory changed")
        if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is None:
            raise ValueError("invalid production diagnostic step")
        prefix = f"{self.number:04d}-{name}"
        self.number += 1
        return self.directory / (prefix + ".stdout"), self.directory / (prefix + ".stderr")

    def run(
        self,
        name: str,
        arguments: Sequence[str],
        *,
        data: bytes = b"",
        environment: Mapping[str, str] | None = None,
    ) -> Result:
        stdout, stderr = self.paths(name)
        with stdout.open("xb") as out, stderr.open("xb") as err:
            os.fchmod(out.fileno(), 0o600)
            os.fchmod(err.fileno(), 0o600)
            try:
                result = subprocess.run(  # noqa: S603 - fixed controller command and verified SSH
                    list(arguments),
                    input=data,
                    stdout=out,
                    stderr=err,
                    env=environment,
                    check=False,
                )
            finally:
                for stream in (out, err):
                    stream.flush()
                    os.fsync(stream.fileno())
                self.sync()
        return Result(result.returncode, stdout, stderr)

    def sync(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            if (metadata.st_dev, metadata.st_ino) != self.identity:
                raise ValueError("production diagnostics directory changed")
            os.fsync(fd)
        finally:
            os.close(fd)


@dataclass(frozen=True)
class Session:
    ssh: tuple[str, ...]
    helper: str
    token: str
    logs: Logs
    owner: subprocess.Popen[bytes]

    def require_owner(self) -> None:
        if self.owner.poll() is not None:
            raise ValueError("production controller connection ended")

    def run(self, name: str, arguments: Sequence[str], *, data: bytes = b"") -> Result:
        self.require_owner()
        result = self.logs.run(
            name,
            [*self.ssh, transport.command(self.helper, self.token, shlex.join(arguments))],
            data=data,
        )
        self.require_owner()
        return result

    def ansible_environment(self, original: Mapping[str, str]) -> dict[str, str]:
        self.require_owner()
        return {
            **original,
            "ANSIBLE_CONNECTION_PLUGINS": str(
                Path(__file__).resolve().parents[1] / "config/ansible/plugins/connection"
            ),
            "LDP_M3_11_ACTION_HELPER": self.helper,
            "LDP_M3_11_LEASE_TOKEN": self.token,
            "ANSIBLE_SSH_USETTY": "false",
            "ANSIBLE_SSH_RETRIES": "0",
            "ANSIBLE_SSH_TRANSFER_METHOD": "piped",
            "ANSIBLE_HOST_KEY_CHECKING": "true",
        }


def _token(process: subprocess.Popen[bytes]) -> str:
    assert process.stdout is not None  # noqa: S101 - owner stdout is a dedicated pipe
    fd = process.stdout.fileno()
    deadline = time.monotonic() + OWNER_READY_SECONDS
    result = bytearray()
    while len(result) < TOKEN_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError("production controller connection was not ready")
        block = os.read(fd, TOKEN_BYTES - len(result))
        if not block:
            raise ValueError("production controller connection ended before admission")
        result.extend(block)
    if re.fullmatch(rb"[0-9a-f]{64}\n", result) is None or result == b"0" * 64 + b"\n":
        raise ValueError("production controller returned invalid authority")
    return result[:-1].decode("ascii")


@contextmanager
def controller(ssh: Sequence[str], directory: Path) -> Iterator[Session]:
    """Stage exact code, retain one owner, and release it after all caller work.

    The caller supplies the preflight's verified SSH argv and an exclusive
    private diagnostics directory. Qualification and original journal gates
    must succeed before this component is allowed to mutate production.
    Closing or losing the control stream makes the remote owner revoke/drain;
    a later controller cannot steal an owner/action still doing that work.
    """
    logs = Logs(directory)
    raw, helper = transport.helper_bundle()
    result = logs.run(
        "stage-controller",
        [
            *ssh,
            shlex.join(
                [
                    "sudo",
                    "--non-interactive",
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    Path(stage.__file__).read_text(),
                    Path(helper).stem,
                ]
            ),
        ],
        data=raw,
    )
    if result.status or result.read() != helper.encode() + b"\n":
        raise ValueError("production controller staging failed")
    _, errors = logs.paths("owner")
    command = [
        *ssh,
        shlex.join(["sudo", "--non-interactive", "/usr/bin/python3", "-I", "-B", helper, "owner"]),
    ]
    with errors.open("xb") as stderr:
        os.fchmod(stderr.fileno(), 0o600)
        process = subprocess.Popen(  # noqa: S603 - exact staged helper and verified SSH destination
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr
        )
        admitted = False
        try:
            token = _token(process)
            admitted = True
            yield Session(tuple(ssh), helper, token, logs, process)
        finally:
            assert process.stdin is not None  # noqa: S101 - dedicated owner control stream
            try:
                if process.poll() is None and admitted:
                    process.stdin.write(b"release\n")
                    process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                with suppress(BrokenPipeError):
                    process.stdin.close()
            try:
                status = process.wait(timeout=OWNER_RELEASE_SECONDS)
            except subprocess.TimeoutExpired:
                # End only our SSH client, never claim the remote owner/action
                # was drained. The next admission still checks its actual locks.
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise ValueError("production controller release was not confirmed") from None
            finally:
                if process.stdout is not None:
                    process.stdout.close()
                stderr.flush()
                os.fsync(stderr.fileno())
                logs.sync()
            if admitted and status:
                raise ValueError("production controller release failed")
