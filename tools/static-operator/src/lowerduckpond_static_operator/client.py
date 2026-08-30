"""Bounded local-file and SSH transport for the static operator protocol."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import select
import stat
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import (
    HEADER_SIZE,
    MAX_RAW_REQUEST_BYTES,
    FrameHeader,
    FrameKind,
    canonical_json_bytes,
    decode_header,
    decode_request,
    decode_result,
    encode_header,
)

_HOSTNAME: Final = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
    flags=re.ASCII,
)
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CHUNK_BYTES: Final = 64 * 1024
_ERROR_BYTES: Final = 4096
_TRANSFER_TOTAL_SECONDS: Final = 20.0 * 60.0
_TRANSFER_IDLE_SECONDS: Final = 30.0
_RESULT_WAIT_SECONDS: Final = 5.0 * 60.0 + 30.0
_RENAME_NOREPLACE: Final = 1


class OperatorClientError(RuntimeError):
    """Local input or the authenticated SSH response violated the protocol."""


@dataclass(frozen=True, slots=True)
class _ArtifactSource:
    file_descriptor: int
    size: int
    sha256: str
    generation: tuple[int, ...]


@dataclass(slots=True)
class _Deadline:
    expires_at: float
    idle_seconds: float
    last_progress: float

    @classmethod
    def start(
        cls,
        *,
        total_seconds: float = _TRANSFER_TOTAL_SECONDS,
        idle_seconds: float = _TRANSFER_IDLE_SECONDS,
    ) -> _Deadline:
        now = time.monotonic()
        return cls(now + total_seconds, idle_seconds, now)

    def timeout(self) -> float:
        now = time.monotonic()
        timeout = min(self.expires_at - now, self.idle_seconds - (now - self.last_progress))
        if timeout <= 0:
            raise OperatorClientError("operator transport timed out")
        return timeout

    def progress(self) -> None:
        self.last_progress = time.monotonic()


class _ProcessChannel:
    """Bound every local pipe operation while retaining only bounded stderr."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("SSH process pipes were not created")  # pragma: no cover
        self.process = process
        self.stdin_fd = process.stdin.fileno()
        self.stdout_fd = process.stdout.fileno()
        self.stderr_fd = process.stderr.fileno()
        for descriptor in (self.stdin_fd, self.stdout_fd, self.stderr_fd):
            os.set_blocking(descriptor, False)
        self.stderr = bytearray()
        self.stderr_open = True
        self.deadline = _Deadline.start()

    def write(self, data: bytes | memoryview) -> None:
        remaining = memoryview(data)
        while remaining:
            self._wait(write=True)
            try:
                written = os.write(self.stdin_fd, remaining)
            except BlockingIOError:
                continue
            if written <= 0:
                raise OperatorClientError("operator transport stopped accepting input")
            remaining = remaining[written:]
            self.deadline.progress()

    def close_input(self) -> None:
        self.process.stdin.close()  # type: ignore[union-attr]

    def begin_result_wait(self) -> None:
        """Allow the server's bounded silent execution window after intake."""

        self.deadline = _Deadline.start(
            total_seconds=_RESULT_WAIT_SECONDS,
            idle_seconds=_RESULT_WAIT_SECONDS,
        )

    def begin_response_transfer(self) -> None:
        """Restore progress-sensitive bounds once response bytes begin."""

        self.deadline = _Deadline.start()

    def read_exact(self, byte_count: int) -> bytes:
        chunks: list[bytes] = []
        remaining = byte_count
        while remaining:
            self._wait(read=True)
            try:
                chunk = os.read(self.stdout_fd, min(remaining, _CHUNK_BYTES))
            except BlockingIOError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            self.deadline.progress()
        return b"".join(chunks)

    def require_output_eof(self) -> None:
        while True:
            self._wait(read=True)
            try:
                chunk = os.read(self.stdout_fd, 1)
            except BlockingIOError:
                continue
            if chunk:
                raise OperatorClientError("operator response contains trailing bytes")
            return

    def wait(self) -> int:
        try:
            return self.process.wait(timeout=self.deadline.timeout())
        except subprocess.TimeoutExpired as error:
            raise OperatorClientError("operator transport timed out") from error

    def error_message(self, return_code: int) -> str:
        self._drain_stderr()
        return self.stderr.decode("utf-8", errors="replace").strip() or (
            f"ssh_status_{return_code}"
        )

    def _wait(self, *, read: bool = False, write: bool = False) -> None:
        while True:
            readable_descriptors = [self.stdout_fd] if read else []
            if self.stderr_open:
                readable_descriptors.append(self.stderr_fd)
            readable, writable, _ = select.select(
                readable_descriptors,
                [self.stdin_fd] if write else [],
                [],
                self.deadline.timeout(),
            )
            if self.stderr_fd in readable and self._drain_stderr():
                self.deadline.progress()
            if (read and self.stdout_fd in readable) or (write and self.stdin_fd in writable):
                return
            if self.process.poll() is not None:
                return

    def _drain_stderr(self) -> bool:
        made_progress = False
        while True:
            try:
                chunk = os.read(self.stderr_fd, _CHUNK_BYTES)
            except BlockingIOError:
                return made_progress
            if not chunk:
                self.stderr_open = False
                return made_progress
            made_progress = True
            available = _ERROR_BYTES - len(self.stderr)
            if available > 0:
                self.stderr.extend(chunk[:available])


@dataclass(slots=True)
class _PendingExport:
    directory_fd: int
    file_descriptor: int
    temporary_name: str
    destination_name: str
    renamed: bool = False
    closed: bool = False

    @classmethod
    def create(cls, destination: Path) -> _PendingExport:
        if destination.name in {"", ".", ".."}:
            raise OperatorClientError("operator export destination is invalid")
        directory_fd = os.open(destination.parent or Path(), _DIRECTORY_FLAGS)
        temporary_name = f".ldp-export-{secrets.token_hex(16)}"
        try:
            try:
                os.stat(destination.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(errno.EEXIST, "export destination exists", destination)
            file_descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
        except BaseException:
            os.close(directory_fd)
            raise
        return cls(directory_fd, file_descriptor, temporary_name, destination.name)

    def commit(self) -> None:
        self._close_file()
        try:
            _rename_no_replace(
                self.directory_fd,
                self.temporary_name,
                self.destination_name,
            )
            self.renamed = True
            os.fsync(self.directory_fd)
        except BaseException:
            self.cleanup()
            raise
        os.close(self.directory_fd)
        self.closed = True

    def cleanup(self) -> None:
        if self.closed:
            return
        self._close_file()
        name = self.destination_name if self.renamed else self.temporary_name
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=self.directory_fd)
        os.fsync(self.directory_fd)
        os.close(self.directory_fd)
        self.closed = True

    def _close_file(self) -> None:
        if self.file_descriptor >= 0:
            os.close(self.file_descriptor)
            self.file_descriptor = -1


def submit(  # noqa: PLR0912,PLR0913,PLR0915 - explicit trusted-workstation boundaries
    *,
    host: str,
    identity_path: Path,
    request_path: Path,
    artifact_path: Path | None = None,
    export_path: Path | None = None,
    ssh_executable: Path = Path("/usr/bin/ssh"),
) -> dict[str, object]:
    """Submit one canonical operation and return its terminal result."""

    _validate_host(host)
    _validate_identity(identity_path)
    raw_request = _read_stable(request_path, maximum_bytes=MAX_RAW_REQUEST_BYTES)
    request = decode_request(raw_request)
    canonical_request = canonical_json_bytes(request)
    artifact = _open_artifact(request, artifact_path)
    pending_export: _PendingExport | None = None
    try:
        process = subprocess.Popen(  # noqa: S603
            [
                os.fspath(ssh_executable),
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "RequestTTY=no",
                "-o",
                "ConnectTimeout=15",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-i",
                os.fspath(identity_path),
                f"ldp-operator@{host}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        channel = _ProcessChannel(process)
        try:
            channel.write(
                encode_header(
                    FrameHeader(
                        FrameKind.REQUEST,
                        len(canonical_request),
                        artifact.size if artifact is not None else None,
                    )
                )
            )
            channel.write(canonical_request)
            if artifact is not None:
                _copy_artifact(artifact, channel)
            channel.close_input()
            channel.begin_result_wait()
            response_header = channel.read_exact(HEADER_SIZE)
            if len(response_header) != HEADER_SIZE:
                return_code = channel.wait()
                raise OperatorClientError(
                    f"operator transport failed: {channel.error_message(return_code)}"
                )
            channel.begin_response_transfer()
            header = decode_header(response_header, expected_kind=FrameKind.RESPONSE)
            raw_result = channel.read_exact(header.document_length)
            if len(raw_result) != header.document_length:
                raise OperatorClientError("operator response ended before its declared result")
            result = decode_result(raw_result)
            if canonical_json_bytes(result) != raw_result:
                raise OperatorClientError("operator result is not canonical")
            if (
                result["correlationId"] != request["correlationId"]
                or result["operation"] != request["operation"]
            ):
                raise OperatorClientError("operator result does not match the submitted request")
            pending_export = _receive_export(
                channel,
                header.payload_length,
                export_path,
                result=result,
            )
            channel.require_output_eof()
            return_code = channel.wait()
            if return_code != 0:
                raise OperatorClientError(
                    f"operator transport failed: {channel.error_message(return_code)}"
                )
            if pending_export is not None:
                pending_export.commit()
            return result
        except BaseException:
            if pending_export is not None:
                pending_export.cleanup()
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    finally:
        if artifact is not None:
            os.close(artifact.file_descriptor)


def _validate_host(host: object) -> None:
    if (
        type(host) is not str
        or _HOSTNAME.fullmatch(host) is None
        or ".." in host
        or host.startswith("-")
    ):
        raise OperatorClientError("operator host is invalid")


def _validate_identity(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
    ):
        raise OperatorClientError("operator identity must be one private regular file")


def _read_stable(path: Path, *, maximum_bytes: int) -> bytes:
    file_descriptor = os.open(path, _READ_FLAGS)
    try:
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OperatorClientError("operator input must be one regular file")
        data = os.read(file_descriptor, maximum_bytes + 1)
        if len(data) > maximum_bytes or os.read(file_descriptor, 1):
            raise OperatorClientError("operator request exceeds its raw byte ceiling")
        after = os.fstat(file_descriptor)
        if _generation(before) != _generation(after) or len(data) != after.st_size:
            raise OperatorClientError("operator request changed while it was read")
        return data
    finally:
        os.close(file_descriptor)


def _open_artifact(
    request: dict[str, object],
    artifact_path: Path | None,
) -> _ArtifactSource | None:
    declared = request.get("artifact")
    if type(declared) is not dict:
        if artifact_path is not None:
            raise OperatorClientError("operation does not accept an artifact")
        return None
    if artifact_path is None:
        raise OperatorClientError("operation requires an artifact")
    file_descriptor = os.open(artifact_path, _READ_FLAGS)
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OperatorClientError("operator artifact must be one regular file")
        if metadata.st_size != declared["size"]:
            raise OperatorClientError("operator artifact size does not match the request")
        digest = _hash_descriptor(file_descriptor)
        if digest != declared["sha256"]:
            raise OperatorClientError("operator artifact digest does not match the request")
        after = os.fstat(file_descriptor)
        if _generation(metadata) != _generation(after):
            raise OperatorClientError("operator artifact changed while it was verified")
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        return _ArtifactSource(
            file_descriptor=file_descriptor,
            size=metadata.st_size,
            sha256=digest,
            generation=_generation(metadata),
        )
    except BaseException:
        os.close(file_descriptor)
        raise


def _copy_artifact(source: _ArtifactSource, channel: _ProcessChannel) -> None:
    before = os.fstat(source.file_descriptor)
    if _generation(before) != source.generation:
        raise OperatorClientError("operator artifact changed before transmission")
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(source.file_descriptor, _CHUNK_BYTES):
        channel.write(chunk)
        digest.update(chunk)
        total += len(chunk)
    after = os.fstat(source.file_descriptor)
    if _generation(after) != source.generation or total != source.size:
        raise OperatorClientError("operator artifact changed during transmission")
    if digest.hexdigest() != source.sha256:
        raise OperatorClientError("operator artifact changed during transmission")


def _hash_descriptor(file_descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(file_descriptor, _CHUNK_BYTES):
        digest.update(chunk)
    return digest.hexdigest()


def _receive_export(
    channel: _ProcessChannel,
    byte_count: int | None,
    destination: Path | None,
    *,
    result: dict[str, object],
) -> _PendingExport | None:
    bundle = result.get("exportBundle")
    if type(bundle) is not dict:
        if byte_count is not None:
            raise OperatorClientError("non-export result contains an export payload")
        return None
    if byte_count is None or byte_count != bundle["size"]:
        raise OperatorClientError("operator export length does not match its result")
    if destination is None:
        raise OperatorClientError("operation returned an export without a destination")
    pending = _PendingExport.create(destination)
    try:
        digest = hashlib.sha256()
        remaining = byte_count
        while remaining:
            chunk = channel.read_exact(min(remaining, _CHUNK_BYTES))
            if not chunk:
                raise OperatorClientError("operator export ended before its declared length")
            _write_all(pending.file_descriptor, chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        os.fsync(pending.file_descriptor)
        binding = bundle["digest"]
        if type(binding) is not dict or digest.hexdigest() != binding["value"]:
            raise OperatorClientError("operator export digest does not match its result")
    except BaseException:
        pending.cleanup()
        raise
    return pending


def _generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(file_descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(file_descriptor, remaining)
        if written <= 0:
            raise OperatorClientError("operator export write made no progress")
        remaining = remaining[written:]


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            directory_fd,
            os.fsencode(source),
            directory_fd,
            os.fsencode(destination),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def print_result(result: dict[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(result))
