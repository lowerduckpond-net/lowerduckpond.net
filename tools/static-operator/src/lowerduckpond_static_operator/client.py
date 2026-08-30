"""Bounded local-file and SSH transport for the static operator protocol."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import IO, Final

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
_CHUNK_BYTES: Final = 64 * 1024
_ERROR_BYTES: Final = 4096


class OperatorClientError(RuntimeError):
    """Local input or the authenticated SSH response violated the protocol."""


def submit(  # noqa: PLR0913 - each path is an explicit trusted-workstation boundary
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
    artifact_fd, artifact_size = _open_artifact(request, artifact_path)
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
                "-i",
                os.fspath(identity_path),
                f"ldp-operator@{host}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("SSH process pipes were not created")  # pragma: no cover
        try:
            process.stdin.write(
                encode_header(
                    FrameHeader(
                        FrameKind.REQUEST,
                        len(canonical_request),
                        artifact_size,
                    )
                )
            )
            process.stdin.write(canonical_request)
            if artifact_fd is not None:
                _copy_artifact(artifact_fd, process.stdin)
            process.stdin.close()
            response_header = _read_exact(process.stdout, HEADER_SIZE)
            if len(response_header) != HEADER_SIZE:
                return_code = process.wait()
                remote_error = process.stderr.read(_ERROR_BYTES).decode("utf-8", errors="replace")
                message = remote_error.strip() or f"ssh_status_{return_code}"
                raise OperatorClientError(f"operator transport failed: {message}")
            header = decode_header(response_header, expected_kind=FrameKind.RESPONSE)
            raw_result = _read_exact(process.stdout, header.document_length)
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
            _receive_export(
                process.stdout,
                header.payload_length,
                export_path,
                result=result,
            )
            if process.stdout.read(1):
                raise OperatorClientError("operator response contains trailing bytes")
            return_code = process.wait()
            if return_code != 0:
                raise OperatorClientError(f"operator transport failed: ssh_status_{return_code}")
            return result
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    finally:
        if artifact_fd is not None:
            os.close(artifact_fd)


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
) -> tuple[int | None, int | None]:
    declared = request.get("artifact")
    if type(declared) is not dict:
        if artifact_path is not None:
            raise OperatorClientError("operation does not accept an artifact")
        return None, None
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
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        return file_descriptor, metadata.st_size
    except BaseException:
        os.close(file_descriptor)
        raise


def _copy_artifact(file_descriptor: int, destination: IO[bytes]) -> None:
    before = os.fstat(file_descriptor)
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(file_descriptor, _CHUNK_BYTES):
        destination.write(chunk)
        digest.update(chunk)
        total += len(chunk)
    after = os.fstat(file_descriptor)
    if _generation(before) != _generation(after) or total != after.st_size:
        raise OperatorClientError("operator artifact changed during transmission")
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    if digest.hexdigest() != _hash_descriptor(file_descriptor):
        raise OperatorClientError("operator artifact changed during transmission")


def _hash_descriptor(file_descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(file_descriptor, _CHUNK_BYTES):
        digest.update(chunk)
    return digest.hexdigest()


def _receive_export(
    source: IO[bytes],
    byte_count: int | None,
    destination: Path | None,
    *,
    result: dict[str, object],
) -> None:
    bundle = result.get("exportBundle")
    if type(bundle) is not dict:
        if byte_count is not None:
            raise OperatorClientError("non-export result contains an export payload")
        if destination is not None:
            raise OperatorClientError("operation returned no export")
        return
    if byte_count is None or byte_count != bundle["size"]:
        raise OperatorClientError("operator export length does not match its result")
    if destination is None:
        raise OperatorClientError("operation returned an export without a destination")
    digest = hashlib.sha256()
    file_descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        remaining = byte_count
        while remaining:
            chunk = source.read(min(remaining, _CHUNK_BYTES))
            if not chunk:
                raise OperatorClientError("operator export ended before its declared length")
            _write_all(file_descriptor, chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        os.fsync(file_descriptor)
        binding = bundle["digest"]
        if type(binding) is not dict or digest.hexdigest() != binding["value"]:
            raise OperatorClientError("operator export digest does not match its result")
    except BaseException:
        os.close(file_descriptor)
        destination.unlink(missing_ok=True)
        raise
    os.close(file_descriptor)


def _read_exact(source: IO[bytes], byte_count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = byte_count
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


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


def print_result(result: dict[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(result))
