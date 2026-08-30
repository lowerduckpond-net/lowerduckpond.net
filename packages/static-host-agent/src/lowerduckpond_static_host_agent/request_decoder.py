"""Resource-isolated structured decoding for authenticated operator requests."""

from __future__ import annotations

import os
import resource
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    MAX_RAW_REQUEST_BYTES,
    ContractError,
    canonical_json_bytes,
    decode_request,
)

_HELPER_TIMEOUT_SECONDS: Final = 15.0
_MAXIMUM_ADDRESS_SPACE: Final = 128 * 1024 * 1024
_MAXIMUM_OPEN_FILES: Final = 16
_MAXIMUM_CPU_SECONDS: Final = 2


class RequestDecodeError(RuntimeError):
    """The isolated request decoder rejected or failed to bound its output."""


class RequestDecoder(Protocol):
    def decode(self, raw_request: bytes) -> tuple[bytes, dict[str, object]]: ...


class LocalRequestDecoder:
    """Hermetic decoder for tests that do not cross the installed process boundary."""

    def decode(self, raw_request: bytes) -> tuple[bytes, dict[str, object]]:
        request = decode_request(raw_request)
        return canonical_json_bytes(request), request


class SubprocessRequestDecoder:
    """Invoke one fixed root-owned helper with no caller path or environment."""

    def __init__(self, executable: Path) -> None:
        if not executable.is_absolute():
            raise ValueError("request decoder executable must be an absolute path")
        self._executable = executable

    def decode(self, raw_request: bytes) -> tuple[bytes, dict[str, object]]:
        if type(raw_request) is not bytes or len(raw_request) > MAX_RAW_REQUEST_BYTES:
            raise RequestDecodeError("request_too_large")
        try:
            # The constructor accepts only one absolute, administrator-selected
            # executable and passes no peer-controlled argument or environment.
            process = subprocess.Popen(  # noqa: S603
                [os.fspath(self._executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd="/",
                env={},
            )
            canonical = _bounded_exchange(process, raw_request)
        except OSError as error:
            raise RequestDecodeError("request_decoder_failed") from error
        if process.returncode != 0:
            raise RequestDecodeError("request_invalid")
        if not canonical or len(canonical) > MAX_CANONICAL_BYTES:
            raise RequestDecodeError("request_decoder_failed")
        try:
            request = decode_request(canonical)
        except ContractError as error:
            raise RequestDecodeError("request_decoder_failed") from error
        if canonical_json_bytes(request) != canonical:
            raise RequestDecodeError("request_decoder_failed")
        return canonical, request


def _bounded_exchange(  # noqa: PLR0912 - duplex process I/O is one bounded state machine
    process: subprocess.Popen[bytes], raw_request: bytes
) -> bytes:
    """Exchange one bounded document without ever buffering unbounded output."""

    if process.stdin is None or process.stdout is None:  # pragma: no cover - PIPE contract
        raise RequestDecodeError("request_decoder_failed")
    input_fd = process.stdin.fileno()
    output_fd = process.stdout.fileno()
    os.set_blocking(input_fd, False)
    os.set_blocking(output_fd, False)
    deadline = time.monotonic() + _HELPER_TIMEOUT_SECONDS
    sent = 0
    output = bytearray()
    output_eof = False
    if not raw_request:
        process.stdin.close()
    try:
        while not output_eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RequestDecodeError("request_decoder_failed")
            readable, writable, _ = select.select(
                [output_fd],
                [input_fd] if sent < len(raw_request) else [],
                [],
                remaining,
            )
            if input_fd in writable:
                written = os.write(input_fd, raw_request[sent:])
                if written <= 0:  # pragma: no cover - defensive kernel boundary
                    raise RequestDecodeError("request_decoder_failed")
                sent += written
                if sent == len(raw_request):
                    process.stdin.close()
            if output_fd in readable:
                chunk = os.read(output_fd, MAX_CANONICAL_BYTES + 1 - len(output))
                if not chunk:
                    output_eof = True
                else:
                    output.extend(chunk)
                    if len(output) > MAX_CANONICAL_BYTES:
                        raise RequestDecodeError("request_decoder_failed")
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return bytes(output)
    except (BrokenPipeError, subprocess.TimeoutExpired) as error:
        raise RequestDecodeError("request_decoder_failed") from error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def decoder_main() -> int:
    """Run the fixed, resource-limited helper protocol on stdin/stdout."""

    os.chdir("/")
    os.umask(0o077)
    os.environ.clear()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (_MAXIMUM_CPU_SECONDS, _MAXIMUM_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_NOFILE, (_MAXIMUM_OPEN_FILES, _MAXIMUM_OPEN_FILES))
    resource.setrlimit(resource.RLIMIT_AS, (_MAXIMUM_ADDRESS_SPACE, _MAXIMUM_ADDRESS_SPACE))
    raw = sys.stdin.buffer.read(MAX_RAW_REQUEST_BYTES + 1)
    if len(raw) > MAX_RAW_REQUEST_BYTES:
        return _fail("request_too_large")
    try:
        request = decode_request(raw)
        canonical = canonical_json_bytes(request)
    except ContractError:
        return _fail("request_invalid")
    if len(canonical) > MAX_CANONICAL_BYTES:
        return _fail("request_too_large")
    sys.stdout.buffer.write(canonical)
    sys.stdout.buffer.flush()
    return 0


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 65
