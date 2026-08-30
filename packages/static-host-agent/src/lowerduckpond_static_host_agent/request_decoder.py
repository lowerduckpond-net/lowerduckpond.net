"""Resource-isolated structured decoding for authenticated operator requests."""

from __future__ import annotations

import os
import resource
import subprocess
import sys
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
            completed = subprocess.run(  # noqa: S603
                [os.fspath(self._executable)],
                input=raw_request,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                close_fds=True,
                cwd="/",
                env={},
                timeout=_HELPER_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RequestDecodeError("request_decoder_failed") from error
        if completed.returncode != 0:
            raise RequestDecodeError("request_invalid")
        canonical = completed.stdout
        if not canonical or len(canonical) > MAX_CANONICAL_BYTES:
            raise RequestDecodeError("request_decoder_failed")
        try:
            request = decode_request(canonical)
        except ContractError as error:
            raise RequestDecodeError("request_decoder_failed") from error
        if canonical_json_bytes(request) != canonical:
            raise RequestDecodeError("request_decoder_failed")
        return canonical, request


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
