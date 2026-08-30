"""Monotonic, exact-length reads for the root-owned operator adapter."""

from __future__ import annotations

import os
import select
import time
from dataclasses import dataclass
from typing import Final, Protocol

_MAX_READ_CHUNK: Final = 64 * 1024


class StreamError(RuntimeError):
    """The operator byte stream violated its exact framing contract."""


class StreamTimeoutError(StreamError):
    """The peer crossed an idle or total monotonic deadline."""


class MonotonicClock(Protocol):
    def __call__(self) -> float: ...


@dataclass(frozen=True, slots=True)
class ReadDeadline:
    """One absolute total deadline plus a per-progress idle ceiling."""

    expires_at: float
    idle_seconds: float

    @classmethod
    def start(
        cls,
        *,
        total_seconds: float,
        idle_seconds: float,
        clock: MonotonicClock = time.monotonic,
    ) -> ReadDeadline:
        if total_seconds <= 0 or idle_seconds <= 0:
            raise ValueError("read deadlines must be positive")
        return cls(clock() + total_seconds, idle_seconds)


class DeadlineReader:
    """Read one descriptor without buffering past an authorized frame."""

    def __init__(
        self,
        file_descriptor: int,
        *,
        clock: MonotonicClock = time.monotonic,
    ) -> None:
        if type(file_descriptor) is not int or file_descriptor < 0:
            raise ValueError("stream descriptor must be nonnegative")
        self._file_descriptor = file_descriptor
        self._clock = clock

    def read_exact(self, byte_count: int, *, deadline: ReadDeadline) -> bytes:
        """Read exactly the declared bytes or fail on EOF/deadline."""

        if type(byte_count) is not int or byte_count < 0:
            raise ValueError("stream byte count must be nonnegative")
        chunks: list[bytes] = []
        remaining = byte_count
        last_progress = self._clock()
        while remaining:
            now = self._clock()
            timeout = min(deadline.expires_at - now, deadline.idle_seconds - (now - last_progress))
            if timeout <= 0:
                raise StreamTimeoutError("read_timeout")
            readable, _, _ = select.select([self._file_descriptor], [], [], timeout)
            if not readable:
                raise StreamTimeoutError("read_timeout")
            chunk = os.read(self._file_descriptor, min(remaining, _MAX_READ_CHUNK))
            if not chunk:
                raise StreamError("unexpected_eof")
            chunks.append(chunk)
            remaining -= len(chunk)
            last_progress = self._clock()
        return b"".join(chunks)

    def require_eof(self, *, deadline: ReadDeadline) -> None:
        """Reject any byte following the one complete declared frame."""

        now = self._clock()
        timeout = min(deadline.expires_at - now, deadline.idle_seconds)
        if timeout <= 0:
            raise StreamTimeoutError("read_timeout")
        readable, _, _ = select.select([self._file_descriptor], [], [], timeout)
        if not readable:
            raise StreamTimeoutError("read_timeout")
        if os.read(self._file_descriptor, 1):
            raise StreamError("trailing_bytes")
