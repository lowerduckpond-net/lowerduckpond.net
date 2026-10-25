"""Read an entire bounded protocol frame under one nonrenewing deadline."""

from __future__ import annotations

import json
import os
import select
import time
from typing import BinaryIO

from scripts.m3_11_retirement_files import RetirementError

FRAME_BYTES = 1024 * 1024


def send(stream: BinaryIO, value: dict[str, object], *, deadline: float) -> None:
    """A stalled peer cannot extend the deadline by refusing its next frame."""
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(raw) > FRAME_BYTES:
        raise RetirementError("retirement request exceeded its frame bound")
    descriptor = stream.fileno()
    blocking = os.get_blocking(descriptor)
    os.set_blocking(descriptor, False)
    try:
        view = memoryview(raw)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [stream], [], remaining)[1]:
                raise TimeoutError("retirement frame submission budget ended; outcome unresolved")
            try:
                written = os.write(descriptor, view)
            except BlockingIOError:
                continue
            if not written:
                raise RetirementError("retirement peer stopped accepting its frame")
            view = view[written:]
    finally:
        os.set_blocking(descriptor, blocking)


def frame(stream: BinaryIO, *, deadline: float) -> dict[str, object]:
    """Bound every byte, including a child that never terminates a JSON line."""
    data = bytearray()
    while len(data) <= FRAME_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError("retirement observation budget ended; outcome unresolved")
        block = os.read(stream.fileno(), 1)
        if not block:
            raise RetirementError("retirement child ended before its complete result")
        data += block
        if block == b"\n":
            value = json.loads(data)
            if not isinstance(value, dict):
                raise RetirementError("retirement response is not a bounded object")
            return value
    raise RetirementError("retirement response exceeded its frame bound")
