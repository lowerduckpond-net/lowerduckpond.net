from __future__ import annotations

import os
from contextlib import closing

import pytest
from lowerduckpond_static_host_agent import (
    DeadlineReader,
    ReadDeadline,
    StreamError,
    StreamTimeoutError,
)


def _deadline(seconds: float = 1.0) -> ReadDeadline:
    return ReadDeadline.start(total_seconds=seconds, idle_seconds=seconds)


def test_reader_consumes_exact_bytes_and_requires_eof() -> None:
    read_fd, write_fd = os.pipe()
    with (
        closing(os.fdopen(read_fd, "rb", closefd=True)),
        closing(os.fdopen(write_fd, "wb", closefd=True)) as writer,
    ):
        writer.write(b"request")
        writer.close()
        reader = DeadlineReader(read_fd)

        assert reader.read_exact(7, deadline=_deadline()) == b"request"
        reader.require_eof(deadline=_deadline())


@pytest.mark.parametrize("payload", [b"short", b""])
def test_reader_rejects_early_eof(payload: bytes) -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(StreamError, match="unexpected_eof"):
            DeadlineReader(read_fd).read_exact(len(payload) + 1, deadline=_deadline())
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_reader_rejects_trailing_byte() -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"ab")
        os.close(write_fd)
        write_fd = -1
        reader = DeadlineReader(read_fd)
        assert reader.read_exact(1, deadline=_deadline()) == b"a"
        with pytest.raises(StreamError, match="trailing_bytes"):
            reader.require_eof(deadline=_deadline())
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_reader_fails_closed_when_peer_stalls() -> None:
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(StreamTimeoutError, match="read_timeout"):
            DeadlineReader(read_fd).read_exact(
                1,
                deadline=ReadDeadline.start(total_seconds=0.01, idle_seconds=0.01),
            )
    finally:
        os.close(read_fd)
        os.close(write_fd)
