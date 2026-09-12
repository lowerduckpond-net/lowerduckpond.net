from __future__ import annotations

import array
import os
import socket
import struct
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryFile

import pytest
from lowerduckpond_static_host_agent import LockManager, LockMode, LockName, StateBusyError
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_REQUEST_BYTES,
    ArchiveChannel,
    ArchiveTransportError,
)

_HEADER = struct.Struct("!8sIB")
_MAGIC = b"LDPARC1\0"


def _channel(stream: socket.socket, *, limit: int = MAX_ARCHIVE_REQUEST_BYTES) -> ArchiveChannel:
    return ArchiveChannel(
        stream,
        expected_peer_uid=os.geteuid(),
        maximum_receive_bytes=limit,
        timeout=1.0,
    )


@pytest.fixture
def raw_peer() -> Iterator[tuple[socket.socket, ArchiveChannel]]:
    sender, receiver = socket.socketpair()
    with sender, _channel(receiver) as channel:
        yield sender, channel


def _fd_count() -> int:
    return len(tuple(Path("/proc/self/fd").iterdir()))


def _rights(*descriptors: int) -> list[tuple[int, int, array.array[int]]]:
    return [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))]


def test_private_channel_rejects_a_different_peer_owner() -> None:
    sender, receiver = socket.socketpair()
    with sender, pytest.raises(ArchiveTransportError, match="owner"):
        ArchiveChannel(
            receiver,
            expected_peer_uid=os.geteuid() + 1,
            maximum_receive_bytes=MAX_ARCHIVE_REQUEST_BYTES,
        )
    assert receiver.fileno() == -1


def test_private_channel_rejects_non_unix_transport() -> None:
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(ArchiveTransportError, match="Unix"):
        _channel(stream)
    assert stream.fileno() == -1


def test_private_channel_preserves_message_boundaries_and_canonical_metadata() -> None:
    first, second = socket.socketpair()
    with _channel(first) as sender, _channel(second) as receiver:
        sender.send({"operation": "begin", "version": 1})
        sender.send({"operation": "inventory"})
        with receiver.receive() as message:
            assert message.payload == {"operation": "begin", "version": 1}
            assert message.descriptor is None
        with receiver.receive() as message:
            assert message.payload == {"operation": "inventory"}


def test_private_channel_transfers_a_noninheritable_descriptor() -> None:
    first, second = socket.socketpair()
    with TemporaryFile() as source, _channel(first) as sender, _channel(second) as receiver:
        source.write(b"private descriptor contents")
        source.seek(0)
        sender.send({"operation": "upload"}, descriptor=source.fileno())
        with receiver.receive() as message:
            assert message.descriptor is not None
            received = message.descriptor
            assert not os.get_inheritable(received)
            assert os.fstat(received).st_ino == os.fstat(source.fileno()).st_ino
            assert os.read(received, 64) == b"private descriptor contents"
        with pytest.raises(OSError):
            os.fstat(received)
        source.seek(0)
        assert source.read() == b"private descriptor contents"


def test_queued_and_received_export_leases_keep_exclusion(tmp_path: Path) -> None:
    first, second = socket.socketpair()
    with (
        LockManager.initialize(tmp_path, expected_owner=os.geteuid()) as owner,
        LockManager(tmp_path, expected_owner=os.geteuid()) as receiver_locks,
        _channel(first) as sender,
        _channel(second) as receiver,
    ):
        with owner.acquire(LockName.EXPORT):
            lease = owner.duplicate_export_descriptor()
            try:
                sender.send({"operation": "begin"}, descriptor=lease)
            finally:
                os.close(lease)
        # The in-flight SCM_RIGHTS reference itself retains the lock.
        with pytest.raises(StateBusyError), owner.acquire(LockName.EXPORT):
            pass
        with receiver.receive() as message:
            assert message.descriptor is not None
            with receiver_locks.borrow_export_descriptor(message.descriptor):
                receiver_locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
            with pytest.raises(StateBusyError), owner.acquire(LockName.EXPORT):
                pass
        with owner.acquire(LockName.EXPORT):
            pass


@pytest.mark.parametrize(
    "encoded",
    [b'{"x":1,"x":2}\n', b'{"x":1}', b'{ "x": 1 }\n', b"[]\n", b'{"x":NaN}\n', b"\xff"],
)
def test_private_channel_rejects_malformed_or_noncanonical_metadata(
    raw_peer: tuple[socket.socket, ArchiveChannel], encoded: bytes
) -> None:
    sender, receiver = raw_peer
    sender.sendall(_HEADER.pack(_MAGIC, len(encoded), 0) + encoded)
    with pytest.raises(ArchiveTransportError):
        receiver.receive()
    assert sender.recv(1) == b""


@pytest.mark.parametrize("length", [0, MAX_ARCHIVE_REQUEST_BYTES + 1, 2**32 - 1])
def test_private_channel_rejects_size_before_reading_payload(
    raw_peer: tuple[socket.socket, ArchiveChannel], length: int
) -> None:
    sender, receiver = raw_peer
    sender.sendall(_HEADER.pack(_MAGIC, length, 0))
    with pytest.raises(ArchiveTransportError, match="header"):
        receiver.receive()


@pytest.mark.parametrize("fragment", [b"", _MAGIC[:3], _HEADER.pack(_MAGIC, 10, 0) + b"{}"])
def test_private_channel_rejects_eof_at_each_frame_section(
    raw_peer: tuple[socket.socket, ArchiveChannel], fragment: bytes
) -> None:
    sender, receiver = raw_peer
    sender.sendall(fragment)
    sender.shutdown(socket.SHUT_WR)
    with pytest.raises(ArchiveTransportError):
        receiver.receive()


@pytest.mark.parametrize("sent_descriptors", [0, 2, 8])
def test_private_channel_closes_mismatched_or_truncated_descriptor_envelopes(
    raw_peer: tuple[socket.socket, ArchiveChannel], sent_descriptors: int
) -> None:
    sender, receiver = raw_peer
    with TemporaryFile() as source:
        before = _fd_count()
        sender.sendmsg(
            [_HEADER.pack(_MAGIC, 3, 1) + b"{}\n"],
            _rights(*([source.fileno()] * sent_descriptors)) if sent_descriptors else [],
        )
        with pytest.raises(ArchiveTransportError):
            receiver.receive()
        assert _fd_count() == before - 1  # only the rejected channel was closed
        assert source.fileno() >= 0


def test_private_channel_closes_descriptor_when_payload_is_incomplete(
    raw_peer: tuple[socket.socket, ArchiveChannel],
) -> None:
    sender, receiver = raw_peer
    with TemporaryFile() as source:
        before = _fd_count()
        sender.sendmsg([_HEADER.pack(_MAGIC, 10, 1) + b"{}"], _rights(source.fileno()))
        sender.shutdown(socket.SHUT_WR)
        with pytest.raises(ArchiveTransportError):
            receiver.receive()
        assert _fd_count() == before - 1


def test_private_channel_rejects_a_descriptor_attached_to_payload(
    raw_peer: tuple[socket.socket, ArchiveChannel],
) -> None:
    sender, receiver = raw_peer
    with TemporaryFile() as source:
        before = _fd_count()
        sender.sendall(_HEADER.pack(_MAGIC, 3, 0))
        sender.sendmsg([b"{}\n"], _rights(source.fileno()))
        with pytest.raises(ArchiveTransportError, match="outside"):
            receiver.receive()
        assert _fd_count() == before - 1


def test_private_channel_accepts_fragmented_header_and_metadata(
    raw_peer: tuple[socket.socket, ArchiveChannel],
) -> None:
    sender, receiver = raw_peer
    encoded = b'{"operation":"inventory"}\n'
    frame = _HEADER.pack(_MAGIC, len(encoded), 0) + encoded

    def transmit() -> None:
        for byte in frame:
            sender.sendall(bytes([byte]))

    with ThreadPoolExecutor(max_workers=1) as pool:
        sent = pool.submit(transmit)
        with receiver.receive() as message:
            assert message.payload == {"operation": "inventory"}
        sent.result(timeout=5)
