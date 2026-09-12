"""Bounded root-peer framing for the archive service's descriptor transport.

This layer authenticates the Unix peer and carries one optional descriptor per
canonical message. It grants no job, path, credential, or remote-object authority;
the service must independently derive that authority from durable state.
"""

from __future__ import annotations

import array
import math
import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Final, Self

from lowerduckpond_static_contracts import (
    ContractError,
    canonical_json_bytes,
    decode_json_object,
)

MAX_ARCHIVE_REQUEST_BYTES: Final = 16 * 1024
MAX_ARCHIVE_RESPONSE_BYTES: Final = 1024 * 1024
_MAXIMUM_TIMEOUT: Final = 300.0
_MAGIC: Final = b"LDPARC1\0"
_HEADER: Final = struct.Struct("!8sIB")
_PEER_CREDENTIALS: Final = struct.Struct("=3i")
_DESCRIPTOR_BYTES: Final = array.array("i").itemsize


class ArchiveTransportError(RuntimeError):
    """A private archive session failed its peer or framing contract."""


@dataclass(slots=True)
class ArchiveMessage:
    """Own the received descriptor until its exact operation has finished."""

    payload: dict[str, object]
    descriptor: int | None = field(default=None, repr=False)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    def close(self) -> None:
        if self.descriptor is not None:
            descriptor, self.descriptor = self.descriptor, None
            os.close(descriptor)


class ArchiveChannel:
    """One authenticated stream; malformed or interrupted frames close it."""

    def __init__(
        self,
        stream: socket.socket,
        *,
        expected_peer_uid: int,
        maximum_receive_bytes: int,
        timeout: float = _MAXIMUM_TIMEOUT,
    ) -> None:
        self._stream = stream
        try:
            if (
                type(maximum_receive_bytes) is not int
                or not 0 < maximum_receive_bytes <= MAX_ARCHIVE_RESPONSE_BYTES
                or not math.isfinite(timeout)
                or not 0 < timeout <= _MAXIMUM_TIMEOUT
            ):
                raise ArchiveTransportError("archive channel bounds are invalid")
            if (
                stream.family != socket.AF_UNIX
                or stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            ):
                raise ArchiveTransportError("archive channel requires a Unix stream")
            credentials = stream.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size
            )
            pid, uid, _gid = _PEER_CREDENTIALS.unpack(credentials)
            if pid <= 0 or uid != expected_peer_uid:
                raise ArchiveTransportError("archive channel peer is not its expected owner")
            stream.settimeout(timeout)
        except BaseException:
            stream.close()
            raise
        self._maximum_receive_bytes = maximum_receive_bytes

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    def close(self) -> None:
        self._stream.close()

    def send(self, payload: dict[str, object], *, descriptor: int | None = None) -> None:
        """Transmit metadata and explicitly lend a descriptor without closing it."""

        try:
            if type(payload) is not dict or (
                descriptor is not None and (type(descriptor) is not int or descriptor < 0)
            ):
                raise ArchiveTransportError("archive message inputs are invalid")
            encoded = canonical_json_bytes(payload, maximum_bytes=MAX_ARCHIVE_RESPONSE_BYTES)
            header = _HEADER.pack(_MAGIC, len(encoded), int(descriptor is not None))
            ancillary = (
                []
                if descriptor is None
                else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))]
            )
            sent = self._stream.sendmsg([header], ancillary)
            if sent <= 0:
                raise ArchiveTransportError("archive header transmission was interrupted")
            self._stream.sendall(header[sent:])
            self._stream.sendall(encoded)
        except BaseException:
            self.close()
            raise

    def receive(self) -> ArchiveMessage:
        """Reject size before allocation; close every received descriptor on error."""

        descriptors: list[int] = []
        try:
            first, ancillary, flags, _address = self._stream.recvmsg(
                1, socket.CMSG_SPACE(_DESCRIPTOR_BYTES), socket.MSG_CMSG_CLOEXEC
            )
            valid_ancillary = _collect_descriptors(ancillary, descriptors)
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or not valid_ancillary:
                raise ArchiveTransportError("archive descriptor envelope is invalid")
            if not first:
                raise ArchiveTransportError("archive session ended before a complete frame")
            header = first + self._read_exact(_HEADER.size - 1)
            magic, length, has_descriptor = _HEADER.unpack(header)
            if (
                magic != _MAGIC
                or has_descriptor not in {0, 1}
                or len(descriptors) != has_descriptor
                or not 0 < length <= self._maximum_receive_bytes
            ):
                raise ArchiveTransportError("archive frame header is invalid")
            encoded = self._read_exact(length)
            payload = _decode_payload(encoded, maximum_bytes=self._maximum_receive_bytes)
            message = ArchiveMessage(payload, descriptors[0] if descriptors else None)
            descriptors.clear()
            return message
        except BaseException:
            self.close()
            raise
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def _read_exact(self, size: int) -> bytes:
        payload = bytearray()
        while len(payload) < size:
            part, ancillary, flags, _address = self._stream.recvmsg(
                min(size - len(payload), 64 * 1024),
                socket.CMSG_SPACE(_DESCRIPTOR_BYTES),
                socket.MSG_CMSG_CLOEXEC,
            )
            descriptors: list[int] = []
            try:
                _collect_descriptors(ancillary, descriptors)
                if ancillary or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                    raise ArchiveTransportError("archive descriptor arrived outside its header")
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
            if not part:
                raise ArchiveTransportError("archive frame transmission was interrupted")
            payload.extend(part)
        return bytes(payload)


def _collect_descriptors(ancillary: list[tuple[int, int, bytes]], descriptors: list[int]) -> bool:
    valid = True
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            valid = False
            continue
        if len(data) % _DESCRIPTOR_BYTES:
            valid = False
        received = array.array("i")
        received.frombytes(data[: len(data) - len(data) % _DESCRIPTOR_BYTES])
        descriptors.extend(received)
    return valid


def _decode_payload(encoded: bytes, *, maximum_bytes: int) -> dict[str, object]:
    try:
        payload = decode_json_object(encoded, maximum_bytes=maximum_bytes)
        if canonical_json_bytes(payload, maximum_bytes=maximum_bytes) != encoded:
            raise ArchiveTransportError("archive metadata is not a canonical object")
    except (ContractError, UnicodeError, ValueError, RecursionError) as error:
        raise ArchiveTransportError("archive metadata is malformed") from error
    return payload
