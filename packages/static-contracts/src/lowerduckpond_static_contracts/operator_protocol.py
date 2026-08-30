"""Strict, versioned framing shared by the trusted operator and root adapter."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from lowerduckpond_static_contracts.canonical import MAX_CANONICAL_BYTES, MAX_RAW_REQUEST_BYTES

MAGIC: Final = b"LDPSTAT\0"
VERSION: Final = 1
HEADER_SIZE: Final = 24
MAX_DEPLOY_ARTIFACT_BYTES: Final = 100 * 1024 * 1024
MAX_IMPORT_ARTIFACT_BYTES: Final = 120 * 1024 * 1024
MAX_RESPONSE_BYTES: Final = MAX_CANONICAL_BYTES
MAX_EXPORT_BYTES: Final = 120 * 1024 * 1024
_HEADER: Final = struct.Struct("!8sBBHIQ")
_ARTIFACT_PRESENT: Final = 0x01
_KNOWN_FLAGS: Final = _ARTIFACT_PRESENT


class FrameKind(IntEnum):
    """Direction-specific frame kind encoded in the header."""

    REQUEST = 1
    RESPONSE = 2


class ProtocolError(ValueError):
    """A peer supplied an unsupported or impossible frame header."""


@dataclass(frozen=True, slots=True)
class FrameHeader:
    """One validated bounded frame header."""

    kind: FrameKind
    document_length: int
    payload_length: int | None


def encode_header(header: FrameHeader) -> bytes:
    """Encode one already bounded request or response header."""

    _validate_lengths(header)
    flags = _ARTIFACT_PRESENT if header.payload_length is not None else 0
    payload_length = header.payload_length or 0
    return _HEADER.pack(
        MAGIC,
        VERSION,
        int(header.kind),
        flags,
        header.document_length,
        payload_length,
    )


def decode_header(raw: bytes, *, expected_kind: FrameKind) -> FrameHeader:
    """Decode and reject an invalid header before any structured parsing."""

    if type(raw) is not bytes or len(raw) != HEADER_SIZE:
        raise ProtocolError("invalid_header")
    magic, version, kind_value, flags, document_length, encoded_payload_length = _HEADER.unpack(raw)
    if magic != MAGIC or version != VERSION:
        raise ProtocolError("unsupported_protocol")
    try:
        kind = FrameKind(kind_value)
    except ValueError as error:
        raise ProtocolError("unsupported_protocol") from error
    if kind is not expected_kind or flags & ~_KNOWN_FLAGS:
        raise ProtocolError("invalid_header")
    payload_present = bool(flags & _ARTIFACT_PRESENT)
    if payload_present != (encoded_payload_length != 0):
        raise ProtocolError("invalid_header")
    header = FrameHeader(
        kind=kind,
        document_length=document_length,
        payload_length=encoded_payload_length if payload_present else None,
    )
    _validate_lengths(header)
    return header


def _validate_lengths(header: FrameHeader) -> None:
    if type(header.kind) is not FrameKind:
        raise ProtocolError("invalid_header")
    if type(header.document_length) is not int or header.document_length <= 0:
        raise ProtocolError("invalid_header")
    maximum_document = (
        MAX_RAW_REQUEST_BYTES if header.kind is FrameKind.REQUEST else MAX_RESPONSE_BYTES
    )
    if header.document_length > maximum_document:
        raise ProtocolError("document_too_large")
    if header.payload_length is None:
        return
    if type(header.payload_length) is not int or header.payload_length <= 0:
        raise ProtocolError("invalid_header")
    maximum_payload = (
        MAX_IMPORT_ARTIFACT_BYTES if header.kind is FrameKind.REQUEST else MAX_EXPORT_BYTES
    )
    if header.payload_length > maximum_payload:
        raise ProtocolError("payload_too_large")
