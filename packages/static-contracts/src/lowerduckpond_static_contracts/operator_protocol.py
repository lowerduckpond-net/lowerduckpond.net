"""Strict, versioned framing shared by the trusted operator and root adapter."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from lowerduckpond_static_contracts.canonical import MAX_CANONICAL_BYTES, MAX_RAW_REQUEST_BYTES
from lowerduckpond_static_contracts.identifiers import validate_uuid7

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
_SHA256_HEX_LENGTH: Final = 64
_ACKNOWLEDGEMENT: Final = struct.Struct("!16s32sQ")
ACKNOWLEDGEMENT_SIZE: Final = _ACKNOWLEDGEMENT.size


class FrameKind(IntEnum):
    """Direction-specific frame kind encoded in the header."""

    REQUEST = 1
    RESPONSE = 2
    ACKNOWLEDGEMENT = 3


@dataclass(frozen=True, slots=True)
class ExportAcknowledgement:
    """Fixed binary receipt for one verified, durably saved download."""

    job_id: str
    sha256: str
    size: int

    def encode(self) -> bytes:
        job_id = validate_uuid7(self.job_id)
        if (
            type(self.sha256) is not str
            or len(self.sha256) != _SHA256_HEX_LENGTH
            or any(character not in "0123456789abcdef" for character in self.sha256)
            or type(self.size) is not int
            or not 0 < self.size <= MAX_EXPORT_BYTES
        ):
            raise ProtocolError("invalid_acknowledgement")
        return _ACKNOWLEDGEMENT.pack(uuid.UUID(job_id).bytes, bytes.fromhex(self.sha256), self.size)

    @classmethod
    def decode(cls, raw: bytes) -> ExportAcknowledgement:
        if type(raw) is not bytes or len(raw) != ACKNOWLEDGEMENT_SIZE:
            raise ProtocolError("invalid_acknowledgement")
        job, digest, size = _ACKNOWLEDGEMENT.unpack(raw)
        receipt = cls(str(uuid.UUID(bytes=job)), digest.hex(), size)
        receipt.encode()
        return receipt


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


def decode_header(raw: bytes, *, expected_kind: FrameKind | tuple[FrameKind, ...]) -> FrameHeader:
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
    allowed = (expected_kind,) if isinstance(expected_kind, FrameKind) else expected_kind
    if kind not in allowed or flags & ~_KNOWN_FLAGS:
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
    if header.kind is FrameKind.ACKNOWLEDGEMENT:
        if (
            type(header.document_length) is not int
            or header.document_length != ACKNOWLEDGEMENT_SIZE
            or header.payload_length is not None
        ):
            raise ProtocolError("invalid_acknowledgement")
        return
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
