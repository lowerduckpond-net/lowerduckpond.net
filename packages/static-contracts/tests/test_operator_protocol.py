from __future__ import annotations

import json
import struct
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ACKNOWLEDGEMENT_SIZE,
    HEADER_SIZE,
    MAX_IMPORT_ARTIFACT_BYTES,
    MAX_RAW_REQUEST_BYTES,
    ContractError,
    Digest,
    ExportAcknowledgement,
    FrameHeader,
    FrameKind,
    ProtocolError,
    archive_record_digest,
    decode_header,
    deployment_record_digest,
    encode_header,
    platform_state_digest,
)
from lowerduckpond_static_contracts._digest import digest_bytes
from lowerduckpond_static_contracts.canonical import canonical_json_bytes

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


@pytest.mark.parametrize("kind", [FrameKind.REQUEST, FrameKind.RESPONSE])
@pytest.mark.parametrize("payload_length", [None, 1, MAX_IMPORT_ARTIFACT_BYTES])
def test_frame_header_round_trips(kind: FrameKind, payload_length: int | None) -> None:
    header = FrameHeader(kind=kind, document_length=123, payload_length=payload_length)

    encoded = encode_header(header)

    assert len(encoded) == HEADER_SIZE
    assert decode_header(encoded, expected_kind=kind) == header


@pytest.mark.parametrize(
    ("header", "message"),
    [
        (FrameHeader(FrameKind.REQUEST, 0, None), "invalid_header"),
        (FrameHeader(FrameKind.REQUEST, MAX_RAW_REQUEST_BYTES + 1, None), "document_too_large"),
        (
            FrameHeader(FrameKind.REQUEST, 1, MAX_IMPORT_ARTIFACT_BYTES + 1),
            "payload_too_large",
        ),
    ],
)
def test_encoder_refuses_impossible_lengths(header: FrameHeader, message: str) -> None:
    with pytest.raises(ProtocolError, match=message):
        encode_header(header)


@pytest.mark.parametrize(
    "replacement",
    [
        b"UNKNOWN\0",
        None,
    ],
)
def test_decoder_rejects_unknown_magic_or_version(replacement: bytes | None) -> None:
    encoded = bytearray(encode_header(FrameHeader(FrameKind.REQUEST, 1, None)))
    if replacement is None:
        encoded[8] = 2
    else:
        encoded[:8] = replacement

    with pytest.raises(ProtocolError, match="unsupported_protocol"):
        decode_header(bytes(encoded), expected_kind=FrameKind.REQUEST)


def test_decoder_rejects_direction_flags_and_artifact_inconsistency() -> None:
    encoded = encode_header(FrameHeader(FrameKind.REQUEST, 1, None))
    with pytest.raises(ProtocolError, match="invalid_header"):
        decode_header(encoded, expected_kind=FrameKind.RESPONSE)

    unknown_flags = bytearray(encoded)
    unknown_flags[10:12] = struct.pack("!H", 0x8000)
    with pytest.raises(ProtocolError, match="invalid_header"):
        decode_header(bytes(unknown_flags), expected_kind=FrameKind.REQUEST)

    missing_payload = bytearray(encoded)
    missing_payload[10:12] = struct.pack("!H", 1)
    with pytest.raises(ProtocolError, match="invalid_header"):
        decode_header(bytes(missing_payload), expected_kind=FrameKind.REQUEST)


@pytest.mark.parametrize(
    ("fixture", "function", "format_identifier"),
    [
        ("platform-namespace.json", platform_state_digest, "lowerduckpond-platform-state-v1"),
        (
            "deployment-record.json",
            deployment_record_digest,
            "lowerduckpond-deployment-record-v1",
        ),
        ("archive-record.json", archive_record_digest, "lowerduckpond-archive-record-v1"),
    ],
)
def test_expected_source_digest_helpers_pin_schema_and_domain(
    fixture: str,
    function: Callable[[object], Digest],
    format_identifier: str,
) -> None:
    document = _fixture(fixture)
    actual = function(document)

    assert actual == digest_bytes(
        canonical_json_bytes(document),
        format_identifier=format_identifier,
    )
    invalid = deepcopy(document)
    invalid["kind"] = "OperationRequest"
    with pytest.raises(ContractError):
        function(invalid)


def test_acknowledgement_frame_is_fixed_binary_and_has_no_payload() -> None:
    receipt = ExportAcknowledgement("0198d17f-6f4a-7000-8000-000000000001", "a" * 64, 123)
    raw = receipt.encode()
    assert len(raw) == ACKNOWLEDGEMENT_SIZE
    assert ExportAcknowledgement.decode(raw) == receipt
    header = FrameHeader(FrameKind.ACKNOWLEDGEMENT, ACKNOWLEDGEMENT_SIZE, None)
    assert (
        decode_header(
            encode_header(header), expected_kind=(FrameKind.REQUEST, FrameKind.ACKNOWLEDGEMENT)
        )
        == header
    )
    for invalid in (
        FrameHeader(FrameKind.ACKNOWLEDGEMENT, ACKNOWLEDGEMENT_SIZE + 1, None),
        FrameHeader(FrameKind.ACKNOWLEDGEMENT, ACKNOWLEDGEMENT_SIZE, 1),
    ):
        with pytest.raises(ProtocolError, match="acknowledgement"):
            encode_header(invalid)
    for invalid_raw in (raw + b"x", raw[:-1], bytes(ACKNOWLEDGEMENT_SIZE)):
        with pytest.raises(ValueError):
            ExportAcknowledgement.decode(invalid_raw)
