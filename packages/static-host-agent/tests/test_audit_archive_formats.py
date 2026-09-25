from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    Digest,
    audit_entry_digest,
    canonical_json_bytes,
)
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent.backup_identity import (
    BackupIdentityError,
    RepositoryIdentity,
    framed_digest,
)

FIXTURES = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
LINEAGE = "0198d17f-6f4a-7000-8000-000000000010"
ROTATION = "0198d17f-6f4a-7000-8000-000000000011"
IDENTITY = RepositoryIdentity("a" * 64, "test-node", "s3:https://nyc3.example.test/backups/test")


def entry(sequence: int = 0, previous: dict[str, str] | None = None) -> dict[str, object]:
    result = json.loads((FIXTURES / "audit-entry.json").read_bytes())
    assert type(result) is dict
    result["sequence"] = sequence
    result["previousEntryDigest"] = previous
    result["correlationId"] = f"0198d17f-6f4a-7000-8000-{sequence + 1:012x}"
    return result


def descriptor(raw: bytes, *, number: int = 0) -> dict[str, object]:
    evidence = formats.inspect_segment(raw)
    return {
        "schema": formats.ROTATION_SCHEMA,
        "rotationId": ROTATION,
        "lineageId": LINEAGE,
        "repositoryBinding": IDENTITY.binding(),
        "createdAt": "2026-09-21T12:00:00Z",
        "segmentNumber": number,
        "segmentName": f"segment-{number:020d}.jsonl",
        "firstSequence": evidence.first_sequence,
        "lastSequence": evidence.first_sequence + evidence.entry_count - 1,
        "entryCount": evidence.entry_count,
        "segmentBytes": len(raw),
        "segmentSha256": hashlib.sha256(raw).hexdigest(),
        "predecessorEntryDigest": evidence.predecessor,
        "terminalEntryDigest": evidence.terminal,
        "previousDescriptorDigest": None
        if number == 0
        else framed_digest(formats.DESCRIPTOR_FORMAT, b"prior"),
        "witnessFormat": formats.WITNESS_FORMAT,
        "witnessBytes": len(evidence.witness),
        "witnessDigest": framed_digest(formats.WITNESS_FORMAT, evidence.witness),
    }


def index_record(record: dict[str, object]) -> dict[str, object]:
    return {
        "schema": formats.INDEX_SCHEMA,
        "descriptor": record,
        "snapshotId": "c" * 64,
        "requiredTags": list(formats.required_archive_tags(record)),
        "descriptorDigest": framed_digest(formats.DESCRIPTOR_FORMAT, canonical_json_bytes(record)),
        "witnessDigest": record["witnessDigest"],
        "previousIndexDigest": None,
    }


def empty_head() -> dict[str, object]:
    return {
        "schema": formats.HEAD_SCHEMA,
        "lineageId": LINEAGE,
        "repositoryBinding": IDENTITY.binding(),
        "indexCount": 0,
        "entryCount": 0,
        "terminalEntryDigest": None,
        "lastIndexDigest": None,
        "lastDescriptorDigest": None,
    }


@pytest.mark.parametrize("variant", ["create", "failed-create", "delete", "emergency-delete"])
def test_witness_reconstructs_exact_original_entry_and_digest(variant: str) -> None:
    first = entry()
    if variant == "failed-create":
        first.update(resultStatus="failed", tenantId=None)
    if variant.endswith("delete"):
        first["operation"] = "delete"
        first["deletionEvidence"] = {
            "mode": "emergency" if variant.startswith("emergency") else "never-deployed",
            "releasedSlugs": ["original-slug", "renamed-slug"],
            "archiveRecordDigest": None,
            "bucket": None,
            "key": None,
            "versionId": None,
            "emergencyReason": (
                'owned test fixture: \n\r\t💧 "quoted" \\path'
                if variant.startswith("emergency")
                else None
            ),
        }
    second = entry(1, audit_entry_digest(first).to_dict())
    second["operation"] = "rename"
    raw = canonical_json_bytes(first) + canonical_json_bytes(second)
    evidence = formats.verify_segment(descriptor(raw), raw)
    # Compare the whole canonical array, including commas, escapes and final LF,
    # independently of how the segment inspector accumulates its witness.
    assert evidence.witness == canonical_json_bytes(
        [
            [
                document["sequence"],
                document["previousEntryDigest"],
                document["timestamp"],
                document["operatorPrincipal"],
                document["operation"],
                document["tenantId"],
                document["correlationId"],
                document["resultDigest"],
                document["resultStatus"],
                document.get("deletionEvidence"),
            ]
            for document in (first, second)
        ]
    )
    # Exercise cold reconstruction and its full validation, not the proof just
    # populated while preparing the original descriptor.
    with formats._PROOF_CACHE_LOCK:
        formats._PROOF_CACHE.clear()
    assert formats.segment_from_witness(evidence.witness) == raw
    assert evidence.terminal == audit_entry_digest(second).to_dict()
    assert json.loads(evidence.witness)[0] == [
        0,
        None,
        first["timestamp"],
        first["operatorPrincipal"],
        first["operation"],
        first["tenantId"],
        first["correlationId"],
        first["resultDigest"],
        first["resultStatus"],
        first.get("deletionEvidence"),
    ]


def test_nonzero_segment_retains_predecessor_without_resetting_sequence() -> None:
    first = entry(
        12, {"format": formats.AUDIT_ENTRY_FORMAT, "algorithm": "sha256", "value": "d" * 64}
    )
    raw = canonical_json_bytes(first)
    record = descriptor(raw, number=1)
    assert formats.decode_rotation(canonical_json_bytes(record)) == record
    evidence = formats.verify_segment(record, raw)
    assert formats.segment_from_witness(evidence.witness) == raw
    assert evidence.first_sequence == first["sequence"]


@pytest.mark.parametrize(
    ("key", "invalid"),
    [
        ("schema", "lowerduckpond-audit-rotation-v2"),
        ("extra", "unknown"),
        ("rotationId", "latest"),
        ("lineageId", "0198d17f-6f4a-4000-8000-000000000010"),
        ("createdAt", "2026-9-21T12:00:00Z"),
        ("createdAt", "2026-09-21T12:00:00+00:00"),
        ("repositoryBinding", framed_digest(formats.INDEX_FORMAT, b"wrong")),
        ("segmentNumber", True),
        ("segmentNumber", -1),
        ("segmentNumber", 4096),
        ("segmentName", "../segment.jsonl"),
        ("segmentName", "segment-0.jsonl"),
        ("firstSequence", 1),
        ("lastSequence", 65536),
        ("entryCount", 0),
        ("entryCount", 2),
        ("segmentBytes", 0),
        ("segmentBytes", formats.MAX_SEGMENT_BYTES + 1),
        ("segmentSha256", "abc123"),
        ("segmentSha256", "A" * 64),
        ("predecessorEntryDigest", framed_digest(formats.AUDIT_ENTRY_FORMAT, b"unexpected")),
        ("terminalEntryDigest", None),
        ("previousDescriptorDigest", framed_digest(formats.DESCRIPTOR_FORMAT, b"unexpected")),
        ("witnessFormat", "json"),
        ("witnessBytes", 0),
        ("witnessBytes", formats.MAX_SEGMENT_BYTES + 1),
        ("witnessDigest", framed_digest(formats.DESCRIPTOR_FORMAT, b"wrong-domain")),
    ],
)
def test_descriptor_refuses_unsupported_or_ambiguous_authority(key: str, invalid: object) -> None:
    record = descriptor(canonical_json_bytes(entry()))
    record[key] = invalid
    with pytest.raises(BackupIdentityError):
        formats.decode_rotation(canonical_json_bytes(record))


@pytest.mark.parametrize("form", ["whitespace", "duplicate", "missing", "no-lf", "oversize"])
def test_descriptor_requires_exact_bounded_canonical_json(form: str) -> None:
    record = descriptor(canonical_json_bytes(entry()))
    raw = canonical_json_bytes(record)
    if form == "whitespace":
        raw = b" " + raw
    elif form == "duplicate":
        raw = b'{"schema":"duplicate",' + raw[1:]
    elif form == "missing":
        del record["terminalEntryDigest"]
        raw = canonical_json_bytes(record)
    elif form == "no-lf":
        raw = raw.rstrip(b"\n")
    else:
        raw += b" " * formats.MAX_DESCRIPTOR_BYTES
    with pytest.raises(BackupIdentityError):
        formats.decode_rotation(raw)


@pytest.mark.parametrize(
    "fault", ["sequence", "predecessor", "duplicate-correlation", "noncanonical"]
)
def test_restored_segment_requires_exact_schema_and_chain(fault: str) -> None:
    first = entry()
    second = entry(1, audit_entry_digest(first).to_dict())
    if fault == "sequence":
        second["sequence"] = 2
    elif fault == "predecessor":
        second["previousEntryDigest"] = audit_entry_digest(second).to_dict()
    elif fault == "duplicate-correlation":
        second["correlationId"] = first["correlationId"]
    raw = canonical_json_bytes(first) + canonical_json_bytes(second)
    if fault == "noncanonical":
        raw = b" " + raw
    with pytest.raises(BackupIdentityError):
        formats.inspect_segment(raw)


@pytest.mark.parametrize(
    "fault", ["short-row", "extra-column", "duplicate-key", "chain", "deletion", "noncanonical"]
)
def test_witness_never_accepts_lossy_or_invented_history(fault: str) -> None:
    raw = canonical_json_bytes(entry())
    witness = formats.inspect_segment(raw).witness
    rows = json.loads(witness)
    if fault == "short-row":
        rows[0].pop()
    elif fault == "extra-column":
        rows[0].append(None)
    elif fault == "chain":
        rows.append(deepcopy(rows[0]))
    elif fault == "deletion":
        rows[0][-1] = {"invented": "authority"}
    witness = canonical_json_bytes(rows)
    if fault == "duplicate-key":
        witness = witness.replace(
            b'"algorithm":"sha256"', b'"algorithm":"sha256","algorithm":"sha256"'
        )
    elif fault == "noncanonical":
        witness += b"\n"
    with pytest.raises(BackupIdentityError):
        formats.segment_from_witness(witness)


@pytest.mark.parametrize(
    "field", ["segmentSha256", "terminalEntryDigest", "witnessDigest", "witnessBytes"]
)
def test_restore_verification_rejects_well_shaped_but_wrong_descriptor(field: str) -> None:
    raw = canonical_json_bytes(entry())
    record = descriptor(raw)
    if field == "segmentSha256":
        record[field] = "e" * 64
    elif field == "witnessBytes":
        record[field] = 1
    else:
        value = record[field]
        assert type(value) is dict
        value["value"] = "e" * 64
    with pytest.raises(BackupIdentityError, match="disagrees"):
        formats.verify_segment(record, raw)


def test_index_binds_exact_snapshot_descriptor_witness_and_required_tags() -> None:
    record = descriptor(canonical_json_bytes(entry()))
    index = index_record(record)
    assert formats.decode_index(canonical_json_bytes(index)) == index
    tags = index["requiredTags"]
    assert type(tags) is list and "scheduled" not in tags
    for key, value in (
        ("snapshotId", "c" * 8),
        ("requiredTags", ["scheduled"]),
        ("descriptorDigest", record["witnessDigest"]),
        ("witnessDigest", index["descriptorDigest"]),
        ("previousIndexDigest", framed_digest(formats.INDEX_FORMAT, b"unexpected")),
    ):
        with pytest.raises(BackupIdentityError):
            formats.decode_index(canonical_json_bytes({**index, key: value}))


def test_empty_head_has_no_fabricated_terminal_or_index() -> None:
    head = empty_head()
    assert formats.decode_head(canonical_json_bytes(head)) == head
    for key, value in (
        ("indexCount", 1),
        ("entryCount", 1),
        ("indexCount", True),
        ("lastIndexDigest", framed_digest(formats.INDEX_FORMAT, b"unexpected")),
    ):
        with pytest.raises(BackupIdentityError):
            formats.decode_head(canonical_json_bytes({**head, key: value}))


def test_cached_segment_evidence_cannot_be_changed_through_returned_digest_objects() -> None:
    first = entry(1, audit_entry_digest(entry()).to_dict())
    raw = canonical_json_bytes(first)
    expected = formats.inspect_segment(raw)
    changed = formats.inspect_segment(raw)
    assert changed.predecessor is not None
    changed.predecessor["value"] = "0" * 64
    changed.terminal["value"] = "0" * 64
    assert formats.inspect_segment(raw) == expected


def test_witness_cache_never_grants_authority_to_changed_bytes() -> None:
    raw = canonical_json_bytes(entry())
    witness = formats.inspect_segment(raw).witness
    assert formats.segment_from_witness(witness) == raw
    rows = json.loads(witness)
    rows[0][0] = 1  # Sequence disagrees with the initial predecessor.
    modified = canonical_json_bytes(rows, maximum_bytes=formats.MAX_SEGMENT_BYTES)
    with pytest.raises(BackupIdentityError):
        formats.segment_from_witness(modified)
    assert formats.segment_from_witness(witness) == raw


def test_segment_cache_never_reuses_a_previous_chain_proof_for_changed_bytes() -> None:
    raw = canonical_json_bytes(entry())
    expected = formats.inspect_segment(raw)
    changed = entry()
    changed["correlationId"] = "0198d17f-6f4a-7000-8000-000000000088"
    current = formats.inspect_segment(canonical_json_bytes(changed))
    assert current.terminal != expected.terminal
    assert current.witness != expected.witness


def test_adjacent_exact_byte_proofs_share_both_directions_with_bounded_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bytes] = []

    def digest(document: object) -> Digest:
        result = audit_entry_digest(document)
        calls.append(canonical_json_bytes(document))
        return result

    with formats._PROOF_CACHE_LOCK:
        formats._PROOF_CACHE.clear()
    monkeypatch.setattr(formats, "audit_entry_digest", digest)
    first = entry()
    second = entry(1, audit_entry_digest(first).to_dict())
    raw = (canonical_json_bytes(first), canonical_json_bytes(second))
    witnesses = tuple(formats.inspect_segment(value).witness for value in raw)
    assert calls == list(raw)
    for _ in range(3):
        for value, witness in zip(raw, witnesses, strict=True):
            assert formats.inspect_segment(bytes(bytearray(value))).witness == witness
            assert formats.segment_from_witness(bytes(bytearray(witness))) == value
    assert calls == list(raw)
    third = canonical_json_bytes(entry(2, audit_entry_digest(second).to_dict()))
    formats.inspect_segment(third)
    # Only two pairs survive; a third segment cannot grow an unbounded history
    # cache, and re-reading an evicted pair performs full validation again.
    formats.inspect_segment(raw[0])
    assert calls == [*raw, third, raw[0]]
