from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TypedDict

import pytest
from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    audit_entry_digest,
    canonical_json_bytes,
)
from lowerduckpond_static_host_agent import (
    AuditError,
    AuditLimits,
    LockManager,
    StateRepository,
    audit,
)
from lowerduckpond_static_host_agent import audit_archive_admission as admission
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent.audit_archive_formats import inspect_segment
from lowerduckpond_static_host_agent.audit_archive_store import head_for_indexes
from lowerduckpond_static_host_agent.durable import DurableDirectory, StatePathError
from test_audit_archive_admission import NOW, available_capacity, grant_protection
from test_audit_archive_formats import descriptor, entry, index_record
from test_audit_archive_store import lineage, put
from test_audit_archive_store import (
    state as state,  # noqa: PLC0414 - re-export shared pytest fixture
)

LIMITS = AuditLimits(maximum_segment_bytes=MAX_CANONICAL_BYTES)
FIRST_SEGMENT = "audit/segment-00000000000000000000.jsonl"
TAIL_SEGMENT = "audit/segment-00000000000000000001.jsonl"


class ReadArguments(TypedDict):
    expected_owner: int
    expected_directory_mode: int
    expected_record_mode: int
    limits: AuditLimits


def history(root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    segment = bytearray()
    previous = None
    while True:
        document = entry(len(records), previous)
        if records:
            document["operation"] = "deploy" if len(records) % 2 else "rename"
        raw = canonical_json_bytes(document)
        records.append(document)
        if len(segment) + len(raw) > LIMITS.maximum_segment_bytes:
            put(root, FIRST_SEGMENT, bytes(segment))
            put(root, TAIL_SEGMENT, raw)
            break
        segment.extend(raw)
        previous = audit_entry_digest(document).to_dict()
    with LockManager.initialize(root / "locks", expected_owner=os.geteuid()):
        pass
    return records


def archive_first(root: Path, *, remove: bool = True) -> bytes:
    raw = (root / FIRST_SEGMENT).read_bytes()
    index = index_record(descriptor(raw))
    put(root, "audit/archive/index-00000000000000000000.json", index)
    put(root, "audit/archive/witness-00000000000000000000.json", inspect_segment(raw).witness)
    put(root, "audit/archive/head.json", head_for_indexes(lineage(root), (index,)))
    if remove:
        (root / FIRST_SEGMENT).unlink()
    return raw


def projection(root: Path, records: list[dict[str, object]]) -> dict[str, object]:
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        chain = repository.inspect_audit(limits=LIMITS)
        correlations = [
            repository.inspect_audit_correlation(record["correlationId"], limits=LIMITS)
            for record in (records[0], records[-2], records[-1])
        ]
        later = repository.inspect_later_audit_transitions(
            records[0]["correlationId"], maximum_transitions=len(records), limits=LIMITS
        )
    with DurableDirectory.open(
        root, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as directory:
        arguments: ReadArguments = {
            "expected_owner": os.geteuid(),
            "expected_directory_mode": 0o700,
            "expected_record_mode": 0o600,
            "limits": LIMITS,
        }
        tenant = records[0]["tenantId"]
        assert type(tenant) is str
        return {
            "chain": (chain.entry_count, chain.segment_count, chain.terminal_digest),
            "correlations": [
                (
                    item.entry,
                    item.previous_tenant_state_transition,
                    item.has_later_tenant_state_transition,
                )
                for item in correlations
            ],
            "later": later,
            "creation": audit.tenant_has_creation_audit_history(directory, tenant, **arguments),
            "identity": audit.tenant_has_identity_audit_history(directory, tenant, **arguments),
            "deployment": audit.tenant_has_deployment_audit_history(directory, tenant, **arguments),
            "deployments": audit.deployment_audit_history_tenant_ids(
                directory, (tenant,), **arguments
            ),
            "prefix": audit.audit_prefix_terminal(directory, len(records) - 1, **arguments),
            "readonly": audit.inspect_audit_readonly(directory, **arguments).terminal_digest,
        }


@pytest.mark.parametrize("keep_local_overlap", [False, True])
def test_every_historical_projection_is_equal_before_and_after_archival(
    state: Path, keep_local_overlap: bool
) -> None:
    records = history(state)
    before = projection(state, records)
    archive_first(state, remove=not keep_local_overlap)
    assert projection(state, records) == before
    assert before["creation"] and before["identity"] and before["deployment"]
    assert before["prefix"] == audit_entry_digest(records[-2]).to_dict()


def test_append_continues_local_tail_after_archived_prefix(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = history(state)
    archive_first(state)
    grant_protection(state)
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", available_capacity)
    candidate = entry(len(records), audit_entry_digest(records[-1]).to_dict())
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        result = repository.append_audit(candidate, limits=LIMITS)
        assert result.state.entry_count == len(records) + 1
        assert result.entry_digest == audit_entry_digest(candidate).to_dict()
    assert not (state / FIRST_SEGMENT).exists()
    assert (state / TAIL_SEGMENT).read_bytes().endswith(canonical_json_bytes(candidate))


@pytest.mark.parametrize(
    "fault", ["missing-tail", "gap", "overlap-fork", "duplicate-correlation", "predecessor"]
)
def test_archive_join_rejects_inconsistent_local_authority(state: Path, fault: str) -> None:
    records = history(state)
    archive_first(state, remove=fault != "overlap-fork")
    projection(state, records)  # Prime exact-byte proofs before altering local authority.
    if fault == "missing-tail":
        (state / TAIL_SEGMENT).unlink()
    elif fault == "gap":
        (state / TAIL_SEGMENT).rename(state / "audit/segment-00000000000000000002.jsonl")
    elif fault == "overlap-fork":
        raw = (
            (state / FIRST_SEGMENT)
            .read_bytes()
            .replace(b"operator@example.test", b"attacker@example.test")
        )
        put(state, FIRST_SEGMENT, raw)
    else:
        tail = records[-1]
        tail["correlationId"] = records[0]["correlationId"]
        if fault == "predecessor":
            tail["previousEntryDigest"] = audit_entry_digest(records[0]).to_dict()
        put(state, TAIL_SEGMENT, tail)
    with (
        StateRepository(state, expected_owner=os.geteuid()) as repository,
        pytest.raises(AuditError),
    ):
        repository.inspect_audit(limits=LIMITS)


def test_archive_metadata_allocation_is_charged_to_ordinary_audit_capacity(state: Path) -> None:
    history(state)
    archive_first(state)
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        observed = repository.inspect_audit(limits=LIMITS)
    metadata = sum(path.stat().st_blocks * 512 for path in (state / "audit/archive").iterdir())
    metadata += (state / "audit/archive").stat().st_blocks * 512
    assert observed.allocated_bytes == metadata + (state / TAIL_SEGMENT).stat().st_blocks * 512


@pytest.mark.parametrize("keep_local_overlap", [False, True])
def test_admission_entry_ceiling_includes_archived_history_and_local_tail_once(
    state: Path, monkeypatch: pytest.MonkeyPatch, keep_local_overlap: bool
) -> None:
    records = history(state)
    archive_first(state, remove=not keep_local_overlap)
    grant_protection(state)
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(admission, "measure_filesystem_capacity_descriptor", available_capacity)
    monkeypatch.setattr(formats, "MAX_WITNESSED_ENTRIES", len(records) + 1)
    candidate = entry(len(records), audit_entry_digest(records[-1]).to_dict())
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        allowed = repository.append_audit(candidate, limits=LIMITS)
        assert allowed.state.entry_count == len(records) + 1
        next_entry = entry(len(records) + 1, audit_entry_digest(candidate).to_dict())
        with pytest.raises(AuditError, match="reserve bounded"):
            repository.append_audit(next_entry, limits=LIMITS)


@pytest.mark.parametrize("fault", ["witness", "descriptor", "head", "mode", "unknown"])
def test_historical_lookup_rechecks_archive_authority_after_a_successful_read(
    state: Path, fault: str
) -> None:
    records = history(state)
    archive_first(state)
    assert projection(state, records)["creation"]
    witness = state / "audit/archive/witness-00000000000000000000.json"
    if fault == "witness":
        put(
            state,
            str(witness.relative_to(state)),
            witness.read_bytes().replace(b"operator@example.test", b"attacker@example.test"),
        )
    elif fault == "descriptor":
        index = state / "audit/archive/index-00000000000000000000.json"
        put(
            state,
            str(index.relative_to(state)),
            index.read_bytes().replace(b'"firstSequence":0', b'"firstSequence":1'),
        )
    elif fault == "head":
        (state / "audit/archive/head.json").unlink()
    elif fault == "mode":
        witness.chmod(0o644)
    else:
        put(state, "audit/archive/unknown-authority", b"preserve this evidence")
    before = {path: path.read_bytes() for path in state.rglob("*") if path.is_file()}
    with (
        StateRepository(state, expected_owner=os.geteuid()) as repository,
        pytest.raises((AuditError, StatePathError)),
    ):
        repository.inspect_audit_correlation(records[0]["correlationId"], limits=LIMITS)
    assert {path: path.read_bytes() for path in state.rglob("*") if path.is_file()} == before


def test_readonly_correlation_lookup_preserves_abandoned_publication(state: Path) -> None:
    records = history(state)
    archive_first(state)
    temporary = state / "audit" / (".ldp-state-" + "a" * 32)
    put(state, str(temporary.relative_to(state)), b"retained publication")
    with DurableDirectory.open(
        state, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as directory:
        found = audit.inspect_audit_correlation(
            directory,
            records[0]["correlationId"],
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
            expected_record_mode=0o600,
            limits=LIMITS,
            read_only=True,
        )
    assert found.entry == records[0]
    assert temporary.read_bytes() == b"retained publication"
