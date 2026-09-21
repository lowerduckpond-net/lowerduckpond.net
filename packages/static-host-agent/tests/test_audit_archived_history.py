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
from lowerduckpond_static_host_agent.audit_archive_formats import inspect_segment
from lowerduckpond_static_host_agent.audit_archive_store import head_for_indexes
from lowerduckpond_static_host_agent.durable import DurableDirectory
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
