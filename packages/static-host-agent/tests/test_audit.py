from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    audit_entry_digest,
    canonical_json_bytes,
)
from lowerduckpond_static_host_agent import (
    AuditCapacityError,
    AuditError,
    AuditLimits,
    DurabilityBoundary,
    LockManager,
    LockMode,
    StateRepository,
)

_FIXTURE = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted/audit-entry.json"
_DIRECTORY_MODE = 0o700
_RECORD_MODE = 0o600
_EXPECTED_CHAIN_ENTRIES = 2
_ROTATED_SEGMENTS = 2


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir()
    root.chmod(_DIRECTORY_MODE)
    for name in ("audit", "locks"):
        child = root / name
        child.mkdir()
        child.chmod(_DIRECTORY_MODE)
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _entry(
    sequence: int,
    previous: dict[str, str] | None,
) -> dict[str, object]:
    document = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert type(document) is dict
    document["sequence"] = sequence
    document["previousEntryDigest"] = previous
    document["correlationId"] = f"0198d17f-6f4a-7000-8000-{sequence + 1:012x}"
    return document


def _repository(root: Path) -> StateRepository:
    return StateRepository(root, expected_owner=os.geteuid())


def test_append_builds_one_exact_canonical_hash_chain(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    first_digest = audit_entry_digest(first).to_dict()
    second = _entry(1, first_digest)
    second["operation"] = "archive"

    with _repository(root) as repository:
        first_result = repository.append_audit(first)
        second_result = repository.append_audit(second)
        state = repository.inspect_audit()
        snapshot = repository.inspect_audit_correlation(first["correlationId"])
        second_snapshot = repository.inspect_audit_correlation(second["correlationId"])
        absent = repository.inspect_audit_correlation("0198d17f-6f4a-7000-8000-ffffffffffff")

    assert first_result.entry_digest == first_digest
    assert second_result.state == state
    assert state.entry_count == _EXPECTED_CHAIN_ENTRIES
    assert state.segment_count == 1
    assert state.terminal_digest == audit_entry_digest(second).to_dict()
    assert snapshot.state == state
    assert snapshot.entry == first
    assert snapshot.previous_tenant_state_transition is None
    assert snapshot.has_later_tenant_state_transition is True
    assert second_snapshot.previous_tenant_state_transition == first
    assert second_snapshot.has_later_tenant_state_transition is False
    assert absent.state == state
    assert absent.entry is None
    assert absent.previous_tenant_state_transition is None
    assert absent.has_later_tenant_state_transition is False
    assert (root / "audit/segment-00000000000000000000.jsonl").read_bytes() == (
        canonical_json_bytes(first) + canonical_json_bytes(second)
    )


def test_correlation_lookup_rejects_duplicate_entries(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    second = _entry(1, audit_entry_digest(first).to_dict())
    second["correlationId"] = first["correlationId"]

    with _repository(root) as repository:
        repository.append_audit(first)
        repository.append_audit(second)
        with pytest.raises(AuditError, match="correlation appears multiple times"):
            repository.inspect_audit_correlation(first["correlationId"])


def test_correlation_lookup_does_not_treat_failure_as_state_supersession(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    second = _entry(1, audit_entry_digest(first).to_dict())
    second["operation"] = "rename"
    second["resultStatus"] = "failed"

    with _repository(root) as repository:
        repository.append_audit(first)
        repository.append_audit(second)
        snapshot = repository.inspect_audit_correlation(first["correlationId"])

    assert snapshot.has_later_tenant_state_transition is False


@pytest.mark.parametrize("invalid_field", ["sequence", "predecessor"])
def test_append_rejects_an_entry_that_does_not_extend_the_chain(
    tmp_path: Path,
    invalid_field: str,
) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)

    with _repository(root) as repository:
        repository.append_audit(first)
        candidate = _entry(1, audit_entry_digest(first).to_dict())
        if invalid_field == "sequence":
            candidate["sequence"] = 2
        else:
            previous = candidate["previousEntryDigest"]
            assert type(previous) is dict
            previous["value"] = "f" * 64
        with pytest.raises(AuditError):
            repository.append_audit(candidate)
        state = repository.inspect_audit()

    assert state.entry_count == 1


def test_rotation_is_bounded_and_canonically_packed(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    limits = AuditLimits(maximum_segment_bytes=MAX_CANONICAL_BYTES)
    previous: dict[str, str] | None = None

    with _repository(root) as repository:
        for sequence in range(80):
            document = _entry(sequence, previous)
            result = repository.append_audit(document, limits=limits)
            previous = result.entry_digest
            if result.state.segment_count == _ROTATED_SEGMENTS:
                break
        state = repository.inspect_audit(limits=limits)

    assert state.segment_count == _ROTATED_SEGMENTS
    first = (root / "audit/segment-00000000000000000000.jsonl").read_bytes()
    second = (root / "audit/segment-00000000000000000001.jsonl").read_bytes()
    assert len(first) <= MAX_CANONICAL_BYTES
    assert len(first) + len(second.splitlines(keepends=True)[0]) > MAX_CANONICAL_BYTES


def test_segment_count_bound_uses_minimum_allocation_not_perfect_packing() -> None:
    limits = AuditLimits(
        maximum_segment_bytes=MAX_CANONICAL_BYTES,
        maximum_ordinary_bytes=2 * MAX_CANONICAL_BYTES,
        maximum_administrator_reserve_bytes=0,
    )

    perfectly_packed = (
        limits.maximum_administrator_bytes + limits.maximum_segment_bytes - 1
    ) // limits.maximum_segment_bytes
    assert limits.maximum_segments == limits.maximum_administrator_bytes // 512
    assert limits.maximum_segments > perfectly_packed


def test_replacement_admission_accounts_for_old_and_temporary_generations(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    second = _entry(1, audit_entry_digest(first).to_dict())

    with _repository(root) as repository:
        state = repository.append_audit(first).state

    filesystem = os.statvfs(root / "audit")
    fragment = filesystem.f_frsize or filesystem.f_bsize
    replacement_bytes = len(canonical_json_bytes(first) + canonical_json_bytes(second))
    replacement_allocation = ((replacement_bytes + fragment - 1) // fragment) * fragment
    limits = AuditLimits(
        maximum_ordinary_bytes=state.allocated_bytes + replacement_allocation - 1,
        maximum_administrator_reserve_bytes=0,
    )

    with (
        _repository(root) as repository,
        pytest.raises(
            AuditCapacityError,
            match="protected capacity",
        ),
    ):
        repository.append_audit(second, limits=limits)


def test_sparse_segment_rotation_is_rejected(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    second = _entry(1, audit_entry_digest(first).to_dict())
    for number, document in enumerate((first, second)):
        path = root / "audit" / f"segment-{number:020d}.jsonl"
        path.write_bytes(canonical_json_bytes(document))
        path.chmod(_RECORD_MODE)

    with _repository(root) as repository, pytest.raises(AuditError, match="packed"):
        repository.inspect_audit()


def test_administrator_reserve_is_unavailable_to_ordinary_append(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    limits = AuditLimits(
        maximum_segment_bytes=MAX_CANONICAL_BYTES,
        maximum_ordinary_bytes=0,
        maximum_administrator_reserve_bytes=16384,
    )
    document = _entry(0, None)

    with _repository(root) as repository:
        with pytest.raises(AuditCapacityError):
            repository.append_audit(document, limits=limits)
        result = repository.append_audit(document, administrator=True, limits=limits)

    assert result.state.entry_count == 1
    assert result.state.allocated_bytes <= limits.maximum_administrator_bytes


@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_failure_injection_leaves_one_complete_old_or_new_chain(
    tmp_path: Path,
    boundary: DurabilityBoundary,
) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    second = _entry(1, audit_entry_digest(first).to_dict())

    def fail_at(observed: DurabilityBoundary) -> None:
        if observed is boundary:
            raise RuntimeError("injected audit failure")

    with _repository(root) as repository:
        repository.append_audit(first)
        with pytest.raises(RuntimeError, match="injected"):
            repository.append_audit(second, failure_hook=fail_at)
        state = repository.inspect_audit()

    assert state.entry_count in {1, 2}
    assert state.terminal_digest in (
        audit_entry_digest(first).to_dict(),
        audit_entry_digest(second).to_dict(),
    )


def test_abandoned_safe_publication_temporary_is_removed(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    temporary = root / "audit/.ldp-state-0123456789abcdef0123456789abcdef"
    temporary.write_bytes(b"interrupted")
    temporary.chmod(_RECORD_MODE)

    with _repository(root) as repository:
        state = repository.inspect_audit()

    assert state.entry_count == 0
    assert not temporary.exists()


@pytest.mark.parametrize("shape", ["unexpected", "symlink", "hardlink", "mode"])
def test_unsafe_segment_shapes_are_rejected(tmp_path: Path, shape: str) -> None:
    root = _state_root(tmp_path)
    audit = root / "audit"
    target = audit / "segment-00000000000000000000.jsonl"
    if shape == "unexpected":
        target = audit / "other.jsonl"
        target.write_bytes(b"x")
    elif shape == "symlink":
        target.symlink_to("/dev/null")
    elif shape == "hardlink":
        source = tmp_path / "source"
        source.write_bytes(canonical_json_bytes(_entry(0, None)))
        source.chmod(_RECORD_MODE)
        os.link(source, target)
    else:
        target.write_bytes(canonical_json_bytes(_entry(0, None)))
        target.chmod(0o644)

    with _repository(root) as repository, pytest.raises((AuditError, RuntimeError)):
        repository.inspect_audit()


def test_noncanonical_or_broken_existing_chain_is_rejected(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    first = _entry(0, None)
    second = _entry(1, audit_entry_digest(first).to_dict())

    with _repository(root) as repository:
        repository.append_audit(first)
        repository.append_audit(second)

    path = root / "audit/segment-00000000000000000000.jsonl"
    previous = second["previousEntryDigest"]
    assert type(previous) is dict
    previous["value"] = "f" * 64
    path.write_bytes(canonical_json_bytes(first) + canonical_json_bytes(second))
    path.chmod(_RECORD_MODE)

    with _repository(root) as repository, pytest.raises(AuditError):
        repository.inspect_audit()


def test_audit_mutation_requires_the_exclusive_tenant_state_lock(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with (
        _repository(root) as repository,
        repository.transaction(mode=LockMode.SHARED) as transaction,
        pytest.raises(RuntimeError, match="exclusive"),
    ):
        transaction.append_audit(_entry(0, None))


@pytest.mark.parametrize(
    "overrides",
    [
        {"maximum_segment_bytes": 8 * 1024 * 1024 + 1},
        {"maximum_ordinary_bytes": 128 * 1024 * 1024 + 1},
        {"maximum_administrator_reserve_bytes": 8 * 1024 * 1024 + 1},
    ],
)
def test_public_limits_cannot_weaken_committed_boundaries(
    overrides: dict[str, int],
) -> None:
    with pytest.raises(ValueError, match="cannot weaken"):
        AuditLimits(**overrides)
