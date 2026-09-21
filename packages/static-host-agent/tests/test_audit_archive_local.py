from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.audit_archive_inventory import ProtectedCopies, ProtectedProof
from lowerduckpond_static_host_agent.audit_archive_restic import VerifiedAuditSnapshot
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, DurableDirectory
from test_audit_archive_admission import available_capacity
from test_audit_archive_formats import IDENTITY, descriptor
from test_audit_archive_store import lineage, put, read
from test_audit_archive_store import state as state  # noqa: PLC0414 - shared private fixture
from test_audit_archived_history import FIRST_SEGMENT, LIMITS, TAIL_SEGMENT, history

TIME = "2026-09-21T12:00:00Z"
FIRST = "c" * 64
SECOND = "d" * 64
GENESIS = "e" * 64


@pytest.fixture
def closed(state: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    history(state)
    monkeypatch.setattr(local, "measure_filesystem_capacity_descriptor", available_capacity)
    return state


def proof(root: Path) -> ProtectedProof:
    raw = (root / FIRST_SEGMENT).read_bytes()
    record = descriptor(raw)
    orphan = VerifiedAuditSnapshot(
        FIRST, record, canonical_json_bytes(record), raw, formats.inspect_segment(raw).witness
    )
    return ProtectedProof(
        (FIRST, SECOND, GENESIS),
        framed_digest(journal.PROTECTION_INVENTORY_FORMAT, b"component proof"),
        2 * (len(raw) + len(orphan.descriptor_bytes)),
        (ProtectedCopies(record, (FIRST, SECOND)),),
        orphan if not read(root).segments else None,
    )


def commit(root: Path, *, hook: local.ArchiveFailureHook | None = None) -> None:
    verified = proof(root)
    with local.archive_transaction(root, os.geteuid()) as directory:
        current = local.observe_archive(directory, lineage(root), os.geteuid(), limits=LIMITS)
        local.commit_protected_proof(
            directory, current, verified, os.geteuid(), TIME, failure_hook=hook
        )


def test_orphan_adoption_commits_verified_index_duplicates_and_status_without_removal(
    closed: Path,
) -> None:
    source = (closed / FIRST_SEGMENT).read_bytes()
    commit(closed)
    prefix = read(closed)
    assert prefix.head is not None and prefix.head["indexCount"] == 1
    assert prefix.segments[0].index["snapshotId"] == FIRST
    assert prefix.segments[0].data == source
    assert prefix.duplicates is not None
    assert prefix.duplicates["entries"] == [
        {"descriptorDigest": prefix.segments[0].index["descriptorDigest"], "snapshotIds": [SECOND]}
    ]
    assert prefix.rotation_intent is not None and prefix.rotation_intent["phase"] == "indexed"
    assert (
        prefix.protection_status is not None and prefix.protection_status["category"] == "verified"
    )
    assert (closed / FIRST_SEGMENT).read_bytes() == source
    before = {path.name: path.read_bytes() for path in (closed / "audit/archive").iterdir()}
    commit(closed)
    assert before == {path.name: path.read_bytes() for path in (closed / "audit/archive").iterdir()}


PUBLICATIONS = [
    ("rotation-intent.json", 1),
    ("witness-00000000000000000000.json", 1),
    ("index-00000000000000000000.json", 1),
    ("duplicates.json", 1),
    ("head.json", 1),
    ("rotation-intent.json", 2),
    ("protection-status.json", 1),
]


@pytest.mark.parametrize("name,occurrence", PUBLICATIONS)
@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_every_publication_interruption_keeps_local_authority_and_resumes_same_index(
    closed: Path, name: str, occurrence: int, boundary: DurabilityBoundary
) -> None:
    before = (closed / FIRST_SEGMENT).read_bytes()
    observed = 0

    def fail(record: str, current: DurabilityBoundary) -> None:
        nonlocal observed
        if record == name and current == boundary:
            observed += 1
            if observed == occurrence:
                raise RuntimeError("interrupted durable primitive")

    with pytest.raises(RuntimeError, match="interrupted"):
        commit(closed, hook=fail)
    assert observed == occurrence
    assert (closed / FIRST_SEGMENT).read_bytes() == before
    read(closed)  # Every observable combination is a valid pending/committed state.
    commit(closed)
    prefix = read(closed)
    assert len(prefix.segments) == 1 and prefix.segments[0].data == before
    assert prefix.rotation_intent is not None and prefix.rotation_intent["phase"] == "indexed"
    assert (closed / FIRST_SEGMENT).read_bytes() == before


@pytest.mark.parametrize(
    "fault", ["no-successor", "source-bytes", "expected-head", "source-generation"]
)
def test_orphan_cannot_override_closed_local_or_pending_authority(closed: Path, fault: str) -> None:
    verified = proof(closed)
    if fault == "no-successor":
        (closed / TAIL_SEGMENT).unlink()
    with local.archive_transaction(closed, os.geteuid()) as directory:
        current = local.observe_archive(directory, lineage(closed), os.geteuid(), limits=LIMITS)
        orphan = verified.orphan
        assert orphan is not None
        if fault == "source-bytes":
            verified = replace(verified, orphan=replace(orphan, segment=b"other"))
        elif fault == "expected-head":
            record = {**orphan.descriptor, "firstSequence": 1}
            verified = replace(verified, orphan=replace(orphan, descriptor=record))
        elif fault == "source-generation":
            generation = [
                str(value)
                for value in directory.regular_metadata_generation(
                    ("audit", Path(FIRST_SEGMENT).name),
                    expected_owner=os.geteuid(),
                    expected_mode=0o600,
                )
            ]
            generation[1] = str(int(generation[1]) + 1)
            intent = {
                "schema": journal.ROTATION_INTENT_SCHEMA,
                "descriptor": orphan.descriptor,
                "expectedHeadDigest": local.head_digest(current.prefix),
                "sourceGeneration": generation,
                "phase": "verified",
                "snapshotIds": [FIRST, SECOND],
            }
            put(closed, "audit/archive/rotation-intent.json", intent)
            current = local.observe_archive(directory, lineage(closed), os.geteuid(), limits=LIMITS)
        with pytest.raises(BackupIdentityError):
            local.commit_protected_proof(directory, current, verified, os.geteuid(), TIME)
    assert not (closed / "audit/archive/index-00000000000000000000.json").exists()
    assert (closed / FIRST_SEGMENT).exists()


def test_commit_requires_same_captured_archive_authority(closed: Path) -> None:
    with local.archive_transaction(closed, os.geteuid()) as directory:
        before = local.observe_archive(directory, lineage(closed), os.geteuid(), limits=LIMITS)
    commit(closed)
    with local.archive_transaction(closed, os.geteuid()) as directory:
        after = local.observe_archive(directory, lineage(closed), os.geteuid(), limits=LIMITS)
    with pytest.raises(BackupIdentityError, match="changed"):
        local.require_same_authority(before, after)


@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_only_explicit_initialization_resumes_an_interrupted_empty_head(
    closed: Path, boundary: DurabilityBoundary
) -> None:
    (closed / "audit/archive/head.json").unlink()

    def fail(name: str, current: DurabilityBoundary) -> None:
        if name == "head.json" and current == boundary:
            raise RuntimeError("interrupted")

    with local.archive_transaction(closed, os.geteuid()) as directory:
        with pytest.raises(AuditError, match="prefix is invalid or incomplete"):
            local.observe_archive(directory, lineage(closed), os.geteuid(), limits=LIMITS)
        with pytest.raises(RuntimeError):
            local.initialize_empty_archive(
                directory, lineage(closed), (), os.geteuid(), failure_hook=fail
            )
        local.initialize_empty_archive(directory, lineage(closed), (), os.geteuid())
        current = local.observe_archive(directory, lineage(closed), os.geteuid(), limits=LIMITS)
    assert not current.prefix.segments and current.prefix.protection_status is None


@pytest.mark.parametrize("authority", ["remote", "index", "status"])
def test_missing_head_is_never_recreated_over_any_existing_authority(
    closed: Path, authority: str
) -> None:
    snapshots: tuple[RepositorySnapshot, ...] = ()
    if authority == "remote":
        snapshots = (RepositorySnapshot(FIRST, IDENTITY.node_name, (formats.ARCHIVE_TAG,)),)
    else:
        commit(closed)
        if authority == "status":
            for name in (
                "index-00000000000000000000.json",
                "witness-00000000000000000000.json",
                "rotation-intent.json",
                "duplicates.json",
            ):
                (closed / "audit/archive" / name).unlink()
    (closed / "audit/archive/head.json").unlink()
    with (
        local.archive_transaction(closed, os.geteuid()) as directory,
        pytest.raises(BackupIdentityError, match="existing archive"),
    ):
        local.initialize_empty_archive(directory, lineage(closed), snapshots, os.geteuid())
    assert not (closed / "audit/archive/head.json").exists()


def test_capacity_failure_precedes_first_authority_write(
    closed: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = (closed / "audit/archive/head.json").read_bytes()
    monkeypatch.setattr(formats, "MAX_ARCHIVE_METADATA_BYTES", 8192)
    with pytest.raises(BackupIdentityError, match="capacity"):
        commit(closed)
    assert (closed / "audit/archive/head.json").read_bytes() == before
    assert not (closed / "audit/archive/rotation-intent.json").exists()


def test_namespace_change_is_detected_before_any_authority_write(closed: Path) -> None:
    record = json.loads((closed / "platform/namespace.json").read_bytes())
    record["tenantBaseDomain"] = "another.example.test"
    put(closed, "platform/namespace.json", record)
    with pytest.raises((BackupIdentityError, AuditError, ValueError)):
        commit(closed)


@pytest.mark.parametrize("name,occurrence", PUBLICATIONS)
@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_process_death_at_each_durable_edge_preserves_chain_and_cleans_only_safe_temporaries(
    closed: Path, name: str, occurrence: int, boundary: DurabilityBoundary
) -> None:
    before = (closed / FIRST_SEGMENT).read_bytes()
    process = os.fork()
    if process == 0:
        observed = 0

        def terminate(record: str, current: DurabilityBoundary) -> None:
            nonlocal observed
            if record == name and current == boundary:
                observed += 1
                if observed == occurrence:
                    os._exit(73)

        try:
            commit(closed, hook=terminate)
        except BaseException:
            os._exit(74)
        os._exit(75)
    _, status = os.waitpid(process, 0)
    assert os.waitstatus_to_exitcode(status) == 73  # noqa: PLR2004 - injected termination status
    assert (closed / FIRST_SEGMENT).read_bytes() == before
    read(closed)
    commit(closed)
    assert read(closed).segments[0].data == before
    assert (closed / FIRST_SEGMENT).read_bytes() == before
    assert not list((closed / "audit/archive").glob(".ldp-state-*"))


@pytest.mark.parametrize("name,occurrence", PUBLICATIONS)
def test_interruption_before_each_publication_does_not_authorize_removal(
    closed: Path, monkeypatch: pytest.MonkeyPatch, name: str, occurrence: int
) -> None:
    publish = local._publish
    observed = 0

    def before(  # noqa: PLR0913 - production publication signature
        directory: DurableDirectory,
        record: str,
        raw: bytes,
        owner: int,
        *,
        immutable: bool,
        failure_hook: local.ArchiveFailureHook | None,
    ) -> None:
        nonlocal observed
        if record == name:
            observed += 1
            if observed == occurrence:
                raise RuntimeError("before first write")
        publish(directory, record, raw, owner, immutable=immutable, failure_hook=failure_hook)

    monkeypatch.setattr(local, "_publish", before)
    with pytest.raises(RuntimeError, match="before first write"):
        commit(closed)
    read(closed)
    assert (closed / FIRST_SEGMENT).exists()
    monkeypatch.setattr(local, "_publish", publish)
    commit(closed)
    assert len(read(closed).segments) == 1
