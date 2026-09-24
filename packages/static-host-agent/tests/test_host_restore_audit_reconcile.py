from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import audit_entry_digest, canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_coordinator as protection
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent import audit_rotation_coordinator as rotation
from lowerduckpond_static_host_agent import host_restore_audit as discovery
from lowerduckpond_static_host_agent import host_restore_audit_reconcile as reconciliation
from lowerduckpond_static_host_agent.audit import AuditError, append_audit, audit_prefix_terminal
from lowerduckpond_static_host_agent.backup_descriptor import encode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.durable import DurabilityBoundary
from lowerduckpond_static_host_agent.host_restore_audit_reconcile import (
    reconstruct_audit,
    verify_reconstructed_audit,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from test_audit_archive_formats import IDENTITY, entry
from test_audit_archive_store import lineage, read
from test_audit_archive_store import state as state  # noqa: PLC0414 - shared archive fixture
from test_audit_archived_history import FIRST_SEGMENT, LIMITS, TAIL_SEGMENT
from test_audit_rotation import SNAPSHOT, Remote
from test_audit_rotation import (
    remote as remote,  # noqa: PLC0414 - real rotation and fake repository
)
from test_backup_descriptor import document as document  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414


def selected(remote: Remote, document: dict[str, object]) -> RestoreSnapshot:
    with local.archive_transaction(remote.root, os.geteuid()) as directory:
        observed = local.observe_archive(directory, lineage(remote.root), os.geteuid())
    document.update(
        lineage=observed.lineage,
        namespaceDigest=observed.lineage["namespaceDigest"],
        capturedAt="2026-09-22T00:00:00Z",
        audit={
            "entryCount": observed.audit.entry_count,
            "segmentCount": observed.audit.segment_count,
            "terminalEntryDigest": observed.audit.terminal_digest,
        },
    )
    return RestoreSnapshot(
        IDENTITY,
        RepositorySnapshot("a" * 64, IDENTITY.node_name, ("scheduled",)),
        encode_backup_descriptor(document),
        observed.lineage,
    )


def destination(remote: Remote, monkeypatch: pytest.MonkeyPatch) -> Path:
    original = remote.root
    candidate = original.parent / "restored"
    shutil.copytree(original, candidate)
    remote.root = candidate
    remote.paths = replace(remote.paths, root=candidate)
    for module in (discovery, protection):
        monkeypatch.setattr(module, "discover_repository", remote.discover)
        monkeypatch.setattr(module, "repository_genesis", remote.genesis)
    monkeypatch.setattr(discovery, "verify_audit_snapshot", remote.restore)
    return original


def validated(store: RestoreStore, journal: RestoreJournal) -> None:
    store.begin(journal)
    current = store.advance(journal, RestorePhase.RESTORED, {"bytes": "measured"})
    store.advance(current, RestorePhase.VALIDATED, {"authority": "verified"})


def test_audit_checkpoint_reverifies_remote_proof_after_local_finalizer_appends(
    remote: Remote,
    root: Path,
    journal: RestoreJournal,
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert remote.rotate()
    monkeypatch.setattr(
        reconciliation, "audit_prefix_terminal", partial(audit_prefix_terminal, limits=LIMITS)
    )
    snapshot = selected(remote, document)
    destination(remote, monkeypatch)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        validated(store, journal)
        evidence = reconstruct_audit(
            store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid()
        )
        current = store.read()
        assert current is not None
        store.immutable(
            "audit-done.json",
            canonical_json_bytes(
                {
                    "schema": "lowerduckpond-host-restore-audit-done-v1",
                    "validatedJournalDigest": current.digest,
                    "evidence": evidence,
                }
            ),
        )
        with local.archive_transaction(remote.root, os.geteuid()) as directory:
            observed = local.observe_archive(directory, snapshot.lineage, os.geteuid())
            append_audit(
                directory,
                entry(observed.audit.entry_count, observed.audit.terminal_digest),
                expected_owner=os.geteuid(),
                expected_directory_mode=0o700,
                expected_record_mode=0o600,
                administrator=True,
                limits=LIMITS,
            )
        with pytest.raises(HostRestoreError, match="local_boundary_changed"):
            reconstruct_audit(
                store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid()
            )
        remote.events.clear()
        proof = verify_reconstructed_audit(store, snapshot, remote.paths, {})
        assert "discover" in remote.events
        assert "restore" in remote.events
        assert proof["checkpointDigest"]
        # A saved checkpoint grants no permission when exact remote evidence
        # disappears or cannot be downloaded on the resumed invocation.
        remote.fault = "restore"
        with pytest.raises(BackupIdentityError, match="remote restore failed"):
            verify_reconstructed_audit(store, snapshot, remote.paths, {})


@pytest.mark.parametrize("interrupted", [False, True])
def test_multiple_post_capture_segments_extend_only_the_identical_captured_suffix(  # noqa: PLR0913, PLR0917 - indexed overlap interruption
    remote: Remote,
    root: Path,
    journal: RestoreJournal,
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    tail = remote.root / TAIL_SEGMENT
    segment = bytearray(tail.read_bytes())
    previous = json.loads(segment)
    while True:
        item = entry(previous["sequence"] + 1, audit_entry_digest(previous).to_dict())
        raw = canonical_json_bytes(item)
        if len(segment) + len(raw) > LIMITS.maximum_segment_bytes:
            tail.write_bytes(segment)
            successor = remote.root / "audit/segment-00000000000000000002.jsonl"
            successor.write_bytes(raw)
            successor.chmod(0o600)
            break
        segment.extend(raw)
        previous = item
    snapshot = selected(remote, document)
    backup = remote.root.parent / "backup"
    shutil.copytree(remote.root, backup)
    assert remote.rotate()
    first_payload, first_snapshot = remote.payloads[SNAPSHOT], remote.snapshots[SNAPSHOT]

    def second(record: dict[str, object], environment: dict[str, str]) -> str:
        remote.create(record, environment)
        remote.payloads["f" * 64] = replace(remote.payloads[SNAPSHOT], snapshot_id="f" * 64)
        remote.snapshots["f" * 64] = replace(remote.snapshots[SNAPSHOT], snapshot_id="f" * 64)
        remote.payloads[SNAPSHOT], remote.snapshots[SNAPSHOT] = first_payload, first_snapshot
        return "f" * 64

    monkeypatch.setattr(rotation, "create_rotation_snapshot", second)
    assert remote.rotate()
    remote.root, remote.paths = backup, replace(remote.paths, root=backup)
    destination(remote, monkeypatch)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        validated(store, journal)
        if interrupted:

            def stop(record: str, boundary: DurabilityBoundary) -> None:
                if record == "head.json" and boundary is DurabilityBoundary.DIRECTORY_SYNC:
                    raise RuntimeError("indexed prefix with pending cleanup")

            with pytest.raises(RuntimeError, match="pending cleanup"):
                reconstruct_audit(
                    store,
                    snapshot,
                    remote.paths,
                    {},
                    owner=os.geteuid(),
                    group=os.getegid(),
                    failure_hook=stop,
                )
        receipt = reconstruct_audit(
            store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid()
        )
    assert len(read(remote.root).segments) == 2  # noqa: PLR2004 - two independent post-capture rotations
    assert not (remote.root / FIRST_SEGMENT).exists() and not (remote.root / TAIL_SEGMENT).exists()
    assert (remote.root / "audit" / successor.name).read_bytes() == successor.read_bytes()
    assert receipt["entryCount"] == cast(dict[str, object], document["audit"])["entryCount"]


def test_prepared_rotation_without_snapshot_reuses_the_original_sealed_attempt(
    remote: Remote,
    root: Path,
    journal: RestoreJournal,
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = selected(remote, document)
    remote.fault = "before-snapshot"
    with pytest.raises(RuntimeError, match="before effect"):
        remote.rotate()
    original = read(remote.root).rotation_intent
    assert original is not None
    remote.fault = None
    destination(remote, monkeypatch)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        validated(store, journal)
        reconstruct_audit(store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid())
    assert read(remote.root).segments[0].descriptor == original["descriptor"]
    assert len(remote.payloads) == 1


@pytest.mark.parametrize("captured_attempt", [False, True])
def test_reconstructs_post_backup_archive_without_replaying_or_losing_original_history(  # noqa: PLR0913, PLR0917 - independent fixture and capture phase
    remote: Remote,
    root: Path,
    journal: RestoreJournal,
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    captured_attempt: bool,
) -> None:
    snapshot = selected(remote, document)
    if captured_attempt:
        remote.fault = "lost-response"
        with pytest.raises(RuntimeError, match="response lost"):
            remote.rotate()
        remote.fault = None
        original = destination(remote, monkeypatch)
    else:
        # Capture local bytes first. The fenced source subsequently rotates only
        # the identical closed segment, without adding another audit entry.
        backup = remote.root.parent / "backup"
        shutil.copytree(remote.root, backup)
        assert remote.rotate()
        remote.root = backup
        remote.paths = replace(remote.paths, root=backup)
        original = destination(remote, monkeypatch)
    before = {
        path.relative_to(original): path.read_bytes()
        for path in original.rglob("*")
        if path.is_file()
    }
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        validated(store, journal)
        receipt = reconstruct_audit(
            store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid()
        )
        assert (
            reconstruct_audit(
                store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid()
            )
            == receipt
        )
    assert before == {
        path.relative_to(original): path.read_bytes()
        for path in original.rglob("*")
        if path.is_file()
    }
    assert not (remote.root / FIRST_SEGMENT).exists()
    assert (remote.root / TAIL_SEGMENT).read_bytes() == (original / TAIL_SEGMENT).read_bytes()
    prefix = read(remote.root)
    assert prefix.rotation_intent is None
    assert prefix.segments[0].data == before[Path(FIRST_SEGMENT)]
    assert prefix.protection_status is not None
    assert receipt["inventoryDigest"] == prefix.protection_status["protectedInventoryDigest"]
    assert remote.creates == 1
    assert len(list(root.glob("audit-source-*.json"))) == int(captured_attempt)


@pytest.mark.parametrize(
    "name",
    [
        "rotation-intent.json",
        "witness-00000000000000000000.json",
        "index-00000000000000000000.json",
        "head.json",
        "protection-status.json",
    ],
)
@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_interrupted_reconstruction_rediscovers_all_remote_proofs_before_finishing(  # noqa: PLR0913, PLR0917 - independent fault matrix
    remote: Remote,
    root: Path,
    journal: RestoreJournal,
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    boundary: DurabilityBoundary,
) -> None:
    snapshot = selected(remote, document)
    remote.fault = "lost-response"
    with pytest.raises(RuntimeError):
        remote.rotate()
    remote.fault = None
    original = destination(remote, monkeypatch)

    def stop(record: str, step: DurabilityBoundary) -> None:
        if record == name and step is boundary:
            raise RuntimeError("interrupted reconstruction")

    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        validated(store, journal)
        with pytest.raises(RuntimeError, match="interrupted reconstruction"):
            reconstruct_audit(
                store,
                snapshot,
                remote.paths,
                {},
                owner=os.geteuid(),
                group=os.getegid(),
                failure_hook=stop,
            )
        previous = remote.events.count("restore")
        reconstruct_audit(store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid())
        assert remote.events.count("restore") > previous
    assert read(remote.root).rotation_intent is None and remote.creates == 1
    assert (original / FIRST_SEGMENT).exists()
    assert read(remote.root).segments[0].data == (original / FIRST_SEGMENT).read_bytes()


@pytest.mark.parametrize(
    "fault", ["future", "missing", "hidden-reference", "source-corrupt", "source-replaced"]
)
def test_inconsistent_remote_or_private_authority_is_preserved_and_never_published(  # noqa: PLR0913, PLR0917 - independent fault matrix
    remote: Remote,
    root: Path,
    journal: RestoreJournal,
    document: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    snapshot = selected(remote, document)
    remote.fault = "lost-response"
    with pytest.raises(RuntimeError):
        remote.rotate()
    remote.fault = None
    # Make the captured intent name the known committed version.
    intent_path = remote.root / "audit/archive/rotation-intent.json"
    intent = read(remote.root).rotation_intent
    assert intent is not None
    intent_path.write_bytes(
        canonical_json_bytes({**intent, "phase": "discovered", "snapshotIds": [SNAPSHOT]})
    )
    original = destination(remote, monkeypatch)
    if fault == "future":
        boundary = cast(dict[str, object], document["audit"])
        boundary["entryCount"] = 1
        boundary["segmentCount"] = 1
        boundary["terminalEntryDigest"] = remote.payloads[SNAPSHOT].descriptor[
            "terminalEntryDigest"
        ]
        snapshot = replace(snapshot, descriptor=encode_backup_descriptor(document))
    elif fault == "missing":
        del remote.snapshots[SNAPSHOT]
    elif fault == "hidden-reference":
        remote.snapshots[SNAPSHOT] = replace(
            remote.snapshots[SNAPSHOT], tags=(), paths=("/unrelated",)
        )
    elif fault == "source-corrupt":
        path = remote.root / FIRST_SEGMENT
        path.write_bytes(
            path.read_bytes().replace(b"operator@example.test", b"attacker@example.test")
        )
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        validated(store, journal)
        if fault == "source-replaced":

            def stop(record: str, step: DurabilityBoundary) -> None:
                if record == "rotation-intent.json" and step is DurabilityBoundary.RENAME:
                    raise RuntimeError("after rebind")

            with pytest.raises(RuntimeError, match="after rebind"):
                reconstruct_audit(
                    store,
                    snapshot,
                    remote.paths,
                    {},
                    owner=os.geteuid(),
                    group=os.getegid(),
                    failure_hook=stop,
                )
            path = remote.root / FIRST_SEGMENT
            temporary = path.with_suffix(".saved")
            temporary.write_bytes(path.read_bytes())
            temporary.chmod(0o600)
            temporary.replace(path)
        before = {
            path.relative_to(remote.root): path.read_bytes()
            for path in remote.root.rglob("*")
            if path.is_file()
        }
        expected_error = (
            AssertionError
            if fault == "hidden-reference"
            else (HostRestoreError, BackupIdentityError, AuditError)
        )
        with pytest.raises(expected_error):
            reconstruct_audit(
                store, snapshot, remote.paths, {}, owner=os.geteuid(), group=os.getegid()
            )
        assert before == {
            path.relative_to(remote.root): path.read_bytes()
            for path in remote.root.rglob("*")
            if path.is_file()
        }
    assert (original / FIRST_SEGMENT).exists()
    assert remote.creates == 1 and not read(remote.root).segments
