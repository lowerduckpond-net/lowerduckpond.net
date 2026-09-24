"""Reconstruct captured audit authority without replaying a later timeline."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent import audit_archive_coordinator as protection
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent import audit_archive_store as archive
from lowerduckpond_static_host_agent import audit_rotation_local as rotation
from lowerduckpond_static_host_agent.audit import audit_prefix_terminal
from lowerduckpond_static_host_agent.audit_archive_inventory import ProtectedProof
from lowerduckpond_static_host_agent.audit_rotation_coordinator import RotationPaths, rotate_archive
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_audit import (
    RestoreAuditProof,
    discover_restore_audit,
    next_restore_segment,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot


def _rebind_source(
    store: RestoreStore,
    root: DurableDirectory,
    current: local.LocalArchive,
    owner: int,
    hook: local.ArchiveFailureHook | None,
) -> None:
    intent = current.prefix.rotation_intent
    if intent is None:
        return
    descriptor = formats.validate_rotation(intent["descriptor"])
    path = ("audit", str(descriptor["segmentName"]))
    try:
        raw = root.read_regular(
            path, expected_owner=owner, expected_mode=0o600, maximum_bytes=formats.MAX_SEGMENT_BYTES
        )
    except FileNotFoundError:
        # An indexed unlink can have completed before the capture. The ordinary
        # finalizer separately demands fresh proof before retiring that intent.
        rotation.source_bytes(root, current, owner)
        return
    formats.verify_segment(descriptor, raw)
    generation = [
        str(value)
        for value in root.regular_metadata_generation(
            path, expected_owner=owner, expected_mode=0o600
        )
    ]
    validated = store.read_bytes("journal-validated.json")
    name = f"audit-source-{descriptor['rotationId']}.json"
    try:
        receipt = decode_json_object(store.read_bytes(name), maximum_bytes=MAX_RESTORE_BYTES)
    except FileNotFoundError:
        receipt = {
            "schema": "lowerduckpond-host-restore-audit-source-v1",
            "validatedJournal": decode_json_object(validated, maximum_bytes=MAX_RESTORE_BYTES),
            "originalIntent": intent,
            "sourceGeneration": generation,
        }
        store.immutable(name, canonical_json_bytes(receipt, maximum_bytes=MAX_RESTORE_BYTES))
    original = journal.decode_rotation_intent(canonical_json_bytes(receipt["originalIntent"]))
    if (
        set(receipt) != {"schema", "validatedJournal", "originalIntent", "sourceGeneration"}
        or receipt["schema"] != "lowerduckpond-host-restore-audit-source-v1"
        or canonical_json_bytes(receipt["validatedJournal"], maximum_bytes=MAX_RESTORE_BYTES)
        != validated
        or original["descriptor"] != descriptor
        or receipt["sourceGeneration"] != generation
        or intent["sourceGeneration"] not in (original["sourceGeneration"], generation)
    ):
        raise HostRestoreError("restore_audit_source_changed")
    if intent["sourceGeneration"] != generation:
        updated = {**intent, "sourceGeneration": generation}
        raw_intent = canonical_json_bytes(updated, maximum_bytes=journal.MAX_JOURNAL_BYTES)
        journal.decode_rotation_intent(raw_intent)
        local.publish_records(
            root, current, owner, [("rotation-intent.json", raw_intent, False)], failure_hook=hook
        )


def _adopt_next(
    root: DurableDirectory,
    current: local.LocalArchive,
    proof: ProtectedProof,
    owner: int,
    hook: local.ArchiveFailureHook | None,
) -> None:
    if current.prefix.maintenance_intent is not None:
        raise HostRestoreError("restore_audit_maintenance_conflict")
    intent, index = local._index_for_orphan(root, current, proof, owner)
    orphan = proof.orphan
    assert orphan is not None  # noqa: S101 - caller requires an independently verified next segment
    number = len(current.prefix.segments)
    indexes = (*tuple(segment.index for segment in current.prefix.segments), index)
    records = [
        (
            "rotation-intent.json",
            canonical_json_bytes(intent, maximum_bytes=journal.MAX_JOURNAL_BYTES),
            False,
        ),
        (archive.witness_name(number), orphan.witness, True),
        (
            archive.index_name(number),
            canonical_json_bytes(index, maximum_bytes=formats.MAX_INDEX_BYTES),
            True,
        ),
        (
            "head.json",
            canonical_json_bytes(archive.head_for_indexes(current.lineage, indexes)),
            False,
        ),
        (
            "rotation-intent.json",
            canonical_json_bytes(
                {**intent, "phase": "indexed"}, maximum_bytes=journal.MAX_JOURNAL_BYTES
            ),
            False,
        ),
    ]
    # Do not publish a partial "verified" status or discard duplicate evidence.
    # The final ordinary verifier commits those against the complete prefix.
    local.publish_records(root, current, owner, records, failure_hook=hook)


def _finish_indexed(
    root: DurableDirectory,
    current: local.LocalArchive,
    proof: ProtectedProof,
    owner: int,
    hook: local.ArchiveFailureHook | None,
) -> bool:
    intent = current.prefix.rotation_intent
    if intent is None:
        return False
    descriptor = formats.validate_rotation(intent["descriptor"])
    number = cast(int, descriptor["segmentNumber"])
    if number >= len(current.prefix.segments):
        return False
    if current.prefix.segments[number].descriptor != descriptor:
        raise HostRestoreError("restore_audit_index_mismatch")
    if intent["phase"] != "indexed":
        local.publish_records(
            root,
            current,
            owner,
            [("rotation-intent.json", canonical_json_bytes({**intent, "phase": "indexed"}), False)],
            failure_hook=hook,
        )
        current = local.observe_archive(root, current.lineage, owner)
    rotation.remove_indexed_source(root, current, proof, owner, failure_hook=hook)
    current = local.observe_archive(root, current.lineage, owner)
    rotation.complete_rotation(root, current, owner, failure_hook=hook)
    return True


def _require_boundary(current: local.LocalArchive, snapshot: RestoreSnapshot) -> None:
    boundary = cast(dict[str, object], decode_backup_descriptor(snapshot.descriptor)["audit"])
    if (
        current.audit.entry_count != boundary["entryCount"]
        or current.audit.terminal_digest != boundary["terminalEntryDigest"]
    ):
        raise HostRestoreError("restore_audit_local_boundary_changed")


def reconstruct_audit(  # noqa: PLR0913 - private roots, original snapshot and credential boundary
    store: RestoreStore,
    snapshot: RestoreSnapshot,
    paths: RotationPaths,
    environment: Mapping[str, str],
    *,
    owner: int,
    group: int,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> dict[str, object]:
    """Caller holds repository EX, selection SH and the restore coordinator lease.

    No network operation holds a tenant-state lock. Every resumed invocation
    independently verifies the entire protected inventory before altering private
    authority. Original backup bytes remain untouched. Individual prefix steps
    reuse only this invocation's proof under the continuous repository lease.
    """
    restoring = store.read()
    if restoring is None or restoring.phase is not RestorePhase.VALIDATED:
        raise HostRestoreError("restore_audit_requires_validated_state")
    discovered: RestoreAuditProof | None = None
    for _ in range(formats.MAX_ARCHIVED_SEGMENTS + 2):
        with local.archive_transaction(paths.root, owner) as root:
            captured = local.observe_archive(root, snapshot.lineage, owner)
            _require_boundary(captured, snapshot)
        if discovered is None:
            discovered = discover_restore_audit(
                snapshot, captured.prefix, environment, paths.workspace, owner=owner, group=group
            )
        proof = next_restore_segment(
            snapshot,
            discovered,
            captured.prefix,
            environment,
            paths.workspace,
            owner=owner,
            group=group,
        )
        with local.archive_transaction(paths.root, owner) as root:
            current = local.observe_archive(root, snapshot.lineage, owner)
            local.require_same_authority(captured, current)
            _rebind_source(store, root, current, owner, failure_hook)
            current = local.observe_archive(root, snapshot.lineage, owner)
            if _finish_indexed(root, current, proof, owner, failure_hook):
                continue
            if proof.orphan is not None:
                _adopt_next(root, current, proof, owner, failure_hook)
                current = local.observe_archive(root, snapshot.lineage, owner)
                _finish_indexed(root, current, proof, owner, failure_hook)
                continue
        if current.prefix.rotation_intent is not None:
            rotate_archive(
                paths,
                environment,
                expected_owner=owner,
                expected_group=group,
                failure_hook=failure_hook,
            )
            discovered = None
            continue
        if current.prefix.maintenance_intent is not None:
            intent = current.prefix.maintenance_intent
            if snapshot.snapshot.snapshot_id in journal.snapshot_ids(intent["removeIds"]):
                raise HostRestoreError("restore_original_snapshot_retention_conflict")
            protection._require_maintenance_proof(
                intent,
                protection.VerifiedArchive(
                    snapshot.identity, discovered.snapshots, current, discovered.proof
                ),
            )
            protection.maintain_archive(
                paths,
                environment,
                expected_owner=owner,
                expected_group=group,
                failure_hook=failure_hook,
            )
            discovered = None
            continue
        verified = protection.verify_archive(
            paths,
            environment,
            expected_owner=owner,
            expected_group=group,
            failure_hook=failure_hook,
        )
        _require_boundary(verified.local, snapshot)
        if verified.proof.inventory_digest != discovered.proof.inventory_digest:
            raise HostRestoreError("restore_audit_inventory_changed")
        return {
            "schema": "lowerduckpond-host-restore-audit-v1",
            "inventoryDigest": verified.proof.inventory_digest,
            "protectedSnapshotCount": len(verified.proof.snapshot_ids),
            "headDigest": local.head_digest(verified.local.prefix),
            "entryCount": verified.local.audit.entry_count,
            "terminalEntryDigest": verified.local.audit.terminal_digest,
        }
    raise HostRestoreError("restore_audit_iteration_limit")


def verify_reconstructed_audit(
    store: RestoreStore,
    snapshot: RestoreSnapshot,
    paths: RotationPaths,
    environment: Mapping[str, str],
) -> dict[str, object]:
    """Reverify the original prefix after finalizers have appended their own audit.

    The immutable checkpoint is committed before any local finalizer. Resuming
    must never rerun reconstruction against an extended local boundary or rely
    on a saved remote-proof status from a previous process.
    """
    raw = store.read_bytes("audit-done.json")
    saved = decode_json_object(raw)
    validated = RestoreJournal.from_bytes(store.read_bytes("journal-validated.json"))
    if (
        saved.get("schema") != "lowerduckpond-host-restore-audit-done-v1"
        or saved.get("validatedJournalDigest") != validated.digest
        or canonical_json_bytes(saved) != raw
    ):
        raise HostRestoreError("restore_audit_completion_unbound")
    boundary = cast(dict[str, object], decode_backup_descriptor(snapshot.descriptor)["audit"])
    with local.archive_transaction(paths.root, store.owner) as root:
        current = local.observe_archive(root, snapshot.lineage, store.owner)
        if (
            current.prefix.rotation_intent is not None
            or current.prefix.maintenance_intent is not None
        ):
            raise HostRestoreError("restore_audit_journal_reappeared")
        if (
            audit_prefix_terminal(
                root,
                cast(int, boundary["entryCount"]),
                expected_owner=store.owner,
                expected_directory_mode=0o700,
                expected_record_mode=0o600,
            )
            != boundary["terminalEntryDigest"]
        ):
            raise HostRestoreError("restore_original_audit_prefix_changed")
    discovered = discover_restore_audit(
        snapshot,
        current.prefix,
        environment,
        paths.workspace,
        owner=store.owner,
        group=store.owner,
    )
    verified = protection.verify_archive(
        paths,
        environment,
        expected_owner=store.owner,
        expected_group=store.owner,
    )
    if verified.proof.inventory_digest != discovered.proof.inventory_digest:
        raise HostRestoreError("restore_audit_inventory_changed")
    return {
        "checkpointDigest": framed_digest("lowerduckpond-host-restore-audit-done-v1", raw),
        "inventoryDigest": verified.proof.inventory_digest,
        "headDigest": local.head_digest(verified.local.prefix),
    }
