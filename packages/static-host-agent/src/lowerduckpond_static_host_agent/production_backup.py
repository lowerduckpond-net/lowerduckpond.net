"""Prove an exact rollout backup by restoring and remeasuring its inert trees."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent.audit_archive_formats import (
    MAX_DESCRIPTOR_BYTES,
    decode_head,
)
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_sources import SOURCE_PATHS, STAGED_PATHS
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreStore,
    full_id,
)
from lowerduckpond_static_host_agent.host_restore_materialize import (
    MaterializationPaths,
    materialize_private_snapshot,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import (
    inspect_restore_tree,
    select_restore_snapshot,
)
from lowerduckpond_static_host_agent.host_restore_validation import (
    require_trusted_policy,
    validate_restored_authority,
)


@dataclass(frozen=True)
class BackupAuthority:
    """Bindings supplied by the original leased rollout, never by restored data."""

    original_sha256: str
    phase_sha256: str
    report_sha256: str
    artifact_sha256: str
    repository_binding: str
    lineage_sha256: str
    namespace: dict[str, object]
    launch: dict[str, object] | None

    def document(self) -> dict[str, object]:
        for value in (
            self.original_sha256,
            self.phase_sha256,
            self.report_sha256,
            self.artifact_sha256,
            self.repository_binding,
            self.lineage_sha256,
        ):
            full_id(value)
        return asdict(self)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_backup(  # noqa: PLR0913 - original authority and privilege boundaries
    snapshot_id: str,
    environment: Mapping[str, str],
    authority: BackupAuthority,
    directory: Path,
    paths: MaterializationPaths,
    *,
    owner: int,
    content_group: int,
) -> dict[str, str]:
    """Caller holds the rollout action, repository EX and selected artifact SH.

    The caller supplies an owned private evidence directory outside all
    live backup sources, plus inert sibling destinations. A failed restoration
    retains its original inputs and partial trees. Retry reuses their exact
    snapshot and inodes; a different snapshot or rollout cannot replace them.
    This verifies a production backup, not a new live-provider qualification.
    """
    protected = [*(Path(value) for value in SOURCE_PATHS.values())]
    protected.append(Path(STAGED_PATHS["database"]).parent)
    for target in (directory, paths.workspace, *paths.targets().values()):
        if target != target.resolve() or any(
            target.is_relative_to(source) or source.is_relative_to(target) for source in protected
        ):
            raise HostRestoreError("production backup proof must use private inert destinations")
    with RestoreStore.locked(directory, owner=owner) as store:
        return _verify_backup(
            snapshot_id, environment, authority, store, paths, content_group=content_group
        )


def _verify_backup(  # noqa: PLR0913 - original authority and privilege boundaries
    snapshot_id: str,
    environment: Mapping[str, str],
    authority: BackupAuthority,
    store: RestoreStore,
    paths: MaterializationPaths,
    *,
    content_group: int,
) -> dict[str, str]:
    full_id(snapshot_id)
    inputs = canonical_json_bytes(
        {
            "format": "lowerduckpond-production-backup-verification-v1",
            "snapshot_id": snapshot_id,
            "authority": authority.document(),
        },
        maximum_bytes=MAX_RESTORE_BYTES,
    )
    if store.read() is not None:
        raise HostRestoreError("production backup proof cannot use a recovery journal")
    store.immutable("backup-inputs.json", inputs)
    snapshot = select_restore_snapshot(snapshot_id, environment)
    if (
        snapshot.identity.binding()["value"] != authority.repository_binding
        or _sha256(canonical_json_bytes(snapshot.lineage)) != authority.lineage_sha256
    ):
        raise HostRestoreError("production backup repository or original lineage changed")
    require_trusted_policy(
        decode_backup_descriptor(snapshot.descriptor),
        repository_genesis=snapshot.lineage,
        artifact_sha256=authority.artifact_sha256,
        namespace=authority.namespace,
        launch=authority.launch,
    )
    filesystems = paths.filesystems()
    inspection = inspect_restore_tree(
        snapshot,
        environment,
        owner=store.owner,
        group=content_group,
        fragments={
            label: filesystems[label].fragment_size for label in (*SOURCE_PATHS, *STAGED_PATHS)
        },
    )
    store.immutable("backup-inspection.json", canonical_json_bytes(inspection))
    materialize_private_snapshot(store, snapshot, paths, environment, inspection)
    measured = validate_restored_authority(
        snapshot.descriptor,
        paths.roots,
        paths.workspace,
        owner=store.owner,
        content_group=content_group,
        repository_genesis=snapshot.lineage,
        artifact_sha256=authority.artifact_sha256,
        namespace=authority.namespace,
        launch=authority.launch,
    )
    raw = canonical_json_bytes(measured, maximum_bytes=MAX_RESTORE_BYTES)
    with DurableDirectory.open(
        paths.roots["state"], expected_owner=store.owner, expected_directory_mode=0o700
    ) as state:
        head = state.read_regular(
            ("audit", "archive", "head.json"),
            expected_owner=store.owner,
            expected_mode=0o600,
            maximum_bytes=MAX_DESCRIPTOR_BYTES,
        )
    decoded = decode_head(head)
    if (
        decoded["lineageId"] != snapshot.lineage["lineageId"]
        or decoded["repositoryBinding"] != snapshot.identity.binding()
    ):
        raise HostRestoreError("production restored audit index differs from its repository")
    # Remeasure the exact restored authority before retaining any passing result.
    # No timestamp, provider proof, rollout phase or host completion is invented.
    store.immutable("backup-restored-authority.json", raw)
    result = {
        "snapshot_id": snapshot_id,
        "descriptor_sha256": _sha256(snapshot.descriptor),
        "index_sha256": _sha256(head),
        "restored_tree_sha256": _sha256(raw),
        "report_sha256": authority.report_sha256,
    }
    store.immutable("backup-verified.json", canonical_json_bytes(cast(dict[str, object], result)))
    descriptor = store.directory.duplicate_descriptor()
    try:
        # Confirm a previously visible but unacknowledged rename before returning
        # the proof to the separately journaled rollout controller.
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return result
