"""Retain one original rollout capture and recover its exact remote outcome."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_coordinator import CapturePaths, capture_backup
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import discover_repository, repository_genesis
from lowerduckpond_static_host_agent.backup_snapshot import create_coherent_snapshot
from lowerduckpond_static_host_agent.backup_sources import MAX_TREE_BYTES
from lowerduckpond_static_host_agent.durable import validate_regular_state_file
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    RestoreStore,
    full_id,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import select_restore_snapshot
from lowerduckpond_static_host_agent.host_restore_validation import require_trusted_policy
from lowerduckpond_static_host_agent.production_backup import BackupAuthority

CHUNK = 64 * 1024


def _database(path: Path, owner: int) -> dict[str, object]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = validate_regular_state_file(fd, expected_owner=owner, expected_mode=0o600)
        if not 0 < before.st_size <= MAX_TREE_BYTES:
            raise BackupIdentityError("production database staging exceeds its bound")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(CHUNK, remaining))
            if not block:
                raise BackupIdentityError("production database staging was truncated")
            digest.update(block)
            remaining -= len(block)
        after = os.fstat(fd)
        named = path.stat(follow_symlinks=False)
        if (
            os.read(fd, 1)
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise BackupIdentityError("production database staging changed")
        return {"size": before.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def _proposal(store: RestoreStore) -> dict[str, object] | None:
    try:
        raw = store.read_bytes("capture-proposal.json")
    except FileNotFoundError:
        return None
    decode_backup_descriptor(raw)
    database_raw = store.read_bytes("capture-database.json")
    database = decode_json_object(database_raw)
    if (
        set(database) != {"size", "sha256"}
        or type(database["size"]) is not int
        or not 0 < database["size"] <= MAX_TREE_BYTES
        or canonical_json_bytes(database) != database_raw
    ):
        raise BackupIdentityError("production database proposal is invalid")
    full_id(database["sha256"])
    return {"descriptor": raw.decode("ascii"), "database": database}


def _sync(store: RestoreStore) -> None:
    descriptor = store.directory.duplicate_descriptor()
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def capture_rollout_backup(
    paths: CapturePaths,
    environment: Mapping[str, str],
    authority: BackupAuthority,
    store: RestoreStore,
    *,
    content_group: int,
) -> str:
    """Caller holds rollout/repository/selection leases and retains its SQL dump.

    A descriptor and database digest are durably retained BEFORE remote upload.
    Retry first discovers the exact original capture. If absent, upload may resume
    only after remeasuring identical live authority and the original staged dump.
    No latest-snapshot selection, new timestamp or replacement capture ID occurs.
    """
    scope = full_id(environment.get("LOWERDUCKPOND_BACKUP_STATUS_SCOPE"))
    if store.read() is not None:
        raise BackupIdentityError("production capture cannot use a recovery journal")
    store.immutable(
        "capture-inputs.json",
        canonical_json_bytes(
            {"authority": authority.document(), "scope": scope}, maximum_bytes=MAX_RESTORE_BYTES
        ),
    )
    original = _proposal(store)
    # A prior caller can die after rename and before its directory fsync. Confirm
    # the visible original proposal is durable before any remote side effect.
    _sync(store)
    identity, snapshots = discover_repository(environment)
    lineage = repository_genesis(identity, snapshots, environment)
    if (
        identity.binding()["value"] != authority.repository_binding
        or lineage is None
        or hashlib.sha256(canonical_json_bytes(lineage)).hexdigest() != authority.lineage_sha256
    ):
        raise BackupIdentityError("production capture repository or original lineage changed")
    prior = None if original is None else cast(str, original["descriptor"]).encode("ascii")
    if prior is not None:
        descriptor = decode_backup_descriptor(prior)
        require_trusted_policy(
            descriptor,
            repository_genesis=lineage,
            artifact_sha256=authority.artifact_sha256,
            namespace=authority.namespace,
            launch=authority.launch,
        )
        matches = [item for item in snapshots if f"capture-{descriptor['captureId']}" in item.tags]
        if len(matches) > 1:
            raise BackupIdentityError("production capture has ambiguous remote outcomes")
        if matches:
            selected = select_restore_snapshot(matches[0].snapshot_id, environment)
            if (
                selected.descriptor != prior
                or selected.identity != identity
                or f"scope-{scope}" not in selected.snapshot.tags
            ):
                raise BackupIdentityError("production capture readback changed")
            return _finish(store, selected.snapshot.snapshot_id)
    try:
        store.read_bytes("capture-result.json")
    except FileNotFoundError:
        pass
    else:
        raise BackupIdentityError("production capture lost its acknowledged snapshot")
    database = _database(paths.staging / "mariadb.sql.gz", store.owner)
    if original is not None and database != original["database"]:
        raise BackupIdentityError("production capture lost its original database dump")

    def retained(raw: bytes, active_environment: Mapping[str, str]) -> str:
        require_trusted_policy(
            decode_backup_descriptor(raw),
            repository_genesis=lineage,
            artifact_sha256=authority.artifact_sha256,
            namespace=authority.namespace,
            launch=authority.launch,
        )
        if _database(paths.staging / "mariadb.sql.gz", store.owner) != database:
            raise BackupIdentityError("production database staging changed before capture")
        # Keep the descriptor byte-exact and within its existing full bound;
        # embedding it as an escaped JSON string would inflate that bound. The
        # descriptor is published last, after its immutable database binding.
        store.immutable("capture-database.json", canonical_json_bytes(database))
        store.immutable("capture-proposal.json", raw)
        _sync(store)
        snapshot_id = create_coherent_snapshot(raw, active_environment)
        if _database(paths.staging / "mariadb.sql.gz", store.owner) != database:
            raise BackupIdentityError("production database staging changed during capture")
        return snapshot_id

    snapshot_id = capture_backup(
        paths,
        environment,
        artifact_sha256=authority.artifact_sha256,
        expected_owner=store.owner,
        content_group=content_group,
        original_descriptor=prior,
        capture=retained,
    )
    return _finish(store, snapshot_id)


def _finish(store: RestoreStore, snapshot_id: str) -> str:
    full_id(snapshot_id)
    store.immutable("capture-result.json", canonical_json_bytes({"snapshot_id": snapshot_id}))
    _sync(store)
    return snapshot_id
