"""Initialize only the empty production namespace's original protected lineage."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from pathlib import Path

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    decode_contract,
    platform_state_digest,
)

from lowerduckpond_static_host_agent import production_namespace as namespace
from lowerduckpond_static_host_agent.audit_archive_formats import decode_head
from lowerduckpond_static_host_agent.audit_archive_inventory import is_audit_snapshot
from lowerduckpond_static_host_agent.audit_archive_local import initialize_empty_archive
from lowerduckpond_static_host_agent.audit_archive_store import head_for_indexes
from lowerduckpond_static_host_agent.backup_entrypoint import ensure_lineage
from lowerduckpond_static_host_agent.backup_identity import (
    BINDING_FORMAT,
    GENESIS_PATH,
    LINEAGE_PATH,
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    decode_lineage,
    require_digest,
)
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    discover_repository,
    repository_genesis,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, StatePathError
from lowerduckpond_static_host_agent.locks import LockMode, LockName

HEAD = ("audit", "archive", "head.json")
MAX_TEMPORARIES = 64


def _metadata(directory: DurableDirectory, allowed: set[str], owner: int) -> None:
    descriptor = directory.duplicate_descriptor()
    try:
        with os.scandir(descriptor) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > len(allowed) + MAX_TEMPORARIES:
                    raise StatePathError("production metadata exceeds its recovery bound")
                if entry.name in allowed:
                    continue
                if re.fullmatch(r"\.ldp-state-[0-9a-f]{32}", entry.name) is None:
                    raise StatePathError("production migration found unexpected metadata")
                # Existing publication primitives own recovery of these bounded
                # temporaries. This inspection neither removes nor trusts them.
                directory.read_regular(
                    (entry.name,),
                    expected_owner=owner,
                    expected_mode=0o600,
                    maximum_bytes=MAX_IDENTITY_BYTES,
                )
    finally:
        os.close(descriptor)


def _read(root: DurableDirectory, path: tuple[str, ...], owner: int) -> bytes:
    return root.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_IDENTITY_BYTES
    )


def _shape(root: DurableDirectory, owner: int) -> None:
    if namespace._names(root, namespace.ROOTS) != namespace.ROOTS:
        raise StatePathError("production migration requires the complete static layout")
    for name in namespace.ROOTS:
        with root.open_descendant((name,)) as directory:
            if name == "platform":
                _metadata(directory, {"namespace.json", LINEAGE_PATH[-1]}, owner)
            elif name == "locks":
                _metadata(
                    directory, {*(lock.filename for lock in LockName), GENESIS_PATH[-1]}, owner
                )
            elif name == "audit":
                if namespace._names(directory, frozenset({"archive"})):
                    with directory.open_descendant(("archive",)) as archive:
                        _metadata(archive, {"head.json"}, owner)
            elif name == "authorization":
                if namespace._names(directory, namespace.AUTHORIZATION) != namespace.AUTHORIZATION:
                    raise StatePathError("production authorization layout is incomplete")
                for child in namespace.AUTHORIZATION:
                    with directory.open_descendant((child,)) as records:
                        namespace._names(records, frozenset())
            else:
                namespace._names(directory, frozenset())


def _inspect(
    root: DurableDirectory, original_namespace: bytes, binding: str, owner: int
) -> tuple[bytes | None, bytes | None]:
    _shape(root, owner)
    if _read(root, namespace.NAMESPACE, owner) != original_namespace:
        raise BackupIdentityError("production namespace differs from its original transaction")
    document = decode_contract(original_namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    if canonical_json_bytes(document) != original_namespace:
        raise BackupIdentityError("production namespace is not canonical")
    expected_namespace = platform_state_digest(document).to_dict()
    local: list[bytes | None] = []
    for path in (GENESIS_PATH, LINEAGE_PATH):
        try:
            raw = _read(root, path, owner)
        except FileNotFoundError:
            local.append(None)
            continue
        lineage = decode_lineage(raw)
        if (
            require_digest(lineage["repositoryBinding"], BINDING_FORMAT)["value"] != binding
            or lineage["namespaceDigest"] != expected_namespace
            or lineage["initialEntryCount"] != 0
            or lineage["initialTerminalEntryDigest"] is not None
        ):
            raise BackupIdentityError(
                "production lineage differs from its empty original namespace"
            )
        local.append(raw)
    genesis, published = local
    if published is not None and genesis != published:
        raise BackupIdentityError("production lineage lost its original genesis")
    try:
        head_raw = _read(root, HEAD, owner)
    except FileNotFoundError:
        head_raw = None
    if head_raw is not None and (
        published is None
        or decode_head(head_raw) != head_for_indexes(decode_lineage(published), ())
    ):
        raise BackupIdentityError("production audit index is not the original empty lineage")
    return published, head_raw


def initialize(
    path: Path,
    original_namespace: bytes,
    binding: str,
    environment: Mapping[str, str],
    *,
    owner: int,
) -> dict[str, str]:
    """Caller holds the rollout action, repository EX and selected artifact SH.

    All network operations remain outside static-state locks. A lost response
    resumes the existing local proposal and independently verified full remote
    genesis; it never initializes a repository or replaces historical authority.
    """
    with namespace._transaction(path, owner, LockMode.SHARED) as root:
        _inspect(root, original_namespace, binding, owner)
    lineage = ensure_lineage(
        path,
        environment,
        initialize=True,
        expected_owner=owner,
        expected_repository_binding=binding,
    )
    identity, snapshots = discover_repository(environment)
    if (
        identity.binding()["value"] != binding
        or repository_genesis(identity, snapshots, environment) != lineage
        or any(is_audit_snapshot(snapshot) for snapshot in snapshots)
    ):
        raise BackupIdentityError("production repository changed its initial protected authority")
    # repository_genesis proved that exactly one full snapshot contains the
    # original canonical lineage, with its exact host, tags and one-file tree.
    snapshot_id = next(
        snapshot.snapshot_id for snapshot in snapshots if LINEAGE_TAG in snapshot.tags
    )
    with namespace._transaction(path, owner, LockMode.EXCLUSIVE) as root:
        _inspect(root, original_namespace, binding, owner)
        initialize_empty_archive(root, lineage, snapshots, owner)
        lineage_raw, head_raw = _inspect(root, original_namespace, binding, owner)
        if lineage_raw is None or lineage_raw != canonical_json_bytes(lineage) or head_raw is None:
            raise BackupIdentityError("production protected metadata is incomplete")
    return {
        "repository_binding": binding,
        "lineage_sha256": hashlib.sha256(lineage_raw).hexdigest(),
        "genesis_snapshot_id": snapshot_id,
        "audit_head_sha256": hashlib.sha256(head_raw).hexdigest(),
    }
