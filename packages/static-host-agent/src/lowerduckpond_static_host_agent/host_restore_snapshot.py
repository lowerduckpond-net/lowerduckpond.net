"""Exact scheduled-snapshot discovery and preallocation tree inspection."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Final, cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_descriptor import (
    MAX_BACKUP_DESCRIPTOR_BYTES,
    decode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import RepositoryIdentity, framed_digest
from lowerduckpond_static_host_agent.backup_restic import (
    RepositorySnapshot,
    _restic,
    discover_repository,
    repository_genesis,
)
from lowerduckpond_static_host_agent.backup_snapshot import STATIC_BACKUP_TAG
from lowerduckpond_static_host_agent.backup_sources import (
    MAX_DEPTH,
    MAX_FILE_BYTES,
    MAX_INVENTORY_BYTES,
    MAX_TREE_BYTES,
    MAX_TREE_ENTRIES,
    SOURCE_PATHS,
    STAGED_PATHS,
)
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, full_id

MAX_NODE_BYTES: Final = 16 * 1024 * 1024
MAX_RESIDENT_TREE_BYTES: Final = 32 * 1024 * 1024
SNAPSHOT_TREE_FORMAT: Final = "lowerduckpond-host-restore-snapshot-tree-v1"
_GO_DIRECTORY: Final = 1 << 31
_MAX_COMPONENT_BYTES: Final = 255
_SOURCES: Final = {**SOURCE_PATHS, **STAGED_PATHS}


@dataclass(frozen=True)
class RestoreSnapshot:
    identity: RepositoryIdentity
    snapshot: RepositorySnapshot
    descriptor: bytes
    lineage: dict[str, object]


def select_restore_snapshot(snapshot_id: str, environment: Mapping[str, str]) -> RestoreSnapshot:
    """A full supplied ID must uniquely bind the scheduled descriptor and lineage."""
    full_id(snapshot_id)
    identity, inventory = discover_repository(environment)
    selected = [entry for entry in inventory if entry.snapshot_id == snapshot_id]
    if len(selected) != 1:
        raise HostRestoreError("restore_snapshot_unavailable")
    snapshot = selected[0]
    lineage = repository_genesis(identity, inventory, environment)
    if lineage is None:
        raise HostRestoreError("restore_lineage_unavailable")
    raw = _restic(
        ("dump", snapshot_id, STAGED_PATHS["descriptor"]), environment, MAX_BACKUP_DESCRIPTOR_BYTES
    )
    descriptor = decode_backup_descriptor(raw)
    tags = set(snapshot.tags)
    scope = [tag for tag in tags if tag.startswith("scope-")]
    expected = {
        "scheduled",
        STATIC_BACKUP_TAG,
        f"capture-{descriptor['captureId']}",
        f"lineage-{lineage['lineageId']}",
        f"repository-{identity.binding()['value']}",
    }
    if len(scope) != 1:
        raise HostRestoreError("restore_snapshot_binding_mismatch")
    full_id(scope[0].removeprefix("scope-"))
    if (
        tags != expected | set(scope)
        or snapshot.hostname != identity.node_name
        or set(snapshot.paths) != set(_SOURCES.values())
        or descriptor["lineage"] != lineage
        or len([item for item in inventory if f"capture-{descriptor['captureId']}" in item.tags])
        != 1
    ):
        raise HostRestoreError("restore_snapshot_binding_mismatch")
    return RestoreSnapshot(identity, snapshot, raw, lineage)


@dataclass
class _TreeWalk:
    environment: Mapping[str, str]
    owner: int
    group: int
    fragments: Mapping[str, int]
    usage: dict[str, dict[str, int]]
    metadata_bytes: int = 0
    entries: int = 0
    content_bytes: int = 0
    root_metadata: dict[str, dict[str, int]] = field(default_factory=dict)

    def walk(
        self, tree: str, path: PurePosixPath, ancestors: tuple[str, ...] = (), resident: int = 0
    ) -> None:
        full_id(tree)
        if tree in ancestors or len(path.parts) > MAX_DEPTH:
            raise HostRestoreError("restore_tree_depth_or_cycle")
        limit = min(
            MAX_NODE_BYTES,
            MAX_INVENTORY_BYTES - self.metadata_bytes,
            MAX_RESIDENT_TREE_BYTES - resident,
        )
        if limit <= 0:
            raise HostRestoreError("restore_tree_resource_limit")
        raw = _restic(("cat", "blob", tree), self.environment, limit)
        self.metadata_bytes += len(raw)
        document = decode_json_object(raw, maximum_bytes=limit)
        nodes = document.get("nodes")
        if set(document) != {"nodes"} or type(nodes) is not list:
            raise HostRestoreError("restore_tree_invalid")
        names: set[str] = set()
        for node in nodes:
            if type(node) is not dict:
                raise HostRestoreError("restore_node_invalid")
            name = node.get("name")
            if (
                type(name) is not str
                or name in {"", ".", ".."}
                or "/" in name
                or "\0" in name
                or name in names
                or len(name.encode()) > _MAX_COMPONENT_BYTES
            ):
                raise HostRestoreError("restore_node_path_invalid")
            names.add(name)
            child = path / name
            label = next(
                (
                    key
                    for key, value in _SOURCES.items()
                    if child == PurePosixPath(value) or child.is_relative_to(value)
                ),
                None,
            )
            structural = any(
                PurePosixPath(value).is_relative_to(child) for value in _SOURCES.values()
            )
            if label is None and not structural:
                raise HostRestoreError("restore_snapshot_has_unknown_input")
            self.entries += 1
            if self.entries > MAX_TREE_ENTRIES:
                raise HostRestoreError("restore_tree_resource_limit")
            self._node(node, child, label)
            if node["type"] == "dir":
                self.walk(
                    full_id(node.get("subtree")), child, (*ancestors, tree), resident + len(raw)
                )

    def _node(  # noqa: PLR0912 - explicit directory/file and included/structural metadata matrix
        self, node: dict[str, object], path: PurePosixPath, label: str | None
    ) -> None:
        kind = node.get("type")
        mode = node.get("mode")
        if (
            kind not in {"dir", "file"}
            or any(type(node.get(key)) is not int for key in ("mode", "uid", "gid"))
            or node["uid"] != self.owner
            or node["gid"] not in {self.owner, self.group}
            or any(
                node.get(key)
                for key in (
                    "extended_attributes",
                    "generic_attributes",
                    "linktarget",
                    "linktarget_raw",
                    "error",
                    "device",
                )
            )
        ):
            raise HostRestoreError("restore_node_metadata_unsafe")
        assert type(mode) is int  # noqa: S101 - exact numeric check above
        if kind == "dir":
            if node.get("content") or mode & ~(_GO_DIRECTORY | 0o777) or mode & 0o022:
                raise HostRestoreError("restore_directory_metadata_unsafe")
        elif (
            label is None
            or node.get("subtree")
            or type(node.get("links")) is not int
            or node["links"] != 1
        ):
            raise HostRestoreError("restore_file_metadata_unsafe")
        if label is None:
            return
        content = label == "content"
        allowed = (
            {0o711, 0o710, 0o750, 0o755}
            if content and kind == "dir"
            else {0o644, 0o640}
            if content
            else {0o700}
            if kind == "dir"
            else {0o600}
        )
        if mode & ~_GO_DIRECTORY not in allowed:
            raise HostRestoreError("restore_source_mode_unsafe")
        if path == PurePosixPath(_SOURCES[label]):
            self.root_metadata[label] = {
                "mode": mode & ~_GO_DIRECTORY,
                "owner": node["uid"],
                "group": node["gid"],
            }
        # A snapshot containing transient/secret paths contradicts its policy,
        # even when its file digest was omitted from the descriptor measurement.
        if any(
            path == PurePosixPath(value) or path.is_relative_to(value)
            for value in (
                "/var/lib/lowerduckpond/static/intake",
                "/var/lib/lowerduckpond/static/exports",
                "/srv/lowerduckpond/sites/.staging",
            )
        ) or path.name.startswith(".ldp-state-"):
            raise HostRestoreError("restore_snapshot_contains_excluded_input")
        size = 0 if kind == "dir" else node.get("size")
        maximum = (
            MAX_TREE_BYTES
            if label == "database"
            else MAX_BACKUP_DESCRIPTOR_BYTES
            if label == "descriptor"
            else MAX_FILE_BYTES
        )
        if type(size) is not int or not 0 <= size <= maximum:
            raise HostRestoreError("restore_file_size_invalid")
        self.content_bytes += size
        if self.content_bytes > MAX_TREE_BYTES:
            raise HostRestoreError("restore_tree_resource_limit")
        if kind == "file":
            blobs = node.get("content")
            if type(blobs) is not list or (size > 0 and not blobs):
                raise HostRestoreError("restore_file_content_invalid")
            for blob in blobs:
                full_id(blob)
        fragment = self.fragments[label]
        if type(fragment) is not int or fragment <= 0:
            raise HostRestoreError("restore_filesystem_fragment_invalid")
        row = self.usage.setdefault(label, {"entries": 0, "contentBytes": 0, "allocatedBytes": 0})
        row["entries"] += 1
        row["contentBytes"] += size
        # One directory-entry growth block plus one data/directory block reserve.
        row["allocatedBytes"] += fragment + max(
            fragment, ((size + fragment - 1) // fragment) * fragment
        )


def inspect_restore_tree(
    snapshot: RestoreSnapshot,
    environment: Mapping[str, str],
    *,
    owner: int,
    group: int,
    fragments: Mapping[str, int],
) -> dict[str, object]:
    if set(fragments) != set(_SOURCES):
        raise HostRestoreError("restore_filesystem_reservations_incomplete")
    raw = _restic(("cat", "snapshot", snapshot.snapshot.snapshot_id), environment, MAX_NODE_BYTES)
    header = decode_json_object(raw, maximum_bytes=MAX_NODE_BYTES)
    if (
        header.get("hostname") != snapshot.snapshot.hostname
        or header.get("paths") != list(snapshot.snapshot.paths)
        or header.get("tags") != list(snapshot.snapshot.tags)
    ):
        raise HostRestoreError("restore_snapshot_header_mismatch")
    tree = full_id(header.get("tree"))
    walk = _TreeWalk(environment, owner, group, fragments, {})
    walk.walk(tree, PurePosixPath("/"))
    if set(walk.usage) != set(_SOURCES):
        raise HostRestoreError("restore_snapshot_sources_incomplete")
    descriptor = decode_backup_descriptor(snapshot.descriptor)
    authority = cast(dict[str, object], descriptor["authority"])
    if (
        sum(walk.usage[label]["entries"] for label in SOURCE_PATHS) != authority["entryCount"]
        or sum(walk.usage[label]["contentBytes"] for label in SOURCE_PATHS)
        != authority["contentBytes"]
    ):
        raise HostRestoreError("restore_snapshot_inventory_mismatch")
    return {
        "snapshotId": snapshot.snapshot.snapshot_id,
        "tree": tree,
        "headerSha256": hashlib.sha256(raw).hexdigest(),
        "sourceUsage": walk.usage,
        "rootMetadata": walk.root_metadata,
        "descriptorDigest": framed_digest("lowerduckpond-static-backup-v1", snapshot.descriptor),
        "inventoryDigest": framed_digest(
            SNAPSHOT_TREE_FORMAT, canonical_json_bytes({"tree": tree, "usage": walk.usage})
        ),
    }
