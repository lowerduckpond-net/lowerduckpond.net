"""Bounded private Restic materialization on the eventual installation filesystems."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_descriptor import BACKUP_SCHEMA
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.backup_restic import _run_restic
from lowerduckpond_static_host_agent.backup_sources import (
    MAX_DEPTH,
    MAX_TREE_ENTRIES,
    SOURCE_PATHS,
    STAGED_PATHS,
)
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityRejectedError,
    FilesystemCapacity,
    measure_filesystem_capacity,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot

MATERIALIZE_SCHEMA = "lowerduckpond-host-restore-materialization-v1"
# New generated runtime, bounded audit/archive workspaces and immutable receipts.
# The source inventory separately reserves every restored data block and inode.
WORKSPACE_BYTES = 256 * 1024 * 1024
WORKSPACE_INODES = 1024


@dataclass(frozen=True)
class MaterializationPaths:
    roots: Mapping[str, Path]
    staging: Path
    workspace: Path

    def targets(self) -> dict[str, Path]:
        if set(self.roots) != set(SOURCE_PATHS):
            raise HostRestoreError("restore source destinations are incomplete")
        targets = {**self.roots, "staging": self.staging}
        values = (*targets.values(), self.workspace)
        if any(not path.is_absolute() for path in values):
            raise HostRestoreError("restore destination must be absolute")
        if any(
            left == right or left.is_relative_to(right) or right.is_relative_to(left)
            for index, left in enumerate(values)
            for right in values[index + 1 :]
        ):
            raise HostRestoreError("restore destinations overlap")
        return targets

    def filesystems(self) -> dict[str, FilesystemCapacity]:
        self.targets()
        return {
            **{
                label: measure_filesystem_capacity(path.parent)
                for label, path in self.roots.items()
            },
            **{label: measure_filesystem_capacity(self.staging.parent) for label in STAGED_PATHS},
            "workspace": measure_filesystem_capacity(self.workspace),
        }


def admit_restore_space(
    inspection: dict[str, object], filesystems: Mapping[str, FilesystemCapacity]
) -> dict[str, object]:
    """Reserve once per physical device, without crediting retained destination bytes.

    Existing candidates and prior roots are already charged by statvfs. A resumed
    materialization conservatively reserves a complete second write of each
    source: it cannot turn partially allocated data into fictitious free space.
    """
    labels = set(SOURCE_PATHS) | set(STAGED_PATHS)
    if set(filesystems) != labels | {"workspace"}:
        raise HostRestoreError("restore capacity inventory is incomplete")
    sources = exact_object(inspection.get("sourceUsage"), labels)
    by_device: dict[int, tuple[FilesystemCapacity, int, int]] = {}
    for label in sorted(filesystems):
        filesystem = filesystems[label]
        if label == "workspace":
            allocated, inodes = WORKSPACE_BYTES, WORKSPACE_INODES
        else:
            row = exact_object(sources[label], {"allocatedBytes", "entries", "contentBytes"})
            if any(type(value) is not int or value < 0 for value in row.values()):
                raise HostRestoreError("restore capacity evidence is invalid")
            allocated, inodes = cast(int, row["allocatedBytes"]), cast(int, row["entries"])
        if filesystem.device in by_device:
            prior, byte_count, inode_count = by_device[filesystem.device]
            if (
                prior.fragment_size != filesystem.fragment_size
                or prior.total_blocks != filesystem.total_blocks
                or prior.total_inodes != filesystem.total_inodes
            ):
                raise HostRestoreError("restore filesystem observations disagree")
            # Other processes may allocate between measurements; the smaller
            # free value is authoritative for this complete aggregate reservation.
            filesystem = FilesystemCapacity(
                prior.device,
                prior.fragment_size,
                prior.total_blocks,
                min(prior.available_blocks, filesystem.available_blocks),
                prior.total_inodes,
                min(prior.available_inodes, filesystem.available_inodes),
            )
            allocated += byte_count
            inodes += inode_count
        by_device[filesystem.device] = filesystem, allocated, inodes
    result: dict[str, object] = {}
    limits = DEFAULT_HOST_CAPACITY_LIMITS
    for device, (filesystem, allocated, inodes) in sorted(by_device.items()):
        required_bytes = max(
            limits.minimum_available_bytes,
            (filesystem.total_bytes * limits.minimum_available_percent + 99) // 100,
        )
        required_inodes = max(
            limits.minimum_available_inodes,
            (filesystem.total_inodes * limits.minimum_available_percent + 99) // 100,
        )
        if (
            filesystem.available_bytes - allocated < required_bytes
            or filesystem.available_inodes - inodes < required_inodes
        ):
            raise CapacityRejectedError("restore_capacity_unavailable")
        result[str(device)] = {"allocatedBytes": allocated, "inodes": inodes}
    return result


def _open_parent(path: Path, owner: int) -> int:
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(descriptor)
    if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) & 0o022:
        os.close(descriptor)
        raise HostRestoreError("restore private parent is unsafe")
    return descriptor


def _private_target(
    store: RestoreStore, label: str, path: Path, metadata_policy: dict[str, int]
) -> dict[str, object]:
    """Only a journal-bound directory may receive or resume a Restic restore."""
    parent = _open_parent(path, store.owner)
    try:
        try:
            raw = store.read_bytes(f"materialize-{label}.json")
        except FileNotFoundError:
            with suppress(FileExistsError):
                os.mkdir(path.name, mode=0o700, dir_fd=parent)
            child = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            try:
                metadata = os.fstat(child)
                if (
                    metadata.st_uid != store.owner
                    or metadata.st_gid != store.owner
                    or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004
                    or metadata.st_dev != os.fstat(parent).st_dev
                ):
                    raise HostRestoreError("restore private root is unsafe")
                with os.scandir(child) as entries:
                    if next(entries, None) is not None:
                        raise HostRestoreError("restore destination has unbound contents")
                os.fsync(child)
                os.fsync(parent)
                raw = canonical_json_bytes(
                    {
                        "schema": MATERIALIZE_SCHEMA,
                        "target": str(path),
                        "device": metadata.st_dev,
                        "inode": metadata.st_ino,
                        "metadata": metadata_policy,
                    }
                )
                store.immutable(f"materialize-{label}.json", raw)
            finally:
                os.close(child)
        result = exact_object(
            decode_json_object(raw), {"schema", "target", "device", "inode", "metadata"}
        )
        metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            canonical_json_bytes(result) != raw
            or result["schema"] != MATERIALIZE_SCHEMA
            or result["target"] != str(path)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != store.owner
            or metadata.st_gid not in {store.owner, metadata_policy["group"]}
            or stat.S_IMODE(metadata.st_mode) not in {0o700, metadata_policy["mode"]}
            or result["metadata"] != metadata_policy
            or result["device"] != metadata.st_dev
            or result["inode"] != metadata.st_ino
        ):
            raise HostRestoreError("restore private root identity changed")
        return result
    finally:
        os.close(parent)


def _sync_tree(path: Path) -> None:
    remaining = MAX_TREE_ENTRIES

    def sync(descriptor: int, depth: int) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            raise HostRestoreError("restore sync exceeds the verified tree bound")
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    child = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                        dir_fd=descriptor,
                    )
                    try:
                        sync(child, depth + 1)
                    finally:
                        os.close(child)
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise HostRestoreError("restore sync encountered an unsafe inode")
        os.fsync(descriptor)

    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        sync(descriptor, 0)
    finally:
        os.close(descriptor)


def _empty_excluded_directory(path: Path, owner: int) -> None:
    parent = _open_parent(path, owner)
    try:
        with suppress(FileExistsError):
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
        child = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            metadata = os.fstat(child)
            if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != 0o700:  # noqa: PLR2004
                raise HostRestoreError("restore transient directory is unsafe")
            with os.scandir(child) as entries:
                if next(entries, None) is not None:
                    raise HostRestoreError("restore transient input unexpectedly exists")
            os.fsync(child)
            os.fsync(parent)
        finally:
            os.close(child)
    finally:
        os.close(parent)


def materialize_snapshot(
    store: RestoreStore,
    snapshot: RestoreSnapshot,
    paths: MaterializationPaths,
    environment: Mapping[str, str],
    inspection: dict[str, object],
) -> dict[str, object]:
    journal = store.read()
    if (
        journal is None
        or journal.phase is not RestorePhase.PREPARED
        or journal.snapshot_id != snapshot.snapshot.snapshot_id
        or inspection.get("snapshotId") != journal.snapshot_id
        or inspection.get("descriptorDigest") != journal.bindings["backupDescriptor"]
    ):
        raise HostRestoreError("restore materialization lacks prepared authority")
    return materialize_private_snapshot(store, snapshot, paths, environment, inspection)


def materialize_private_snapshot(
    store: RestoreStore,
    snapshot: RestoreSnapshot,
    paths: MaterializationPaths,
    environment: Mapping[str, str],
    inspection: dict[str, object],
) -> dict[str, object]:
    """Restore inert trees after the caller binds its original operation authority.

    Full reconstruction requires its prepared journal above. Production backup
    verification instead retains its exact original rollout and snapshot inputs;
    it never creates a recovery journal or installs these private candidate roots.
    Both callers retain the repository/selection leases and use the same resource,
    metadata, inode, descriptor and Restic readback checks below.
    """
    snapshot_id = snapshot.snapshot.snapshot_id
    if inspection.get("snapshotId") != snapshot_id or inspection.get(
        "descriptorDigest"
    ) != framed_digest(BACKUP_SCHEMA, snapshot.descriptor):
        raise HostRestoreError("restore materialization inspection changed")
    targets = paths.targets()
    root_metadata = exact_object(
        inspection.get("rootMetadata"), set(SOURCE_PATHS) | set(STAGED_PATHS)
    )
    policies = {
        **{label: cast(dict[str, int], root_metadata[label]) for label in SOURCE_PATHS},
        "staging": {"mode": 0o700, "owner": store.owner, "group": store.owner},
    }
    reservations = admit_restore_space(inspection, paths.filesystems())
    identities = {
        label: _private_target(store, label, target, policies[label])
        for label, target in sorted(targets.items())
    }
    # Subfolder restoration removes the original absolute prefix. The staging
    # directory was independently inspected and may contain exactly our two files.
    sources = {**SOURCE_PATHS, "staging": str(Path(STAGED_PATHS["database"]).parent)}
    for label, target in sorted(targets.items()):
        _run_restic(
            (
                "--no-cache",
                "restore",
                f"{snapshot_id}:{sources[label]}",
                "--target",
                str(target),
                "--verify",
                "--quiet",
            ),
            environment,
            256 * 1024,
            None,
            timeout_seconds=1800,
        )
        if _private_target(store, label, target, policies[label]) != identities[label]:
            raise HostRestoreError("restore private root changed during materialization")
        descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchown(descriptor, policies[label]["owner"], policies[label]["group"])
            os.fchmod(descriptor, policies[label]["mode"])
        finally:
            os.close(descriptor)
        _sync_tree(target)
    for path in (
        paths.roots["state"] / "intake",
        paths.roots["state"] / "exports",
        paths.roots["content"] / "sites" / ".staging",
    ):
        _empty_excluded_directory(path, store.owner)
    with DurableDirectory.open(
        paths.staging, expected_owner=store.owner, expected_directory_mode=0o700
    ) as staging:
        raw = staging.read_regular(
            (Path(STAGED_PATHS["descriptor"]).name,),
            expected_owner=store.owner,
            expected_mode=0o600,
            maximum_bytes=256 * 1024,
        )
    if raw != snapshot.descriptor:
        raise HostRestoreError("restore descriptor bytes changed during materialization")
    return {"roots": identities, "reservations": reservations, "inventory": inspection}
