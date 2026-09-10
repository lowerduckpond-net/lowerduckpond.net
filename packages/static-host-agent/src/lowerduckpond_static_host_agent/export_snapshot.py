"""Verified independent export copies captured under shared tenant-state."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    Digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.capacity import CapacityReservation
from lowerduckpond_static_host_agent.export_spool import (
    ExportSpool,
    ExportSpoolAccounting,
    ExportSpoolError,
)
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.portable_bundle import MAXIMUM_PORTABLE_BUNDLE_BYTES
from lowerduckpond_static_host_agent.release_tree import (
    MAX_RELEASE_CONTENT_BYTES,
    MAX_RELEASE_DEPTH,
    MAX_RELEASE_ENTRIES,
    MAX_RELEASE_FILE_BYTES,
    ReleaseTreeMeasurement,
    measure_release_tree_capture,
    measure_release_tree_snapshot,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath, StoredContract

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_CHUNK_BYTES = 64 * 1024
_METADATA_RESERVATION = 32 * 1024
_RELEASE_DIRECTORY_MODE = 0o755


@dataclass(slots=True)
class _CopyBudget:
    owner: int
    device: int
    entries: int = 0
    content_bytes: int = 0


class ExportCaptureBoundary(StrEnum):
    SOURCE_VERIFIED = "source-verified"
    FILE_CHUNK = "file-chunk"
    CONTENT_COPIED = "content-copied"
    SNAPSHOT_SEALED = "snapshot-sealed"
    SNAPSHOT_VERIFIED = "snapshot-verified"


class ExportCaptureTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ExportSnapshot:
    """Canonical source authority and a sealed copy independent of the release."""

    manifest: dict[str, object]
    deployment: dict[str, object]
    content: Path
    measurement: ReleaseTreeMeasurement


def capture_export_snapshot(  # noqa: PLR0913 - each authority boundary is explicit
    spool: ExportSpool,
    transaction: ExportCaptureTransaction,
    *,
    release_root: Path,
    tenant_id: object,
    expected_manifest_digest: Digest,
    expected_deployment_digest: Digest,
    expected_owner: int,
    hook: Callable[[ExportCaptureBoundary], None] | None = None,
) -> ExportSnapshot:
    """Copy and verify before the caller releases its shared state transaction."""

    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.SHARED)
    tenant = validate_uuid7(tenant_id)
    manifest = transaction.read(StateRecordPath.tenant_desired(tenant)).document
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    desired = spec.get("desiredDeployment")
    if (
        metadata["id"] != tenant
        or spec["desiredState"] not in {"active", "suspended"}
        or type(desired) is not dict
        or manifest_digest(manifest) != expected_manifest_digest
    ):
        raise ExportSpoolError("export source manifest disagrees with authority")
    deployment_id = validate_uuid7(desired["id"])
    deployment = transaction.read(StateRecordPath.tenant_deployment(tenant, deployment_id)).document
    validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    if (
        deployment["tenantId"] != tenant
        or deployment["id"] != deployment_id
        or deployment["archiveSha256"] != desired["archiveSha256"]
        or deployment_record_digest(deployment) != expected_deployment_digest
    ):
        raise ExportSpoolError("export source deployment disagrees with authority")
    parent = _open_release_parent(release_root, tenant, expected_owner)
    try:
        source = Path(f"/proc/self/fd/{parent}/{deployment_id}")
        before = measure_release_tree_capture(
            source, lock_manager=transaction, expected_owner=expected_owner
        )
        if before.digest.to_dict() != deployment["releaseTreeDigest"]:
            raise ExportSpoolError("export source content disagrees with its deployment")
        fragment = spool.fragment_size()
        spool.reserve(
            CapacityReservation(
                before.logical_content_bytes
                + (before.entry_count + 8) * fragment
                + _METADATA_RESERVATION
                + MAXIMUM_PORTABLE_BUNDLE_BYTES,
                before.entry_count + 5,
            )
        )
        _notify(hook, ExportCaptureBoundary.SOURCE_VERIFIED)
        content = spool.workspace / "content"
        _copy_content(source, content, spool, hook)
        _notify(hook, ExportCaptureBoundary.CONTENT_COPIED)
        _write_metadata(spool.workspace / "manifest.json", canonical_json_bytes(manifest))
        _write_metadata(spool.workspace / "deployment.json", canonical_json_bytes(deployment))
        _notify(hook, ExportCaptureBoundary.SNAPSHOT_SEALED)
        copied = measure_release_tree_snapshot(
            content, lock_manager=spool.locks, expected_owner=expected_owner, read_only=True
        )
        after = measure_release_tree_capture(
            source, lock_manager=transaction, expected_owner=expected_owner
        )
        if before != after or (
            copied.digest != before.digest
            or copied.entry_count != before.entry_count
            or copied.logical_content_bytes != before.logical_content_bytes
        ):
            raise ExportSpoolError("export content changed during snapshot capture")
        if (spool.workspace / "manifest.json").read_bytes() != canonical_json_bytes(manifest) or (
            (spool.workspace / "deployment.json").read_bytes() != canonical_json_bytes(deployment)
        ):
            raise ExportSpoolError("export metadata changed during snapshot capture")
        if transaction.read(StateRecordPath.tenant_desired(tenant)).document != manifest or (
            transaction.read(StateRecordPath.tenant_deployment(tenant, deployment_id)).document
            != deployment
        ):
            raise ExportSpoolError("export authority changed during snapshot capture")
        spool.reserve(CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES, 1))
        _notify(hook, ExportCaptureBoundary.SNAPSHOT_VERIFIED)
        return ExportSnapshot(manifest, deployment, content, copied)
    finally:
        os.close(parent)


def _open_release_parent(root: Path, tenant: str, owner: int) -> int:
    descriptor = os.open(root, _DIRECTORY_FLAGS)
    try:
        for component in (tenant, "releases"):
            metadata = os.fstat(descriptor)
            if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ExportSpoolError("export release parent is not root controlled")
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != _RELEASE_DIRECTORY_MODE:
            raise ExportSpoolError("export release namespace is unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _copy_content(
    source: Path,
    destination: Path,
    spool: ExportSpool,
    hook: Callable[[ExportCaptureBoundary], None] | None,
) -> None:
    source_fd = os.open(source, _DIRECTORY_FLAGS)
    try:
        destination.mkdir(mode=0o700)
        destination_fd = os.open(destination, _DIRECTORY_FLAGS)
        try:
            metadata = os.fstat(source_fd)
            budget = _CopyBudget(metadata.st_uid, metadata.st_dev)
            with spool.accounting() as account:
                _copy_directory(source_fd, destination_fd, account, hook, budget=budget, depth=0)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def _copy_directory(  # noqa: PLR0913 - descriptors, limits, and failure boundary
    source: int,
    destination: int,
    account: ExportSpoolAccounting,
    hook: Callable[[ExportCaptureBoundary], None] | None,
    *,
    budget: _CopyBudget,
    depth: int,
) -> None:
    if depth > MAX_RELEASE_DEPTH:
        raise ExportSpoolError("export copy exceeds its depth bound")
    names: list[str] = []
    with os.scandir(source) as entries:
        for entry in entries:
            budget.entries += 1
            if budget.entries > MAX_RELEASE_ENTRIES:
                raise ExportSpoolError("export copy exceeds its entry bound")
            names.append(entry.name)
    for name in sorted(names):
        metadata = os.stat(name, dir_fd=source, follow_symlinks=False)
        if metadata.st_uid != budget.owner or metadata.st_dev != budget.device:
            raise ExportSpoolError("export source ownership or filesystem changed")
        account.reserve(
            CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES + _METADATA_RESERVATION, 4)
        )
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, _DIRECTORY_FLAGS, dir_fd=source)
            try:
                os.mkdir(name, mode=0o700, dir_fd=destination)
                copied = os.open(name, _DIRECTORY_FLAGS, dir_fd=destination)
                try:
                    account.record(destination)
                    account.record(copied)
                    _copy_directory(child, copied, account, hook, budget=budget, depth=depth + 1)
                finally:
                    os.close(copied)
            finally:
                os.close(child)
        else:
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 <= metadata.st_size <= MAX_RELEASE_FILE_BYTES
            ):
                raise ExportSpoolError("export source exceeds its file boundary")
            budget.content_bytes += metadata.st_size
            if budget.content_bytes > MAX_RELEASE_CONTENT_BYTES:
                raise ExportSpoolError("export copy exceeds its content bound")
            _copy_file(source, destination, name, account, hook, expected=metadata)
    os.fchmod(destination, 0o555)
    os.fsync(destination)
    account.record(destination)


def _copy_file(  # noqa: PLR0913 - explicit measured source binding
    source: int,
    destination: int,
    name: str,
    account: ExportSpoolAccounting,
    hook: Callable[[ExportCaptureBoundary], None] | None,
    *,
    expected: os.stat_result,
) -> None:
    source_fd = os.open(name, _READ_FLAGS, dir_fd=source)
    try:
        metadata = os.fstat(source_fd)
        if metadata != expected or not stat.S_ISREG(metadata.st_mode):
            raise ExportSpoolError("export copy encountered a non-regular source")
        target = os.open(name, _CREATE_FLAGS, 0o600, dir_fd=destination)
        try:
            account.record(destination)
            account.record(target)
            remaining = metadata.st_size
            while remaining:
                account.reserve(
                    CapacityReservation(
                        MAXIMUM_PORTABLE_BUNDLE_BYTES + _METADATA_RESERVATION + _CHUNK_BYTES, 3
                    )
                )
                chunk = os.read(source_fd, min(remaining, _CHUNK_BYTES))
                if not chunk:
                    raise ExportSpoolError("export source ended before its measured size")
                _write_all(target, chunk)
                account.record(target)
                remaining -= len(chunk)
                _notify(hook, ExportCaptureBoundary.FILE_CHUNK)
            if os.read(source_fd, 1):
                raise ExportSpoolError("export source grew during copy")
            os.fchmod(target, 0o444)
            os.fsync(target)
            account.record(target)
        finally:
            os.close(target)
    finally:
        os.close(source_fd)


def _write_metadata(path: Path, data: bytes) -> None:
    descriptor = os.open(path, _CREATE_FLAGS, 0o600)
    try:
        _write_all(descriptor, data)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, _DIRECTORY_FLAGS)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise ExportSpoolError("export write made no progress")
        remaining = remaining[written:]


def _notify(
    hook: Callable[[ExportCaptureBoundary], None] | None,
    boundary: ExportCaptureBoundary,
) -> None:
    if hook is not None:
        hook(boundary)
