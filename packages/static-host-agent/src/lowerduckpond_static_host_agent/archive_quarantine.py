"""Bounded durable archive-admission closure, separate from lifecycle authority."""

from __future__ import annotations

import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteError,
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
)
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository

_PATH: Final = ("platform", "archive-quarantine.json")
_MAXIMUM_BYTES: Final = 32 * 1024 * 1024
_MAXIMUM_ENTRIES: Final = 10_000
_FORMAT: Final = "lowerduckpond-archive-quarantine-v2"
_IDENTITY_FIELDS: Final = 2
_MAXIMUM_STRING_BYTES: Final = 1024


class ArchiveQuarantine:
    """Preserve observations on every error; presence always closes admission.

    Root recovery owns resolution. Reopening requires a complete inventory and
    exact retained bytes after every lifecycle and remote journal is resolved.
    This boundary never grants authority to delete an unknown object.
    """

    def __init__(
        self, state_root: Path, *, bucket: str, expected_owner: int, locks: LockManager
    ) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket):
            raise ArchiveRemoteError("archive quarantine bucket is invalid")
        self.root = state_root
        self.bucket = bucket
        self.owner = expected_owner
        self.locks = locks

    def require_empty(self) -> None:
        if self.read() is not None:
            raise ArchiveRemoteError("archive admission is closed by durable quarantine")

    def read(self) -> dict[str, object] | None:
        self.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
        with DurableDirectory.open(
            self.root, expected_owner=self.owner, expected_directory_mode=0o700
        ) as root:
            try:
                raw = root.read_regular(
                    _PATH,
                    expected_owner=self.owner,
                    expected_mode=0o600,
                    maximum_bytes=_MAXIMUM_BYTES,
                )
            except FileNotFoundError:
                return None
        document = decode_json_object(raw, maximum_bytes=_MAXIMUM_BYTES)
        if (
            set(document)
            != {"format", "bucket", "discoveryIncomplete", "versions", "multipartUploads"}
            or document["format"] != _FORMAT
            or document["bucket"] != self.bucket
            or type(document["discoveryIncomplete"]) is not bool
            or canonical_json_bytes(document, maximum_bytes=_MAXIMUM_BYTES) != raw
        ):
            raise ArchiveRemoteError("archive quarantine metadata is inconsistent")
        _validate_entries(document)
        return document

    def record(self, inventory: RemoteInventory | None) -> None:
        self.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
        with self.locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE):
            self._record_locked(inventory)

    def resolve(self, repository: StateRepository, remote: ArchiveRemoteStore) -> bool:
        """Remove only quarantine proven resolved against locked current authority.

        Reconcile all journals and authorized cleanup first. A full version and
        multipart inventory must then exactly match every authoritative archive
        record, both before and after independent verification of retained bytes.
        Capacity admission remains a separate check, so a full but consistent
        bucket does not prevent recovery from completing.
        """
        self.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
        if remote.bucket != self.bucket:
            raise ArchiveRemoteError("quarantine resolution selected another bucket")
        with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            previous = self.read()
            if previous is None:
                return False
            if transaction.measure_intent_records().records:
                raise ArchiveRemoteError("resolve all intents before reopening archive admission")
            records = [
                transaction.read(StateRecordPath.tenant_archive(tenant_id, deployment_id)).document
                for tenant_id in transaction.measure_inventory().tenant_ids
                for deployment_id in transaction.tenant_archive_ids(tenant_id)
            ]
            known: set[RemoteVersion] = set()
            for record in records:
                if record["bucket"] != remote.bucket or any(
                    entry.key == record["key"] for entry in known
                ):
                    raise ArchiveRemoteError("archive bindings disagree with configured inventory")
                known.add(
                    RemoteVersion(
                        cast(str, record["key"]),
                        cast(str, record["versionId"]),
                        cast(int, record["bundleSize"]),
                        False,
                    )
                )
            inventory: RemoteInventory | None = None
            try:
                inventory = remote.inventory()
                _require_exact_inventory(inventory, known)
                for record in records:
                    remote.read_verified(
                        cast(str, record["key"]),
                        cast(str, record["versionId"]),
                        size=cast(int, record["bundleSize"]),
                        sha256=cast(str, cast(dict[str, object], record["bundleDigest"])["value"]),
                    )
                inventory = remote.inventory()
                _require_exact_inventory(inventory, known)
            except Exception:
                if inventory is not None:
                    self._record_locked(inventory)
                self._record_locked(None)
                raise
            # Tenant-state and export exclusion still cover the authority used
            # above and the final durable removal. No writer can reopen a race
            # between that proof and removing the admission closure.
            with DurableDirectory.open(
                self.root, expected_owner=self.owner, expected_directory_mode=0o700
            ) as root:
                root.remove(_PATH)
            return True

    def _record_locked(self, inventory: RemoteInventory | None) -> None:
        previous = self.read()
        document = previous or {
            "format": _FORMAT,
            "bucket": self.bucket,
            "discoveryIncomplete": False,
            "versions": [],
            "multipartUploads": [],
        }
        if inventory is None:
            document["discoveryIncomplete"] = True
        else:
            versions = cast(list[dict[str, object]], document["versions"])
            uploads = cast(list[list[str]], document["multipartUploads"])
            # Preserve every known coordinate and even conflicting size evidence.
            for version in inventory.versions:
                value = asdict(version)
                if value not in versions:
                    versions.append(value)
            for upload in inventory.multipart_uploads:
                if list(upload) not in uploads:
                    uploads.append(list(upload))
        _validate_entries(document)
        raw = canonical_json_bytes(document, maximum_bytes=_MAXIMUM_BYTES)
        with DurableDirectory.open(
            self.root, expected_owner=self.owner, expected_directory_mode=0o700
        ) as root:
            descriptor = root.duplicate_descriptor()
            try:
                admit_release_capacity(
                    ReleaseCapacityUsage(()),
                    CapacityReservation(
                        root.allocation_upper_bound(len(raw))
                        + root.namespace_allocation_upper_bound(2),
                        2,
                    ),
                    measure_filesystem_capacity_descriptor(descriptor),
                )
            finally:
                os.close(descriptor)
            root.replace(_PATH, raw, mode=0o600)


def _validate_entries(document: dict[str, object]) -> None:
    versions = document["versions"]
    uploads = document["multipartUploads"]
    if (
        type(versions) is not list
        or type(uploads) is not list
        or len(versions) + len(uploads) > _MAXIMUM_ENTRIES
    ):
        raise ArchiveRemoteError("archive quarantine exceeds its bounded inventory")
    for value in versions:
        if (
            type(value) is not dict
            or set(value) != {"key", "version_id", "size", "delete_marker"}
            or not _text(value["key"])
            or not _text(value["version_id"])
            or type(value["size"]) is not int
            or value["size"] < 0
            or type(value["delete_marker"]) is not bool
        ):
            raise ArchiveRemoteError("archive quarantine contains an invalid version")
    for value in uploads:
        if (
            type(value) is not list
            or len(value) != _IDENTITY_FIELDS
            or not all(_text(item) for item in value)
        ):
            raise ArchiveRemoteError("archive quarantine contains an invalid multipart identity")


def _text(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= _MAXIMUM_STRING_BYTES


def _require_exact_inventory(inventory: RemoteInventory, known: set[RemoteVersion]) -> None:
    if inventory.multipart_uploads or frozenset(inventory.versions) != known:
        raise ArchiveRemoteError("archive quarantine still has unresolved remote inventory")
