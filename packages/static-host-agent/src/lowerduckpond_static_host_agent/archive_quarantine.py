"""Bounded durable archive-admission closure, separate from lifecycle authority."""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, RemoteInventory
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

_PATH: Final = ("platform", "archive-quarantine.json")
_MAXIMUM_BYTES: Final = 32 * 1024 * 1024
_MAXIMUM_ENTRIES: Final = 10_000
_FORMAT: Final = "lowerduckpond-archive-quarantine-v1"
_IDENTITY_FIELDS: Final = 2
_MAXIMUM_STRING_BYTES: Final = 1024


class ArchiveQuarantine:
    """Preserve observations on every error; presence always closes admission.

    Root recovery owns resolution. This sink deliberately has no clear method:
    neither an empty current-key view nor process exit is an absence proof for
    every version, marker, upload, and outstanding intent retained here.
    """

    def __init__(self, state_root: Path, *, expected_owner: int, locks: LockManager) -> None:
        self.root = state_root
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
            set(document) != {"format", "discoveryIncomplete", "versions", "multipartUploads"}
            or document["format"] != _FORMAT
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

    def _record_locked(self, inventory: RemoteInventory | None) -> None:
        previous = self.read()
        document = previous or {
            "format": _FORMAT,
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
