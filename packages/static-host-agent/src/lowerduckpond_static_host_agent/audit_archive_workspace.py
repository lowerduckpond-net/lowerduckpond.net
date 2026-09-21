"""One disposable, bounded audit verification workspace under repository serialization."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.audit_archive_formats import (
    MAX_DESCRIPTOR_BYTES,
    MAX_SEGMENT_BYTES,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory

MAX_WORKSPACE_BYTES: Final = 32 * 1024 * 1024
MAX_WORKSPACE_INODES: Final = 128
_PAYLOADS: Final = {
    "descriptor.json": MAX_DESCRIPTOR_BYTES,
    "segment.jsonl": MAX_SEGMENT_BYTES,
    "witness.json": MAX_SEGMENT_BYTES,
}


def _discard_verified_workspace(directory: DurableDirectory, owner: int) -> None:
    """Discard only classified private outputs, never an unknown filesystem tree."""
    temporaries = directory.publication_temporaries(
        expected_owner=owner, expected_mode=0o600, maximum_entries=MAX_WORKSPACE_INODES - 1
    )
    descriptor = directory.duplicate_descriptor()
    try:
        names = []
        with os.scandir(descriptor) as iterator:
            for item in iterator:
                names.append(item.name)
                if len(names) + 1 > MAX_WORKSPACE_INODES:
                    raise BackupIdentityError(
                        "audit verification workspace exceeds its inode bound"
                    )
        allocation = os.fstat(descriptor).st_blocks * 512
        logical = 0
        for name in names:
            if name not in _PAYLOADS and name not in temporaries:
                raise BackupIdentityError("audit verification workspace contains unknown data")
            generation = directory.regular_metadata_generation(
                (name,), expected_owner=owner, expected_mode=0o600
            )
            limit = _PAYLOADS.get(name, MAX_SEGMENT_BYTES)
            if generation[2] > limit:
                raise BackupIdentityError("audit verification workspace contains oversized data")
            logical += generation[2]
            allocation += directory.regular_allocation(
                (name,), expected_owner=owner, expected_mode=0o600
            )
            if max(logical, allocation) > MAX_WORKSPACE_BYTES:
                raise BackupIdentityError("audit verification workspace exceeds its byte bound")
        # Classify the entire inventory before removing even one safe output.
        for name in names:
            directory.remove((name,))
    finally:
        os.close(descriptor)


@contextmanager
def verification_workspace(path: Path, *, expected_owner: int) -> Iterator[DurableDirectory]:
    """Caller holds the repository lease; workspace is separate from static authority."""
    with DurableDirectory.open(
        path, expected_owner=expected_owner, expected_directory_mode=0o700
    ) as directory:
        _discard_verified_workspace(directory, expected_owner)
        descriptor = directory.duplicate_descriptor()
        try:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(MAX_WORKSPACE_BYTES, MAX_WORKSPACE_INODES),
                measure_filesystem_capacity_descriptor(descriptor),
            )
        finally:
            os.close(descriptor)
        try:
            yield directory
        finally:
            _discard_verified_workspace(directory, expected_owner)


def restore_payload(directory: DurableDirectory, name: str, raw: bytes, owner: int) -> bytes:
    """Persist one independently dumped fixed payload and validate its readback."""
    if name not in _PAYLOADS or not raw or len(raw) > _PAYLOADS[name]:
        raise BackupIdentityError("audit verification payload has an invalid boundary")
    directory.create_immutable((name,), raw, mode=0o600)
    restored = directory.read_regular(
        (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=_PAYLOADS[name]
    )
    if restored != raw:
        raise BackupIdentityError("audit verification workspace changed after restoration")
    return restored
