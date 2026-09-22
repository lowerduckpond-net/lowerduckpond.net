"""Bounded sealed snapshot inputs; unknown or conflicting staging is preserved."""

from __future__ import annotations

import os
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_local as local
from lowerduckpond_static_host_agent.audit_archive_workspace import (
    MAX_WORKSPACE_BYTES,
    MAX_WORKSPACE_INODES,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory

_PAYLOADS = {
    "descriptor.json": formats.MAX_DESCRIPTOR_BYTES,
    "segment.jsonl": formats.MAX_SEGMENT_BYTES,
}


def _inventory(directory: DurableDirectory, owner: int) -> dict[str, bytes]:
    temporaries = directory.publication_temporaries(
        expected_owner=owner, expected_mode=0o600, maximum_entries=MAX_WORKSPACE_INODES - 1
    )
    descriptor = directory.duplicate_descriptor()
    try:
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) + 1 > MAX_WORKSPACE_INODES:
                    raise BackupIdentityError("audit snapshot staging exceeds its inode bound")
        allocated = os.fstat(descriptor).st_blocks * 512
        logical = 0
        for name in names:
            if name not in _PAYLOADS and name not in temporaries:
                raise BackupIdentityError("audit snapshot staging contains unknown evidence")
            generation = directory.regular_metadata_generation(
                (name,), expected_owner=owner, expected_mode=0o600
            )
            if generation[2] > _PAYLOADS.get(name, formats.MAX_SEGMENT_BYTES):
                raise BackupIdentityError("audit snapshot staging contains oversized evidence")
            logical += generation[2]
            allocated += directory.regular_allocation(
                (name,), expected_owner=owner, expected_mode=0o600
            )
            if max(logical, allocated) > MAX_WORKSPACE_BYTES:
                raise BackupIdentityError("audit snapshot staging exceeds its byte bound")
        return {
            name: directory.read_regular(
                (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=_PAYLOADS[name]
            )
            for name in names
            if name in _PAYLOADS
        }
    finally:
        os.close(descriptor)


def stage_attempt(
    path: Path,
    record: dict[str, object],
    segment: bytes,
    owner: int,
    *,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> None:
    formats.verify_segment(record, segment)
    payloads = {"descriptor.json": canonical_json_bytes(record), "segment.jsonl": segment}
    with DurableDirectory.open(
        path, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        existing = _inventory(directory, owner)
        if any(raw != payloads[name] for name, raw in existing.items()):
            raise BackupIdentityError("audit snapshot staging conflicts with its durable attempt")
        descriptor = directory.duplicate_descriptor()
        try:
            # Account for a complete verification workspace as well as all new
            # staging generations before allocating the first snapshot input.
            allocation = sum(
                directory.allocation_upper_bound(len(raw)) for raw in payloads.values()
            )
            allocation += directory.namespace_allocation_upper_bound(len(payloads))
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(
                    MAX_WORKSPACE_BYTES + allocation, MAX_WORKSPACE_INODES + len(payloads)
                ),
                measure_filesystem_capacity_descriptor(descriptor),
            )
        finally:
            os.close(descriptor)
        directory.remove_abandoned_publication_temporaries(
            expected_owner=owner, expected_mode=0o600, maximum_entries=MAX_WORKSPACE_INODES - 1
        )
        for name, raw in payloads.items():
            hook = (
                None
                if failure_hook is None
                else lambda key, boundary: failure_hook("snapshot/" + key, boundary)
            )
            local._publish(directory, name, raw, owner, immutable=True, failure_hook=hook)
        if _inventory(directory, owner) != payloads:
            raise BackupIdentityError("audit snapshot staging changed after publication")


def discard_stage(
    path: Path,
    owner: int,
    *,
    record: dict[str, object] | None = None,
    failure_hook: local.ArchiveFailureHook | None = None,
) -> None:
    """Classify every byte before cleanup, including safe pre-intent leftovers."""
    with DurableDirectory.open(
        path, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        payloads = _inventory(directory, owner)
        descriptor = record
        if "descriptor.json" in payloads:
            staged = formats.decode_rotation(payloads["descriptor.json"])
            if descriptor is not None and staged != descriptor:
                raise BackupIdentityError("audit snapshot cleanup conflicts with its attempt")
            descriptor = staged
        if "segment.jsonl" in payloads:
            if descriptor is None:
                formats.inspect_segment(payloads["segment.jsonl"])
            else:
                formats.verify_segment(descriptor, payloads["segment.jsonl"])
        directory.remove_abandoned_publication_temporaries(
            expected_owner=owner, expected_mode=0o600, maximum_entries=MAX_WORKSPACE_INODES - 1
        )
        for name in payloads:
            hook = (
                None
                if failure_hook is None
                else lambda boundary, name=name: failure_hook("snapshot/" + name, boundary)
            )
            directory.remove((name,), failure_hook=hook)
        local._sync(directory)  # Also completes a removal interrupted before its parent sync.
