"""Local protection cache and reserved archival capacity for ordinary audit work."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_journal as journal
from lowerduckpond_static_host_agent.audit_archive_store import ArchivePrefix
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.capacity import (
    CapacityError,
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory

MAX_PROTECTION_AGE_SECONDS: Final = 24 * 60 * 60
_ROTATION_INODES: Final = 7


class AuditProtectionError(BackupIdentityError):
    """Ordinary writes cannot rely on the current protected-audit proof."""


class AuditArchiveCapacityError(BackupIdentityError):
    """Ordinary work cannot reserve the next protected rotation safely."""


def require_ordinary_protection(prefix: ArchivePrefix) -> None:
    if prefix.head is None:
        return
    status = prefix.protection_status
    if (
        status is None
        or status["category"] != "verified"
        or any(status[key] != prefix.head[key] for key in ("lineageId", "repositoryBinding"))
        or status["headDigest"]
        != framed_digest(formats.HEAD_FORMAT, canonical_json_bytes(prefix.head))
    ):
        raise AuditProtectionError(
            "ordinary audit work requires protection for the current index head"
        )
    verified_at = formats.archive_timestamp(status["verifiedAt"])
    verified = datetime.strptime(verified_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    age = time.time() - verified
    if not 0 <= age <= MAX_PROTECTION_AGE_SECONDS:
        raise AuditProtectionError("ordinary audit work requires a fresh protected snapshot proof")


def rotation_reservation(directory: DurableDirectory) -> CapacityReservation:
    """Reserve one maximum witness, index, intent replacement and head/status.

    Only one rotation can run under the repository lock. Include the old and new
    intent while replacement is in flight, a new duplicate inventory, and ext4
    namespace growth. Existing generations and safe temporaries are already
    charged by the local archive inventory. This never draws on administrator
    reserve or increases a committed limit.
    """
    sizes = (
        formats.MAX_SEGMENT_BYTES,
        formats.MAX_INDEX_BYTES,
        journal.MAX_JOURNAL_BYTES,
        journal.MAX_JOURNAL_BYTES,
        journal.MAX_JOURNAL_BYTES,
        formats.MAX_DESCRIPTOR_BYTES,
        journal.MAX_STATUS_BYTES,
    )
    allocation = sum(directory.allocation_upper_bound(size) for size in sizes)
    allocation += directory.namespace_allocation_upper_bound(_ROTATION_INODES)
    return CapacityReservation(allocation, _ROTATION_INODES)


def admit_archive_append(
    directory: DurableDirectory, prefix: ArchivePrefix, append_allocation: int, *, entry_count: int
) -> int:
    """Return additional ordinary-audit headroom after proving all free floors."""
    if prefix.head is None:
        return 0
    require_ordinary_protection(prefix)
    reservation = rotation_reservation(directory)
    head = prefix.head
    if (
        prefix.allocated_bytes + reservation.allocated_bytes > formats.MAX_ARCHIVE_METADATA_BYTES
        or prefix.inodes + reservation.unique_inodes > formats.MAX_ARCHIVE_METADATA_INODES
        or head["indexCount"] == formats.MAX_ARCHIVED_SEGMENTS
        or entry_count >= formats.MAX_WITNESSED_ENTRIES
    ):
        raise AuditArchiveCapacityError(
            "ordinary work cannot reserve bounded audit archive metadata"
        )
    descriptor = directory.duplicate_descriptor()
    try:
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                reservation.allocated_bytes + append_allocation, reservation.unique_inodes + 1
            ),
            measure_filesystem_capacity_descriptor(descriptor),
        )
    except CapacityError as error:
        raise AuditArchiveCapacityError(
            "ordinary audit work cannot preserve filesystem free floors"
        ) from error
    finally:
        os.close(descriptor)
    return reservation.allocated_bytes
