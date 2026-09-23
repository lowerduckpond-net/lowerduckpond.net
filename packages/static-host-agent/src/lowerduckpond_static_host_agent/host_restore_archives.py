"""Read-only exact-version proof; restored intents cannot clean a later timeline."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    canonical_json_bytes,
    manifest_digest,
    validate_contract,
)

from lowerduckpond_static_host_agent.archive_bundle import require_archive_inspection
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
)
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import MAX_RESTORE_BYTES, HostRestoreError
from lowerduckpond_static_host_agent.portable_bundle import (
    MAXIMUM_PORTABLE_BUNDLE_BYTES,
    inspect_portable_bundle,
)


@dataclass(frozen=True)
class RestoreArchive:
    record: dict[str, object]
    manifest: dict[str, object] | None
    required: bool = True

    def version(self, bucket: str) -> RemoteVersion:
        validate_contract(self.record, expected_kind=ContractKind.ARCHIVE_RECORD)
        if self.record["bucket"] != bucket or type(self.required) is not bool:
            raise HostRestoreError("restore_archive_authority_mismatch")
        if self.manifest is None:
            if self.required:
                raise HostRestoreError("restore_required_archive_manifest_unavailable")
            # A completed deletion may retain only its digest-bound retirement
            # record. If bytes exist, independently parse their provenance below;
            # absence is allowed only for an authorized optional retirement.
            return RemoteVersion(
                cast(str, self.record["key"]),
                cast(str, self.record["versionId"]),
                cast(int, self.record["bundleSize"]),
                False,
            )
        validate_contract(self.manifest, expected_kind=ContractKind.SITE)
        metadata = cast(dict[str, object], self.manifest["metadata"])
        spec = cast(dict[str, object], self.manifest["spec"])
        deployment = spec.get("desiredDeployment")
        if (
            self.record["bucket"] != bucket
            or self.record["manifestDigest"] != manifest_digest(self.manifest).to_dict()
            or self.record["tenantId"] != metadata["id"]
            or spec["desiredState"] != "archived"
            or type(deployment) is not dict
            or self.record["deploymentId"] != deployment["id"]
            or type(self.required) is not bool
        ):
            raise HostRestoreError("restore_archive_authority_mismatch")
        return RemoteVersion(
            cast(str, self.record["key"]),
            cast(str, self.record["versionId"]),
            cast(int, self.record["bundleSize"]),
            False,
        )


def require_verified_archive(
    proof: dict[str, object], record: dict[str, object], *, required: bool
) -> None:
    """Bind a local lifecycle choice to the credential helper's complete proof."""
    rows = proof.get("archives")
    digest = archive_record_digest(record).to_dict()
    matches = (
        [row for row in rows if type(row) is dict and row.get("archiveDigest") == digest]
        if type(rows) is list
        else []
    )
    if (
        len(matches) != 1
        or set(matches[0]) != {"archiveDigest", "required", "present"}
        or type(matches[0]["required"]) is not bool
        or type(matches[0]["present"]) is not bool
        or (required and not matches[0]["present"])
        or proof.get("multipartCount") != 0
    ):
        raise HostRestoreError("restore_archive_proof_unavailable")


def _inventory_document(inventory: RemoteInventory) -> dict[str, object]:
    return {
        "versions": [
            {
                "key": row.key,
                "versionId": row.version_id,
                "size": row.size,
                "deleteMarker": row.delete_marker,
            }
            for row in sorted(inventory.versions, key=lambda value: (value.key, value.version_id))
        ],
        "multipartUploads": [list(row) for row in sorted(inventory.multipart_uploads)],
    }


def verify_restore_archives(
    remote: ArchiveRemoteStore,
    authority: Sequence[RestoreArchive],
    workspace: Path,
    *,
    owner: int,
) -> dict[str, object]:
    """Verify bundles without tenant restore, upload, deletion or quarantine writes.

    Optional versions must already be classified by a terminal retirement plan;
    their absence never excuses a required archived tenant. Unknown versions,
    markers and multipart uploads preserve all remote bytes and close the host.
    A second complete listing detects an unfenced or inconsistent remote view.
    """
    known: dict[RemoteVersion, RestoreArchive] = {}
    for item in authority:
        version = item.version(remote.bucket)
        if version in known or any(other.key == version.key for other in known):
            raise HostRestoreError("restore_archive_ambiguous")
        known[version] = item
    inventory = remote.inventory()
    present = frozenset(inventory.versions)
    required = frozenset(version for version, item in known.items() if item.required)
    if not required <= present:
        raise HostRestoreError("restore_required_archive_unavailable")
    if inventory.multipart_uploads or not present <= known.keys():
        raise HostRestoreError("restore_later_remote_timeline")
    rows: list[dict[str, object]] = []
    with DurableDirectory.open(
        workspace, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        descriptor = directory.duplicate_descriptor()
        try:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES, 2),
                measure_filesystem_capacity_descriptor(descriptor),
            )
        finally:
            os.close(descriptor)
    for version, item in sorted(known.items(), key=lambda pair: (pair[0].key, pair[0].version_id)):
        if version in present:
            with tempfile.TemporaryDirectory(prefix="archive-", dir=workspace) as private:
                bundle = Path(private) / "bundle.zip"
                descriptor = os.open(
                    bundle,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                )
                with os.fdopen(descriptor, "wb", buffering=0) as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    remote.read_verified(
                        version.key,
                        version.version_id,
                        size=version.size,
                        sha256=cast(dict[str, str], item.record["bundleDigest"])["value"],
                        destination=stream,
                    )
                    os.fsync(stream.fileno())
                inspected = inspect_portable_bundle(bundle, expected_owner=owner)
                manifest = inspected.provenance_manifest if item.manifest is None else item.manifest
                RestoreArchive(item.record, manifest, item.required).version(remote.bucket)
                require_archive_inspection(inspected, item.record, manifest)
        rows.append(
            {
                "archiveDigest": archive_record_digest(item.record).to_dict(),
                "required": item.required,
                "present": version in present,
            }
        )
    final = remote.inventory()
    if _inventory_document(final) != _inventory_document(inventory):
        raise HostRestoreError("restore_remote_inventory_changed")
    return {
        "archives": rows,
        "inventoryDigest": framed_digest(
            "lowerduckpond-host-restore-remote-v1",
            canonical_json_bytes(_inventory_document(inventory), maximum_bytes=MAX_RESTORE_BYTES),
        ),
        "versionCount": len(inventory.versions),
        "multipartCount": 0,
    }
