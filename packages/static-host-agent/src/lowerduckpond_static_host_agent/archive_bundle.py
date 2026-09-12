"""Exact archived-bundle validation inside the existing bounded export spool."""

from __future__ import annotations

import os
from typing import cast

from lowerduckpond_static_contracts import ContractKind, manifest_digest, validate_contract

from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, ArchiveRemoteStore
from lowerduckpond_static_host_agent.capacity import CapacityReservation
from lowerduckpond_static_host_agent.export_spool import EXPORT_WORKSPACE_BUNDLE_NAME, ExportSpool
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.portable_bundle import (
    MAXIMUM_PORTABLE_BUNDLE_BYTES,
    PortableBundleInspection,
    inspect_portable_bundle,
)


def fetch_archive_bundle(
    remote: ArchiveRemoteStore,
    spool: ExportSpool,
    record: dict[str, object],
    manifest: dict[str, object],
    *,
    expected_owner: int,
) -> PortableBundleInspection:
    """Download only a bound version; leave publication to its transaction.

    The caller holds shared tenant-state while capturing these records and
    export exclusion until publication or retirement. A failed download remains
    private incomplete work, removed by the ordinary spool cleanup path.
    """
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    validate_contract(record, expected_kind=ContractKind.ARCHIVE_RECORD)
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    spec = cast(dict[str, object], manifest["spec"])
    metadata = cast(dict[str, object], manifest["metadata"])
    desired = spec.get("desiredDeployment")
    if (
        record["bucket"] != remote.bucket
        or record["manifestDigest"] != manifest_digest(manifest).to_dict()
        or record["tenantId"] != metadata["id"]
        or spec["desiredState"] != "archived"
        or type(desired) is not dict
        or record["deploymentId"] != desired["id"]
    ):
        raise ArchiveRemoteError("archive record is not bound to this archived manifest")
    spool.reserve(CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES, 1))
    parent = os.open(spool.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        descriptor = os.open(
            EXPORT_WORKSPACE_BUNDLE_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb", buffering=0) as destination:
            os.fchmod(destination.fileno(), 0o600)
            remote.read_verified(
                cast(str, record["key"]),
                cast(str, record["versionId"]),
                size=cast(int, record["bundleSize"]),
                sha256=cast(str, cast(dict[str, object], record["bundleDigest"])["value"]),
                destination=destination,
            )
            os.fsync(destination.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    spool.reserve(CapacityReservation(0, 0))
    inspection = inspect_portable_bundle(
        spool.workspace / EXPORT_WORKSPACE_BUNDLE_NAME, expected_owner=expected_owner
    )
    require_archive_inspection(inspection, record, manifest)
    return inspection


def require_archive_inspection(
    inspection: PortableBundleInspection,
    record: dict[str, object],
    manifest: dict[str, object],
) -> None:
    """Verify content, canonical manifest, and exact bytes independently of S3."""
    if (
        inspection.provenance_manifest != manifest
        or inspection.provenance_manifest_digest.to_dict() != record["manifestDigest"]
        or inspection.bundle_digest.to_dict() != record["bundleDigest"]
        or inspection.bundle_size != record["bundleSize"]
        or inspection.release_tree_digest.to_dict() != record["releaseTreeDigest"]
    ):
        raise ArchiveRemoteError("remote bundle does not match its complete archive record")
