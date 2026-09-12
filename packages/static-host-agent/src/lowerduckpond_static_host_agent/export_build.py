"""Bounded portable-bundle construction shared by exports and remote archives."""

from __future__ import annotations

import os

from lowerduckpond_static_host_agent.capacity import CapacityReservation
from lowerduckpond_static_host_agent.export_snapshot import ExportSnapshot
from lowerduckpond_static_host_agent.export_spool import (
    EXPORT_WORKSPACE_BUNDLE_NAME,
    ExportSpool,
    ExportSpoolError,
)
from lowerduckpond_static_host_agent.portable_bundle import (
    MAXIMUM_PORTABLE_BUNDLE_BYTES,
    PortableBundleInspection,
    build_portable_bundle,
    inspect_portable_bundle,
)


def build_snapshot_bundle(
    spool: ExportSpool, snapshot: ExportSnapshot, *, expected_owner: int
) -> PortableBundleInspection:
    spool.reserve(CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES, 2))
    parent = os.open(spool.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with spool.accounting() as accounting:

            def check_capacity(descriptor: int, byte_count: int) -> None:
                accounting.record(parent)
                accounting.record(descriptor)
                fragment = spool.fragment_size()
                allocation = ((byte_count + fragment - 1) // fragment) * fragment
                accounting.reserve(CapacityReservation(allocation + fragment, 0))

            bundle = build_portable_bundle(
                snapshot.content,
                snapshot.manifest,
                output_parent=spool.workspace,
                output_name=EXPORT_WORKSPACE_BUNDLE_NAME,
                lock_manager=spool.locks,
                expected_owner=expected_owner,
                read_only_snapshot=True,
                check_capacity=check_capacity,
            )
        spool.reserve(CapacityReservation(0, 0))
        inspection = inspect_portable_bundle(
            spool.workspace / bundle.output_name, expected_owner=expected_owner
        )
        if (
            inspection.bundle_size != bundle.bundle_size
            or inspection.bundle_digest != bundle.bundle_digest
            or inspection.provenance_manifest != snapshot.manifest
            or inspection.release_tree_digest != snapshot.measurement.digest
        ):
            raise ExportSpoolError("completed export disagrees with its captured source")
        return inspection
    finally:
        os.close(parent)
