from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity, ReleaseCapacityUsage
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore, ReleaseStoreError
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_export_handler import _archived_source, _filesystem  # noqa: F401 - capacity fixture

_NEW_DEPLOYMENT = "0199d17f-6f4a-7000-8000-000000000003"


@pytest.mark.parametrize("tamper", [None, "bundleDigest", "releaseTreeDigest", "manifestDigest"])
def test_restore_stages_only_the_complete_bound_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str | None
) -> None:
    root, releases, body, record = _archived_source(tmp_path)
    releases.chmod(0o710)
    (releases / ".staging").mkdir(mode=0o700)
    for module in ("portable_bundle", "zip_structure"):
        monkeypatch.setattr(
            f"lowerduckpond_static_host_agent.{module}.measure_filesystem_capacity_descriptor",
            lambda fd: FilesystemCapacity(
                os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
            ),
        )
    tenant = str(record["tenantId"])
    with (
        StateRepository(root, expected_owner=os.geteuid()) as repository,
        ExportSpool(root, expected_owner=os.geteuid()) as spool,
        DeploymentReleaseStore(
            releases,
            releases / ".staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store,
        spool.locks.acquire(LockName.INTAKE),
        spool.construction(),
        repository.publication_transaction() as transaction,
    ):
        manifest = transaction.read(StateRecordPath.tenant_desired(tenant)).document
        bundle = spool.workspace / "bundle.zip"
        bundle.write_bytes(body)
        bundle.chmod(0o600)
        if tamper:
            cast(dict[str, object], record[tamper])["value"] = "0" * 64
            with pytest.raises(ReleaseStoreError):
                store.stage_archive(
                    spool,
                    record,
                    manifest,
                    tenant_id=tenant,
                    deployment_id=_NEW_DEPLOYMENT,
                    retained_usage=ReleaseCapacityUsage(()),
                    publication_lock=transaction,
                )
            assert list((releases / ".staging").iterdir()) == []
            return
        staged = store.stage_archive(
            spool,
            record,
            manifest,
            tenant_id=tenant,
            deployment_id=_NEW_DEPLOYMENT,
            retained_usage=ReleaseCapacityUsage(()),
            publication_lock=transaction,
        )
        assert staged.measurement.digest.to_dict() == record["releaseTreeDigest"]
        assert not (releases / tenant / "releases" / _NEW_DEPLOYMENT).exists()
        store.publish(staged, publication_lock=transaction)
        restored = releases / tenant / "releases" / _NEW_DEPLOYMENT
        assert (restored / "index.html").read_bytes() == b"export content\n"
        assert not (restored / "manifest.json").exists()
        assert transaction.read(StateRecordPath.tenant_desired(tenant)).document == manifest
        for selected_tenant, selected_deployment in (
            (_NEW_DEPLOYMENT, _NEW_DEPLOYMENT),
            (tenant, record["deploymentId"]),
        ):
            with pytest.raises(ReleaseStoreError, match="new deployment"):
                store.stage_archive(
                    spool,
                    record,
                    manifest,
                    tenant_id=selected_tenant,
                    deployment_id=selected_deployment,
                    retained_usage=ReleaseCapacityUsage(()),
                    publication_lock=transaction,
                )
