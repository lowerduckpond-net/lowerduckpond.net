from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archive_proof
from lowerduckpond_static_host_agent.archive_commit import ArchiveCommitBoundary
from lowerduckpond_static_host_agent.backup_caddy import (
    CaddyBackupEvidence,
    CaddyGenerationEvidence,
)
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput, build_tenant_caddy_routes
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartTarget
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_archive import reconcile_archive
from lowerduckpond_static_host_agent.host_restore_journal import RestoreJournal, RestoreStore
from lowerduckpond_static_host_agent.lifecycle_plan import ArchiveTransitionPlan
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_commit import _prepared
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin


def evidence(
    repository: StateRepository, plan: ArchiveTransitionPlan, choice: str
) -> CaddyBackupEvidence:
    recorded = cast(dict[str, object], plan.intent["archiveRecovery"])
    generation = str(recorded[choice + "RuntimeGenerationId"])
    routes = build_tenant_caddy_routes(
        platform_namespace=repository.read(StateRecordPath.platform_namespace()).document,
        tenants=()
        if choice == "candidate"
        else (
            TenantRouteInput(
                cast(dict[str, object], recorded["sourceManifest"]),
                cast(dict[str, object], recorded["sourceObservedState"]),
                repository.read(
                    StateRecordPath.tenant_deployment(
                        plan.tenant_id, plan.archive_record["deploymentId"]
                    )
                ).document,
            ),
        ),
        runtime_generation_id=generation,
        origin_pull_ca_der=CA,
        origin_pull_required=True,
    )
    return CaddyBackupEvidence(
        generation,
        None,
        (
            CaddyGenerationEvidence(
                CaddyStartTarget(generation, "a" * 64),
                cast(dict[str, str], routes.route_metadata["routeStateDigest"]),
            ),
        ),
    )


@pytest.mark.parametrize("choice", ["source", "candidate"])
@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_restore_archive_keeps_original_history_and_remote_cleanup_barrier(  # noqa: PLR0913, PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    choice: str,
    lifecycle: str,
) -> None:
    monkeypatch.setattr(
        archive_proof,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        _prepared(tmp_path, lifecycle) as (archives, releases, job, plan),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(archives.repository, plan, choice)
        proof = archive_proof.verify_restore_archives(
            archives.remote,
            [
                archive_proof.RestoreArchive(
                    plan.archive_record, plan.manifest, required=choice == "candidate"
                )
            ],
            workspace,
            owner=os.geteuid(),
        )
        begin(store, journal)
        decision = reconcile_archive(
            store,
            archives.repository,
            archives.spool,
            releases,
            plan.intent_id,
            selected,
            CA,
            proof,
        )
        assert (
            reconcile_archive(
                store,
                archives.repository,
                archives.spool,
                releases,
                plan.intent_id,
                selected,
                CA,
                proof,
            )
            == decision
        )
        result = archives.repository.read(
            StateRecordPath.authorization_result(job.document["jobId"])
        ).document
        assert result["status"] == ("succeeded" if choice == "candidate" else "failed")
        if choice == "source":
            assert result["errorCode"] == "archive_unavailable"
        assert (
            archives.repository.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            == plan.intent[choice + "Manifest"]
        )
        assert [row.intent_id for row in archives.repository.measure_intent_records().records] == [
            plan.construction_intent_id
        ]
        assert archives.remote.inventory().versions
        with archives.repository.publication_transaction() as transaction:
            assert transaction.inspect_audit().entry_count == 1
            assert (
                list(transaction.tenant_deployment_ids(plan.tenant_id))
                == job.document["dispatchDeploymentIds"]
            )


@pytest.mark.parametrize(
    "choice, boundary",
    [
        *(("candidate", step.value) for step in ArchiveCommitBoundary),
        *(
            ("source", step)
            for step in (
                "observed.json",
                "desired.json",
                "archive-unbound",
                "intent-removed",
                "audit-sync",
                "result-sync",
                "job-sync",
            )
        ),
    ],
)
def test_archive_reconstruction_resumes_every_local_boundary(  # noqa: PLR0913, PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    choice: str,
    boundary: str,
) -> None:
    monkeypatch.setattr(
        archive_proof,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        _prepared(tmp_path) as (archives, releases, job, plan),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(archives.repository, plan, choice)
        proof = archive_proof.verify_restore_archives(
            archives.remote,
            [
                archive_proof.RestoreArchive(
                    plan.archive_record, plan.manifest, required=choice == "candidate"
                )
            ],
            workspace,
            owner=os.geteuid(),
        )
        begin(store, journal)

        def interrupt(step: str) -> None:
            if step == boundary:
                raise RuntimeError("restore interrupted")

        with pytest.raises(RuntimeError, match="restore interrupted"):
            reconcile_archive(
                store,
                archives.repository,
                archives.spool,
                releases,
                plan.intent_id,
                selected,
                CA,
                proof,
                failure_hook=interrupt,
            )
        reconcile_archive(
            store,
            archives.repository,
            archives.spool,
            releases,
            plan.intent_id,
            selected,
            CA,
            proof,
        )
        with archives.repository.publication_transaction() as transaction:
            assert transaction.inspect_audit().entry_count == 1
            assert transaction.read(
                StateRecordPath.authorization_job(job.document["jobId"])
            ).document["phase"] == ("completed" if choice == "candidate" else "failed")
