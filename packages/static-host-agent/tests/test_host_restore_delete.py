from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archive_proof
from lowerduckpond_static_host_agent.backup_caddy import (
    CaddyBackupEvidence,
    CaddyGenerationEvidence,
)
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput, build_tenant_caddy_routes
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartTarget
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.delete_commit import (
    DeleteCommitBoundary,
    finalize_delete_transition,
)
from lowerduckpond_static_host_agent.delete_plan import DeleteTransitionPlan
from lowerduckpond_static_host_agent.host_restore_delete import reconcile_delete
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_delete_commit import _deleting
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin


def evidence(
    repository: StateRepository, plan: DeleteTransitionPlan, choice: str
) -> CaddyBackupEvidence:
    recorded = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    source = cast(dict[str, object], plan.intent["sourceManifest"])
    generation = str(recorded[choice + "RuntimeGenerationId"])
    tenants = (
        ()
        if choice == "candidate"
        or cast(dict[str, object], source["spec"])["desiredState"] == "archived"
        else (
            TenantRouteInput(
                source, cast(dict[str, object], recorded["sourceObservedState"]), None
            ),
        )
    )
    routes = build_tenant_caddy_routes(
        platform_namespace=repository.read(StateRecordPath.platform_namespace()).document,
        tenants=tenants,
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


@pytest.mark.parametrize("archived", [False, True])
@pytest.mark.parametrize("choice", ["source", "candidate"])
def test_delete_reconstruction_preserves_source_or_exact_permanent_tombstone(  # noqa: PLR0913, PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    archived: bool,
    choice: str,
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
        _deleting(tmp_path, archived=archived) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, choice)
        obligations = (
            []
            if prepared.retirement is None
            else [
                archive_proof.RestoreArchive(
                    cast(dict[str, object], prepared.retirement.document["archiveRecord"]),
                    cast(dict[str, object], prepared.plan.intent["sourceManifest"]),
                    required=choice == "source",
                )
            ]
        )
        proof = archive_proof.verify_restore_archives(
            remote.remote, obligations, workspace, owner=os.geteuid()
        )
        begin(store, journal)
        with remote.repository.publication_transaction() as transaction:
            receipt = reconcile_delete(
                store,
                transaction,
                remote.spool,
                releases,
                prepared.plan.intent_id,
                selected,
                CA,
                proof,
            )
            assert (
                reconcile_delete(
                    store,
                    transaction,
                    remote.spool,
                    releases,
                    prepared.plan.intent_id,
                    selected,
                    CA,
                    proof,
                )
                == receipt
            )
            result = transaction.read(
                StateRecordPath.authorization_result(prepared.job.document["jobId"])
            ).document
            assert result["status"] == ("succeeded" if choice == "candidate" else "failed")
            assert (prepared.plan.tenant_id in transaction.measure_inventory().tenant_ids) == (
                choice == "source"
            )
            assert len(transaction.measure_intent_records().records) == int(archived)
            audit = transaction.inspect_audit_correlation(
                prepared.plan.intent["correlationId"]
            ).entry
            assert audit is not None
            if choice == "candidate":
                assert audit == prepared.plan.audit_entry
            else:
                assert "deletionEvidence" not in audit


@pytest.mark.parametrize("boundary", list(DeleteCommitBoundary))
def test_candidate_delete_resumes_after_tombstone_and_partial_namespace_removal(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    boundary: DeleteCommitBoundary,
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
        _deleting(tmp_path, archived=True) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, "candidate")
        assert prepared.retirement is not None
        proof = archive_proof.verify_restore_archives(
            remote.remote,
            [
                archive_proof.RestoreArchive(
                    cast(dict[str, object], prepared.retirement.document["archiveRecord"]),
                    cast(dict[str, object], prepared.plan.intent["sourceManifest"]),
                    required=False,
                )
            ],
            workspace,
            owner=os.geteuid(),
        )
        begin(store, journal)

        def interrupt(step: str) -> None:
            if step == boundary:
                raise RuntimeError("restore interrupted")

        with remote.repository.publication_transaction() as transaction:
            with pytest.raises(RuntimeError, match="restore interrupted"):
                reconcile_delete(
                    store,
                    transaction,
                    remote.spool,
                    releases,
                    prepared.plan.intent_id,
                    selected,
                    CA,
                    proof,
                    failure_hook=interrupt,
                )
            reconcile_delete(
                store,
                transaction,
                remote.spool,
                releases,
                prepared.plan.intent_id,
                selected,
                CA,
                proof,
            )
            assert (
                transaction.inspect_audit_correlation(prepared.plan.intent["correlationId"]).entry
                == prepared.plan.audit_entry
            )
            assert prepared.plan.tenant_id not in transaction.measure_inventory().tenant_ids


def test_captured_source_cannot_undo_a_committed_tombstone(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
) -> None:
    with (
        _deleting(tmp_path, archived=False) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, "source")
        begin(store, journal)

        def interrupt(step: DeleteCommitBoundary) -> None:
            if step is DeleteCommitBoundary.AUDIT_SYNC:
                raise RuntimeError("tombstone committed")

        with remote.repository.publication_transaction() as transaction:
            with pytest.raises(RuntimeError, match="tombstone committed"):
                finalize_delete_transition(
                    remote.repository,
                    transaction,
                    remote.spool,
                    releases,
                    prepared.job,
                    prepared.plan,
                    prepared.retirement,
                    failure_hook=interrupt,
                )
            before = transaction.inspect_audit()
            with pytest.raises(HostRestoreError):
                reconcile_delete(
                    store,
                    transaction,
                    remote.spool,
                    releases,
                    prepared.plan.intent_id,
                    selected,
                    CA,
                    {},
                )
            assert transaction.inspect_audit() == before
            assert (
                transaction.read(StateRecordPath.tenant_desired(prepared.plan.tenant_id)).document
                == prepared.plan.intent["sourceManifest"]
            )
