from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archives
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_journal import RestoreJournal, RestoreStore
from lowerduckpond_static_host_agent.host_restore_tenant_restore import reconcile_tenant_restore
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.restore_commit import (
    RestoreCommitBoundary,
    finalize_restore_transition,
)
from lowerduckpond_static_host_agent.restore_prepare import PreparedRestoreTransition
from test_archive_journal import MemoryRemote
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_host_restore_deployments import evidence
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin
from test_restore_commit import _restoring


def proof(
    remote: ArchiveRemoteStore,
    prepared: PreparedRestoreTransition,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    choice: str,
) -> dict[str, object]:
    monkeypatch.setattr(
        archives,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    archive = cast(dict[str, object], prepared.retirement.document["archiveRecord"])
    manifest = cast(dict[str, object], prepared.plan.intent["sourceManifest"])
    return archives.verify_restore_archives(
        remote,
        [archives.RestoreArchive(archive, manifest, required=choice == "source")],
        workspace,
        owner=os.geteuid(),
    )


@pytest.mark.parametrize("choice", ["source", "candidate"])
@pytest.mark.parametrize("predecessors", [False, True])
def test_captured_restore_preserves_archived_source_or_original_new_deployment(  # noqa: PLR0913, PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    choice: str,
    predecessors: bool,
) -> None:
    with (
        _restoring(tmp_path, monkeypatch, predecessors=predecessors) as (
            remote,
            releases,
            prepared,
            _,
        ),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, choice)
        archive_proof = proof(remote.remote, prepared, tmp_path, monkeypatch, choice)
        begin(store, journal)
        with remote.repository.publication_transaction() as transaction:
            receipt = reconcile_tenant_restore(
                store,
                transaction,
                remote.spool,
                releases,
                prepared.plan.intent_id,
                selected,
                CA,
                archive_proof,
            )
            assert (
                reconcile_tenant_restore(
                    store,
                    transaction,
                    remote.spool,
                    releases,
                    prepared.plan.intent_id,
                    selected,
                    CA,
                    archive_proof,
                )
                == receipt
            )
            result = transaction.read(
                StateRecordPath.authorization_result(prepared.job.document["jobId"])
            ).document
            assert result["status"] == ("succeeded" if choice == "candidate" else "failed")
            assert (
                transaction.read(StateRecordPath.tenant_desired(prepared.plan.tenant_id)).document
                == prepared.plan.intent[choice + "Manifest"]
            )
            assert [row.intent_id for row in transaction.measure_intent_records().records] == [
                prepared.retirement.document["intentId"]
            ]
            assert transaction.inspect_audit().entry_count == 2  # noqa: PLR2004 - archive + restore
        assert remote.remote.inventory().versions


@pytest.mark.parametrize("boundary", list(RestoreCommitBoundary))
def test_restore_candidate_resumes_each_commit_boundary(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    boundary: RestoreCommitBoundary,
) -> None:
    with (
        _restoring(tmp_path, monkeypatch, predecessors=True) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, "candidate")
        archive_proof = proof(remote.remote, prepared, tmp_path, monkeypatch, "candidate")
        begin(store, journal)

        def interrupt(step: str) -> None:
            if step == boundary:
                raise RuntimeError("restore interrupted")

        with remote.repository.publication_transaction() as transaction:
            with pytest.raises(RuntimeError, match="restore interrupted"):
                reconcile_tenant_restore(
                    store,
                    transaction,
                    remote.spool,
                    releases,
                    prepared.plan.intent_id,
                    selected,
                    CA,
                    archive_proof,
                    failure_hook=interrupt,
                )
            reconcile_tenant_restore(
                store,
                transaction,
                remote.spool,
                releases,
                prepared.plan.intent_id,
                selected,
                CA,
                archive_proof,
            )
            assert (
                transaction.read(
                    StateRecordPath.authorization_result(prepared.job.document["jobId"])
                ).document
                == prepared.plan.result
            )
            assert transaction.inspect_audit().entry_count == 2  # noqa: PLR2004 - archive + restore


def test_candidate_can_retire_an_absent_exact_version_only_with_durable_release(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with (
        _restoring(tmp_path, monkeypatch) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, "candidate")
        cast(MemoryRemote, remote.remote.client).versions.clear()
        archive_proof = proof(remote.remote, prepared, tmp_path, monkeypatch, "candidate")
        begin(store, journal)
        with remote.repository.publication_transaction() as transaction:
            reconcile_tenant_restore(
                store,
                transaction,
                remote.spool,
                releases,
                prepared.plan.intent_id,
                selected,
                CA,
                archive_proof,
            )
            assert (
                transaction.read(
                    StateRecordPath.authorization_result(prepared.job.document["jobId"])
                ).document
                == prepared.plan.result
            )


@pytest.mark.parametrize(
    "boundary",
    [
        RestoreCommitBoundary.DEPLOYMENT_SYNC,
        RestoreCommitBoundary.DESIRED_STATE_SYNC,
        RestoreCommitBoundary.OBSERVED_STATE_SYNC,
    ],
)
def test_source_choice_reverts_partial_candidate_with_four_deployment_records(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    boundary: RestoreCommitBoundary,
) -> None:
    with (
        _restoring(tmp_path, monkeypatch, predecessors=True) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        selected = evidence(remote.repository, prepared.plan, "source")
        archive_proof = proof(remote.remote, prepared, tmp_path, monkeypatch, "source")
        begin(store, journal)

        def interrupt(step: RestoreCommitBoundary) -> None:
            if step == boundary:
                raise RuntimeError("partial restore")

        with remote.repository.publication_transaction() as transaction:
            with pytest.raises(RuntimeError, match="partial restore"):
                finalize_restore_transition(
                    transaction,
                    remote.spool,
                    releases,
                    prepared.job,
                    prepared.plan,
                    prepared.retirement,
                    failure_hook=interrupt,
                )
            reconcile_tenant_restore(
                store,
                transaction,
                remote.spool,
                releases,
                prepared.plan.intent_id,
                selected,
                CA,
                archive_proof,
            )
            assert (
                list(transaction.tenant_deployment_ids(prepared.plan.tenant_id))
                == prepared.job.document["dispatchDeploymentIds"]
            )
            assert (
                transaction.read(StateRecordPath.tenant_desired(prepared.plan.tenant_id)).document
                == prepared.plan.intent["sourceManifest"]
            )
