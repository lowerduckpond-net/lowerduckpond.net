from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archives
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.backup_caddy import (
    CaddyBackupEvidence,
    CaddyGenerationEvidence,
)
from lowerduckpond_static_host_agent.caddy_routes import build_tenant_caddy_routes
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartTarget
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.emergency_delete import EmergencyDeletion
from lowerduckpond_static_host_agent.host_restore_emergency import reconcile_emergency
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_journal import _BUCKET
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_emergency_delete import _CORRELATION, _PRINCIPAL, _REASON, _emergency
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin


def prepare(
    handler: EmergencyDeletion, tenant: str, choice: str
) -> tuple[dict[str, object], CaddyBackupEvidence]:
    def interrupt(step: str) -> None:
        if step == ("authority-sync" if choice == "source" else "candidate-selected"):
            raise RuntimeError("captured emergency")

    handler.hook = interrupt
    with pytest.raises(RuntimeError, match="captured emergency"):
        handler.execute(tenant, _CORRELATION, operator_principal=_PRINCIPAL, reason=_REASON)
    intent = handler.repository.read(
        StateRecordPath.emergency_deletion_intent(_CORRELATION)
    ).document
    source = EmergencyDeletion._source(intent)
    generation = str(intent[choice + "RuntimeGenerationId"])
    routes = build_tenant_caddy_routes(
        platform_namespace=handler.repository.read(StateRecordPath.platform_namespace()).document,
        tenants=()
        if choice == "candidate"
        or cast(dict[str, object], source.manifest["spec"])["desiredState"] == "archived"
        else (source,),
        runtime_generation_id=generation,
        origin_pull_ca_der=CA,
        origin_pull_required=True,
    )
    return intent, CaddyBackupEvidence(
        generation,
        None,
        (
            CaddyGenerationEvidence(
                CaddyStartTarget(generation, "a" * 64),
                cast(dict[str, str], routes.route_metadata["routeStateDigest"]),
            ),
        ),
    )


def proof(
    remote: ArchiveRemoteStore,
    intent: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    archive = intent["archiveRecord"]
    authority = (
        []
        if archive is None
        else [
            archives.RestoreArchive(
                cast(dict[str, object], archive),
                cast(dict[str, object], intent["sourceManifest"]),
                required=False,
            )
        ]
    )
    return archives.verify_restore_archives(remote, authority, workspace, owner=os.geteuid())


@pytest.mark.parametrize("lifecycle", ["active", "suspended", "undeployed", "archived"])
@pytest.mark.parametrize("choice", ["source", "candidate"])
def test_recovery_never_invents_emergency_authority_or_a_failed_administrator_result(  # noqa: PLR0913, PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    lifecycle: str,
    choice: str,
) -> None:
    with (
        _emergency(tmp_path, lifecycle) as (handler, tenant, memory),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        intent, selected = prepare(handler, tenant, choice)
        archive_proof = proof(
            ArchiveRemoteStore(memory, bucket=_BUCKET), intent, tmp_path, monkeypatch
        )
        begin(store, journal)
        with (
            handler.spool.locks.acquire(LockName.EXPORT),
            handler.repository.publication_transaction() as transaction,
        ):
            before = transaction.inspect_audit()
            if choice == "source":
                with pytest.raises(HostRestoreError, match="no_authorized_failure"):
                    reconcile_emergency(
                        store,
                        transaction,
                        handler.spool,
                        handler.store,
                        _CORRELATION,
                        selected,
                        CA,
                        archive_proof,
                    )
                assert transaction.inspect_audit() == before
                assert (
                    transaction.read(StateRecordPath.tenant_desired(tenant)).document
                    == intent["sourceManifest"]
                )
                assert (
                    transaction.read(
                        StateRecordPath.emergency_deletion_intent(_CORRELATION)
                    ).document
                    == intent
                )
                with pytest.raises(FileNotFoundError):
                    transaction.read(StateRecordPath.emergency_result(_CORRELATION))
            else:
                decision = reconcile_emergency(
                    store,
                    transaction,
                    handler.spool,
                    handler.store,
                    _CORRELATION,
                    selected,
                    CA,
                    archive_proof,
                )
                assert (
                    reconcile_emergency(
                        store,
                        transaction,
                        handler.spool,
                        handler.store,
                        _CORRELATION,
                        selected,
                        CA,
                        archive_proof,
                    )
                    == decision
                )
                assert (
                    transaction.read(StateRecordPath.emergency_result(_CORRELATION)).document
                    == intent["result"]
                )
                assert (
                    transaction.inspect_audit_correlation(_CORRELATION).entry
                    == intent["auditEntry"]
                )
                assert tenant not in transaction.measure_inventory().tenant_ids
                assert len(transaction.measure_intent_records().records) == int(
                    lifecycle == "archived"
                )
        assert "delete" not in memory.calls


@pytest.mark.parametrize(
    "boundary",
    [
        "retirement-sync",
        "audit-sync",
        "release-removed",
        "state-record-removed",
        "state-directory-removed",
        "tenant-removed",
        "result-sync",
        "intent-removed",
    ],
)
def test_emergency_candidate_resumes_every_local_commit_boundary(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    with (
        _emergency(tmp_path, "archived") as (handler, tenant, memory),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        intent, selected = prepare(handler, tenant, "candidate")
        archive_proof = proof(
            ArchiveRemoteStore(memory, bucket=_BUCKET), intent, tmp_path, monkeypatch
        )
        begin(store, journal)

        def interrupt(step: str) -> None:
            if step == boundary:
                raise RuntimeError("restore interrupted")

        with (
            handler.spool.locks.acquire(LockName.EXPORT),
            handler.repository.publication_transaction() as transaction,
        ):
            with pytest.raises(RuntimeError, match="restore interrupted"):
                reconcile_emergency(
                    store,
                    transaction,
                    handler.spool,
                    handler.store,
                    _CORRELATION,
                    selected,
                    CA,
                    archive_proof,
                    failure_hook=interrupt,
                )
            reconcile_emergency(
                store,
                transaction,
                handler.spool,
                handler.store,
                _CORRELATION,
                selected,
                CA,
                archive_proof,
            )
            assert transaction.inspect_audit_correlation(_CORRELATION).entry == intent["auditEntry"]
            assert tenant not in transaction.measure_inventory().tenant_ids
