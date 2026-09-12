from __future__ import annotations

import os
import socket
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import archive_handler as handler_module
from lowerduckpond_static_host_agent.archive_activate import activate_archive_transition
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_commit import ArchiveCommitBoundary
from lowerduckpond_static_host_agent.archive_construction_service import (
    ArchiveConstructionClient,
    serve_archive_construction,
)
from lowerduckpond_static_host_agent.archive_handler import ArchiveLifecycleHandler
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, ArchiveRemoteStore
from lowerduckpond_static_host_agent.archive_revalidate import revalidate_archive
from lowerduckpond_static_host_agent.archive_service import ArchiveExportClient
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.delete_handler import DeleteLifecycleHandler
from lowerduckpond_static_host_agent.execution import AuthorizationExecutor
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.restore_handler import RestoreLifecycleHandler
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes
from test_archive_activate import SimulatedCrashError
from test_archive_cleanup_service import _serve as _serve_cleanup
from test_archive_journal import (
    _BUCKET,
    _CORRELATION,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    OpenGate,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    setup_root,
)
from test_archive_service import _serve as _serve_export
from test_route_commit import _Entropy, _Runtime


def _serve_construction(stream: socket.socket, root: Path, remote: ArchiveRemoteStore) -> None:
    with (
        StateRepository(root, expected_owner=_OWNER) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
    ):
        serve_archive_construction(
            stream,
            repository,
            spool,
            remote,
            expected_owner=_OWNER,
            quarantine=ArchiveQuarantine(
                root, bucket=remote.bucket, expected_owner=_OWNER, locks=spool.locks
            ),
        )


@contextmanager
def _host(  # noqa: PLR0913 - explicit private service fixture modes
    tmp_path: Path,
    *,
    lost_response: bool = False,
    revalidation: bool = False,
    restore: bool = False,
    deletion: bool = False,
    now: Callable[[], datetime] = lambda: _NOW,
    executor_factory: list[Callable[[str], AuthorizationExecutor]] | None = None,
) -> Iterator[
    tuple[AuthorizationExecutor, str, StateRepository, MemoryRemote, _Runtime, list[Future[None]]]
]:
    root, releases = setup_root(tmp_path)
    (root / "intake").mkdir(mode=0o700)
    releases.chmod(0o710)
    (releases / ".staging").mkdir(mode=0o700)
    memory = MemoryRemote()
    memory.lose_response = lost_response
    memory.require_intent = False
    memory.expected_intent = root / "intents"
    remote = ArchiveRemoteStore(memory, bucket=_BUCKET)
    futures: list[Future[None]] = []
    with (
        ThreadPoolExecutor() as pool,
        StateRepository(root, expected_owner=_OWNER, tenant_release_root=releases) as repository,
        ExportSpool(root, expected_owner=_OWNER) as spool,
        ArtifactIntake(root, expected_owner=_OWNER) as intake,
        DeploymentReleaseStore(
            releases,
            releases / ".staging",
            expected_owner=_OWNER,
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store,
    ):

        def connect(*, construction: bool) -> socket.socket:
            sender, receiver = socket.socketpair()
            futures.append(
                pool.submit(
                    _serve_construction if construction else _serve_cleanup, receiver, root, remote
                )
            )
            return sender

        runtime = _Runtime()
        with repository.publication_transaction() as transaction:
            observed = transaction.read(StateRecordPath.tenant_observed(_TENANT)).document
            runtime.active = cast(str, observed["runtimeGenerationId"])
            runtime.running = runtime.active
            runtime.snapshots[runtime.active] = snapshot_tenant_routes(transaction)
        issuer = AuthorizationIssuer(repository, gate=OpenGate(), entropy=_Entropy())
        issued = issuer.issue(
            canonical_json_bytes(
                {
                    "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                    "kind": "OperationRequest",
                    "operation": "archive",
                    "tenantId": _TENANT,
                    "correlationId": _CORRELATION,
                }
            ),
            operator_principal="operator@example.test",
            now=now(),
            artifact=None,
        )
        cleanup = ArchiveCleanupClient(
            spool, connector=partial(connect, construction=False), expected_peer_uid=_OWNER
        )
        handler = ArchiveLifecycleHandler(
            repository,
            spool,
            cast(CaddyRuntime, runtime),
            store,
            OpenGate(),
            state_root=root,
            release_root=releases,
            expected_owner=_OWNER,
            construction_client=ArchiveConstructionClient(
                spool, connector=partial(connect, construction=True), expected_peer_uid=_OWNER
            ),
            cleanup_client=cleanup,
            now=now,
            clock=lambda: 1_789_000_000_000,
            entropy=_Entropy(),
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        def connect_read() -> socket.socket:
            sender, receiver = socket.socketpair()
            futures.append(pool.submit(_serve_export, receiver, root, remote))
            return sender

        restore_handler = RestoreLifecycleHandler(
            repository,
            spool,
            cast(CaddyRuntime, runtime),
            store,
            OpenGate(),
            expected_owner=_OWNER,
            archive_source=ArchiveExportClient(
                spool, connector=connect_read, expected_peer_uid=_OWNER
            ),
            cleanup_client=cleanup,
            now=now,
            clock=lambda: 1_789_000_001_000,
            entropy=_Entropy(),
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        delete_handler = DeleteLifecycleHandler(
            repository,
            spool,
            cast(CaddyRuntime, runtime),
            store,
            OpenGate(),
            cleanup_client=cleanup,
            now=now,
            clock=lambda: 1_789_000_002_000,
            entropy=_Entropy(),
            reloader=runtime.reload,
            restorer=runtime.restore,
            verifier=runtime.verify,
        )

        def executor_for(canonical_job: str) -> AuthorizationExecutor:
            return AuthorizationExecutor(
                repository,
                intake,
                handlers={"archive": handler, "restore": restore_handler, "delete": delete_handler},
                deleted_tenant_release_validator=lambda tenant: not (releases / tenant).exists(),
                deleted_tenant_route_validator=lambda tenant: all(
                    cast(dict[str, object], value.manifest["metadata"])["id"] != tenant
                    for value in runtime.snapshots[runtime.active].tenants
                ),
                retained_archive_validator=partial(
                    cleanup.verify_terminal, canonical_job, mode="retained"
                ),
                retired_archive_validator=partial(
                    cleanup.verify_terminal, canonical_job, mode="retired"
                ),
                unreturned_archive_validator=lambda job_id: cleanup.verify_terminal(
                    job_id, None, mode="accounted"
                ),
                tenant_runtime_validator=lambda *_args: True,
            )

        if executor_factory is not None:
            executor_factory.append(executor_for)
        executor = executor_for(issued.job_id)
        if revalidation or restore or deletion:
            assert executor.execute(issued.job_id).result["status"] == "succeeded"
            issued = issuer.issue(
                canonical_json_bytes(
                    {
                        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                        "kind": "OperationRequest",
                        "operation": "delete" if deletion else "restore" if restore else "archive",
                        "tenantId": _TENANT,
                        "correlationId": "0198d17f-6f4a-7000-8000-000000000999",
                    }
                ),
                operator_principal="operator@example.test",
                now=now(),
                artifact=None,
            )
            executor = executor_for(issued.job_id)
        yield executor, issued.job_id, repository, memory, runtime, futures


def test_new_archive_authorization_revalidates_the_unchanged_archived_object(
    tmp_path: Path,
) -> None:
    with _host(tmp_path, revalidation=True) as (
        executor,
        job_id,
        repository,
        remote,
        runtime,
        futures,
    ):
        source = repository.read(StateRecordPath.tenant_desired(_TENANT))
        observed = repository.read(StateRecordPath.tenant_observed(_TENANT))
        selected = runtime.active
        outcome = executor.execute(job_id)
        result = outcome.result
        assert result["status"] == "succeeded"
        record = cast(dict[str, object], result["archiveRecord"])
        assert record["correlationId"] != result["correlationId"]
        assert repository.read(StateRecordPath.tenant_desired(_TENANT)).revision == source.revision
        assert (
            repository.read(StateRecordPath.tenant_observed(_TENANT)).revision == observed.revision
        )
        assert runtime.active == selected
        assert not repository.measure_intent_records().records
        assert executor.execute(job_id).result == result
        for future in futures:
            future.result(timeout=5)
        assert remote.calls.count("put") == 1


@pytest.mark.parametrize("boundary", ["intent-sync", "audit-sync", "result-sync", "job-sync"])
def test_archived_revalidation_recovers_each_durable_boundary_without_reupload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    def interrupt(event: str) -> None:
        if event == boundary:
            raise SimulatedCrashError

    with _host(tmp_path, revalidation=True) as (
        executor,
        job_id,
        repository,
        remote,
        runtime,
        futures,
    ):
        selected = runtime.active
        with monkeypatch.context() as patch:
            patch.setattr(
                handler_module,
                "revalidate_archive",
                partial(revalidate_archive, failure_hook=interrupt),
            )
            with pytest.raises(SimulatedCrashError):
                executor.execute(job_id)
        assert repository.measure_intent_records().records
        assert executor.execute(job_id).result["status"] == "succeeded"
        assert not repository.measure_intent_records().records
        assert runtime.active == selected
        assert remote.calls.count("put") == 1
        for future in futures:
            future.result(timeout=5)


def test_archived_revalidation_refuses_changed_remote_bytes_before_result_publication(
    tmp_path: Path,
) -> None:
    with _host(tmp_path, revalidation=True) as (
        executor,
        job_id,
        repository,
        remote,
        runtime,
        futures,
    ):
        selected = runtime.active
        remote.body = b"x" * len(remote.body)
        with pytest.raises(ArchiveRemoteError):
            executor.execute(job_id)
        with pytest.raises(FileNotFoundError):
            repository.read(StateRecordPath.authorization_result(job_id))
        assert not repository.measure_intent_records().records
        assert runtime.active == selected
        assert remote.versions
        assert (tmp_path / "state" / "platform" / "archive-quarantine.json").exists()
        for future in futures[:-1]:
            future.result(timeout=5)
        with pytest.raises(ArchiveRemoteError):
            futures[-1].result(timeout=5)


def test_archive_handler_constructs_publishes_and_revalidates_through_private_services(
    tmp_path: Path,
) -> None:
    with _host(tmp_path) as (executor, job_id, repository, remote, runtime, futures):
        result = executor.execute(job_id).result
        assert result["status"] == "succeeded"
        manifest = cast(dict[str, object], result["manifest"])
        assert cast(dict[str, object], manifest["spec"])["desiredState"] == "archived"
        assert (tmp_path / "sites" / _TENANT / "releases").is_dir()
        assert not runtime.snapshots[runtime.active].tenants
        assert (
            repository.read(StateRecordPath.authorization_job(job_id)).document[
                "executionValidated"
            ]
            is True
        )
        assert not repository.measure_intent_records().records
        assert executor.execute(job_id).result == result
        for future in futures:
            future.result(timeout=5)
        assert remote.calls.count("put") == 1
        assert remote.versions


def test_archive_handler_resolves_lost_upload_response_without_repeating_put(
    tmp_path: Path,
) -> None:
    with _host(tmp_path, lost_response=True) as (
        executor,
        job_id,
        repository,
        remote,
        runtime,
        futures,
    ):
        before = runtime.active
        result = executor.execute(job_id).result
        assert result["status"] == "failed"
        assert result["archiveRecord"] is None
        assert result["errorCode"] == "archive_unavailable"
        assert runtime.active == before
        assert (tmp_path / "sites" / _TENANT).exists()
        assert not remote.versions
        assert not (tmp_path / "state" / "platform" / "archive-quarantine.json").exists()
        assert not repository.measure_intent_records().records
        assert executor.execute(job_id).result == result
        with pytest.raises(TimeoutError):
            futures[0].result(timeout=5)
        for future in futures[1:]:
            future.result(timeout=5)
        assert remote.calls.count("put") == 1


@pytest.mark.parametrize(
    "boundary", [ArchiveCommitBoundary.RELEASE_VERIFIED, ArchiveCommitBoundary.RESULT_SYNC]
)
def test_archive_handler_recovers_partial_local_commit_without_uploading_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: ArchiveCommitBoundary
) -> None:
    original = activate_archive_transition

    def interrupt(event: ArchiveCommitBoundary) -> None:
        if event == boundary:
            raise SimulatedCrashError

    with _host(tmp_path) as (executor, job_id, repository, remote, _runtime, futures):
        with monkeypatch.context() as patch:
            patch.setattr(
                handler_module,
                "activate_archive_transition",
                partial(original, commit_failure_hook=interrupt),
            )
            with pytest.raises(SimulatedCrashError):
                executor.execute(job_id)
        assert repository.measure_intent_records().records
        assert executor.execute(job_id).result["status"] == "succeeded"
        assert not repository.measure_intent_records().records
        for future in futures:
            future.result(timeout=5)
        assert remote.calls.count("put") == 1


def test_archive_handler_replays_a_lost_cleanup_receipt_without_losing_remote_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ArchiveCleanupClient.finish

    def interrupt(client: ArchiveCleanupClient, job_id: str, intent_id: str) -> None:
        original(client, job_id, intent_id)
        raise SimulatedCrashError

    with _host(tmp_path) as (executor, job_id, repository, remote, _runtime, futures):
        with monkeypatch.context() as patch:
            patch.setattr(ArchiveCleanupClient, "finish", interrupt)
            with pytest.raises(SimulatedCrashError):
                executor.execute(job_id)
        assert not repository.measure_intent_records().records
        assert (
            repository.read(StateRecordPath.authorization_job(job_id)).document[
                "executionValidated"
            ]
            is False
        )
        assert executor.execute(job_id).result["status"] == "succeeded"
        assert (
            repository.read(StateRecordPath.authorization_job(job_id)).document[
                "executionValidated"
            ]
            is True
        )
        for future in futures:
            future.result(timeout=5)
        assert remote.calls.count("put") == 1
