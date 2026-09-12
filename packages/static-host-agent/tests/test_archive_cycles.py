from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.execution import AuthorizationExecutor
from lowerduckpond_static_host_agent.issuance import AuthorizationIssuer
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_handler import _host
from test_archive_journal import _NOW, _TENANT, OpenGate, capacity  # noqa: F401 - capacity fixture
from test_restore_handler import extraction_capacity  # noqa: F401 - extraction capacity fixture
from test_route_commit import _Entropy

_CYCLES = 4
_HISTORY_LIMIT = 3


def test_repeated_private_archive_restore_and_deletion_preserve_exact_history(
    tmp_path: Path,
) -> None:
    instant = [_NOW]
    factories: list[Callable[[str], AuthorizationExecutor]] = []
    with _host(now=lambda: instant[0], executor_factory=factories, tmp_path=tmp_path) as (
        first_executor,
        first_job,
        repository,
        remote,
        runtime,
        futures,
    ):
        initial = repository.read(StateRecordPath.tenant_desired(_TENANT)).document
        keys: set[str] = set()
        deployments: set[str] = set()
        completed: list[tuple[str, dict[str, object]]] = []
        issuer = AuthorizationIssuer(repository, gate=OpenGate(), entropy=_Entropy())
        ordinal = 40

        def followup(operation: str) -> tuple[AuthorizationExecutor, str]:
            nonlocal ordinal
            ordinal += 1
            instant[0] += timedelta(minutes=1)
            job = issuer.issue(
                canonical_json_bytes(
                    {
                        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                        "kind": "OperationRequest",
                        "operation": operation,
                        "tenantId": _TENANT,
                        "correlationId": f"0198d17f-6f4a-7000-8000-{ordinal:012d}",
                    }
                ),
                operator_principal="operator@example.test",
                now=instant[0],
                artifact=None,
            )
            return factories[0](job.job_id), job.job_id

        executor = first_executor
        archive_job = first_job
        for iteration in range(_CYCLES):
            archive_result = executor.execute(archive_job).result
            completed.append((archive_job, archive_result))
            record = cast(dict[str, object], archive_result["archiveRecord"])
            assert record["key"] not in keys
            keys.add(str(record["key"]))
            assert not runtime.snapshots[runtime.active].tenants
            assert len(remote.versions) == 1
            restore_executor, restore_job = followup("restore")
            restored = restore_executor.execute(restore_job).result
            completed.append((restore_job, restored))
            manifest = cast(dict[str, object], restored["manifest"])
            assert manifest["metadata"] == initial["metadata"]
            selected = cast(
                dict[str, object], cast(dict[str, object], manifest["spec"])["desiredDeployment"]
            )
            assert selected["id"] not in deployments
            deployments.add(str(selected["id"]))
            assert not remote.versions
            with repository.publication_transaction() as transaction:
                retained = transaction.tenant_deployment_ids(_TENANT)
                assert len(retained) == min(iteration + 2, _HISTORY_LIMIT)
                assert not transaction.tenant_archive_ids(_TENANT)
            assert {
                path.name for path in (tmp_path / "sites" / _TENANT / "releases").iterdir()
            } == set(retained)
            for old_job, old_result in completed:
                assert factories[0](old_job).execute(old_job).result == old_result
            executor, archive_job = followup("archive")
        final_archive = executor.execute(archive_job).result
        delete_executor, delete_job = followup("delete")
        deleted = delete_executor.execute(delete_job).result
        assert deleted["status"] == "succeeded"
        assert not remote.versions
        assert not (tmp_path / "state" / "tenants" / _TENANT).exists()
        assert not (tmp_path / "sites" / _TENANT).exists()
        assert not repository.measure_intent_records().records
        assert factories[0](archive_job).execute(archive_job).result == final_archive
        for old_job, old_result in completed:
            assert factories[0](old_job).execute(old_job).result == old_result
        for future in futures:
            future.result(timeout=5)
