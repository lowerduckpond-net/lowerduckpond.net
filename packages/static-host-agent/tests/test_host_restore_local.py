from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_descriptor import INTENT_DIGEST_FORMAT
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.host_restore_archive_authority import collect_restore_archives
from lowerduckpond_static_host_agent.host_restore_archives import verify_restore_archives
from lowerduckpond_static_host_agent.host_restore_journal import RestoreJournal, RestoreStore
from lowerduckpond_static_host_agent.host_restore_local import (
    LocalRecovery,
    finish_restored_jobs,
    local_work,
)
from lowerduckpond_static_host_agent.host_restore_remote import finish_restore_remote
from lowerduckpond_static_host_agent.host_restore_verification import verify_authorization
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRevision,
    StoredContract,
    _StateTransaction,
)
from test_archive_commit import _prepared
from test_archive_journal import MemoryRemote
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_delete_commit import _deleting
from test_host_restore_archive import evidence as archive_evidence
from test_host_restore_delete import evidence as delete_evidence
from test_host_restore_deployments import evidence as restore_evidence
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_remote import proof_capacity as proof_capacity  # noqa: PLC0414
from test_host_restore_routes import CA, begin
from test_restore_commit import _restoring


class InterruptedLocalError(BaseException):
    pass


@pytest.fixture(autouse=True)
def executor_history_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    # The lower-level commit fixtures intentionally bind only the fields their
    # finalizers need. This composition additionally exercises ordinary result
    # replay, which requires the executor's complete dispatch history bundle.
    original = _StateTransaction.bind_dispatch_authority

    def bind(
        transaction: _StateTransaction,
        path: StateRecordPath,
        revision: StateRevision,
        document: dict[str, object],
        *,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> StoredContract:
        request = cast(dict[str, object], document["request"])
        tenant = request["tenantId"]
        tenants = transaction.measure_inventory().tenant_ids
        additions: dict[str, object] = {
            "dispatchArchiveDeploymentIds": list(transaction.tenant_archive_ids(tenant)),
            "dispatchTenantIds": list(tenants),
            "dispatchTenantRecordHistories": [
                [
                    identity,
                    list(transaction.tenant_archive_ids(identity)),
                    list(transaction.tenant_deployment_ids(identity)),
                ]
                for identity in tenants
            ],
        }
        for key, value in additions.items():
            if document.get(key) is None:
                document[key] = value
        return original(transaction, path, revision, document, capacity_limits=capacity_limits)

    monkeypatch.setattr(_StateTransaction, "bind_dispatch_authority", bind)


@pytest.mark.parametrize("operation", ["archive", "restore", "delete"])
@pytest.mark.parametrize("choice", ["source", "candidate"])
def test_local_work_resumes_original_finalizer_then_remote_cleanup_then_jobs(  # noqa: PLR0913,PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    choice: str,
) -> None:
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with ExitStack() as contexts:
        if operation == "archive":
            remote, releases, _, plan = contexts.enter_context(_prepared(tmp_path, "active"))
            evidence = archive_evidence(remote.repository, plan, choice)
        elif operation == "restore":
            remote, releases, prepared, _ = contexts.enter_context(
                _restoring(tmp_path, monkeypatch)
            )
            evidence = restore_evidence(remote.repository, prepared.plan, choice)
        else:
            remote, releases, deleted, _ = contexts.enter_context(
                _deleting(tmp_path, archived=True)
            )
            evidence = delete_evidence(remote.repository, deleted.plan, choice)
        store = contexts.enter_context(RestoreStore.locked(root, owner=os.geteuid()))
        begin(store, journal)
        with remote.repository.publication_transaction() as transaction:
            intents = [
                transaction.read_intent(row.intent_id)[1].document
                for row in transaction.measure_intent_records().records
            ]
        descriptor: dict[str, object] = {
            "intents": [
                {
                    "intentId": intent["intentId"],
                    "tenantId": intent["tenantId"],
                    "kind": intent["kind"],
                    "digest": framed_digest(INTENT_DIGEST_FORMAT, canonical_json_bytes(intent)),
                }
                for intent in intents
            ]
        }
        work = local_work(store, remote.repository, descriptor)
        verify_authorization(remote.repository, settled=False)
        authority = collect_restore_archives(store, remote, evidence, CA, remote.remote.inventory())
        proof = verify_restore_archives(remote.remote, authority, workspace, owner=os.geteuid())
        local = LocalRecovery(
            store, remote.repository, remote.spool, releases, evidence, CA, remote.remote.bucket
        )
        original_write = store.immutable

        def interrupt(name: str, raw: bytes, **kwargs: object) -> None:
            if name == "local-done.json":
                raise InterruptedLocalError
            original_write(name, raw)

        with monkeypatch.context() as patch:
            patch.setattr(store, "immutable", interrupt)
            with pytest.raises(InterruptedLocalError):
                local.reconcile(work, proof)
        # The removed local intent must not change the original captured work.
        assert local_work(store, remote.repository, descriptor) == work
        remaining = local.reconcile(work, proof)
        assert len(remaining) == 1
        with remote.repository.publication_transaction() as transaction:
            results = {
                identity: transaction.read(StateRecordPath.authorization_result(identity)).document
                for identity in transaction.measure_authorization_records().job_ids
            }
        client = cast(MemoryRemote, remote.remote.client)
        client.calls.clear()
        finish_restore_remote(store, remote, remaining[0], workspace)
        assert local.reconcile(work, proof) == remaining
        client.expected_intent = root
        finish_restore_remote(store, remote, remaining[0], workspace)
        finish_restored_jobs(store, remote.repository, work)
        finish_restored_jobs(store, remote.repository, work)
        verify_authorization(remote.repository, settled=True)
        assert not remote.repository.measure_intent_records().records
        assert "put" not in client.calls
        assert client.calls.count("delete") == int(
            choice == ("source" if operation == "archive" else "candidate")
        )
        for identity, result in results.items():
            assert (
                remote.repository.read(StateRecordPath.authorization_result(identity)).document
                == result
            )
