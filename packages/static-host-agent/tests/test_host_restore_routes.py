from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_caddy import (
    CaddyBackupEvidence,
    CaddyGenerationEvidence,
)
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput, build_tenant_caddy_routes
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartTarget
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_routes import reconcile_route
from lowerduckpond_static_host_agent.lifecycle_plan import RouteTransitionPlan
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_commit import RouteCommitBoundary
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_route_commit import _capacity_isolated as _capacity_isolated  # noqa: PLC0414
from test_route_commit import _fixture, _prepared, _source, _write_correlation

CA = (b"original trusted certificate DER",)


def evidence(plan: RouteTransitionPlan, choice: str, state: str) -> CaddyBackupEvidence:
    recovery = cast(dict[str, object], plan.intent["lifecycleRecovery"])
    identifier = str(recovery[choice + "RuntimeGenerationId"])
    manifest = cast(dict[str, object], plan.intent[choice + "Manifest"])
    observed = cast(dict[str, object], recovery[choice + "ObservedState"])
    deployment = _source(state)[2]
    routes = build_tenant_caddy_routes(
        platform_namespace=_fixture("platform-namespace.json"),
        tenants=() if state == "archived" else (TenantRouteInput(manifest, observed, deployment),),
        runtime_generation_id=identifier,
        origin_pull_ca_der=CA,
        origin_pull_required=True,
    )
    return CaddyBackupEvidence(
        identifier,
        None,
        (
            CaddyGenerationEvidence(
                CaddyStartTarget(identifier, "a" * 64),
                cast(dict[str, str], routes.route_metadata["routeStateDigest"]),
            ),
        ),
    )


def begin(store: RestoreStore, journal: RestoreJournal) -> None:
    store.begin(journal)
    current = store.advance(journal, RestorePhase.RESTORED, {"captured": True})
    store.advance(current, RestorePhase.VALIDATED, {"measured": True})


@pytest.mark.parametrize(
    "operation,state",
    [
        ("suspend", "active"),
        ("resume", "suspended"),
        ("rename", "active"),
        ("rename", "undeployed"),
        ("reconcile", "archived"),
    ],
)
@pytest.mark.parametrize("choice", ["source", "candidate"])
def test_captured_choice_preserves_exact_route_lifecycle_and_immutable_result(  # noqa: PLR0913, PLR0917 - operation/state/selection matrix
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    operation: str,
    state: str,
    choice: str,
) -> None:
    repository, job, plan = _prepared(
        tmp_path,
        operation=operation,
        state=state,
        slug="new-slug" if operation == "rename" else None,
    )
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(plan, choice, state)
        begin(store, journal)
        with repository.publication_transaction() as transaction:
            decision = reconcile_route(store, transaction, plan.intent_id, selected, CA)
            result = transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
            assert not transaction.measure_intent_records().records
            assert transaction.inspect_audit().entry_count == 1
            assert result["status"] == ("succeeded" if choice == "candidate" else "failed")
            if choice == "source":
                assert result["errorCode"] == "unavailable"
            desired = transaction.read(StateRecordPath.tenant_desired(plan.tenant_id)).document
            assert desired == plan.intent[choice + "Manifest"]
            assert reconcile_route(store, transaction, plan.intent_id, selected, CA) == decision
            assert (
                transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
                == result
            )
            assert transaction.inspect_audit().entry_count == 1


@pytest.mark.parametrize("boundary", list(RouteCommitBoundary))
def test_captured_candidate_finishes_each_partial_commit_without_runtime_payload_reuse(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    boundary: RouteCommitBoundary,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(plan, "candidate", "active")
        begin(store, journal)

        def stop(step: RouteCommitBoundary) -> None:
            if step is boundary:
                raise RuntimeError("interrupted route restore")

        with (
            repository.publication_transaction() as transaction,
            pytest.raises(RuntimeError, match="interrupted route restore"),
        ):
            reconcile_route(store, transaction, plan.intent_id, selected, CA, failure_hook=stop)
        with repository.publication_transaction() as transaction:
            reconcile_route(store, transaction, plan.intent_id, selected, CA)
            assert (
                transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
                == plan.result
            )
            assert not transaction.measure_intent_records().records
            assert transaction.inspect_audit().entry_count == 1


def test_source_failure_repairs_result_first_audit_loss_without_repeating_or_restamping(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(plan, "source", "active")
        begin(store, journal)
        append = _StateTransaction.append_audit

        def stop(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("lost audit reply")

        monkeypatch.setattr(_StateTransaction, "append_audit", stop)
        with repository.publication_transaction() as transaction:
            with pytest.raises(RuntimeError, match="lost audit reply"):
                reconcile_route(store, transaction, plan.intent_id, selected, CA)
            original = transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
        monkeypatch.setattr(_StateTransaction, "append_audit", append)
        with repository.publication_transaction() as transaction:
            reconcile_route(store, transaction, plan.intent_id, selected, CA)
            assert (
                transaction.read(StateRecordPath.authorization_result(job["jobId"])).document
                == original
            )
            assert transaction.inspect_audit().entry_count == 1
            assert not transaction.measure_intent_records().records


@pytest.mark.parametrize("fault", ["selection", "trust", "unrelated", "contradictory-result"])
def test_ambiguous_route_authority_never_rolls_back_or_completes_a_candidate(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    fault: str,
) -> None:
    repository, job, plan = _prepared(tmp_path)
    with repository, RestoreStore.locked(root, owner=os.geteuid()) as store:
        _write_correlation(repository, job)
        selected = evidence(plan, "source", "active")
        trust = CA
        if fault == "trust":
            trust = (b"wrong original certificate",)
        elif fault == "selection":
            selected = CaddyBackupEvidence(
                "0198d17f-6f4a-7000-8000-000000000099",
                None,
                (
                    CaddyGenerationEvidence(
                        CaddyStartTarget("0198d17f-6f4a-7000-8000-000000000099", "a" * 64),
                        selected.generations[0].route_state_digest,
                    ),
                ),
            )
        begin(store, journal)
        with repository.publication_transaction() as transaction:
            path = StateRecordPath.tenant_desired(plan.tenant_id)
            if fault == "unrelated":
                stored = transaction.read(path)
                document = stored.document
                cast(dict[str, object], document["metadata"])["slug"] = "unrelated"
                transaction.compare_and_swap(path, stored.revision, document)
            elif fault == "contradictory-result":
                transaction.create_immutable(
                    StateRecordPath.authorization_result(job["jobId"]), plan.result
                )
            before = canonical_json_bytes(transaction.read(path).document)
            with pytest.raises(HostRestoreError):
                reconcile_route(store, transaction, plan.intent_id, selected, trust)
            assert canonical_json_bytes(transaction.read(path).document) == before
            assert transaction.measure_intent_records().records
            assert transaction.inspect_audit().entry_count == 0
