from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.archive_commit import (
    ArchiveCommitBoundary,
    ArchiveCommitError,
    finalize_archive_transition,
)
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.lifecycle_plan import (
    ArchiveTransitionPlan,
    plan_archive_transition,
)
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordPath,
    StoredContract,
)
from test_archive_journal import (
    _DEPLOYMENT,
    _NOW,
    _OWNER,
    _TENANT,
    MemoryRemote,
    capacity,  # noqa: F401 - shared autouse capacity fixture
    prepared_source,
)


@contextmanager
def _prepared(
    tmp_path: Path,
    lifecycle: str = "active",
) -> Iterator[tuple[ArchiveJournal, DeploymentReleaseStore, StoredContract, ArchiveTransitionPlan]]:
    with prepared_source(tmp_path, MemoryRemote(), lifecycle=lifecycle) as (
        journal,
        job_id,
        snapshot,
        _quarantine,
    ):
        uploaded = journal.construct(job_id, snapshot, now=_NOW)
        source = snapshot.source_manifest
        assert source is not None
        releases = tmp_path / "sites"
        # The journal fixture uses a measured ordinary directory; the installed
        # release store adds its private root and same-filesystem staging boundary.
        releases.chmod(0o710)
        (releases / ".staging").mkdir(mode=0o700)
        with DeploymentReleaseStore(
            releases,
            releases / ".staging",
            expected_owner=_OWNER,
            expected_release_group=os.getegid(),
            expected_staging_group=os.getegid(),
        ) as store:
            with journal.repository.publication_transaction() as transaction:
                job = transaction.read(StateRecordPath.authorization_job(job_id))
                document = job.document
                observed = transaction.read(StateRecordPath.tenant_observed(_TENANT)).document
                source_generation = (
                    observed["runtimeGenerationId"] or "0198d17f-6f4a-7000-8000-000000000004"
                )
                source_routes = "both" if lifecycle == "active" else "absent"
                document.update(
                    dispatchSourceObservedState=observed,
                    dispatchSourceRuntimeGenerationId=source_generation,
                    dispatchSourceRouteSet=source_routes,
                    dispatchDeploymentIds=list(transaction.tenant_deployment_ids(_TENANT)),
                )
                job = transaction.bind_dispatch_authority(
                    StateRecordPath.authorization_job(job_id),
                    job.revision,
                    document,
                )
                plan = plan_archive_transition(
                    job.document,
                    transaction.read(StateRecordPath.platform_namespace()).document,
                    source,
                    observed,
                    snapshot.deployment,
                    uploaded.construction.document,
                    uploaded.record,
                    source_runtime_generation_id=source_generation,
                    candidate_runtime_generation_id="0198d17f-6f4a-7000-8000-000000000006",
                    source_route_set=source_routes,
                    audit_state=transaction.inspect_audit(),
                    now=_NOW,
                    clock=lambda: 1_789_000_000_000,
                    entropy=lambda length: b"\x07" * length,
                )
                transaction.create_immutable(
                    StateRecordPath.transaction_intent(plan.intent_id), plan.intent
                )
            yield journal, store, job, plan


def _finish(
    journal: ArchiveJournal,
    store: DeploymentReleaseStore,
    job: StoredContract,
    plan: ArchiveTransitionPlan,
) -> None:
    with journal.repository.publication_transaction() as transaction:
        outcome = finalize_archive_transition(transaction, journal.spool, store, job, plan)
        assert outcome.result == plan.result


@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_archive_commit_preserves_release_history_and_remote_journal_for_verification(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    with _prepared(tmp_path, lifecycle) as (journal, store, job, plan):
        _finish(journal, store, job, plan)
        assert (tmp_path / "sites" / _TENANT / "releases").is_dir()
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).document
            == plan.manifest
        )
        assert (
            journal.repository.read(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT)).document
            == plan.archive_record
        )
        assert journal.repository.read(StateRecordPath.tenant_deployment(_TENANT, _DEPLOYMENT))
        identities = journal.repository.measure_intent_records().records
        assert tuple(identity.intent_id for identity in identities) == (
            plan.construction_intent_id,
        )
        with journal.repository.publication_transaction() as transaction:
            assert not finalize_archive_transition(
                transaction, journal.spool, store, job, plan
            ).created
        journal.finish(plan.construction_intent_id)
        assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize("boundary", list(ArchiveCommitBoundary))
@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_archive_commit_recovers_each_durable_boundary_without_repeating_audit(
    tmp_path: Path,
    boundary: ArchiveCommitBoundary,
    lifecycle: str,
) -> None:
    class SimulatedCrashError(RuntimeError):
        pass

    def interrupt(observed: ArchiveCommitBoundary) -> None:
        if observed is boundary:
            raise SimulatedCrashError

    with _prepared(tmp_path, lifecycle) as (journal, store, job, plan):
        with (
            pytest.raises(SimulatedCrashError),
            journal.repository.publication_transaction() as transaction,
        ):
            finalize_archive_transition(
                transaction, journal.spool, store, job, plan, failure_hook=interrupt
            )
        _finish(journal, store, job, plan)
        with journal.repository.publication_transaction() as transaction:
            assert transaction.inspect_audit().entry_count == 1
            assert (
                transaction.read(StateRecordPath.authorization_job(job.document["jobId"])).document[
                    "phase"
                ]
                == "completed"
            )
        journal.finish(plan.construction_intent_id)
        assert not journal.repository.measure_intent_records().records


@pytest.mark.parametrize("defect", ["record", "history", "observed-first", "missing-construction"])
def test_archive_commit_rejects_drift_while_preserving_source_releases(
    tmp_path: Path,
    defect: str,
) -> None:
    with _prepared(tmp_path) as (journal, store, job, plan):
        if defect == "record":
            changed = deepcopy(plan.archive_record)
            changed["versionId"] = "unbound-version"
            journal.repository.create_immutable(
                StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT), changed
            )
        elif defect == "history":
            path = StateRecordPath.authorization_job(job.document["jobId"])
            changed = job.document
            changed["dispatchDeploymentIds"] = []
            (tmp_path / "state").joinpath(*path.components).write_bytes(
                canonical_json_bytes(changed)
            )
        elif defect == "observed-first":
            path = StateRecordPath.tenant_observed(_TENANT)
            current = journal.repository.read(path)
            journal.repository.compare_and_swap(path, current.revision, plan.observed_state)
        else:
            path = StateRecordPath.archive_construction_intent(plan.construction_intent_id)
            (tmp_path / "state").joinpath(*path.components).unlink()
        with pytest.raises((ArchiveCommitError, StateConflictError, FileNotFoundError)):
            _finish(journal, store, job, plan)
        assert (
            tmp_path / "sites" / _TENANT / "releases" / _DEPLOYMENT / "index.html"
        ).read_text() == "archived bytes"


def test_archive_commit_reserves_terminal_capacity_before_any_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _prepared(tmp_path) as (journal, store, job, plan):
        monkeypatch.setattr(
            "lowerduckpond_static_host_agent.repository._StateTransaction.measure_filesystem_capacity",
            lambda _self: FilesystemCapacity(1, 4096, 8_000_000, 0, 4_000_000, 3_000_000),
        )
        with pytest.raises(CapacityRejectedError):
            _finish(journal, store, job, plan)
        assert (
            journal.repository.read(StateRecordPath.tenant_desired(_TENANT)).document
            == plan.intent["sourceManifest"]
        )
        with pytest.raises(FileNotFoundError):
            journal.repository.read(StateRecordPath.tenant_archive(_TENANT, _DEPLOYMENT))
        assert (tmp_path / "sites" / _TENANT / "releases" / _DEPLOYMENT / "index.html").exists()
