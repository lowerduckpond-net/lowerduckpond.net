"""Archive lifecycle dispatch using credential-free construction and cleanup clients."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import Digest, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock

from lowerduckpond_static_host_agent.archive_abort import finalize_failed_construction
from lowerduckpond_static_host_agent.archive_activate import activate_archive_transition
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_construction_service import ArchiveConstructionClient
from lowerduckpond_static_host_agent.archive_journal import ArchiveConstructionJournal
from lowerduckpond_static_host_agent.archive_prepare import prepare_archive_transition
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_recover import reconstruct_archive_transition
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.archive_revalidate import revalidate_archive
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
)
from lowerduckpond_static_host_agent.execution import (
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
)
from lowerduckpond_static_host_agent.export_build import build_snapshot_bundle
from lowerduckpond_static_host_agent.export_delivery import ExportDelivery
from lowerduckpond_static_host_agent.export_snapshot import capture_export_snapshot
from lowerduckpond_static_host_agent.export_spool import EXPORT_WORKSPACE_BUNDLE_NAME, ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.route_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
)
from lowerduckpond_static_host_agent.route_handler import (
    _entropy,
    _utc_now,
    _wall_clock_milliseconds,
)


class ArchiveLifecycleError(RuntimeError):
    """Archive dispatch cannot select one exact durable recovery path."""


@dataclass(frozen=True, slots=True)
class _ArchiveState:
    job: StoredContract
    construction: StoredContract | None
    transaction_id: str | None
    result: dict[str, object] | None
    failed_audit: bool


class ArchiveLifecycleHandler:
    def __init__(  # noqa: PLR0913 - explicit trusted boundaries
        self,
        repository: StateRepository,
        spool: ExportSpool,
        runtime: CaddyRuntime,
        release_store: DeploymentReleaseStore,
        gate: PublicationGate,
        *,
        state_root: Path,
        release_root: Path,
        expected_owner: int,
        construction_client: ArchiveConstructionClient,
        cleanup_client: ArchiveCleanupClient,
        now: Callable[[], datetime] = _utc_now,
        clock: MillisecondClock = _wall_clock_milliseconds,
        entropy: EntropySource = _entropy,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
        reloader: GenerationReloader = reload_caddy_generation,
        restorer: GenerationRestorer = restore_caddy_generation,
        verifier: GenerationVerifier = verify_running_caddy,
    ) -> None:
        self._repository = repository
        self._spool = spool
        self._runtime = runtime
        self._release_store = release_store
        self._gate = gate
        self._state_root = state_root
        self._release_root = release_root
        self._owner = expected_owner
        self._construction_client = construction_client
        self._cleanup_client = cleanup_client
        self._now = now
        self._clock = clock
        self._entropy = entropy
        self._limits = capacity_limits
        self._reloader = reloader
        self._restorer = restorer
        self._verifier = verifier

    def execute(  # noqa: PLR0911 - explicit durable recovery cases
        self, job_id: str, *, claim: LifecycleArtifact | None, blocking: bool
    ) -> ExecutionOutcome:
        canonical = validate_uuid7(job_id)
        if claim is not None:
            raise LifecycleJobRejectionError("invalid_artifact")
        with self._spool.locks.acquire(LockName.EXPORT, blocking=blocking):
            state = self._classify(canonical, blocking=blocking)
            expected = cast(dict[str, object], state.job.document["expectedSource"])
            if expected["lifecycle"] == "archived" and (
                state.result is None or state.transaction_id is not None
            ):
                return revalidate_archive(
                    self._repository,
                    self._spool,
                    self._runtime,
                    self._gate,
                    self._cleanup_client,
                    canonical,
                    now=self._now(),
                    clock=self._clock,
                    entropy=self._entropy,
                    verifier=self._verifier,
                    capacity_limits=self._limits,
                    blocking=blocking,
                )
            if state.transaction_id is not None:
                prepared = reconstruct_archive_transition(
                    self._repository,
                    self._spool,
                    self._runtime,
                    self._gate,
                    canonical,
                    capacity_limits=self._limits,
                    blocking=blocking,
                )
                outcome = activate_archive_transition(
                    self._repository,
                    self._spool,
                    self._runtime,
                    self._release_store,
                    self._gate,
                    prepared,
                    reloader=self._reloader,
                    restorer=self._restorer,
                    verifier=self._verifier,
                    blocking=blocking,
                )
                self._cleanup_client.finish(canonical, prepared.plan.construction_intent_id)
                return ExecutionOutcome(outcome.result, outcome.created)
            if state.result is not None:
                if state.construction is not None:
                    # A crash after result publication can precede the job's phase write.
                    if state.result["status"] == "failed":
                        finalize_failed_construction(
                            self._repository,
                            self._spool,
                            canonical,
                            capacity_limits=self._limits,
                            blocking=blocking,
                        )
                    self._cleanup_client.finish(
                        canonical, str(state.construction.document["intentId"])
                    )
                return ExecutionOutcome(
                    state.result,
                    False,
                    replay_existing=state.result.get("failurePublisher")
                    == "authorization-executor",
                )
            if state.construction is not None:
                if state.construction.document["phase"] == "prepared" or state.failed_audit:
                    return self._abort(canonical, state.construction, blocking=blocking)
                return self._publish(canonical, state.construction, blocking=blocking)
            self._gate.require_enabled()
            ExportDelivery(self._repository, self._spool, now=self._now).reconcile_locked()
            self._spool.prepare_workspace()
            try:
                construction = self._construct(canonical, blocking=blocking)
            except ArchiveRemoteError, OSError:
                interrupted = self._classify(canonical, blocking=blocking)
                if interrupted.construction is None:
                    raise
                return self._abort(canonical, interrupted.construction, blocking=blocking)
            finally:
                self._spool.discard_workspace()
            return self._publish(canonical, construction, blocking=blocking)

    def _construct(self, job_id: str, *, blocking: bool) -> StoredContract:
        with self._repository.transaction(mode=LockMode.SHARED, blocking=blocking) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id)).document
            request = cast(dict[str, object], job["request"])
            expected = cast(dict[str, object], job["expectedSource"])
            if build_expected_source(transaction, request) != expected:
                raise LifecycleJobRejectionError("state_drift")
            snapshot = capture_export_snapshot(
                self._spool,
                transaction,
                release_root=self._release_root,
                tenant_id=request["tenantId"],
                expected_manifest_digest=_digest(expected["manifestDigest"]),
                expected_deployment_digest=_digest(expected["deploymentDigest"]),
                expected_owner=self._owner,
                archive=True,
            )
        build_snapshot_bundle(self._spool, snapshot, expected_owner=self._owner)
        with self._construction_client.session(job_id) as session:
            quarantine = ArchiveQuarantine(
                self._state_root,
                bucket=session.bucket,
                expected_owner=self._owner,
                locks=self._spool.locks,
            )
            journal = ArchiveConstructionJournal(
                self._repository,
                self._spool,
                expected_owner=self._owner,
                bucket=session.bucket,
                require_quarantine_empty=quarantine.require_empty,
            )
            prepared = journal.prepare(job_id, snapshot, now=self._now())
            descriptor = os.open(
                self._spool.workspace / EXPORT_WORKSPACE_BUNDLE_NAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            with os.fdopen(descriptor, "rb") as source:
                receipt = session.upload(prepared, source)
            return journal.confirm(prepared, receipt).construction

    def _publish(
        self, job_id: str, construction: StoredContract, *, blocking: bool
    ) -> ExecutionOutcome:
        prepared = prepare_archive_transition(
            self._repository,
            self._spool,
            self._runtime,
            self._gate,
            job_id,
            construction.document["intentId"],
            now=self._now(),
            clock=self._clock,
            entropy=self._entropy,
            capacity_limits=self._limits,
            blocking=blocking,
        )
        outcome = activate_archive_transition(
            self._repository,
            self._spool,
            self._runtime,
            self._release_store,
            self._gate,
            prepared,
            reloader=self._reloader,
            restorer=self._restorer,
            verifier=self._verifier,
            blocking=blocking,
        )
        self._cleanup_client.finish(job_id, prepared.plan.construction_intent_id)
        return ExecutionOutcome(outcome.result, outcome.created)

    def _abort(
        self, job_id: str, construction: StoredContract, *, blocking: bool
    ) -> ExecutionOutcome:
        outcome = finalize_failed_construction(
            self._repository, self._spool, job_id, capacity_limits=self._limits, blocking=blocking
        )
        self._cleanup_client.finish(job_id, str(construction.document["intentId"]))
        return outcome

    def _classify(self, job_id: str, *, blocking: bool) -> _ArchiveState:
        with self._repository.publication_transaction(blocking=blocking) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id))
            request = cast(dict[str, object], job.document["request"])
            if (
                job.document["compatibilityVersion"] != "static-job-v2"
                or request["operation"] != "archive"
            ):
                raise ArchiveLifecycleError("archive handler received other authority")
            try:
                result = transaction.read(StateRecordPath.authorization_result(job_id)).document
            except FileNotFoundError:
                result = None
            construction = None
            transaction_id = None
            for identity in transaction.measure_intent_records().records:
                _path, intent = transaction.read_intent(identity.intent_id)
                document = intent.document
                if (
                    document["tenantId"] != request["tenantId"]
                    or document["correlationId"] != request["correlationId"]
                ):
                    raise ArchiveLifecycleError("archive waits for unrelated lifecycle recovery")
                if (
                    document["kind"] == "ArchiveConstructionIntent"
                    and document["jobId"] == job_id
                    and construction is None
                ):
                    construction = intent
                elif (
                    document["kind"] == "TransactionIntent"
                    and document["operation"] == "archive"
                    and transaction_id is None
                ):
                    transaction_id = identity.intent_id
                else:
                    raise ArchiveLifecycleError(
                        "archive journals exceed one construction and transaction"
                    )
            if (
                transaction_id is not None
                and construction is None
                and cast(dict[str, object], job.document["expectedSource"])["lifecycle"]
                != "archived"
            ):
                raise ArchiveLifecycleError("archive transaction lost its construction")
            audit = transaction.inspect_audit_correlation(request["correlationId"])
            return _ArchiveState(
                job,
                construction,
                transaction_id,
                result,
                audit.entry is not None and audit.entry["resultStatus"] == "failed",
            )


def _digest(value: object) -> Digest:
    if type(value) is not dict:
        raise ArchiveLifecycleError("archive source omitted its digest")
    return Digest(
        cast(str, value["format"]), cast(str, value["algorithm"]), cast(str, value["value"])
    )
