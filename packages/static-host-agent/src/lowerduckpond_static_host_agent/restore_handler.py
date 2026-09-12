"""Dispatch archive restore and recover local commitment before remote retirement."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import ContractKind, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock

from lowerduckpond_static_host_agent.archive_bundle import ArchiveBundleSource, fetch_archive_bundle
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_journal import ArchiveRetirementJournal
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
from lowerduckpond_static_host_agent.deployment_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
)
from lowerduckpond_static_host_agent.execution import (
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
)
from lowerduckpond_static_host_agent.export_delivery import ExportDelivery
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate, build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.restore_activate import activate_restore_transition
from lowerduckpond_static_host_agent.restore_prepare import (
    PreparedRestoreTransition,
    prepare_restore_transition,
    reconstruct_restore_transition,
)
from lowerduckpond_static_host_agent.route_handler import (
    _entropy,
    _utc_now,
    _wall_clock_milliseconds,
)


class RestoreLifecycleError(RuntimeError):
    """A restore job cannot select an exact replay path."""


@dataclass(frozen=True, slots=True)
class _RestoreState:
    job: StoredContract
    retirement: StoredContract | None
    transaction: bool
    result: dict[str, object] | None


class RestoreLifecycleHandler:
    def __init__(  # noqa: PLR0913 - independent worker and private service boundaries
        self,
        repository: StateRepository,
        spool: ExportSpool,
        runtime: CaddyRuntime,
        store: DeploymentReleaseStore,
        gate: PublicationGate,
        *,
        expected_owner: int,
        archive_source: ArchiveBundleSource,
        cleanup_client: ArchiveCleanupClient,
        now: Callable[[], datetime] = _utc_now,
        clock: MillisecondClock = _wall_clock_milliseconds,
        entropy: EntropySource = _entropy,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
        reloader: GenerationReloader = reload_caddy_generation,
        restorer: GenerationRestorer = restore_caddy_generation,
        verifier: GenerationVerifier = verify_running_caddy,
    ) -> None:
        self._repository, self._spool, self._runtime = repository, spool, runtime
        self._store, self._gate, self._owner = store, gate, expected_owner
        self._source, self._cleanup = archive_source, cleanup_client
        self._now, self._clock, self._entropy, self._limits = now, clock, entropy, capacity_limits
        self._reloader, self._restorer, self._verifier = reloader, restorer, verifier

    def execute(
        self, job_id: str, *, claim: LifecycleArtifact | None, blocking: bool
    ) -> ExecutionOutcome:
        canonical = validate_uuid7(job_id)
        if claim is not None:
            raise LifecycleJobRejectionError("invalid_artifact")
        with (
            self._spool.locks.acquire(LockName.INTAKE, blocking=blocking),
            self._spool.locks.acquire(LockName.EXPORT, blocking=blocking),
        ):
            state = self._classify(canonical, blocking=blocking)
            if state.transaction:
                prepared = reconstruct_restore_transition(
                    self._repository,
                    self._spool,
                    self._runtime,
                    self._store,
                    self._gate,
                    canonical,
                    capacity_limits=self._limits,
                    blocking=blocking,
                )
            elif state.result is not None:
                if state.retirement is not None:
                    self._cleanup.finish(canonical, str(state.retirement.document["intentId"]))
                return ExecutionOutcome(
                    state.result,
                    False,
                    replay_existing=state.result.get("failurePublisher")
                    == "authorization-executor",
                )
            else:
                prepared = self._prepare(canonical, state, blocking=blocking)
            outcome = activate_restore_transition(
                self._repository,
                self._spool,
                self._runtime,
                self._store,
                self._gate,
                prepared,
                reloader=self._reloader,
                restorer=self._restorer,
                verifier=self._verifier,
                blocking=blocking,
            )
            self._cleanup.finish(canonical, str(prepared.retirement.document["intentId"]))
            return outcome

    def _prepare(
        self, job_id: str, state: _RestoreState, *, blocking: bool
    ) -> PreparedRestoreTransition:
        self._gate.require_enabled()
        authority = cast(dict[str, object], state.job.document["sourceAuthority"])
        source = cast(dict[str, object], authority["manifest"])
        archive = cast(dict[str, object], authority["archiveRecord"])
        if state.retirement is None:
            self._cleanup.verify_source(job_id, archive)
        ExportDelivery(self._repository, self._spool, now=self._now).reconcile_locked()
        self._spool.prepare_workspace()
        try:
            fetch_archive_bundle(
                self._source,
                self._spool,
                archive,
                source,
                job_id=job_id,
                expected_owner=self._owner,
            )
            retirement = state.retirement or ArchiveRetirementJournal(
                self._repository, self._spool, bucket=str(archive["bucket"])
            ).prepare(job_id, now=self._now())
            return prepare_restore_transition(
                self._repository,
                self._spool,
                self._runtime,
                self._store,
                self._gate,
                job_id,
                str(retirement.document["intentId"]),
                now=self._now(),
                clock=self._clock,
                entropy=self._entropy,
                capacity_limits=self._limits,
                blocking=blocking,
            )
        finally:
            self._spool.discard_workspace()

    def _classify(self, job_id: str, *, blocking: bool) -> _RestoreState:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE, blocking=blocking
        ) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id))
            request = cast(dict[str, object], job.document["request"])
            if (
                request["operation"] != "restore"
                or job.document["compatibilityVersion"] != "static-job-v2"
            ):
                raise RestoreLifecycleError("restore handler received another authorization")
            records = [
                transaction.read_intent(value.intent_id)[1]
                for value in transaction.measure_intent_records().records
            ]
            retirement: StoredContract | None = None
            local = False
            for record in records:
                document = record.document
                if (
                    document.get("tenantId") != request["tenantId"]
                    or document.get("correlationId") != request["correlationId"]
                ):
                    raise RestoreLifecycleError("another lifecycle authority is active")
                if (
                    record.revision.contract_kind is ContractKind.ARCHIVE_RETIREMENT_INTENT
                    and retirement is None
                    and document["provenance"] == {"kind": "authorization-job", "jobId": job_id}
                    and document["transition"] == "restore"
                ):
                    retirement = record
                elif (
                    record.revision.contract_kind is ContractKind.TRANSACTION_INTENT
                    and not local
                    and document["operation"] == "restore"
                ):
                    local = True
                else:
                    raise RestoreLifecycleError("restore journals are ambiguous")
            if local and retirement is None:
                raise RestoreLifecycleError("restore transaction omitted retirement authority")
            try:
                result = transaction.read(StateRecordPath.authorization_result(job_id)).document
            except FileNotFoundError:
                result = None
            if (
                result is None
                and not local
                and (
                    job.document["phase"] != "claimed"
                    or build_expected_source(transaction, request) != job.document["expectedSource"]
                )
            ):
                raise LifecycleJobRejectionError("state_drift")
            return _RestoreState(job, retirement, local, result)
