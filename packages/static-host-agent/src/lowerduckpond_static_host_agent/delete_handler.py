"""Dispatch ordinary archived and never-deployed deletion with separate authorization."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock

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
from lowerduckpond_static_host_agent.delete_publication import (
    activate_delete_transition,
    prepare_delete_transition,
    reconstruct_delete_transition,
)
from lowerduckpond_static_host_agent.execution import (
    ExecutionOutcome,
    LifecycleArtifact,
    LifecycleJobRejectionError,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import PublicationGate
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


class DeleteLifecycleError(RuntimeError):
    """Ordinary deletion cannot select one exact replay path."""


class DeleteLifecycleHandler:
    def __init__(  # noqa: PLR0913 - trusted local and credential-bearing boundaries
        self,
        repository: StateRepository,
        spool: ExportSpool,
        runtime: CaddyRuntime,
        store: DeploymentReleaseStore,
        gate: PublicationGate,
        *,
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
        self._store, self._gate, self._cleanup = store, gate, cleanup_client
        self._now, self._clock, self._entropy, self._limits = now, clock, entropy, capacity_limits
        self._reloader, self._restorer, self._verifier = reloader, restorer, verifier

    def execute(
        self, job_id: str, *, claim: LifecycleArtifact | None, blocking: bool
    ) -> ExecutionOutcome:
        canonical = validate_uuid7(job_id)
        if claim is not None:
            raise LifecycleJobRejectionError("invalid_artifact")
        with self._spool.locks.acquire(LockName.EXPORT, blocking=blocking):
            job, retirement, local, result, audited = self._classify(canonical, blocking=blocking)
            authority = cast(dict[str, object], job.document["sourceAuthority"])
            archive = authority["archiveRecord"]
            if local:
                prepared = reconstruct_delete_transition(
                    self._repository,
                    self._spool,
                    self._runtime,
                    self._gate,
                    canonical,
                    capacity_limits=self._limits,
                    blocking=blocking,
                )
            elif result is not None:
                if retirement is not None:
                    self._cleanup.finish(canonical, str(retirement.document["intentId"]))
                return ExecutionOutcome(
                    result,
                    False,
                    replay_existing=result.get("failurePublisher") == "authorization-executor",
                )
            else:
                self._gate.require_enabled()
                if type(archive) is dict:
                    self._cleanup.verify_source(canonical, archive)
                    if retirement is None:
                        retirement = ArchiveRetirementJournal(
                            self._repository, self._spool, bucket=str(archive["bucket"])
                        ).prepare(canonical, now=self._now())
                prepared = prepare_delete_transition(
                    self._repository,
                    self._spool,
                    self._runtime,
                    self._gate,
                    canonical,
                    retirement,
                    now=self._now(),
                    clock=self._clock,
                    entropy=self._entropy,
                    capacity_limits=self._limits,
                    blocking=blocking,
                )
            if type(archive) is dict and not audited:
                self._cleanup.verify_source(canonical, archive)
            outcome = activate_delete_transition(
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
            if prepared.retirement is not None:
                self._cleanup.finish(canonical, str(prepared.retirement.document["intentId"]))
            return outcome

    def _classify(
        self, job_id: str, *, blocking: bool
    ) -> tuple[StoredContract, StoredContract | None, bool, dict[str, object] | None, bool]:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE, blocking=blocking
        ) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id))
            request = cast(dict[str, object], job.document["request"])
            if (
                job.document["compatibilityVersion"] != "static-job-v2"
                or request["operation"] != "delete"
            ):
                raise DeleteLifecycleError("delete handler received another authorization")
            retirement: StoredContract | None = None
            local = False
            for identity in transaction.measure_intent_records().records:
                _path, record = transaction.read_intent(identity.intent_id)
                document = record.document
                if (
                    document["tenantId"] != request["tenantId"]
                    or document["correlationId"] != request["correlationId"]
                ):
                    raise DeleteLifecycleError("another lifecycle authority is active")
                if (
                    document["kind"] == "ArchiveRetirementIntent"
                    and document["provenance"] == {"kind": "authorization-job", "jobId": job_id}
                    and document["transition"] == "delete"
                    and retirement is None
                ):
                    retirement = record
                elif (
                    document["kind"] == "TransactionIntent"
                    and document["operation"] == "delete"
                    and not local
                ):
                    local = True
                else:
                    raise DeleteLifecycleError("delete journals are ambiguous")
            try:
                result = transaction.read(StateRecordPath.authorization_result(job_id)).document
            except FileNotFoundError:
                result = None
            if result is None and job.document["phase"] != "claimed":
                raise DeleteLifecycleError("delete job is not claimed")
            audited = (
                transaction.inspect_audit_correlation(request["correlationId"]).entry is not None
            )
            return job, retirement, local, result, audited
