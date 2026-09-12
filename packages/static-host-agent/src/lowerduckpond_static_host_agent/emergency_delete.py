"""Separately authenticated root deletion with durable administrator recovery authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, validate_uuid7
from lowerduckpond_static_domain import EntropySource, MillisecondClock, generate_uuid7

from lowerduckpond_static_host_agent.archive_activate import _ensure_forward_candidate
from lowerduckpond_static_host_agent.archive_commit import _missing_exact
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.caddy_admin import (
    reload_caddy_generation,
    restore_caddy_generation,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_routes import TenantRouteInput
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.emergency_plan import plan_emergency_deletion
from lowerduckpond_static_host_agent.emergency_state import (
    remove_emergency_state,
    verify_emergency_state,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_activate import (
    GenerationReloader,
    GenerationRestorer,
    GenerationVerifier,
    _ensure_candidate_running,
)
from lowerduckpond_static_host_agent.route_commit import _audit_needs_append, _ensure_audit
from lowerduckpond_static_host_agent.route_handler import (
    _entropy,
    _utc_now,
    _wall_clock_milliseconds,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    RouteOverlayMode,
    TenantRouteOverlay,
    TenantRouteSnapshot,
    snapshot_other_tenant_routes,
    snapshot_tenant_routes,
)
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class EmergencyDeletionError(RuntimeError):
    """Administrator deletion cannot prove its exact recorded recovery path."""


class _RemovalGate:
    def require_enabled(self) -> None:
        """Root emergency authority permits only the independently checked removal projection."""


class EmergencyDeletion:
    def __init__(  # noqa: PLR0913 - separate root-only authority and publication mechanisms
        self,
        repository: StateRepository,
        spool: ExportSpool,
        runtime: CaddyRuntime,
        store: DeploymentReleaseStore,
        *,
        cleanup: Callable[[dict[str, object] | None, dict[str, object]], None],
        now: Callable[[], datetime] = _utc_now,
        clock: MillisecondClock = _wall_clock_milliseconds,
        entropy: EntropySource = _entropy,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
        reloader: GenerationReloader = reload_caddy_generation,
        restorer: GenerationRestorer = restore_caddy_generation,
        verifier: GenerationVerifier = verify_running_caddy,
        hook: Callable[[str], None] = lambda _boundary: None,
    ) -> None:
        self.repository, self.spool, self.runtime, self.store = repository, spool, runtime, store
        self.cleanup, self.now, self.clock, self.entropy = cleanup, now, clock, entropy
        self.limits, self.reloader, self.restorer, self.verifier = (
            capacity_limits,
            reloader,
            restorer,
            verifier,
        )
        self.hook = hook

    def execute(
        self, tenant_id: str, correlation_id: str, *, operator_principal: str, reason: str
    ) -> dict[str, object]:
        tenant, correlation = validate_uuid7(tenant_id), validate_uuid7(correlation_id)
        with (
            self.spool.locks.acquire(LockName.INTAKE, blocking=True),
            self.spool.locks.acquire(LockName.EXPORT, blocking=True),
        ):
            with self.repository.publication_transaction(blocking=True) as transaction:
                try:
                    result = transaction.read(
                        StateRecordPath.emergency_result(correlation)
                    ).document
                except FileNotFoundError:
                    result = None
                if result is not None:
                    self._require_retry(result, tenant, correlation, operator_principal, reason)
                records = [
                    transaction.read_intent(value.intent_id)[1]
                    for value in transaction.measure_intent_records().records
                ]
                local = [
                    record
                    for record in records
                    if record.document["kind"] == "EmergencyDeletionIntent"
                ]
                if local:
                    if len(local) != 1:
                        raise EmergencyDeletionError("emergency recovery has ambiguous journals")
                    self._require_retry(
                        cast(dict[str, object], local[0].document["result"]),
                        tenant,
                        correlation,
                        operator_principal,
                        reason,
                    )
                    prepared = local[0]
                elif result is None:
                    if records:
                        raise EmergencyDeletionError("another lifecycle authority is active")
                    prepared = self._prepare(
                        transaction, tenant, correlation, operator_principal, reason
                    )
                else:
                    prepared = None
            if prepared is not None:
                result = self._commit(prepared)
            if result is None:  # pragma: no cover - both paths establish a result
                raise EmergencyDeletionError("emergency deletion has no result")
            with (
                self.repository.publication_transaction(blocking=True) as transaction,
                self.runtime.using_held_publication_lock(self.repository),
            ):
                self._verify_absence(transaction, tenant)
                audit = transaction.inspect_audit_correlation(correlation).entry
                if audit is None:
                    raise EmergencyDeletionError("emergency result lost its permanent evidence")
                remaining = [
                    transaction.read_intent(value.intent_id)[1].document
                    for value in transaction.measure_intent_records().records
                ]
                if len(remaining) > 1 or (
                    remaining
                    and (
                        remaining[0]["kind"] != "ArchiveRetirementIntent"
                        or remaining[0]["correlationId"] != correlation
                        or remaining[0]["tenantId"] != tenant
                        or remaining[0]["provenance"]
                        != {"kind": "emergency-administrator", "reason": reason}
                        or remaining[0]["operatorPrincipal"] != operator_principal
                    )
                ):
                    raise EmergencyDeletionError("emergency cleanup has unrelated authority")
            self.cleanup(next(iter(remaining), None), audit)
            self.hook("remote-cleaned")
            return result

    @staticmethod
    def _require_retry(
        result: dict[str, object], tenant: str, correlation: str, principal: str, reason: str
    ) -> None:
        if (
            result["operation"] != "delete"
            or result["status"] != "succeeded"
            or result["tenantId"] != tenant
            or result["correlationId"] != correlation
            or result["provenance"]
            != {"kind": "emergency-administrator", "operatorPrincipal": principal, "reason": reason}
        ):
            raise EmergencyDeletionError(
                "emergency correlation is bound to different administrator authority"
            )

    def _prepare(
        self,
        transaction: _StateTransaction,
        tenant: str,
        correlation: str,
        principal: str,
        reason: str,
    ) -> StoredContract:
        inventory = transaction.measure_authorization_records()
        if (
            correlation in {*inventory.correlation_ids, *inventory.job_ids, *inventory.result_ids}
            or transaction.inspect_audit_correlation(correlation).entry is not None
        ):
            raise EmergencyDeletionError("emergency correlation has existing authority")
        source = transaction.read(StateRecordPath.tenant_desired(tenant)).document
        observed = transaction.read(StateRecordPath.tenant_observed(tenant)).document
        deployments = [
            transaction.read(StateRecordPath.tenant_deployment(tenant, identity)).document
            for identity in transaction.tenant_deployment_ids(tenant)
        ]
        archives = [
            transaction.read(StateRecordPath.tenant_archive(tenant, identity)).document
            for identity in transaction.tenant_archive_ids(tenant)
        ]
        if len(archives) > 1:
            raise EmergencyDeletionError("emergency source has ambiguous archive authority")
        with self.runtime.using_held_publication_lock(self.repository):
            active = self.runtime.open_active_verified()
            try:
                source_id = active.generation_id
            finally:
                active.generation.close()
            if self.runtime.read_generation_route_snapshot(source_id) != snapshot_tenant_routes(
                transaction
            ):
                raise EmergencyDeletionError(
                    "emergency source differs from complete selected runtime"
                )
        intent = plan_emergency_deletion(
            source,
            observed,
            deployments,
            next(iter(archives), None),
            operator_principal=principal,
            reason=reason,
            correlation_id=correlation,
            source_runtime_generation_id=source_id,
            candidate_runtime_generation_id=generate_uuid7(clock=self.clock, entropy=self.entropy),
            retirement_intent_id=generate_uuid7(clock=self.clock, entropy=self.entropy),
            audit_state=transaction.inspect_audit(),
            now=self.now(),
        )
        verify_emergency_state(self.repository, transaction, intent, committed=False)
        self._admit(transaction, intent, preparing=True, audit_missing=True, result_missing=True)
        stored = transaction.create_immutable(
            StateRecordPath.emergency_deletion_intent(correlation), intent
        )
        self.hook("authority-sync")
        return stored

    def _commit(self, prepared: StoredContract) -> dict[str, object]:
        document = prepared.document
        tenant = str(document["tenantId"])
        identity = str(document["intentId"])
        result = cast(dict[str, object], document["result"])
        audit = cast(dict[str, object], document["auditEntry"])
        retirement = cast(dict[str, object] | None, document["retirementIntent"])
        with (
            self.repository.publication_transaction(blocking=True) as transaction,
            self.runtime.using_held_publication_lock(self.repository),
        ):
            path = StateRecordPath.emergency_deletion_intent(identity)
            if transaction.read(path).revision != prepared.revision:
                raise EmergencyDeletionError("emergency authority changed")
            inventory = transaction.measure_intent_records()
            expected = {identity} if retirement is None else {identity, str(retirement["intentId"])}
            if not {value.intent_id for value in inventory.records}.issubset(expected):
                raise EmergencyDeletionError("emergency transaction has unrelated journals")
            audit_missing = _audit_needs_append(transaction.inspect_audit(), audit)
            result_missing = _missing_exact(
                transaction, StateRecordPath.emergency_result(identity), result
            )
            if not result_missing and audit_missing:
                raise EmergencyDeletionError("emergency result precedes its tombstone")
            verify_emergency_state(
                self.repository, transaction, document, committed=not audit_missing
            )
            self._verify_releases(transaction, document, committed=not audit_missing)
            self._admit(
                transaction,
                document,
                preparing=False,
                audit_missing=audit_missing,
                result_missing=result_missing,
            )
            if retirement is not None:
                remote_path = StateRecordPath.archive_retirement_intent(retirement["intentId"])
                if _missing_exact(transaction, remote_path, retirement):
                    if not audit_missing:
                        raise EmergencyDeletionError(
                            "committed emergency deletion lost retirement authority"
                        )
                    transaction.create_immutable(remote_path, retirement)
                self.hook("retirement-sync")
            source_id, candidate_id = self._candidate(
                transaction, document, audit_missing=audit_missing
            )
            with (
                self.runtime.open_verified_generation(source_id) as previous,
                self.runtime.open_verified_generation(candidate_id) as candidate,
            ):
                self.runtime.remove_abandoned_reference_temporaries()
                if audit_missing:
                    _ensure_candidate_running(
                        self.runtime,
                        previous,
                        candidate,
                        reloader=self.reloader,
                        restorer=self.restorer,
                        verifier=self.verifier,
                        candidate_selection_is_durable=False,
                    )
                else:
                    _ensure_forward_candidate(
                        self.runtime,
                        previous,
                        candidate,
                        reloader=self.reloader,
                        verifier=self.verifier,
                    )
                self.hook("candidate-selected")
                _ensure_audit(transaction, audit)
                self.hook("audit-sync")
                for record in cast(list[dict[str, object]], document["deploymentRecords"]):
                    self.store.remove_release(
                        tenant,
                        record["id"],
                        expected_release_tree_digest=cast(
                            dict[str, object], record["releaseTreeDigest"]
                        ),
                        publication_lock=transaction,
                    )
                    self.hook("release-removed")
                remove_emergency_state(self.repository, transaction, document, hook=self.hook)
                self._verify_absence(transaction, tenant)
                if result_missing:
                    transaction.create_immutable(StateRecordPath.emergency_result(identity), result)
                self.hook("result-sync")
                original = next(value for value in inventory.records if value.intent_id == identity)
                transaction.remove_reconciled_intent(
                    path, IntentRemovalToken(prepared.revision, original.metadata_generation)
                )
                self.hook("intent-removed")
                return result

    def _candidate(
        self, transaction: _StateTransaction, document: dict[str, object], *, audit_missing: bool
    ) -> tuple[str, str]:
        tenant = str(document["tenantId"])
        others = self._others(transaction, tenant)
        source = self._source(document)
        source_expected = (
            others
            if cast(dict[str, object], source.manifest["spec"])["desiredState"] == "archived"
            else TenantRouteSnapshot(
                others.platform_namespace,
                tuple(
                    sorted(
                        (*others.tenants, source),
                        key=lambda value: str(
                            cast(dict[str, object], value.manifest["metadata"])["id"]
                        ),
                    )
                ),
            )
        )
        source_id, candidate_id = (
            str(document["sourceRuntimeGenerationId"]),
            str(document["candidateRuntimeGenerationId"]),
        )
        if self.runtime.read_generation_route_snapshot(source_id) != source_expected:
            raise EmergencyDeletionError("emergency recovery changed other tenant authority")
        try:
            candidate_snapshot = self.runtime.read_generation_route_snapshot(candidate_id)
        except FileNotFoundError:
            if not audit_missing:
                raise EmergencyDeletionError(
                    "committed emergency deletion lost its runtime"
                ) from None
            self.runtime.prune_unreferenced_generations((), keep_newest_unprotected=1)
            self.runtime.publish_candidate(
                candidate_id,
                transaction=transaction,
                overlay=TenantRouteOverlay(RouteOverlayMode.REMOVE, source, source),
                gate=_RemovalGate(),
            )
            candidate_snapshot = self.runtime.read_generation_route_snapshot(candidate_id)
        if candidate_snapshot != others:
            raise EmergencyDeletionError("emergency candidate changed other tenant routes")
        self.hook("candidate-published")
        return source_id, candidate_id

    def _verify_releases(
        self, transaction: _StateTransaction, intent: dict[str, object], *, committed: bool
    ) -> None:
        tenant = str(intent["tenantId"])
        records = cast(list[dict[str, object]], intent["deploymentRecords"])
        actual = dict(
            self.store.published_inventory(publication_lock=transaction).tenant_releases
        ).get(tenant, ())
        expected = tuple(str(record["id"]) for record in records)
        if not set(actual).issubset(expected) or (not committed and actual != expected):
            raise EmergencyDeletionError("emergency releases exceed their recorded authority")
        for record in records:
            if (
                record["id"] in actual
                and self.store.measure(
                    tenant, record["id"], publication_lock=transaction
                ).digest.to_dict()
                != record["releaseTreeDigest"]
            ):
                raise EmergencyDeletionError("emergency release content changed")

    def _verify_absence(self, transaction: _StateTransaction, tenant: str) -> None:
        if tenant in transaction.measure_inventory().tenant_ids or tenant in dict(
            self.store.published_inventory(publication_lock=transaction).tenant_releases
        ):
            raise EmergencyDeletionError("emergency deletion retained local tenant authority")
        active = self.runtime.open_active_verified()
        try:
            if self.runtime.read_generation_route_snapshot(
                active.generation_id
            ) != snapshot_tenant_routes(transaction):
                raise EmergencyDeletionError("emergency deletion retained tenant routes")
            self.verifier(active.generation)
        finally:
            active.generation.close()

    @staticmethod
    def _source(document: dict[str, object]) -> TenantRouteInput:
        source = cast(dict[str, object], document["sourceManifest"])
        desired = cast(dict[str, object], source["spec"]).get("desiredDeployment")
        previous = (
            None
            if desired is None
            else next(
                record
                for record in cast(list[dict[str, object]], document["deploymentRecords"])
                if record["id"] == cast(dict[str, object], desired)["id"]
            )
        )
        return TenantRouteInput(
            source, cast(dict[str, object], document["sourceObservedState"]), previous
        )

    @staticmethod
    def _others(transaction: _StateTransaction, tenant: str) -> TenantRouteSnapshot:
        return (
            snapshot_other_tenant_routes(transaction, excluded_tenant_id=tenant)
            if tenant in transaction.measure_inventory().tenant_ids
            else snapshot_tenant_routes(transaction)
        )

    def _admit(
        self,
        transaction: _StateTransaction,
        intent: dict[str, object],
        *,
        preparing: bool,
        audit_missing: bool,
        result_missing: bool,
    ) -> None:
        audit = cast(dict[str, object], intent["auditEntry"])
        result = cast(dict[str, object], intent["result"])
        if audit_missing:
            transaction.admit_audit_append(audit)
        if result_missing:
            transaction.admit_inventory(
                StateInventoryReservation(
                    authorization_records=1,
                    authorization_allocated_bytes=transaction.allocation_upper_bound(
                        len(canonical_json_bytes(result))
                    ),
                )
            )
        writes = ([intent] if preparing else []) + ([result] if result_missing else [])
        retirement = intent["retirementIntent"]
        if type(retirement) is dict and (
            preparing
            or _missing_exact(
                transaction,
                StateRecordPath.archive_retirement_intent(retirement["intentId"]),
                retirement,
            )
        ):
            writes.append(retirement)
        allocated = sum(
            transaction.allocation_upper_bound(len(canonical_json_bytes(value))) for value in writes
        )
        if audit_missing:
            allocated += transaction.allocation_upper_bound(
                DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
            )
        count = len(writes) + int(audit_missing)
        if count:
            admit_release_capacity(
                ReleaseCapacityUsage(()),
                CapacityReservation(
                    allocated + transaction.namespace_allocation_upper_bound(count), count
                ),
                transaction.measure_filesystem_capacity(),
                limits=self.limits,
            )
