"""Opaque authorization-job validation, claim, and terminal execution."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Final, Protocol, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    archive_record_digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    request_digest,
    result_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.audit import (
    DEFAULT_AUDIT_LIMITS,
    AuditCorrelationSnapshot,
    AuditError,
)
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    FilesystemCapacity,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.intake import (
    AdmittedArtifact,
    ArtifactClaim,
    ArtifactIntake,
    IntakeArtifactUnavailableError,
    IntakeError,
)
from lowerduckpond_static_host_agent.issuance import (
    SourceStateError,
    VerifiedArtifact,
    build_expected_source,
)
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import (
    StateConflictError,
    StateRecordError,
    StateRecordPath,
    StateRepository,
    StateRevision,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
    IntentRecordInventory,
    StateInventory,
    StateInventoryProjection,
    StateInventoryReservation,
)

_NOT_IMPLEMENTED: Final = "not_implemented"
_AUTHORIZATION_EXECUTOR: Final = "authorization-executor"
_MAX_RETAINED_DEPLOYMENTS: Final = 3


class ExecutionError(RuntimeError):
    """An opaque authorized job could not reach one safe terminal result."""


class _InvalidArtifactContentError(ExecutionError):
    """A hash-bound admitted artifact violates its operation-specific format."""


class JobHandoff(Protocol):
    """Queue one validated opaque UUID without carrying operation authority."""

    def enqueue(self, job_id: str) -> None: ...


class ExecutionTransaction(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...

    def tenant_has_deployment_history(self, tenant_id: object) -> bool: ...

    def tenant_archive_ids(self, tenant_id: object) -> tuple[str, ...]: ...

    def tenant_deployment_ids(self, tenant_id: object) -> tuple[str, ...]: ...

    def deployment_for_digest(
        self,
        tenant_id: object,
        expected_digest: dict[str, object],
    ) -> dict[str, object]: ...

    def validate_export_bundle(
        self,
        job_id: object,
        binding: dict[str, object],
        *,
        source_manifest: dict[str, object],
        source_release_tree_digest: dict[str, object],
    ) -> None: ...

    def compare_and_swap(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
    ) -> StoredContract: ...

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract: ...

    def measure_inventory(self) -> StateInventory: ...

    def tenant_has_identity_history(self, tenant_id: object) -> bool: ...

    def measure_intent_records(self) -> IntentRecordInventory: ...

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]: ...

    def inspect_audit_correlation(
        self,
        correlation_id: object,
    ) -> AuditCorrelationSnapshot: ...

    def append_audit(self, document: dict[str, object]) -> object: ...

    def allocation_upper_bound(self, byte_count: int) -> int: ...

    def namespace_allocation_upper_bound(self, entry_count: int) -> int: ...

    def admit_inventory(
        self,
        reservation: StateInventoryReservation,
    ) -> StateInventoryProjection: ...

    def measure_filesystem_capacity(self) -> FilesystemCapacity: ...


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """One immutable terminal result and whether this call published it."""

    result: dict[str, object]
    created: bool


@dataclass(frozen=True, slots=True)
class LifecycleArtifact:
    """Read-only artifact identity exposed to one lifecycle handler."""

    artifact: AdmittedArtifact


@dataclass(frozen=True, slots=True)
class _PreparedDispatch:
    """A held intake claim and its independently derived release authority."""

    claim: ArtifactClaim | None
    artifact_release_tree_digest: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class _LifecycleDispatchAuthority:
    """Durable lifecycle authority retained while an external handler runs."""

    source_manifest: dict[str, object] | None
    source_observed_state: dict[str, object] | None
    source_runtime_generation_id: str | None
    source_route_set: str | None
    candidate_observed_state: dict[str, object] | None
    candidate_runtime_generation_id: str | None
    candidate_route_set: str | None
    archive_record: dict[str, object] | None
    archive_construction_present: bool
    artifact_release_tree_digest: dict[str, object] | None = None
    source_release_tree_digest: dict[str, object] | None = None
    source_archive_deployment_ids: tuple[str, ...] | None = None
    source_deployment_ids: tuple[str, ...] | None = None
    source_tenant_ids: tuple[str, ...] | None = None
    execution_validation_committed: bool = False


class LifecycleJobHandler(Protocol):
    """Complete one validated root-owned lifecycle job and its durable result."""

    def execute(
        self,
        job_id: str,
        *,
        claim: LifecycleArtifact | None,
        blocking: bool,
    ) -> ExecutionOutcome: ...


class AuthorizationExecutor:
    """Validate, claim, and dispatch only one root-owned authorization job."""

    def __init__(  # noqa: PLR0913 - independent execution boundary dependencies
        self,
        repository: StateRepository,
        intake: ArtifactIntake,
        *,
        handlers: Mapping[str, LifecycleJobHandler] | None = None,
        deleted_tenant_release_validator: Callable[[str], bool] | None = None,
        deleted_tenant_route_validator: Callable[[str], bool] | None = None,
        retained_archive_validator: Callable[[dict[str, object]], bool] | None = None,
        retired_archive_validator: Callable[[dict[str, object]], bool] | None = None,
        tenant_runtime_validator: Callable[
            [str, str, str | None, dict[str, object], dict[str, object] | None],
            bool,
        ]
        | None = None,
        tenant_release_validator: Callable[[str, dict[str, object]], bool] | None = None,
        tenant_release_inventory_validator: Callable[[], bool] | None = None,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> None:
        self._repository = repository
        self._intake = intake
        self._handlers = dict(handlers or {})
        self._deleted_tenant_release_validator = deleted_tenant_release_validator
        self._deleted_tenant_route_validator = deleted_tenant_route_validator
        self._retained_archive_validator = retained_archive_validator
        self._retired_archive_validator = retired_archive_validator
        self._tenant_runtime_validator = tenant_runtime_validator
        self._tenant_release_validator = tenant_release_validator
        self._tenant_release_inventory_validator = tenant_release_inventory_validator
        self._capacity_limits = capacity_limits

    def execute(self, job_id: object, *, blocking: bool = False) -> ExecutionOutcome:
        """Execute exactly one canonical UUIDv7 job and no caller-selected fields."""

        canonical_id = validate_uuid7(job_id)
        path = StateRecordPath.authorization_job(canonical_id)
        initial = self._repository.read(path, blocking=blocking)
        handler = self._handler_for(initial.document)
        existing = self._read_result(canonical_id, blocking=blocking)
        if existing is not None:
            return self._replay_existing_result(
                canonical_id,
                initial,
                existing,
                handler=handler,
                blocking=blocking,
            )

        artifact = _job_artifact(initial.document)
        if artifact is None:
            return self._execute_with_claim(
                canonical_id,
                initial,
                claim=None,
                handler=handler,
                blocking=blocking,
            )
        with ExitStack() as claim_stack:
            try:
                claim = claim_stack.enter_context(
                    self._intake.claim(
                        correlation_id=_correlation_id(initial.document),
                        declared=artifact,
                        blocking=blocking,
                    )
                )
            except IntakeArtifactUnavailableError:
                recovered = self._recover_claimed_lifecycle_without_artifact(
                    canonical_id,
                    initial,
                    handler=handler,
                    blocking=blocking,
                )
                if recovered is not None:
                    return recovered
                return self._fail_without_claim(
                    canonical_id,
                    initial,
                    error_code="invalid_artifact",
                    handler=handler,
                    blocking=blocking,
                )
            except IntakeError as error:
                raise ExecutionError(
                    "authorized artifact failed its root-owned validation"
                ) from error
            outcome = self._execute_with_claim(
                canonical_id,
                initial,
                claim=claim,
                handler=handler,
                blocking=blocking,
            )
            claim.consume()
            return outcome

    def _recover_claimed_lifecycle_without_artifact(
        self,
        job_id: str,
        initial: StoredContract,
        *,
        handler: LifecycleJobHandler | None,
        blocking: bool,
    ) -> ExecutionOutcome | None:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            phase = current.document["phase"]
            if phase not in {"claimed", "completed", "failed"}:
                return None
            _validate_request_integrity(current.document)
            _request, intents = _bound_lifecycle_intents(transaction, current.document)
            existing = _read_result_transaction(transaction, job_id)
            if not intents:
                if phase == "claimed":
                    if existing is not None:
                        return None
                    error_code = _expected_source_error(transaction, current.document)
                    if error_code is None:
                        error_code = _NOT_IMPLEMENTED if handler is None else "invalid_artifact"
                    result = _failure_result(current.document, error_code)
                    _publish_result(
                        transaction,
                        current,
                        result,
                        limits=self._capacity_limits,
                    )
                    return ExecutionOutcome(result, True)
                return None
            _require_available_lifecycle_handler(True, handler)
            if phase != "claimed" and existing is None:
                raise ExecutionError("terminal lifecycle job has no durable result")
            if existing is not None:
                _validate_result_binding(current.document, existing.document)
                _validate_result_intent_binding(existing.document, _request, intents)
        if handler is None:  # pragma: no cover - active intent requires a handler
            raise ExecutionError("authorization handler selection was lost")
        return self._execute_handler(
            job_id,
            initial,
            handler,
            prepared=_PreparedDispatch(None, None),
            blocking=blocking,
        )

    def _replay_existing_result(
        self,
        job_id: str,
        initial: StoredContract,
        existing: StoredContract,
        *,
        handler: LifecycleJobHandler | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        _validate_result_binding(initial.document, existing.document)
        _validate_request_integrity(initial.document)
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            durable = _read_result_transaction(transaction, job_id)
            if durable is None or durable.document != existing.document:
                raise ExecutionError("terminal result changed during replay")
            _validate_result_binding(current.document, durable.document)
            dispatch = _has_bound_lifecycle_intent(
                transaction,
                current.document,
                result=durable.document,
            )
            _require_available_lifecycle_handler(dispatch, handler)
        if not dispatch:
            completed = self._validated_completed_replay(
                job_id,
                initial,
                existing.document,
                blocking=blocking,
            )
            if completed is None:  # pragma: no cover - intent was checked under the same lock
                raise ExecutionError("terminal lifecycle intent changed during replay")
            self._consume_terminal_artifact(initial.document, blocking=blocking)
            return completed
        if handler is None:  # pragma: no cover - dispatch proves a handler
            raise ExecutionError("authorization handler selection was lost")
        artifact = _job_artifact(initial.document)
        if artifact is None:
            return self._execute_handler(
                job_id,
                initial,
                handler,
                prepared=_PreparedDispatch(None, None),
                blocking=blocking,
            )
        with ExitStack() as claim_stack:
            try:
                claim = claim_stack.enter_context(
                    self._intake.claim(
                        correlation_id=_correlation_id(initial.document),
                        declared=artifact,
                        blocking=blocking,
                    )
                )
            except IntakeArtifactUnavailableError as error:
                completed = self._completed_replay_after_artifact_loss(
                    job_id,
                    initial,
                    existing.document,
                    blocking=blocking,
                )
                if completed is not None:
                    return completed
                recovered = self._recover_claimed_lifecycle_without_artifact(
                    job_id,
                    initial,
                    handler=handler,
                    blocking=blocking,
                )
                if recovered is not None:
                    return recovered
                raise ExecutionError("lifecycle replay artifact is unavailable") from error
            except IntakeError as error:
                raise ExecutionError(
                    "lifecycle replay artifact failed root-owned validation"
                ) from error
            artifact_release_tree_digest = self._derive_artifact_release_tree_digest(
                initial.document,
                claim,
            )
            outcome = self._execute_handler(
                job_id,
                initial,
                handler,
                prepared=_PreparedDispatch(claim, artifact_release_tree_digest),
                blocking=blocking,
            )
            claim.consume()
            return outcome

    def _completed_replay_after_artifact_loss(
        self,
        job_id: str,
        initial: StoredContract,
        expected_result: dict[str, object],
        *,
        blocking: bool,
    ) -> ExecutionOutcome | None:
        return self._validated_completed_replay(
            job_id,
            initial,
            expected_result,
            blocking=blocking,
        )

    def _validated_completed_replay(
        self,
        job_id: str,
        initial: StoredContract,
        expected_result: dict[str, object],
        *,
        blocking: bool,
    ) -> ExecutionOutcome | None:
        """Revalidate one intent-free result before exact retry acceptance."""

        _validate_result_binding(initial.document, expected_result)
        authority: _LifecycleDispatchAuthority | None = None
        audit_is_latest_for_tenant = False
        job: dict[str, object] | None = None
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            durable = _read_result_transaction(transaction, job_id)
            if durable is None or durable.document != expected_result:
                raise ExecutionError("terminal result changed after artifact replay race")
            _validate_result_binding(current.document, durable.document)
            if _has_bound_lifecycle_intent(
                transaction,
                current.document,
                result=durable.document,
            ):
                return None
            if _is_executor_failure(durable.document):
                _repair_executor_failure_audit(
                    transaction,
                    current.document,
                    durable.document,
                    limits=self._capacity_limits,
                )
            audit_is_latest_for_tenant = _validate_result_audit(
                transaction,
                current.document,
                durable.document,
            )
            if current.document["compatibilityVersion"] == "static-job-v2":
                authority = _capture_replay_authority(
                    transaction,
                    current.document,
                    durable.document,
                    validation_was_committed=current.document["executionValidated"] is True,
                    audit_is_latest_for_tenant=audit_is_latest_for_tenant,
                )
                _validate_handler_result_state(
                    transaction,
                    current.document,
                    durable.document,
                    authority=authority,
                    audit_is_latest_for_tenant=audit_is_latest_for_tenant,
                )
            result = _repair_terminal_phase_transaction(transaction, current, durable)
            job = current.document
        if job is None:  # pragma: no cover - the locked branch assigns terminal state
            raise ExecutionError("terminal replay job selection was lost")
        self._validate_external_terminal_state(
            job,
            result,
            authority=authority,
            audit_is_latest_for_tenant=audit_is_latest_for_tenant,
            blocking=blocking,
        )
        self._mark_execution_validated(
            job_id,
            initial,
            result,
            blocking=blocking,
        )
        return ExecutionOutcome(result, False)

    def _consume_terminal_artifact(
        self,
        job: dict[str, object],
        *,
        blocking: bool,
    ) -> None:
        artifact = _job_artifact(job)
        if artifact is None:
            return
        try:
            with self._intake.claim(
                correlation_id=_correlation_id(job),
                declared=artifact,
                blocking=blocking,
            ) as claim:
                claim.consume()
        except IntakeArtifactUnavailableError:
            return
        except IntakeError as error:
            raise ExecutionError("terminal artifact cleanup failed closed") from error

    def _execute_with_claim(  # noqa: PLR0912 - transactional execution matrix
        self,
        job_id: str,
        initial: StoredContract,
        *,
        claim: ArtifactClaim | None,
        handler: LifecycleJobHandler | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        path = StateRecordPath.authorization_job(job_id)
        replay: StoredContract | None = None
        artifact_release_tree_digest: dict[str, object] | None = None
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(path)
            _require_same_authority(initial.document, current.document)
            existing = _read_result_transaction(transaction, job_id)
            if existing is not None:
                _validate_result_binding(current.document, existing.document)
                has_lifecycle_intent = _has_bound_lifecycle_intent(
                    transaction,
                    current.document,
                    result=existing.document,
                )
                _require_available_lifecycle_handler(has_lifecycle_intent, handler)
                if not has_lifecycle_intent:
                    replay = existing
            else:
                _validate_job_integrity(current.document, claim=claim)
                has_lifecycle_intent = False
                if current.document["phase"] == "claimed":
                    _request, intents = _bound_lifecycle_intents(
                        transaction,
                        current.document,
                    )
                    has_lifecycle_intent = bool(intents)
                if current.document["phase"] == "pending" or (
                    current.document["phase"] == "claimed" and not has_lifecycle_intent
                ):
                    error_code = _expected_source_error(transaction, current.document)
                    if error_code is not None:
                        result = _failure_result(current.document, error_code)
                        _publish_result(
                            transaction,
                            current,
                            result,
                            limits=self._capacity_limits,
                        )
                        return ExecutionOutcome(result, True)
                if current.document["phase"] == "claimed" and handler is None:
                    if not has_lifecycle_intent:
                        result = _failure_result(current.document, _NOT_IMPLEMENTED)
                        _publish_result(
                            transaction,
                            current,
                            result,
                            limits=self._capacity_limits,
                        )
                        return ExecutionOutcome(result, True)
                    raise ExecutionError("claimed lifecycle job handler is unavailable")
                if handler is not None:
                    try:
                        artifact_release_tree_digest = self._derive_artifact_release_tree_digest(
                            current.document,
                            claim,
                        )
                    except _InvalidArtifactContentError:
                        if has_lifecycle_intent:
                            raise
                        result = _failure_result(current.document, "invalid_artifact")
                        _publish_result(
                            transaction,
                            current,
                            result,
                            limits=self._capacity_limits,
                        )
                        return ExecutionOutcome(result, True)
                claimed = _claim_pending(transaction, current)
                if handler is None:
                    # Unsupported lifecycle operations remain mutation-free until
                    # their independently reviewed handlers become available.
                    result = _failure_result(claimed.document, _NOT_IMPLEMENTED)
                    _publish_result(transaction, claimed, result, limits=self._capacity_limits)
                    return ExecutionOutcome(result, True)
        if replay is not None:
            return self._replay_existing_result(
                job_id,
                initial,
                replay,
                handler=handler,
                blocking=blocking,
            )
        if handler is None:  # pragma: no cover - every in-lock branch returns
            raise ExecutionError("authorization handler selection was lost")
        return self._execute_handler(
            job_id,
            initial,
            handler,
            prepared=_PreparedDispatch(claim, artifact_release_tree_digest),
            blocking=blocking,
        )

    def _execute_handler(
        self,
        job_id: str,
        initial: StoredContract,
        handler: LifecycleJobHandler,
        *,
        prepared: _PreparedDispatch,
        blocking: bool,
    ) -> ExecutionOutcome:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            current = _bind_dispatch_authority(
                transaction,
                current,
                artifact_release_tree_digest=prepared.artifact_release_tree_digest,
            )
            authority = _capture_authorized_lifecycle_authority(
                transaction,
                current.document,
            )
        handler_claim = (
            None if prepared.claim is None else LifecycleArtifact(prepared.claim.artifact)
        )
        returned = handler.execute(job_id, claim=handler_claim, blocking=blocking)
        if type(returned) is not ExecutionOutcome:
            raise ExecutionError("lifecycle handler returned a malformed outcome")
        result = deepcopy(returned.result)
        validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
        if _is_executor_failure(result):
            raise ExecutionError("lifecycle handler claimed executor failure publication")
        audit_is_latest_for_tenant = False
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            stored = _read_result_transaction(transaction, job_id)
            if stored is None or stored.document != result:
                raise ExecutionError("lifecycle handler result is not durably exact")
            _validate_result_binding(current.document, result)
            if _has_bound_lifecycle_intent(
                transaction,
                current.document,
                result=stored.document,
            ):
                raise ExecutionError("lifecycle handler returned before clearing its intent")
            _require_current_success_result_shape(result)
            audit_is_latest_for_tenant = _validate_result_audit(
                transaction,
                current.document,
                result,
                require_failure=True,
            )
            _validate_handler_result_state(
                transaction,
                current.document,
                result,
                authority=authority,
                audit_is_latest_for_tenant=audit_is_latest_for_tenant,
            )
            authority = _capture_terminal_runtime_authority(
                transaction,
                result,
                authority=authority,
                audit_is_latest_for_tenant=audit_is_latest_for_tenant,
            )
            expected_phase = "completed" if result["status"] == "succeeded" else "failed"
            if current.document["phase"] != expected_phase:
                raise ExecutionError("lifecycle handler returned before terminal job commit")
        self._validate_external_terminal_state(
            current.document,
            result,
            authority=authority,
            audit_is_latest_for_tenant=audit_is_latest_for_tenant,
            blocking=blocking,
        )
        self._mark_execution_validated(
            job_id,
            initial,
            result,
            blocking=blocking,
        )
        return ExecutionOutcome(result, returned.created)

    def _derive_artifact_release_tree_digest(
        self,
        job: dict[str, object],
        claim: ArtifactClaim | None,
    ) -> dict[str, object] | None:
        request = job["request"]
        if type(request) is not dict:
            raise ExecutionError("authorization request authority is malformed")
        operation = request["operation"]
        if operation not in {"deploy", "import"} or claim is None:
            return None
        try:
            digest = (
                self._intake.deployment_release_tree_digest(claim.artifact)
                if operation == "deploy"
                else self._intake.import_release_tree_digest(claim.artifact)
            )
            release_authority = digest.to_dict()
            return dict[str, object](release_authority)
        except IntakeError as error:
            raise _InvalidArtifactContentError(
                "authorized artifact release content failed independent validation"
            ) from error

    def _validate_external_terminal_state(  # noqa: PLR0911,PLR0912 - explicit matrix
        self,
        job: dict[str, object],
        result: dict[str, object],
        *,
        authority: _LifecycleDispatchAuthority | None = None,
        audit_is_latest_for_tenant: bool = True,
        blocking: bool = False,
    ) -> None:
        if authority is None:
            return
        self._validate_retired_archive_absence(result, authority=authority)
        release_inventory_validator = self._tenant_release_inventory_validator
        if release_inventory_validator is not None and release_inventory_validator() is not True:
            raise ExecutionError(
                "lifecycle handler changed tenant release inventory outside authority"
            )
        if not audit_is_latest_for_tenant:
            return
        if result["status"] == "failed":
            self._validate_failed_external_terminal_state(
                job,
                result,
                authority=authority,
                blocking=blocking,
            )
            return
        if result["operation"] == "archive":
            archive = result.get("archiveRecord")
            validator = self._retained_archive_validator
            if type(archive) is not dict or validator is None or validator(archive) is not True:
                if self._result_was_superseded(job, result, blocking=blocking):
                    return
                raise ExecutionError(
                    "successful archive result has no exact retained archive object"
                )
        tenant_id = validate_uuid7(result["tenantId"])
        if result["operation"] == "delete":
            self._validate_deleted_external_terminal_state(
                job,
                result,
                tenant_id=tenant_id,
                blocking=blocking,
            )
            return
        candidate_manifest = result.get("manifest")
        release_validator = self._tenant_release_validator
        if type(candidate_manifest) is not dict or (
            release_validator is not None
            and release_validator(tenant_id, candidate_manifest) is not True
        ):
            if self._result_was_superseded(job, result, blocking=blocking):
                return
            raise ExecutionError(
                "successful lifecycle result did not select its authorized release"
            )
        if authority.candidate_route_set is None:
            return
        generation_id = authority.candidate_runtime_generation_id
        runtime_validator = self._tenant_runtime_validator
        if runtime_validator is None and authority.execution_validation_committed:
            return
        if (
            (generation_id is None and authority.candidate_route_set == "both")
            or runtime_validator is None
            or runtime_validator(
                tenant_id,
                authority.candidate_route_set,
                generation_id,
                candidate_manifest,
                authority.candidate_observed_state,
            )
            is not True
        ):
            if runtime_validator is not None and self._current_runtime_matches_after_cross_tenant(
                job,
                result,
                tenant_id=tenant_id,
                route_set=authority.candidate_route_set,
                manifest=candidate_manifest,
                observed_state=authority.candidate_observed_state,
                runtime_validator=runtime_validator,
                blocking=blocking,
            ):
                return
            if self._result_was_superseded(job, result, blocking=blocking):
                return
            raise ExecutionError("successful lifecycle result did not select its authorized routes")

    def _current_runtime_matches_after_cross_tenant(  # noqa: PLR0913
        self,
        job: dict[str, object],
        result: dict[str, object],
        *,
        tenant_id: str,
        route_set: str,
        manifest: dict[str, object],
        observed_state: dict[str, object] | None,
        runtime_validator: Callable[
            [str, str, str | None, dict[str, object], dict[str, object] | None],
            bool,
        ],
        blocking: bool,
    ) -> bool:
        """Accept a newer complete generation selected by another tenant."""

        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            job_id = validate_uuid7(job["jobId"])
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(job, current.document)
            stored = _read_result_transaction(transaction, job_id)
            if stored is None or stored.document != result:
                raise ExecutionError("terminal result changed during runtime validation")
            audit_is_latest = _validate_result_audit(transaction, current.document, result)
            snapshot = transaction.inspect_audit_correlation(result["correlationId"])
            has_later_cross_tenant_transition = any(
                later_tenant_id != tenant_id
                for _operation, later_tenant_id in snapshot.later_tenant_state_transitions
            )
        return (
            audit_is_latest
            and has_later_cross_tenant_transition
            and runtime_validator(
                tenant_id,
                route_set,
                None,
                manifest,
                observed_state,
            )
            is True
        )

    def _validate_retired_archive_absence(
        self,
        result: dict[str, object],
        *,
        authority: _LifecycleDispatchAuthority,
    ) -> None:
        if result["status"] != "succeeded" or result["operation"] not in {
            "delete",
            "restore",
        }:
            return
        archive = authority.archive_record
        if archive is None:
            return
        validator = self._retired_archive_validator
        if validator is None or validator(archive) is not True:
            raise ExecutionError("successful lifecycle result retained its retired archive object")

    def _validate_deleted_external_terminal_state(
        self,
        job: dict[str, object],
        result: dict[str, object],
        *,
        tenant_id: str,
        blocking: bool,
    ) -> None:
        release_validator = self._deleted_tenant_release_validator
        if release_validator is None or release_validator(tenant_id) is not True:
            if self._result_was_superseded(job, result, blocking=blocking):
                return
            raise ExecutionError("successful delete retained tenant release bytes")
        route_validator = self._deleted_tenant_route_validator
        if route_validator is None or route_validator(tenant_id) is not True:
            if self._result_was_superseded(job, result, blocking=blocking):
                return
            raise ExecutionError("successful delete retained an active tenant route")

    def _validate_failed_external_terminal_state(
        self,
        job: dict[str, object],
        result: dict[str, object],
        *,
        authority: _LifecycleDispatchAuthority,
        blocking: bool,
    ) -> None:
        source_manifest = authority.source_manifest
        source_route_set = authority.source_route_set
        archive = authority.archive_record
        if result["operation"] in {"delete", "restore"} and archive is not None:
            validator = self._retained_archive_validator
            if validator is None or validator(archive) is not True:
                raise ExecutionError("failed lifecycle result lost its retained archive object")
        if source_manifest is None:
            return
        tenant_id = validate_uuid7(result["tenantId"])
        release_validator = self._tenant_release_validator
        if (
            release_validator is not None
            and release_validator(tenant_id, source_manifest) is not True
        ):
            if self._result_was_superseded(job, result, blocking=blocking):
                return
            raise ExecutionError("failed lifecycle result did not restore its authorized release")
        if source_route_set is None:
            return
        runtime_validator = self._tenant_runtime_validator
        if runtime_validator is None and authority.execution_validation_committed:
            return
        if (
            runtime_validator is not None
            and runtime_validator(
                tenant_id,
                source_route_set,
                authority.source_runtime_generation_id,
                source_manifest,
                authority.source_observed_state,
            )
            is True
        ):
            return
        if self._result_was_superseded(job, result, blocking=blocking):
            return
        raise ExecutionError("failed lifecycle result did not restore its authorized routes")

    def _result_was_superseded(
        self,
        job: dict[str, object],
        result: dict[str, object],
        *,
        blocking: bool,
    ) -> bool:
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            job_id = validate_uuid7(job["jobId"])
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(job, current.document)
            stored = _read_result_transaction(transaction, job_id)
            if stored is None or stored.document != result:
                raise ExecutionError("terminal result changed during runtime validation")
            return not _validate_result_audit(transaction, current.document, result)

    def _mark_execution_validated(
        self,
        job_id: str,
        initial: StoredContract,
        result: dict[str, object],
        *,
        blocking: bool,
    ) -> None:
        if initial.document["compatibilityVersion"] != "static-job-v2":
            return
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            stored = _read_result_transaction(transaction, job_id)
            if stored is None or stored.document != result:
                raise ExecutionError("validated lifecycle result is no longer durable")
            if current.document["executionValidated"] is True:
                return
            expected_phase = "completed" if result["status"] == "succeeded" else "failed"
            if current.document["phase"] != expected_phase:
                raise ExecutionError("validated lifecycle job is not terminal")
            validated = current.document
            validated["executionValidated"] = True
            try:
                transaction.compare_and_swap(
                    StateRecordPath.authorization_job(job_id),
                    current.revision,
                    validated,
                )
            except StateConflictError as error:
                raise ExecutionError(
                    "authorization validation marker changed during commit"
                ) from error

    def _handler_for(self, job: dict[str, object]) -> LifecycleJobHandler | None:
        request = job["request"]
        if type(request) is not dict:  # pragma: no cover - validated reads prove this
            raise ExecutionError("authorization job request is not an object")
        operation = request["operation"]
        if type(operation) is not str:  # pragma: no cover - schema validation proves this
            raise ExecutionError("authorization operation is not a string")
        return self._handlers.get(operation)

    def _fail_without_claim(
        self,
        job_id: str,
        initial: StoredContract,
        *,
        error_code: str,
        handler: LifecycleJobHandler | None,
        blocking: bool,
    ) -> ExecutionOutcome:
        existing: StoredContract | None = None
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            current = transaction.read(StateRecordPath.authorization_job(job_id))
            _require_same_authority(initial.document, current.document)
            existing = _read_result_transaction(transaction, job_id)
            if existing is None:
                if current.document["phase"] != "pending":
                    raise ExecutionError("artifact failure publication lost pending job authority")
                result = _failure_result(current.document, error_code)
                _publish_result(transaction, current, result, limits=self._capacity_limits)
                return ExecutionOutcome(result, True)
        return self._replay_existing_result(
            job_id,
            initial,
            existing,
            handler=handler,
            blocking=blocking,
        )

    def _read_result(self, job_id: str, *, blocking: bool) -> StoredContract | None:
        try:
            return self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=blocking,
            )
        except FileNotFoundError:
            return None


def _job_artifact(job: dict[str, object]) -> VerifiedArtifact | None:
    declared = job["artifact"]
    if declared is None:
        return None
    if type(declared) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job artifact binding is not an object")
    return VerifiedArtifact(size=cast(int, declared["size"]), sha256=cast(str, declared["sha256"]))


def _correlation_id(job: dict[str, object]) -> str:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    return validate_uuid7(request["correlationId"])


def _require_same_authority(
    expected: dict[str, object],
    current: dict[str, object],
) -> None:
    first = deepcopy(expected)
    second = deepcopy(current)
    first.pop("phase", None)
    second.pop("phase", None)
    first.pop("executionValidated", None)
    second.pop("executionValidated", None)
    first.pop("dispatchArchiveDeploymentIds", None)
    second.pop("dispatchArchiveDeploymentIds", None)
    first.pop("dispatchArtifactReleaseTreeDigest", None)
    second.pop("dispatchArtifactReleaseTreeDigest", None)
    first.pop("dispatchSourceReleaseTreeDigest", None)
    second.pop("dispatchSourceReleaseTreeDigest", None)
    first.pop("dispatchDeploymentIds", None)
    second.pop("dispatchDeploymentIds", None)
    first.pop("dispatchTenantIds", None)
    second.pop("dispatchTenantIds", None)
    if first != second:
        raise ExecutionError("authorization job authority changed before execution")


def _validate_job_integrity(
    job: dict[str, object],
    *,
    claim: ArtifactClaim | None,
) -> None:
    _validate_request_integrity(job)
    declared = _job_artifact(job)
    if (declared is None) != (claim is None):
        raise ExecutionError("authorization artifact presence does not match its envelope")
    if declared is not None and claim is not None and claim.artifact.verified != declared:
        raise ExecutionError("claimed artifact does not match its authorization envelope")


def _validate_request_integrity(job: dict[str, object]) -> None:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    if request_digest(request).to_dict() != job["requestDigest"]:
        raise ExecutionError("authorization request digest does not match its envelope")


def _expected_source_error(
    transaction: ExecutionTransaction,
    job: dict[str, object],
) -> str | None:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - contract validation proves this
        raise ExecutionError("authorization expected source is not an object")
    if (
        request["operation"] == "delete"
        and job["compatibilityVersion"] == "static-job-v1"
        and "deletionEvidence" not in expected
    ):
        # The legacy envelope remains decodable for startup reconciliation, but
        # it never crosses the mutation boundary without the durable authority
        # introduced by static-job-v2.
        return "state_drift"
    if request["operation"] == "delete" and expected.get("deletionEvidence") is None:
        return "state_drift"
    try:
        actual = build_expected_source(transaction, request)
    except FileNotFoundError, SourceStateError:
        return "state_drift"
    if actual != expected:
        return "state_drift"
    if request["operation"] == "create":
        inventory = transaction.measure_inventory()
        slug = request["slug"]
        for tenant_id in inventory.tenant_ids:
            desired = transaction.read(StateRecordPath.tenant_desired(tenant_id)).document
            metadata = desired["metadata"]
            if type(metadata) is dict and metadata.get("slug") == slug:
                return "state_drift"
    return None


def _capture_authorized_lifecycle_authority(  # noqa: PLR0912,PLR0915 - authority matrix
    transaction: ExecutionTransaction,
    job: dict[str, object],
) -> _LifecycleDispatchAuthority:
    request = job["request"]
    expected = job["expectedSource"]
    if type(request) is not dict or type(expected) is not dict:
        raise ExecutionError("authorization source authority is malformed")
    if request["operation"] == "delete":
        _request, intents = _bound_lifecycle_intents(transaction, job)
        retirement_intent = next(
            (intent for intent in intents if intent["kind"] == "ArchiveRetirementIntent"),
            None,
        )
        if retirement_intent is None:
            _source_manifest, delete_archive_record = _job_source_authority(job)
        else:
            raw_archive = retirement_intent.get("archiveRecord")
            if type(raw_archive) is not dict:
                raise ExecutionError("delete retirement authority is malformed")
            delete_archive_record = deepcopy(raw_archive)
        return _LifecycleDispatchAuthority(
            source_manifest=None,
            source_observed_state=None,
            source_runtime_generation_id=None,
            source_route_set=None,
            candidate_observed_state=None,
            candidate_runtime_generation_id=None,
            candidate_route_set=None,
            archive_record=delete_archive_record,
            archive_construction_present=False,
            artifact_release_tree_digest=_dispatch_artifact_release_tree_digest(job),
            source_release_tree_digest=_dispatch_source_release_tree_digest(job),
            source_archive_deployment_ids=_dispatch_archive_deployment_ids(job),
            source_deployment_ids=_dispatch_deployment_ids(job),
            source_tenant_ids=_dispatch_tenant_ids(job),
        )
    _request, intents = _bound_lifecycle_intents(transaction, job)
    transaction_intent = next(
        (intent for intent in intents if intent["kind"] == "TransactionIntent"),
        None,
    )
    construction_intent = next(
        (intent for intent in intents if intent["kind"] == "ArchiveConstructionIntent"),
        None,
    )
    retirement_intent = next(
        (intent for intent in intents if intent["kind"] == "ArchiveRetirementIntent"),
        None,
    )
    source_observed: dict[str, object] | None = None
    source_generation: str | None = None
    source_route_set: str | None = None
    candidate_observed: dict[str, object] | None = None
    candidate_generation: str | None = None
    candidate_route_set: str | None = None
    archive_record: dict[str, object] | None = None
    if transaction_intent is None and request["operation"] == "create":
        return _LifecycleDispatchAuthority(
            source_manifest=None,
            source_observed_state=None,
            source_runtime_generation_id=None,
            source_route_set=None,
            candidate_observed_state=None,
            candidate_runtime_generation_id=None,
            candidate_route_set=None,
            archive_record=None,
            archive_construction_present=False,
            artifact_release_tree_digest=_dispatch_artifact_release_tree_digest(job),
            source_release_tree_digest=_dispatch_source_release_tree_digest(job),
            source_archive_deployment_ids=_dispatch_archive_deployment_ids(job),
            source_deployment_ids=_dispatch_deployment_ids(job),
            source_tenant_ids=_dispatch_tenant_ids(job),
        )
    if transaction_intent is None:
        source = transaction.read(StateRecordPath.tenant_desired(request["tenantId"])).document
        if construction_intent is not None:
            archive_record = _archive_record_for_construction_authority(
                transaction,
                construction_intent,
                source,
            )
        if (
            request["operation"] in {"archive", "restore"}
            and manifest_digest(source).to_dict() != expected["manifestDigest"]
        ):
            source = (
                _reconstruct_archive_source_manifest(job, source)
                if request["operation"] == "archive"
                else _reconstruct_restore_source_manifest(transaction, job, source)
            )
    else:
        source_value = transaction_intent["sourceManifest"]
        if request["operation"] == "create":
            if source_value is not None:
                raise ExecutionError("create lifecycle source authority is malformed")
            source = None
        elif type(source_value) is not dict:
            raise ExecutionError("lifecycle source manifest is not authorization-bound")
        else:
            source = source_value
        recovery_name = (
            "archiveRecovery" if request["operation"] == "archive" else "lifecycleRecovery"
        )
        recovery = transaction_intent[recovery_name]
        if type(recovery) is dict:
            raw_source_generation = recovery["sourceRuntimeGenerationId"]
            raw_source_route_set = recovery["sourceRouteSet"]
            raw_generation = recovery["candidateRuntimeGenerationId"]
            raw_route_set = recovery["candidateRouteSet"]
            if (
                type(raw_source_generation) is not str
                or type(raw_source_route_set) is not str
                or type(raw_generation) is not str
                or type(raw_route_set) is not str
            ):
                raise ExecutionError("lifecycle runtime authority is malformed")
            source_generation = validate_uuid7(raw_source_generation)
            source_route_set = raw_source_route_set
            candidate_generation = validate_uuid7(raw_generation)
            candidate_route_set = raw_route_set
            raw_source_observed = recovery.get("sourceObservedState")
            if raw_source_observed is not None:
                if type(raw_source_observed) is not dict:
                    raise ExecutionError("lifecycle source observed authority is malformed")
                source_observed = deepcopy(raw_source_observed)
            raw_observed = recovery.get("candidateObservedState")
            if raw_observed is not None:
                if type(raw_observed) is not dict:
                    raise ExecutionError("lifecycle observed-state authority is malformed")
                candidate_observed = deepcopy(raw_observed)
            raw_archive = recovery.get("candidateArchiveRecord")
            if raw_archive is not None:
                if type(raw_archive) is not dict:
                    raise ExecutionError("archive record authority is malformed")
                archive_record = deepcopy(raw_archive)
    if request["operation"] == "create":
        if expected["manifestDigest"] is not None:
            raise ExecutionError("create lifecycle source authority is malformed")
    elif request["operation"] == "restore":
        if type(source) is not dict:
            raise ExecutionError("restore source manifest is not authorization-bound")
        archive_record = _restore_source_archive_authority(
            transaction,
            request,
            expected,
            source,
            retirement_intent,
        )
    if request["operation"] != "create" and (
        type(expected["manifestDigest"]) is not dict
        or type(source) is not dict
        or manifest_digest(source).to_dict() != expected["manifestDigest"]
    ):
        raise ExecutionError("lifecycle source manifest is not authorization-bound")
    if request["operation"] != "create":
        if type(source) is not dict:  # pragma: no cover - checked immediately above
            raise ExecutionError("lifecycle source manifest is not authorization-bound")
        _validate_durable_source_authority(job, request, source, archive_record)
    return _LifecycleDispatchAuthority(
        source_manifest=deepcopy(source),
        source_observed_state=source_observed,
        source_runtime_generation_id=source_generation,
        source_route_set=source_route_set,
        candidate_observed_state=candidate_observed,
        candidate_runtime_generation_id=candidate_generation,
        candidate_route_set=candidate_route_set,
        archive_record=archive_record,
        archive_construction_present=construction_intent is not None,
        artifact_release_tree_digest=_dispatch_artifact_release_tree_digest(job),
        source_release_tree_digest=_dispatch_source_release_tree_digest(job),
        source_archive_deployment_ids=_dispatch_archive_deployment_ids(job),
        source_deployment_ids=_dispatch_deployment_ids(job),
        source_tenant_ids=_dispatch_tenant_ids(job),
    )


def _validate_durable_source_authority(
    job: dict[str, object],
    request: dict[str, object],
    source: dict[str, object],
    archive_record: dict[str, object] | None,
) -> None:
    if job["compatibilityVersion"] != "static-job-v2":
        return
    durable_source, durable_archive = _job_source_authority(job)
    if source != durable_source or (
        request["operation"] == "restore" and archive_record != durable_archive
    ):
        raise ExecutionError("lifecycle source exceeds durable job authority")


def _restore_source_archive_authority(
    transaction: ExecutionTransaction,
    request: dict[str, object],
    expected: dict[str, object],
    source: dict[str, object],
    retirement_intent: dict[str, object] | None,
) -> dict[str, object]:
    raw_archive = (
        retirement_intent.get("archiveRecord") if type(retirement_intent) is dict else None
    )
    if raw_archive is None:
        source_spec = source["spec"]
        if type(source_spec) is not dict:
            raise ExecutionError("restore source manifest authority is malformed")
        source_deployment = source_spec.get("desiredDeployment")
        if type(source_deployment) is not dict:
            raise ExecutionError("restore source deployment authority is malformed")
        raw_archive = transaction.read(
            StateRecordPath.tenant_archive(
                request["tenantId"],
                source_deployment["id"],
            )
        ).document
    if (
        type(raw_archive) is not dict
        or archive_record_digest(raw_archive).to_dict() != expected["archiveRecordDigest"]
    ):
        raise ExecutionError("restore source archive is not authorization-bound")
    return deepcopy(raw_archive)


def _capture_replay_authority(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    validation_was_committed: bool,
    audit_is_latest_for_tenant: bool,
) -> _LifecycleDispatchAuthority:
    """Reconstruct only authority that remains provable after intent cleanup."""

    request = job["request"]
    if type(request) is not dict:
        raise ExecutionError("terminal replay request authority is malformed")
    source, archive_record = _job_source_authority(job)
    if result["status"] != "succeeded":
        source_observed: dict[str, object] | None = None
        source_generation: str | None = None
        source_route_set: str | None = None
        if audit_is_latest_for_tenant and request["operation"] != "create":
            if source is None:  # pragma: no cover - current contract validation proves this
                raise ExecutionError("failed replay lost its exact source manifest")
            tenant_id = validate_uuid7(result["tenantId"])
            try:
                source_observed = transaction.read(
                    StateRecordPath.tenant_observed(tenant_id)
                ).document
            except FileNotFoundError:
                source_observed = None
            if source_observed is not None:
                validate_contract(
                    source_observed,
                    expected_kind=ContractKind.TENANT_OBSERVED_STATE,
                )
            source_spec = source["spec"]
            if type(source_spec) is not dict:
                raise ExecutionError("failed replay source manifest is malformed")
            source_route_set = "both" if source_spec["desiredState"] == "active" else "absent"
            raw_generation = (
                None if source_observed is None else source_observed.get("runtimeGenerationId")
            )
            if raw_generation is not None:
                source_generation = validate_uuid7(raw_generation)
        return _LifecycleDispatchAuthority(
            source_manifest=source,
            source_observed_state=source_observed,
            source_runtime_generation_id=source_generation,
            source_route_set=source_route_set,
            candidate_observed_state=None,
            candidate_runtime_generation_id=None,
            candidate_route_set=None,
            archive_record=archive_record,
            archive_construction_present=False,
            artifact_release_tree_digest=_dispatch_artifact_release_tree_digest(job),
            source_release_tree_digest=_dispatch_source_release_tree_digest(job),
            source_archive_deployment_ids=_dispatch_archive_deployment_ids(job),
            source_deployment_ids=_dispatch_deployment_ids(job),
            source_tenant_ids=_dispatch_tenant_ids(job),
            execution_validation_committed=validation_was_committed,
        )
    operation = result["operation"]

    observed: dict[str, object] | None = None
    generation: str | None = None
    route_set: str | None = None
    if audit_is_latest_for_tenant and operation != "delete":
        manifest = result.get("manifest")
        if type(manifest) is not dict:
            raise ExecutionError("successful replay has no exact manifest")
        tenant_id = validate_uuid7(result["tenantId"])
        observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
        validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
        spec = manifest["spec"]
        if type(spec) is not dict:
            raise ExecutionError("successful replay manifest is malformed")
        route_set = "both" if spec["desiredState"] == "active" else "absent"
        raw_generation = observed.get("runtimeGenerationId")
        if raw_generation is not None:
            generation = validate_uuid7(raw_generation)
    return _LifecycleDispatchAuthority(
        source_manifest=source,
        source_observed_state=None,
        source_runtime_generation_id=None,
        source_route_set=None,
        candidate_observed_state=observed,
        candidate_runtime_generation_id=generation,
        candidate_route_set=route_set,
        archive_record=archive_record,
        archive_construction_present=False,
        artifact_release_tree_digest=_dispatch_artifact_release_tree_digest(job),
        source_release_tree_digest=_dispatch_source_release_tree_digest(job),
        source_archive_deployment_ids=_dispatch_archive_deployment_ids(job),
        source_deployment_ids=_dispatch_deployment_ids(job),
        source_tenant_ids=_dispatch_tenant_ids(job),
        execution_validation_committed=validation_was_committed,
    )


def _capture_terminal_runtime_authority(
    transaction: ExecutionTransaction,
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
    audit_is_latest_for_tenant: bool,
) -> _LifecycleDispatchAuthority:
    """Bind post-handler runtime validation to already validated durable state."""

    if (
        not audit_is_latest_for_tenant
        or result["status"] != "succeeded"
        or result["operation"] == "delete"
        or authority.candidate_route_set is not None
    ):
        return authority
    manifest = result.get("manifest")
    if type(manifest) is not dict:
        raise ExecutionError("successful lifecycle result has no runtime manifest")
    tenant_id = validate_uuid7(result["tenantId"])
    observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    spec = manifest["spec"]
    if type(spec) is not dict:
        raise ExecutionError("successful lifecycle runtime manifest is malformed")
    route_set = "both" if spec["desiredState"] == "active" else "absent"
    raw_generation = observed.get("runtimeGenerationId")
    generation = None if raw_generation is None else validate_uuid7(raw_generation)
    return replace(
        authority,
        candidate_observed_state=deepcopy(observed),
        candidate_runtime_generation_id=generation,
        candidate_route_set=route_set,
    )


def _job_source_authority(
    job: dict[str, object],
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Read the immutable exact source bound into one current authorization job."""

    request = job["request"]
    authority = job.get("sourceAuthority")
    if type(request) is not dict:
        raise ExecutionError("authorization request authority is malformed")
    if request["operation"] == "create":
        if authority is not None:
            raise ExecutionError("create job carries tenant source authority")
        return None, None
    if type(authority) is not dict:
        raise ExecutionError("tenant job lost its exact source authority")
    manifest = authority.get("manifest")
    archive = authority.get("archiveRecord")
    if type(manifest) is not dict or (archive is not None and type(archive) is not dict):
        raise ExecutionError("tenant job source authority is malformed")
    return deepcopy(manifest), deepcopy(archive)


def _archive_record_for_construction_authority(
    transaction: ExecutionTransaction,
    construction: dict[str, object],
    committed_manifest: dict[str, object],
) -> dict[str, object] | None:
    spec = committed_manifest["spec"]
    if type(spec) is not dict:
        raise ExecutionError("archive construction manifest authority is malformed")
    deployment = spec.get("desiredDeployment")
    if type(deployment) is not dict:
        raise ExecutionError("archive construction deployment authority is malformed")
    try:
        archive = transaction.read(
            StateRecordPath.tenant_archive(construction["tenantId"], deployment["id"])
        ).document
    except FileNotFoundError:
        return None
    expected = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "ArchiveRecord",
        "tenantId": construction["tenantId"],
        "deploymentId": deployment["id"],
        "releaseTreeDigest": construction["releaseTreeDigest"],
        "manifestDigest": construction["candidateManifestDigest"],
        "bundleDigest": construction["bundleDigest"],
        "bundleSize": construction["bundleSize"],
        "bucket": construction["bucket"],
        "key": construction["key"],
        "versionId": construction["versionId"],
        "createdAt": archive.get("createdAt"),
        "correlationId": construction["correlationId"],
    }
    if archive != expected:
        raise ExecutionError("committed archive record exceeds construction authority")
    return deepcopy(archive)


def _reconstruct_archive_source_manifest(
    job: dict[str, object],
    archived: dict[str, object],
) -> dict[str, object]:
    expected = job["expectedSource"]
    if type(expected) is not dict or expected["lifecycle"] not in {"active", "suspended"}:
        raise ExecutionError("archive source reconstruction authority is malformed")
    source = deepcopy(archived)
    spec = source["spec"]
    if type(spec) is not dict:
        raise ExecutionError("archive source reconstruction manifest is malformed")
    spec["desiredState"] = expected["lifecycle"]
    return source


def _reconstruct_restore_source_manifest(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    restored: dict[str, object],
) -> dict[str, object]:
    request = job["request"]
    expected = job["expectedSource"]
    if (
        type(request) is not dict
        or type(expected) is not dict
        or type(expected["deploymentDigest"]) is not dict
    ):
        raise ExecutionError("restore source reconstruction authority is malformed")
    try:
        deployment = transaction.deployment_for_digest(
            request["tenantId"],
            expected["deploymentDigest"],
        )
    except (FileNotFoundError, StatePathError, StateRecordError) as error:
        raise ExecutionError("restore source reconstruction is unavailable") from error
    source = deepcopy(restored)
    spec = source["spec"]
    if type(spec) is not dict:
        raise ExecutionError("restore source reconstruction manifest is malformed")
    spec["desiredState"] = "archived"
    spec["desiredDeployment"] = {
        "id": deployment["id"],
        "archiveSha256": deployment["archiveSha256"],
    }
    return source


def _claim_pending(
    transaction: ExecutionTransaction,
    current: StoredContract,
) -> StoredContract:
    phase = current.document["phase"]
    if phase == "claimed":
        return current
    if phase != "pending":
        raise ExecutionError("authorization job has no result in a terminal phase")
    claimed = current.document
    claimed["phase"] = "claimed"
    return transaction.compare_and_swap(
        StateRecordPath.authorization_job(claimed["jobId"]),
        current.revision,
        claimed,
    )


def _bind_dispatch_authority(  # noqa: PLR0912,PLR0915 - dispatch authority matrix
    transaction: ExecutionTransaction,
    current: StoredContract,
    *,
    artifact_release_tree_digest: dict[str, object] | None,
) -> StoredContract:
    """Persist exact pre-dispatch history and admitted release content once."""

    job = current.document
    if job["compatibilityVersion"] != "static-job-v2":
        return current
    existing_archives = _dispatch_archive_deployment_ids(job)
    existing_deployments = _dispatch_deployment_ids(job)
    existing_tenants = _dispatch_tenant_ids(job)
    existing_release_digest = _dispatch_artifact_release_tree_digest(job)
    existing_source_release_digest = _dispatch_source_release_tree_digest(job)
    request = job["request"]
    if type(request) is not dict:
        raise ExecutionError("authorization request authority is malformed")
    artifact_operation = request["operation"] in {"deploy", "import"}
    export_operation = request["operation"] == "export"
    if not artifact_operation and existing_release_digest is not None:
        raise ExecutionError("non-artifact dispatch carries artifact release authority")
    if not export_operation and existing_source_release_digest is not None:
        raise ExecutionError("non-export dispatch carries source release authority")
    if (
        export_operation
        and existing_source_release_digest is not None
        and existing_archives is None
        and existing_deployments is None
        and existing_tenants is None
    ):
        raise ExecutionError("dispatch export authority is only partially bound")
    if (
        existing_archives is not None
        and existing_deployments is not None
        and existing_tenants is not None
    ):
        if artifact_operation and existing_release_digest is None:
            raise ExecutionError("dispatch artifact authority is not bound")
        if export_operation and existing_source_release_digest is None:
            rebound = job
            rebound["dispatchSourceReleaseTreeDigest"] = _export_source_release_tree_digest(
                transaction, job, request
            )
            try:
                return transaction.compare_and_swap(
                    StateRecordPath.authorization_job(rebound["jobId"]),
                    current.revision,
                    rebound,
                )
            except StateConflictError as error:
                raise ExecutionError("export source authority changed during dispatch") from error
        if (
            artifact_release_tree_digest is not None
            and existing_release_digest != artifact_release_tree_digest
        ):
            raise ExecutionError("dispatch artifact release authority changed")
        return current
    if (
        len(
            {
                existing_archives is None,
                existing_deployments is None,
                existing_tenants is None,
            }
        )
        != 1
    ):
        raise ExecutionError("dispatch record-history authority is only partially bound")
    if artifact_operation and artifact_release_tree_digest is None:
        raise ExecutionError("dispatch artifact release authority is unavailable")
    source_release_tree_digest: dict[str, object] | None = None
    if export_operation:
        source_release_tree_digest = _export_source_release_tree_digest(
            transaction,
            job,
            request,
        )
    if request["operation"] == "create":
        archive_ids: tuple[str, ...] = ()
        deployment_ids: tuple[str, ...] = ()
    else:
        archive_ids = transaction.tenant_archive_ids(request["tenantId"])
        deployment_ids = transaction.tenant_deployment_ids(request["tenantId"])
    bound = job
    bound["dispatchArchiveDeploymentIds"] = list(archive_ids)
    bound["dispatchArtifactReleaseTreeDigest"] = artifact_release_tree_digest
    bound["dispatchSourceReleaseTreeDigest"] = source_release_tree_digest
    bound["dispatchDeploymentIds"] = list(deployment_ids)
    bound["dispatchTenantIds"] = list(transaction.measure_inventory().tenant_ids)
    try:
        return transaction.compare_and_swap(
            StateRecordPath.authorization_job(bound["jobId"]),
            current.revision,
            bound,
        )
    except StateConflictError as error:
        raise ExecutionError("record-history authority changed during dispatch") from error


def _export_source_release_tree_digest(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    request: dict[str, object],
) -> dict[str, object]:
    expected = job["expectedSource"]
    deployment_digest = None if type(expected) is not dict else expected.get("deploymentDigest")
    if type(deployment_digest) is not dict:
        raise ExecutionError("dispatch export source deployment authority is unavailable")
    try:
        deployment = transaction.deployment_for_digest(
            request["tenantId"],
            deployment_digest,
        )
    except (FileNotFoundError, StatePathError, StateRecordError) as error:
        raise ExecutionError(
            "dispatch export source deployment authority is unavailable"
        ) from error
    raw_source_release_tree_digest = deployment.get("releaseTreeDigest")
    if type(raw_source_release_tree_digest) is not dict:
        raise ExecutionError("dispatch export source release authority is malformed")
    return deepcopy(raw_source_release_tree_digest)


def _dispatch_archive_deployment_ids(job: dict[str, object]) -> tuple[str, ...] | None:
    return _dispatch_record_ids(
        job,
        field="dispatchArchiveDeploymentIds",
        label="archive-history",
    )


def _dispatch_artifact_release_tree_digest(
    job: dict[str, object],
) -> dict[str, object] | None:
    raw = job.get("dispatchArtifactReleaseTreeDigest")
    if raw is None:
        return None
    if type(raw) is not dict:
        raise ExecutionError("dispatch artifact release authority is malformed")
    return deepcopy(raw)


def _dispatch_source_release_tree_digest(
    job: dict[str, object],
) -> dict[str, object] | None:
    raw = job.get("dispatchSourceReleaseTreeDigest")
    if raw is None:
        return None
    if type(raw) is not dict:
        raise ExecutionError("dispatch source release authority is malformed")
    return deepcopy(raw)


def _dispatch_deployment_ids(job: dict[str, object]) -> tuple[str, ...] | None:
    return _dispatch_record_ids(
        job,
        field="dispatchDeploymentIds",
        label="deployment-history",
    )


def _dispatch_tenant_ids(job: dict[str, object]) -> tuple[str, ...] | None:
    return _dispatch_record_ids(
        job,
        field="dispatchTenantIds",
        label="tenant-inventory",
    )


def _dispatch_record_ids(
    job: dict[str, object],
    *,
    field: str,
    label: str,
) -> tuple[str, ...] | None:
    raw = job.get(field)
    if raw is None:
        return None
    if type(raw) is not list:
        raise ExecutionError(f"dispatch {label} authority is malformed")
    try:
        record_ids = tuple(validate_uuid7(value) for value in raw)
    except (TypeError, ValueError) as error:
        raise ExecutionError(f"dispatch {label} authority is malformed") from error
    if record_ids != tuple(sorted(set(record_ids))):
        raise ExecutionError(f"dispatch {label} authority is not canonical")
    return record_ids


def _failure_result(job: dict[str, object], error_code: str) -> dict[str, object]:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - schema validation proves this
        raise ExecutionError("authorization job request is not an object")
    result: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": request["correlationId"],
        "operation": request["operation"],
        "status": "failed",
        "errorCode": error_code,
        "failurePublisher": _AUTHORIZATION_EXECUTOR,
        "tenantId": None if request["operation"] == "create" else request["tenantId"],
    }
    if request["operation"] == "archive":
        result["archiveRecord"] = None
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    return result


def _publish_result(
    transaction: ExecutionTransaction,
    job: StoredContract,
    result: dict[str, object],
    *,
    limits: HostCapacityLimits,
) -> None:
    if result["status"] != "failed":  # pragma: no cover - only internal failures publish here
        raise ExecutionError("direct result publication is limited to failures")
    if not _is_executor_failure(result):
        raise ExecutionError("direct failure has no executor publication authority")
    audit_snapshot = _failure_audit_snapshot(transaction, result)
    result["failureAuditPredecessorDigest"] = audit_snapshot.state.terminal_digest
    result["failureAuditSequence"] = audit_snapshot.state.entry_count
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    canonical = canonical_json_bytes(result)
    allocation = transaction.allocation_upper_bound(len(canonical))
    audit_allocation = 0
    audit_inodes = 0
    if audit_snapshot.entry is None:
        audit_allocation = transaction.allocation_upper_bound(
            DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
        ) + transaction.namespace_allocation_upper_bound(1)
        audit_inodes = 1
    reservation = StateInventoryReservation(
        authorization_records=1,
        authorization_allocated_bytes=allocation,
    )
    transaction.admit_inventory(reservation)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(
            allocated_bytes=(
                allocation + transaction.namespace_allocation_upper_bound(1) + audit_allocation
            ),
            unique_inodes=1 + audit_inodes,
        ),
        transaction.measure_filesystem_capacity(),
        limits=limits,
    )
    transaction.create_immutable(
        StateRecordPath.authorization_result(job.document["jobId"]),
        result,
    )
    _ensure_failure_audit(
        transaction,
        job.document,
        result,
        snapshot=audit_snapshot,
    )
    _set_terminal_phase(
        transaction,
        job,
        result,
        execution_validated=True,
    )


def _read_result_transaction(
    transaction: ExecutionTransaction,
    job_id: str,
) -> StoredContract | None:
    try:
        return transaction.read(StateRecordPath.authorization_result(job_id))
    except FileNotFoundError:
        return None


def _has_bound_lifecycle_intent(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    *,
    result: dict[str, object],
) -> bool:
    request, matching_intents = _bound_lifecycle_intents(transaction, job)
    if matching_intents:
        _validate_result_intent_binding(result, request, matching_intents)
    return bool(matching_intents)


def validate_result_lifecycle_authority(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
) -> bool:
    """Validate a terminal result against any durable lifecycle authority."""

    _validate_result_binding(job, result)
    has_lifecycle_intent = _has_bound_lifecycle_intent(transaction, job, result=result)
    if not has_lifecycle_intent:
        if (
            _is_executor_failure(result)
            and _failure_audit_snapshot(
                transaction,
                result,
            ).entry
            is None
        ):
            return True
        _validate_result_audit(transaction, job, result)
    return has_lifecycle_intent


def _bound_lifecycle_intents(
    transaction: ExecutionTransaction,
    job: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization job request is not an object")
    correlation_id = validate_uuid7(request["correlationId"])
    correlation = transaction.read(StateRecordPath.authorization_correlation(correlation_id))
    _require_same_authority(job, correlation.document)
    matching_kinds: set[str] = set()
    matching_intents: list[dict[str, object]] = []
    for identity in transaction.measure_intent_records().records:
        path, intent = transaction.read_intent(identity.intent_id)
        kind = cast(str, intent.document["kind"])
        expected_paths = {
            "TransactionIntent": StateRecordPath.transaction_intent,
            "ArchiveConstructionIntent": StateRecordPath.archive_construction_intent,
            "ArchiveRetirementIntent": StateRecordPath.archive_retirement_intent,
        }
        try:
            expected_path = expected_paths[kind](identity.intent_id)
        except KeyError as error:  # pragma: no cover - repository reads recognize intent kinds
            raise ExecutionError("lifecycle intent kind is not recognized") from error
        if path != expected_path:
            raise ExecutionError("lifecycle intent path disagrees with its identity")
        if not _intent_binds_job(transaction, intent.document, job, request):
            continue
        if kind in matching_kinds:
            raise ExecutionError("authorization job repeats one lifecycle intent kind")
        matching_kinds.add(kind)
        matching_intents.append(intent.document)
    _validate_archive_intent_relationships(matching_intents)
    return request, matching_intents


def _validate_archive_intent_relationships(intents: list[dict[str, object]]) -> None:
    transaction_intent = next(
        (intent for intent in intents if intent["kind"] == "TransactionIntent"),
        None,
    )
    construction_intent = next(
        (intent for intent in intents if intent["kind"] == "ArchiveConstructionIntent"),
        None,
    )
    retirement_intent = next(
        (intent for intent in intents if intent["kind"] == "ArchiveRetirementIntent"),
        None,
    )
    if (
        transaction_intent is not None
        and transaction_intent["operation"] == "restore"
        and retirement_intent is None
    ):
        raise ExecutionError("restore transaction has no retirement authority")
    if transaction_intent is not None and retirement_intent is not None:
        _validate_retirement_transaction_relationship(
            transaction_intent,
            retirement_intent,
        )
    if transaction_intent is None or construction_intent is None:
        return
    recovery = transaction_intent["archiveRecovery"]
    if type(recovery) is not dict:
        raise ExecutionError("archive transaction has no construction recovery authority")
    archive = recovery["candidateArchiveRecord"]
    if type(archive) is not dict:  # pragma: no cover - contract validation proves this
        raise ExecutionError("archive transaction candidate record is malformed")
    if (
        construction_intent["candidateManifestDigest"]
        != transaction_intent["candidateManifestDigest"]
        or construction_intent["candidateManifestDigest"] != archive["manifestDigest"]
        or construction_intent["releaseTreeDigest"] != archive["releaseTreeDigest"]
        or construction_intent["bundleDigest"] != archive["bundleDigest"]
        or construction_intent["bundleSize"] != archive["bundleSize"]
        or construction_intent["bucket"] != archive["bucket"]
        or construction_intent["key"] != archive["key"]
        or construction_intent["versionId"] != archive["versionId"]
    ):
        raise ExecutionError("archive lifecycle intents disagree on candidate authority")


def _validate_retirement_transaction_relationship(
    transaction_intent: dict[str, object],
    retirement_intent: dict[str, object],
) -> None:
    if (
        transaction_intent["operation"] != retirement_intent["transition"]
        or transaction_intent["tenantId"] != retirement_intent["tenantId"]
        or transaction_intent["sourceManifestDigest"] != retirement_intent["sourceManifestDigest"]
    ):
        raise ExecutionError("archive retirement and transaction authority disagree")
    if transaction_intent["operation"] != "restore":
        return

    source = transaction_intent["sourceManifest"]
    candidate = transaction_intent["candidateManifest"]
    recovery = transaction_intent["lifecycleRecovery"]
    archive = retirement_intent["archiveRecord"]
    if not all(type(value) is dict for value in (source, candidate, recovery, archive)):
        raise ExecutionError("restore lifecycle authority is malformed")
    source = cast(dict[str, object], source)
    candidate = cast(dict[str, object], candidate)
    recovery = cast(dict[str, object], recovery)
    archive = cast(dict[str, object], archive)
    source_spec = source["spec"]
    candidate_spec = candidate["spec"]
    candidate_observed = recovery["candidateObservedState"]
    bundle_digest = archive["bundleDigest"]
    if not all(
        type(value) is dict
        for value in (source_spec, candidate_spec, candidate_observed, bundle_digest)
    ):
        raise ExecutionError("restore deployment authority is malformed")
    source_deployment = cast(dict[str, object], source_spec)["desiredDeployment"]
    candidate_deployment = cast(dict[str, object], candidate_spec)["desiredDeployment"]
    if type(source_deployment) is not dict or type(candidate_deployment) is not dict:
        raise ExecutionError("restore deployment selection is malformed")
    if (
        source_deployment["id"] != archive["deploymentId"]
        or candidate_deployment["id"] == archive["deploymentId"]
        or candidate_deployment["archiveSha256"] != cast(dict[str, object], bundle_digest)["value"]
        or cast(dict[str, object], candidate_observed)["activeDeploymentId"]
        != candidate_deployment["id"]
    ):
        raise ExecutionError("restore candidate disagrees with archive retirement authority")


def _require_available_lifecycle_handler(
    has_lifecycle_intent: bool,
    handler: LifecycleJobHandler | None,
) -> None:
    if has_lifecycle_intent and handler is None:
        raise ExecutionError("result-bearing lifecycle job handler is unavailable")


def _validate_result_intent_binding(
    result: dict[str, object],
    request: dict[str, object],
    intents: list[dict[str, object]],
) -> None:
    if result["status"] != "succeeded":
        return
    _validate_archive_result_intent_binding(result, request, intents)
    _validate_restore_result_retirement_binding(result, request, intents)
    matching = [intent for intent in intents if intent["kind"] == "TransactionIntent"]
    if request["operation"] == "create" and len(matching) != 1:
        raise ExecutionError("successful create result has no exact lifecycle intent")
    if not matching:
        return
    if len(matching) != 1:  # pragma: no cover - duplicate kinds fail during collection
        raise ExecutionError("successful result has no exact lifecycle intent")
    intent = matching[0]
    manifest = result.get("manifest")
    if manifest is None:
        if request["operation"] == "delete":
            return
        raise ExecutionError("successful lifecycle result has no exact manifest")
    if type(manifest) is not dict:
        raise ExecutionError("successful lifecycle result manifest is malformed")
    candidate_digest = manifest_digest(manifest).to_dict()
    intent_candidate = intent["candidateManifest"]
    if (
        result["tenantId"] != intent["tenantId"]
        or candidate_digest != intent["candidateManifestDigest"]
        or manifest != intent_candidate
    ):
        raise ExecutionError("successful result disagrees with its lifecycle intent")
    if request["operation"] != "create":
        return
    recovery = intent["lifecycleRecovery"]
    if type(recovery) is not dict:
        raise ExecutionError("successful create recovery authority is malformed")
    metadata = manifest["metadata"]
    candidate_observed = recovery["candidateObservedState"]
    if type(metadata) is not dict or type(candidate_observed) is not dict:
        raise ExecutionError("successful create candidate authority is malformed")
    if (
        not result["tenantId"] == metadata["id"] == intent["tenantId"]
        or result["canonicalOrigin"] != metadata["canonicalOrigin"]
        or candidate_digest != intent["candidateManifestDigest"]
        or candidate_observed["tenantId"] != intent["tenantId"]
        or candidate_observed["desiredManifestDigest"] != candidate_digest
    ):
        raise ExecutionError("successful create result disagrees with its lifecycle intent")


def _validate_handler_result_state(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
    audit_is_latest_for_tenant: bool,
) -> None:
    if result["status"] == "succeeded" and result["operation"] == "export":
        _validate_export_bundle(transaction, job, result, authority=authority)
    if result["status"] == "succeeded" and result["operation"] != "delete":
        committed_manifest = result.get("manifest")
        if type(committed_manifest) is not dict:
            raise ExecutionError("successful lifecycle result has no exact manifest")
        _validate_committed_manifest_request_binding(
            transaction,
            job,
            result,
            committed_manifest,
            source_manifest=authority.source_manifest,
        )
    if not audit_is_latest_for_tenant:
        # A later fully audited lifecycle operation may legitimately supersede
        # this result for the same tenant before the executor reacquires
        # serialization.
        if result["status"] == "succeeded":
            _validate_success_tenant_inventory(
                transaction,
                result,
                authority=authority,
            )
        return
    if result["status"] == "failed":
        _validate_failed_handler_result_state(transaction, job, result, authority=authority)
        return
    tenant_id = validate_uuid7(result["tenantId"])
    desired_path = StateRecordPath.tenant_desired(tenant_id)
    if result["operation"] == "delete":
        _validate_deleted_tenant_state(transaction, tenant_id)
        _validate_success_tenant_inventory(
            transaction,
            result,
            authority=authority,
        )
        return
    manifest = result.get("manifest")
    if type(manifest) is not dict:
        raise ExecutionError("successful lifecycle result has no exact manifest")
    try:
        desired = transaction.read(desired_path).document
    except FileNotFoundError as error:
        raise ExecutionError(
            "successful lifecycle result has no authoritative tenant state"
        ) from error
    if desired != manifest:
        raise ExecutionError(
            "successful lifecycle result disagrees with authoritative tenant state"
        )
    _validate_observed_state(
        transaction,
        result,
        manifest,
        expected=authority.candidate_observed_state,
    )
    _validate_selected_deployment_state(
        transaction,
        job,
        result,
        manifest,
        authority=authority,
    )
    _validate_success_record_history(transaction, result, authority=authority)
    _validate_success_tenant_inventory(
        transaction,
        result,
        authority=authority,
    )


def _validate_failed_handler_result_state(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
) -> None:
    if result["operation"] == "create":
        _validate_failed_create_tenant_inventory(
            transaction,
            job,
            result,
            authority=authority,
        )
        return
    tenant_id = result["tenantId"]
    source_archive_ids = authority.source_archive_deployment_ids
    source_deployment_ids = authority.source_deployment_ids
    if (
        tenant_id is not None
        and source_archive_ids is not None
        and transaction.tenant_archive_ids(tenant_id) != source_archive_ids
    ):
        raise ExecutionError("failed lifecycle handler retained unauthorized archive history")
    if (
        tenant_id is not None
        and source_deployment_ids is not None
        and transaction.tenant_deployment_ids(tenant_id) != source_deployment_ids
    ):
        raise ExecutionError("failed lifecycle handler retained unauthorized deployment history")
    if authority.execution_validation_committed:
        return
    if _expected_source_error(transaction, job) is not None:
        raise ExecutionError("failed lifecycle handler did not restore its authorized source")


def _validate_failed_create_tenant_inventory(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
) -> None:
    source_tenant_ids = authority.source_tenant_ids
    if source_tenant_ids is None:
        if _is_executor_failure(result):
            # The executor publishes before any lifecycle handler can mutate
            # tenant state, including for legacy jobs without inventory
            # authority. Replaying that terminal failure must remain safe.
            return
        # Terminal jobs committed before the inventory-binding boundary remain
        # replayable. Every newly dispatched v2 handler binds this field first.
        if _expected_source_error(transaction, job) is not None:
            raise ExecutionError("failed lifecycle handler did not restore its authorized source")
        return
    try:
        snapshot = transaction.inspect_audit_correlation(result["correlationId"])
    except AuditError as error:
        raise ExecutionError("failed create audit authority is invalid") from error
    expected = set(source_tenant_ids)
    for operation, tenant_id in snapshot.later_tenant_inventory_transitions:
        if operation == "create":
            expected.add(tenant_id)
        else:
            expected.discard(tenant_id)
    if transaction.measure_inventory().tenant_ids != tuple(sorted(expected)):
        raise ExecutionError("failed create changed the authorized tenant inventory")


def _validate_success_tenant_inventory(
    transaction: ExecutionTransaction,
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
) -> None:
    """Require exactly the requested tenant delta plus later audited work."""

    source_tenant_ids = authority.source_tenant_ids
    if source_tenant_ids is None:
        # Terminal jobs committed before this dispatch boundary remain
        # replayable. Every newly dispatched v2 handler binds this field first.
        return
    tenant_id = validate_uuid7(result["tenantId"])
    expected = set(source_tenant_ids)
    operation = result["operation"]
    if operation == "create":
        expected.add(tenant_id)
    elif operation == "delete":
        expected.discard(tenant_id)
    try:
        snapshot = transaction.inspect_audit_correlation(result["correlationId"])
    except AuditError as error:
        raise ExecutionError("successful lifecycle audit authority is invalid") from error
    for later_operation, later_tenant_id in snapshot.later_tenant_inventory_transitions:
        if later_operation == "create":
            expected.add(later_tenant_id)
        else:
            expected.discard(later_tenant_id)
    if transaction.measure_inventory().tenant_ids != tuple(sorted(expected)):
        raise ExecutionError(
            "successful lifecycle handler changed tenant inventory outside authority"
        )


def _validate_success_record_history(
    transaction: ExecutionTransaction,
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
) -> None:
    operation = result["operation"]
    no_history_operation = operation in {
        "create",
        "export",
        "rename",
        "reconcile",
        "resume",
        "suspend",
    }
    history_operation = operation in {
        "archive",
        "deploy",
        "import",
        "restore",
        "rollback",
    }
    if not no_history_operation and not history_operation:
        return
    tenant_id = result["tenantId"]
    source_archive_ids = authority.source_archive_deployment_ids
    source_deployment_ids = authority.source_deployment_ids
    if source_archive_ids is None and source_deployment_ids is None:
        # Jobs committed before this dispatch boundary remain replayable; no
        # lifecycle handler can create such a terminal job after this upgrade.
        return
    if tenant_id is None or source_archive_ids is None or source_deployment_ids is None:
        raise ExecutionError("successful lifecycle result lost retained-history authority")
    expected_archive_ids = source_archive_ids
    expected_deployment_ids = source_deployment_ids
    if operation in {"deploy", "import", "restore"}:
        selected_id = _successful_selected_deployment_id(result)
        expected_deployment_ids = _retained_deployment_history(
            (*source_deployment_ids, selected_id),
            selected_id=selected_id,
        )
    elif operation == "rollback":
        selected_id = _successful_selected_deployment_id(result)
        expected_deployment_ids = _retained_deployment_history(
            source_deployment_ids,
            selected_id=selected_id,
        )
    if operation == "archive":
        selected_id = _successful_selected_deployment_id(result)
        expected_archive_ids = tuple(sorted({*source_archive_ids, selected_id}))
    elif operation == "restore":
        source_archive = authority.archive_record
        if type(source_archive) is not dict:
            raise ExecutionError("successful restore lost its source archive authority")
        restored_archive_id = validate_uuid7(source_archive["deploymentId"])
        expected_archive_ids = tuple(
            archive_id for archive_id in source_archive_ids if archive_id != restored_archive_id
        )
    if (
        transaction.tenant_archive_ids(tenant_id) != expected_archive_ids
        or transaction.tenant_deployment_ids(tenant_id) != expected_deployment_ids
    ):
        raise ExecutionError(
            "successful lifecycle result changed retained history outside authority"
        )


def _successful_selected_deployment_id(result: dict[str, object]) -> str:
    manifest = result.get("manifest")
    spec = manifest.get("spec") if type(manifest) is dict else None
    selected = spec.get("desiredDeployment") if type(spec) is dict else None
    selected_id = selected.get("id") if type(selected) is dict else None
    if type(selected_id) is not str:
        raise ExecutionError("successful lifecycle result has no history identity")
    return validate_uuid7(selected_id)


def _retained_deployment_history(
    deployment_ids: tuple[str, ...],
    *,
    selected_id: str,
) -> tuple[str, ...]:
    """Return the selected deployment and its two chronological predecessors."""

    ordered = tuple(sorted(set(deployment_ids)))
    try:
        selected_index = ordered.index(selected_id)
    except ValueError as error:
        raise ExecutionError("successful lifecycle selection is absent from history") from error
    first_retained = max(0, selected_index - (_MAX_RETAINED_DEPLOYMENTS - 1))
    return ordered[first_retained : selected_index + 1]


def _validate_export_bundle(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
) -> None:
    binding = result.get("exportBundle")
    if type(binding) is not dict:
        raise ExecutionError("successful export result has no bundle binding")
    source_manifest = authority.source_manifest
    release_tree_digest = authority.source_release_tree_digest
    if source_manifest is None:
        raise ExecutionError("successful export lost its source authority")
    if release_tree_digest is None and "dispatchSourceReleaseTreeDigest" not in job:
        # Terminal jobs from before source release binding remain replayable
        # while their bounded deployment record is still retained.
        request = job["request"]
        if type(request) is not dict:
            raise ExecutionError("successful export lost its source authority")
        release_tree_digest = _export_source_release_tree_digest(
            transaction,
            job,
            request,
        )
    if type(release_tree_digest) is not dict:
        raise ExecutionError("successful export lost its source authority")
    try:
        transaction.validate_export_bundle(
            job["jobId"],
            binding,
            source_manifest=source_manifest,
            source_release_tree_digest=release_tree_digest,
        )
    except (FileNotFoundError, OSError, StatePathError, StateRecordError) as error:
        raise ExecutionError("successful export result has no exact bundle") from error


def _validate_committed_manifest_request_binding(  # noqa: PLR0912 - explicit lifecycle matrix
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    manifest: dict[str, object],
    *,
    source_manifest: dict[str, object] | None,
) -> None:
    request = job["request"]
    if type(request) is not dict:
        raise ExecutionError("successful lifecycle request authority is malformed")
    operation = result["operation"]
    if operation == "create":
        _validate_candidate_request_binding(transaction, request, manifest)
        return
    if source_manifest is None:
        raise ExecutionError("successful lifecycle result lost its source manifest authority")
    expected = deepcopy(source_manifest)
    expected_spec = expected["spec"]
    result_spec = manifest["spec"]
    if type(expected_spec) is not dict or type(result_spec) is not dict:
        raise ExecutionError("successful lifecycle manifest authority is malformed")
    if operation == "rename":
        metadata = expected["metadata"]
        if type(metadata) is not dict:
            raise ExecutionError("successful rename metadata authority is malformed")
        metadata["slug"] = request["slug"]
    elif operation in {"deploy", "import", "rollback", "restore"}:
        reference = result_spec.get("desiredDeployment")
        if type(reference) is not dict:
            raise ExecutionError("successful deployment selection authority is malformed")
        expected_spec["desiredDeployment"] = deepcopy(reference)
        if operation in {"import", "restore"} or (
            operation == "deploy" and expected_spec["desiredState"] != "suspended"
        ):
            expected_spec["desiredState"] = "active"
    elif operation == "suspend":
        expected_spec["desiredState"] = "suspended"
    elif operation == "resume":
        expected_spec["desiredState"] = "active"
    elif operation == "archive":
        expected_spec["desiredState"] = "archived"
    elif operation not in {"export", "reconcile"}:
        raise ExecutionError("successful lifecycle operation has no manifest authority rule")
    if expected != manifest:
        raise ExecutionError("successful lifecycle manifest exceeds its request authority")


def _validate_deleted_tenant_state(
    transaction: ExecutionTransaction,
    tenant_id: str,
) -> None:
    for path in (
        StateRecordPath.tenant_desired(tenant_id),
        StateRecordPath.tenant_observed(tenant_id),
    ):
        try:
            transaction.read(path)
        except FileNotFoundError:
            continue
        raise ExecutionError("successful delete result retained authoritative tenant state")
    if tenant_id in transaction.measure_inventory().tenant_ids:
        raise ExecutionError("successful delete result retained its tenant namespace")


def _validate_observed_state(
    transaction: ExecutionTransaction,
    result: dict[str, object],
    manifest: dict[str, object],
    *,
    expected: dict[str, object] | None,
) -> None:
    tenant_id = validate_uuid7(result["tenantId"])
    try:
        observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
    except FileNotFoundError as error:
        raise ExecutionError("successful lifecycle result has no observed tenant state") from error
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
    metadata = manifest["metadata"]
    spec = manifest["spec"]
    if type(metadata) is not dict or type(spec) is not dict:
        raise ExecutionError("successful lifecycle tenant state is malformed")
    lifecycle = spec["desiredState"]
    deployment = spec.get("desiredDeployment")
    active_deployment_id = None
    if lifecycle in {"active", "suspended"}:
        if type(deployment) is not dict:
            raise ExecutionError("successful lifecycle deployment selection is malformed")
        active_deployment_id = deployment["id"]
    if (
        observed["tenantId"] != tenant_id
        or metadata["id"] != tenant_id
        or observed["desiredManifestDigest"] != manifest_digest(manifest).to_dict()
        or observed["observedState"] != lifecycle
        or observed["activeDeploymentId"] != active_deployment_id
    ):
        raise ExecutionError("successful lifecycle observed state is not authoritative")
    if expected is not None and observed != expected:
        raise ExecutionError("successful lifecycle observed state exceeds runtime authority")


def _validate_selected_deployment_state(  # noqa: PLR0912 - explicit operation matrix
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    manifest: dict[str, object],
    *,
    authority: _LifecycleDispatchAuthority,
) -> None:
    operation = result["operation"]
    spec = manifest["spec"]
    request = job["request"]
    if type(spec) is not dict or type(request) is not dict:
        raise ExecutionError("successful deployment authority is malformed")
    reference = spec.get("desiredDeployment")
    if spec["desiredState"] == "undeployed":
        return
    if type(reference) is not dict:
        raise ExecutionError("successful deployment selection is malformed")
    tenant_id = validate_uuid7(result["tenantId"])
    deployment_id = validate_uuid7(reference["id"])
    try:
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(tenant_id, deployment_id)
        ).document
    except FileNotFoundError as error:
        raise ExecutionError("successful lifecycle result has no deployment record") from error
    validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
    matches = (
        deployment["tenantId"] == tenant_id
        and deployment["id"] == deployment_id
        and deployment["archiveSha256"] == reference["archiveSha256"]
    )
    if operation in {"deploy", "import"}:
        artifact = request["artifact"]
        artifact_release_digest = authority.artifact_release_tree_digest
        if type(artifact) is not dict or type(artifact_release_digest) is not dict:
            raise ExecutionError("successful deployment artifact authority is malformed")
        matches = (
            matches
            and deployment["archiveSha256"] == artifact["sha256"]
            and deployment["releaseTreeDigest"] == artifact_release_digest
            and deployment["correlationId"] == result["correlationId"]
        )
    elif operation == "restore":
        matches = matches and _restore_deployment_matches(
            transaction,
            job,
            result,
            deployment,
            source_archive=authority.archive_record,
        )
    else:
        matches = matches and (operation != "rollback" or deployment_id == request["deploymentId"])
    if not matches:
        raise ExecutionError("successful lifecycle result has an unbound deployment record")
    if spec["desiredState"] != "archived":
        return
    try:
        archive = transaction.read(
            StateRecordPath.tenant_archive(tenant_id, deployment_id)
        ).document
    except FileNotFoundError as error:
        raise ExecutionError("successful archive result has no archive record") from error
    validate_contract(archive, expected_kind=ContractKind.ARCHIVE_RECORD)
    archive_matches = (
        archive["tenantId"] == tenant_id
        and archive["deploymentId"] == deployment_id
        and archive["manifestDigest"] == manifest_digest(manifest).to_dict()
        and archive["releaseTreeDigest"] == deployment["releaseTreeDigest"]
        and (operation != "archive" or archive["correlationId"] == result["correlationId"])
    )
    if not archive_matches:
        raise ExecutionError("successful lifecycle result has an unbound archive record")
    if operation == "archive" and result.get("archiveRecord") != archive:
        raise ExecutionError("successful archive result lost its durable archive authority")
    if authority.archive_construction_present and authority.archive_record is None:
        raise ExecutionError("successful archive result lost its construction authority")
    if authority.archive_record is not None and archive != authority.archive_record:
        raise ExecutionError("successful archive record exceeds construction authority")


def _restore_deployment_matches(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    deployment: dict[str, object],
    *,
    source_archive: dict[str, object] | None,
) -> bool:
    expected = job["expectedSource"]
    if type(expected) is not dict or type(expected["deploymentDigest"]) is not dict:
        raise ExecutionError("restore source deployment authority is malformed")
    try:
        archived_deployment = transaction.deployment_for_digest(
            validate_uuid7(result["tenantId"]),
            expected["deploymentDigest"],
        )
    except (FileNotFoundError, StatePathError, StateRecordError) as error:
        raise ExecutionError("restore source deployment authority is unavailable") from error
    if (
        type(source_archive) is not dict
        or archive_record_digest(source_archive).to_dict() != expected["archiveRecordDigest"]
    ):
        raise ExecutionError("restore source archive authority is unavailable")
    bundle_digest = source_archive["bundleDigest"]
    if type(bundle_digest) is not dict:
        raise ExecutionError("restore source archive bundle authority is malformed")
    return (
        deployment["correlationId"] == result["correlationId"]
        and deployment["releaseTreeDigest"] == archived_deployment["releaseTreeDigest"]
        and deployment["releaseTreeDigest"] == source_archive["releaseTreeDigest"]
        and deployment["archiveSha256"] == bundle_digest["value"]
    )


def _validate_result_audit(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    require_failure: bool = False,
) -> bool:
    if (
        result["status"] == "failed"
        and not require_failure
        and job["compatibilityVersion"] == "static-job-v1"
    ):
        return False
    try:
        snapshot = transaction.inspect_audit_correlation(result["correlationId"])
    except AuditError as error:
        raise ExecutionError("lifecycle audit authority is invalid") from error
    entry = snapshot.entry
    if entry is None:
        raise ExecutionError("lifecycle result has no durable audit authority")
    if (
        entry["operatorPrincipal"] != job["operatorPrincipal"]
        or entry["operation"] != result["operation"]
        or entry["tenantId"] != result["tenantId"]
        or entry["correlationId"] != result["correlationId"]
        or entry["resultDigest"] != result_digest(result).to_dict()
        or entry["resultStatus"] != result["status"]
    ):
        raise ExecutionError("lifecycle result disagrees with durable audit authority")
    _validate_result_audit_timestamp(
        transaction,
        job,
        result,
        entry,
        snapshot=snapshot,
    )
    if result["operation"] == "delete" and result["status"] == "succeeded":
        _validate_delete_audit_evidence(job, entry)
    failure_audit_sequence = _validate_failure_audit_position(result, entry)
    previous_transition = snapshot.previous_tenant_state_transition
    previous_transition_sequence = (
        None if previous_transition is None else previous_transition["sequence"]
    )
    if previous_transition_sequence is not None and type(previous_transition_sequence) is not int:
        raise ExecutionError("previous tenant audit position is malformed")
    repaired_after_superseding_transition = (
        failure_audit_sequence is not None
        and previous_transition_sequence is not None
        and previous_transition_sequence >= failure_audit_sequence
    )
    return not (snapshot.has_later_tenant_state_transition or repaired_after_superseding_transition)


def _validate_result_audit_timestamp(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    entry: dict[str, object],
    *,
    snapshot: AuditCorrelationSnapshot,
) -> None:
    """Bind audit time to transition state without backdating to issuance."""

    if job["compatibilityVersion"] == "static-job-v1":
        return
    observed_transitions = {
        "archive",
        "create",
        "deploy",
        "import",
        "reconcile",
        "rename",
        "restore",
        "resume",
        "rollback",
        "suspend",
    }
    exact_observed_transition = (
        result["status"] == "succeeded"
        and result["operation"] in observed_transitions
        and type(result.get("manifest")) is dict
        and not snapshot.has_later_tenant_state_transition
    )
    if exact_observed_transition:
        tenant_id = validate_uuid7(result["tenantId"])
        try:
            observed = transaction.read(StateRecordPath.tenant_observed(tenant_id)).document
        except FileNotFoundError as error:
            raise ExecutionError(
                "successful lifecycle audit has no observed tenant state"
            ) from error
        validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
        if entry["timestamp"] != observed["reconciledAt"]:
            raise ExecutionError("lifecycle audit disagrees with durable transition time")


def _validate_failure_audit_position(
    result: dict[str, object],
    entry: dict[str, object],
) -> int | None:
    """Validate an executor failure's pre-publication audit-chain position."""

    if not _is_executor_failure(result):
        return None
    sequence = result.get("failureAuditSequence")
    predecessor = result.get("failureAuditPredecessorDigest")
    if sequence is None and "failureAuditPredecessorDigest" not in result:
        # Pre-upgrade executor failures remain replayable but cannot infer
        # supersession from timestamps that are independent of chain order.
        return None
    if type(sequence) is not int or sequence < 0:
        raise ExecutionError("executor failure audit position is malformed")
    entry_sequence = entry["sequence"]
    if type(entry_sequence) is not int or entry_sequence < sequence:
        raise ExecutionError("executor failure audit position exceeds its durable entry")
    if entry_sequence == sequence and entry["previousEntryDigest"] != predecessor:
        raise ExecutionError("executor failure audit predecessor changed")
    return sequence


def _failure_audit_snapshot(
    transaction: ExecutionTransaction,
    result: dict[str, object],
) -> AuditCorrelationSnapshot:
    try:
        return transaction.inspect_audit_correlation(result["correlationId"])
    except AuditError as error:
        raise ExecutionError("failure audit authority is invalid") from error


def _ensure_failure_audit(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    snapshot: AuditCorrelationSnapshot | None = None,
) -> None:
    """Idempotently bind an executor-produced terminal failure to the audit chain."""

    if not _is_executor_failure(result):
        raise ExecutionError("failure result has no executor publication authority")
    if snapshot is None:
        snapshot = _failure_audit_snapshot(transaction, result)
    if snapshot.entry is not None:
        _validate_result_audit(transaction, job, result, require_failure=True)
        return
    entry: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": snapshot.state.entry_count,
        "previousEntryDigest": snapshot.state.terminal_digest,
        "timestamp": job["acceptedAt"],
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": result["operation"],
        "tenantId": result["tenantId"],
        "correlationId": result["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": "failed",
    }
    try:
        transaction.append_audit(entry)
    except AuditError as error:
        raise ExecutionError("failure audit authority could not be committed") from error


def _repair_executor_failure_audit(
    transaction: ExecutionTransaction,
    job: dict[str, object],
    result: dict[str, object],
    *,
    limits: HostCapacityLimits,
) -> None:
    """Complete the audit half of one immutable executor failure publication."""

    snapshot = _failure_audit_snapshot(transaction, result)
    if snapshot.entry is None:
        audit_allocation = transaction.allocation_upper_bound(
            DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
        ) + transaction.namespace_allocation_upper_bound(1)
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                allocated_bytes=audit_allocation,
                unique_inodes=1,
            ),
            transaction.measure_filesystem_capacity(),
            limits=limits,
        )
    _ensure_failure_audit(
        transaction,
        job,
        result,
        snapshot=snapshot,
    )


def _is_executor_failure(result: dict[str, object]) -> bool:
    return (
        result.get("failurePublisher") == _AUTHORIZATION_EXECUTOR
        and result.get("status") == "failed"
    )


def _validate_delete_audit_evidence(
    job: dict[str, object],
    entry: dict[str, object],
) -> None:
    evidence = entry.get("deletionEvidence")
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if type(evidence) is not dict or evidence != expected.get("deletionEvidence"):
        raise ExecutionError("successful delete audit disagrees with source authority")


def _require_current_success_result_shape(result: dict[str, object]) -> None:
    if (
        result["status"] == "succeeded"
        and result["operation"] != "delete"
        and type(result.get("manifest")) is not dict
    ):
        raise ExecutionError("new successful lifecycle result has no exact manifest")


def _validate_candidate_request_binding(
    transaction: ExecutionTransaction,
    request: dict[str, object],
    manifest: dict[str, object],
) -> None:
    operation = request["operation"]
    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    matches = True
    if operation == "create":
        matches = metadata["slug"] == request["slug"] and spec["quotas"] == request["quotas"]
    elif operation == "rename":
        matches = metadata["slug"] == request["slug"]
    elif operation in {"deploy", "import"}:
        artifact = cast(dict[str, object], request["artifact"])
        deployment = cast(dict[str, object], spec["desiredDeployment"])
        matches = deployment["archiveSha256"] == artifact["sha256"]
    elif operation == "rollback":
        deployment = cast(dict[str, object], spec["desiredDeployment"])
        tenant_id = request["tenantId"]
        deployment_id = request["deploymentId"]
        try:
            record = transaction.read(
                StateRecordPath.tenant_deployment(tenant_id, deployment_id)
            ).document
        except FileNotFoundError as error:
            raise ExecutionError("rollback target deployment is unavailable") from error
        matches = deployment == {
            "id": record["id"],
            "archiveSha256": record["archiveSha256"],
        }
    if not matches:
        raise ExecutionError("lifecycle candidate disagrees with its request target")


def _validate_archive_result_intent_binding(
    result: dict[str, object],
    request: dict[str, object],
    intents: list[dict[str, object]],
) -> None:
    if request["operation"] != "archive":
        return
    matching = [intent for intent in intents if intent["kind"] == "ArchiveConstructionIntent"]
    if not matching:
        return
    if len(matching) != 1:  # pragma: no cover - duplicate kinds fail during collection
        raise ExecutionError("successful archive result has no exact construction intent")
    manifest = result.get("manifest")
    if type(manifest) is not dict:
        raise ExecutionError("successful archive result manifest is malformed")
    intent = matching[0]
    transaction_intents = [
        candidate for candidate in intents if candidate["kind"] == "TransactionIntent"
    ]
    if len(transaction_intents) == 1 and result.get("archiveRecord") is not None:
        recovery = transaction_intents[0]["archiveRecovery"]
        if type(recovery) is not dict:
            raise ExecutionError("successful archive result has no recovery authority")
        candidate_archive = recovery["candidateArchiveRecord"]
        if type(candidate_archive) is not dict or result["archiveRecord"] != candidate_archive:
            raise ExecutionError("successful archive result exceeds its recovery authority")
    if (
        result["tenantId"] != intent["tenantId"]
        or manifest_digest(manifest).to_dict() != intent["candidateManifestDigest"]
    ):
        raise ExecutionError("successful archive result disagrees with its construction intent")


def _validate_restore_result_retirement_binding(
    result: dict[str, object],
    request: dict[str, object],
    intents: list[dict[str, object]],
) -> None:
    if request["operation"] != "restore":
        return
    matching = [intent for intent in intents if intent["kind"] == "ArchiveRetirementIntent"]
    if not matching:
        return
    if len(matching) != 1:  # pragma: no cover - duplicate kinds fail during collection
        raise ExecutionError("successful restore result has no exact retirement intent")
    manifest = result.get("manifest")
    if type(manifest) is not dict:
        raise ExecutionError("successful restore result manifest is malformed")
    intent = matching[0]
    archive = intent["archiveRecord"]
    spec = manifest["spec"]
    if type(archive) is not dict or type(spec) is not dict:
        raise ExecutionError("restore retirement authority is malformed")
    deployment = spec["desiredDeployment"]
    bundle_digest = archive["bundleDigest"]
    if type(deployment) is not dict or type(bundle_digest) is not dict:
        raise ExecutionError("restore deployment authority is malformed")
    if (
        result["tenantId"] != intent["tenantId"]
        or deployment["id"] == archive["deploymentId"]
        or deployment["archiveSha256"] != bundle_digest["value"]
    ):
        raise ExecutionError("successful restore result disagrees with retirement authority")


def _intent_binds_job(
    transaction: ExecutionTransaction,
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    kind = intent["kind"]
    if kind == "TransactionIntent":
        return _transaction_intent_binds_job(transaction, intent, job, request)
    if kind == "ArchiveConstructionIntent":
        return _archive_construction_intent_binds_job(transaction, intent, job, request)
    if kind == "ArchiveRetirementIntent":
        return _archive_retirement_intent_binds_job(transaction, intent, job, request)
    raise ExecutionError("lifecycle intent kind is not recognized")


def _transaction_intent_binds_job(
    transaction: ExecutionTransaction,
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    if intent["correlationId"] != request["correlationId"]:
        return False
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if (
        intent["operation"] != request["operation"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or (request["operation"] != "create" and intent["tenantId"] != request["tenantId"])
    ):
        raise ExecutionError("lifecycle intent authority does not match its job")
    candidate = intent["candidateManifest"]
    if candidate is not None:
        if type(candidate) is not dict:  # pragma: no cover - validated reads prove this
            raise ExecutionError("lifecycle candidate authority is not an object")
        _validate_candidate_request_binding(transaction, request, candidate)
    return True


def _archive_construction_intent_binds_job(
    transaction: ExecutionTransaction,
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    overlaps = (
        intent["jobId"] == job["jobId"] or intent["correlationId"] == request["correlationId"]
    )
    if not overlaps:
        return False
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if (
        request["operation"] != "archive"
        or intent["jobId"] != job["jobId"]
        or intent["operatorPrincipal"] != job["operatorPrincipal"]
        or intent["tenantId"] != request["tenantId"]
        or intent["correlationId"] != request["correlationId"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or intent["deploymentRecordDigest"] != expected["deploymentDigest"]
    ):
        raise ExecutionError("archive construction authority does not match its job")
    try:
        desired = transaction.read(StateRecordPath.tenant_desired(request["tenantId"])).document
        spec = desired["spec"]
        if type(spec) is not dict:
            raise ExecutionError("archive source manifest spec is malformed")
        deployment_reference = spec["desiredDeployment"]
        if type(deployment_reference) is not dict:
            raise ExecutionError("archive source deployment reference is malformed")
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(
                request["tenantId"],
                deployment_reference["id"],
            )
        ).document
    except FileNotFoundError as error:
        raise ExecutionError("archive source deployment authority is unavailable") from error
    if (
        deployment_record_digest(deployment).to_dict() != intent["deploymentRecordDigest"]
        or deployment["releaseTreeDigest"] != intent["releaseTreeDigest"]
    ):
        raise ExecutionError("archive construction release tree is not source-authorized")
    return True


def _archive_retirement_intent_binds_job(
    transaction: ExecutionTransaction,
    intent: dict[str, object],
    job: dict[str, object],
    request: dict[str, object],
) -> bool:
    provenance = intent["provenance"]
    if type(provenance) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("archive retirement provenance is not an object")
    if provenance["kind"] == "emergency-administrator":
        if intent["correlationId"] == request["correlationId"]:
            raise ExecutionError("emergency intent collides with job authority")
        return False
    overlaps = (
        provenance["jobId"] == job["jobId"] or intent["correlationId"] == request["correlationId"]
    )
    if not overlaps:
        return False
    expected = job["expectedSource"]
    if type(expected) is not dict:  # pragma: no cover - validated reads prove this
        raise ExecutionError("authorization expected source is not an object")
    if (
        intent["transition"] != request["operation"]
        or provenance != {"kind": "authorization-job", "jobId": job["jobId"]}
        or intent["operatorPrincipal"] != job["operatorPrincipal"]
        or intent["tenantId"] != request["tenantId"]
        or intent["correlationId"] != request["correlationId"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or intent["archiveRecordDigest"] != expected["archiveRecordDigest"]
    ):
        raise ExecutionError("archive retirement authority does not match its job")
    if request["operation"] != "restore":
        return True
    archive = intent["archiveRecord"]
    if type(archive) is not dict or type(expected["deploymentDigest"]) is not dict:
        raise ExecutionError("archive retirement release authority is malformed")
    try:
        source_deployment = transaction.deployment_for_digest(
            request["tenantId"],
            expected["deploymentDigest"],
        )
    except (FileNotFoundError, StatePathError, StateRecordError) as error:
        raise ExecutionError("archive retirement source deployment is unavailable") from error
    if source_deployment["releaseTreeDigest"] != archive["releaseTreeDigest"]:
        raise ExecutionError("archive retirement release is not source-authorized")
    return True


def _repair_terminal_phase_transaction(
    transaction: ExecutionTransaction,
    job: StoredContract,
    result: StoredContract,
) -> dict[str, object]:
    _validate_result_binding(job.document, result.document)
    expected_phase = "completed" if result.document["status"] == "succeeded" else "failed"
    if job.document["phase"] != expected_phase:
        _set_terminal_phase(transaction, job, result.document)
    return result.document


def _set_terminal_phase(
    transaction: ExecutionTransaction,
    job: StoredContract,
    result: dict[str, object],
    *,
    execution_validated: bool = False,
) -> None:
    expected_phase = "completed" if result["status"] == "succeeded" else "failed"
    marker_is_current = (
        job.document["compatibilityVersion"] != "static-job-v2"
        or job.document["executionValidated"] is execution_validated
        or not execution_validated
    )
    if job.document["phase"] == expected_phase and marker_is_current:
        return
    terminal = job.document
    terminal["phase"] = expected_phase
    if terminal["compatibilityVersion"] == "static-job-v2" and execution_validated:
        terminal["executionValidated"] = True
    try:
        transaction.compare_and_swap(
            StateRecordPath.authorization_job(terminal["jobId"]),
            job.revision,
            terminal,
        )
    except StateConflictError as error:
        raise ExecutionError("authorization phase changed during terminal commit") from error


def _validate_result_binding(job: dict[str, object], result: dict[str, object]) -> None:
    request = job["request"]
    provenance = result["provenance"]
    if type(request) is not dict or type(provenance) is not dict:
        raise ExecutionError("terminal result binding is malformed")
    tenant_id = _expected_result_tenant(request, result)
    if (
        provenance != {"kind": "authorization-job", "jobId": job["jobId"]}
        or result["correlationId"] != request["correlationId"]
        or result["operation"] != request["operation"]
        or result["tenantId"] != tenant_id
    ):
        raise ExecutionError("terminal result does not match its authorization job")
    if (
        job["compatibilityVersion"] == "static-job-v2"
        and result["operation"] == "archive"
        and result["status"] == "succeeded"
        and type(result.get("archiveRecord")) is not dict
    ):
        raise ExecutionError("successful archive result has no durable archive authority")


def _expected_result_tenant(
    request: dict[str, object],
    result: dict[str, object],
) -> object:
    if request["operation"] != "create":
        return request["tenantId"]
    if result["status"] == "failed":
        return None
    try:
        return validate_uuid7(result["tenantId"])
    except (TypeError, ValueError) as error:
        raise ExecutionError("successful create result has no generated tenant") from error
