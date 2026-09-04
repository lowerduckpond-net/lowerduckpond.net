"""Strict, lock-protected access to canonical authoritative state records."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from bisect import bisect_right
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    MAX_EXPORT_BYTES,
    ContractKind,
    canonical_json_bytes,
    decode_contract,
    deployment_record_digest,
    manifest_digest,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.audit import (
    DEFAULT_AUDIT_LIMITS,
    AuditAppend,
    AuditCorrelationSnapshot,
    AuditLimits,
    AuditState,
    AuditTransition,
    tenant_has_deployment_audit_history,
    tenant_has_identity_audit_history,
)
from lowerduckpond_static_host_agent.audit import (
    append_audit as append_audit_record,
)
from lowerduckpond_static_host_agent.audit import (
    inspect_audit as inspect_audit_records,
)
from lowerduckpond_static_host_agent.audit import (
    inspect_audit_correlation as inspect_audit_correlation_records,
)
from lowerduckpond_static_host_agent.audit import (
    inspect_later_audit_transitions as inspect_later_audit_transition_records,
)
from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    CapacityReservation,
    FilesystemCapacity,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    FailureHook,
    validate_state_directory,
)
from lowerduckpond_static_host_agent.locks import (
    LockManager,
    LockMode,
    LockName,
    LockRequest,
)
from lowerduckpond_static_host_agent.portable_bundle import (
    PortableBundleError,
    inspect_portable_bundle_descriptor,
)
from lowerduckpond_static_host_agent.state_inventory import (
    DEFAULT_INTENT_INVENTORY_LIMITS,
    DEFAULT_STATE_INVENTORY_LIMITS,
    AuthorizationRecordInventory,
    IntentInventoryLimits,
    IntentRecordInventory,
    StateInventory,
    StateInventoryLimits,
    StateInventoryProjection,
    StateInventoryReservation,
    admit_state_inventory,
    measure_authorization_records,
    measure_intent_records,
    measure_state_inventory,
)

_STATE_REVISION_FORMAT: Final = b"lowerduckpond-state-revision-v1"
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
_RECOVERY_CURSOR_COMPONENTS: Final = ("locks", "authorization-recovery.cursor")
_RECOVERY_CURSOR_MAXIMUM_BYTES: Final = 36
_DIRECTORY_OPEN_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_TENANT_CHILD_DIRECTORIES: Final = ("archives", "deployments")
_MAX_RETAINED_DEPLOYMENT_RECORDS: Final = 3
_DEFAULT_TENANT_RELEASE_ROOT: Final = Path("/srv/lowerduckpond/sites")
_DISPATCH_AUTHORITY_FIELDS: Final = (
    "dispatchArchiveDeploymentIds",
    "dispatchArtifactReleaseTreeDigest",
    "dispatchSourceReleaseTreeDigest",
    "dispatchDeploymentIds",
    "dispatchTenantIds",
    "dispatchTenantRecordHistories",
)


class StateRecordError(RuntimeError):
    """An authoritative record did not satisfy its storage contract."""


class StateConflictError(RuntimeError):
    """A compare-and-swap source revision is no longer current."""


class TenantNamespaceBoundary(StrEnum):
    """Durability barriers for an intent-authorized tenant namespace."""

    TENANT_DIRECTORY_SYNC = "tenant-directory-sync"
    TENANT_ROOT_SYNC = "tenant-root-sync"
    CHILD_DIRECTORIES_SYNC = "child-directories-sync"
    CHILD_DIRECTORIES_REMOVED = "child-directories-removed"
    TENANT_DIRECTORY_REMOVED = "tenant-directory-removed"


TenantNamespaceFailureHook = Callable[[TenantNamespaceBoundary], None]


class CreateStateBoundary(StrEnum):
    """Durable record boundaries for an intent-authorized create commit."""

    DESIRED_STATE_SYNC = "desired-state-sync"
    OBSERVED_STATE_SYNC = "observed-state-sync"


CreateStateFailureHook = Callable[[CreateStateBoundary], None]


class _StateRecordName(StrEnum):
    """The authoritative paths whose layouts are already committed by M3."""

    PLATFORM_NAMESPACE = "platform-namespace"
    PLATFORM_LAUNCH = "platform-launch"
    TENANT_DESIRED = "tenant-desired"
    TENANT_OBSERVED = "tenant-observed"
    TENANT_DEPLOYMENT = "tenant-deployment"
    TENANT_ARCHIVE = "tenant-archive"
    AUTHORIZATION_JOB = "authorization-job"
    AUTHORIZATION_RESULT = "authorization-result"
    EMERGENCY_RESULT = "emergency-result"
    AUTHORIZATION_CORRELATION = "authorization-correlation"
    TRANSACTION_INTENT = "transaction-intent"
    ARCHIVE_CONSTRUCTION_INTENT = "archive-construction-intent"
    ARCHIVE_RETIREMENT_INTENT = "archive-retirement-intent"


@dataclass(frozen=True, slots=True, init=False)
class StateRecordPath:
    """One typed path in the fixed authoritative-state layout."""

    name: _StateRecordName
    tenant_id: str | None
    deployment_id: str | None
    record_id: str | None

    @classmethod
    def platform_namespace(cls) -> Self:
        return cls._new(_StateRecordName.PLATFORM_NAMESPACE)

    @classmethod
    def platform_launch(cls) -> Self:
        return cls._new(_StateRecordName.PLATFORM_LAUNCH)

    @classmethod
    def tenant_desired(cls, tenant_id: object) -> Self:
        return cls._new(
            _StateRecordName.TENANT_DESIRED,
            tenant_id=validate_uuid7(tenant_id),
        )

    @classmethod
    def tenant_observed(cls, tenant_id: object) -> Self:
        return cls._new(
            _StateRecordName.TENANT_OBSERVED,
            tenant_id=validate_uuid7(tenant_id),
        )

    @classmethod
    def tenant_deployment(cls, tenant_id: object, deployment_id: object) -> Self:
        return cls._new(
            _StateRecordName.TENANT_DEPLOYMENT,
            tenant_id=validate_uuid7(tenant_id),
            deployment_id=validate_uuid7(deployment_id),
        )

    @classmethod
    def tenant_archive(cls, tenant_id: object, deployment_id: object) -> Self:
        return cls._new(
            _StateRecordName.TENANT_ARCHIVE,
            tenant_id=validate_uuid7(tenant_id),
            deployment_id=validate_uuid7(deployment_id),
        )

    @classmethod
    def authorization_job(cls, job_id: object) -> Self:
        return cls._new(
            _StateRecordName.AUTHORIZATION_JOB,
            record_id=validate_uuid7(job_id),
        )

    @classmethod
    def authorization_result(cls, job_id: object) -> Self:
        return cls._new(
            _StateRecordName.AUTHORIZATION_RESULT,
            record_id=validate_uuid7(job_id),
        )

    @classmethod
    def emergency_result(cls, correlation_id: object) -> Self:
        return cls._new(
            _StateRecordName.EMERGENCY_RESULT,
            record_id=validate_uuid7(correlation_id),
        )

    @classmethod
    def authorization_correlation(cls, correlation_id: object) -> Self:
        return cls._new(
            _StateRecordName.AUTHORIZATION_CORRELATION,
            record_id=validate_uuid7(correlation_id),
        )

    @classmethod
    def transaction_intent(cls, intent_id: object) -> Self:
        return cls._new(
            _StateRecordName.TRANSACTION_INTENT,
            record_id=validate_uuid7(intent_id),
        )

    @classmethod
    def archive_construction_intent(cls, intent_id: object) -> Self:
        return cls._new(
            _StateRecordName.ARCHIVE_CONSTRUCTION_INTENT,
            record_id=validate_uuid7(intent_id),
        )

    @classmethod
    def archive_retirement_intent(cls, intent_id: object) -> Self:
        return cls._new(
            _StateRecordName.ARCHIVE_RETIREMENT_INTENT,
            record_id=validate_uuid7(intent_id),
        )

    @classmethod
    def _new(
        cls,
        name: _StateRecordName,
        *,
        tenant_id: str | None = None,
        deployment_id: str | None = None,
        record_id: str | None = None,
    ) -> Self:
        value = object.__new__(cls)
        object.__setattr__(value, "name", name)
        object.__setattr__(value, "tenant_id", tenant_id)
        object.__setattr__(value, "deployment_id", deployment_id)
        object.__setattr__(value, "record_id", record_id)
        return value

    @property
    def contract_kind(self) -> ContractKind:
        return {
            _StateRecordName.PLATFORM_NAMESPACE: ContractKind.PLATFORM_NAMESPACE,
            _StateRecordName.PLATFORM_LAUNCH: ContractKind.LAUNCH_RECORD,
            _StateRecordName.TENANT_DESIRED: ContractKind.SITE,
            _StateRecordName.TENANT_OBSERVED: ContractKind.TENANT_OBSERVED_STATE,
            _StateRecordName.TENANT_DEPLOYMENT: ContractKind.DEPLOYMENT_RECORD,
            _StateRecordName.TENANT_ARCHIVE: ContractKind.ARCHIVE_RECORD,
            _StateRecordName.AUTHORIZATION_JOB: ContractKind.AUTHORIZATION_JOB,
            _StateRecordName.AUTHORIZATION_RESULT: ContractKind.OPERATION_RESULT,
            _StateRecordName.EMERGENCY_RESULT: ContractKind.OPERATION_RESULT,
            _StateRecordName.AUTHORIZATION_CORRELATION: ContractKind.AUTHORIZATION_JOB,
            _StateRecordName.TRANSACTION_INTENT: ContractKind.TRANSACTION_INTENT,
            _StateRecordName.ARCHIVE_CONSTRUCTION_INTENT: (
                ContractKind.ARCHIVE_CONSTRUCTION_INTENT
            ),
            _StateRecordName.ARCHIVE_RETIREMENT_INTENT: ContractKind.ARCHIVE_RETIREMENT_INTENT,
        }[self.name]

    @property
    def components(self) -> tuple[str, ...]:
        components: tuple[str, ...]
        if self.name is _StateRecordName.PLATFORM_NAMESPACE:
            components = ("platform", "namespace.json")
        elif self.name is _StateRecordName.PLATFORM_LAUNCH:
            components = ("platform", "launch.json")
        elif self.name is _StateRecordName.AUTHORIZATION_JOB:
            components = ("authorization", "jobs", f"{self._require_record_id()}.json")
        elif self.name in {
            _StateRecordName.AUTHORIZATION_RESULT,
            _StateRecordName.EMERGENCY_RESULT,
        }:
            components = ("authorization", "results", f"{self._require_record_id()}.json")
        elif self.name is _StateRecordName.AUTHORIZATION_CORRELATION:
            components = (
                "authorization",
                "correlations",
                f"{self._require_record_id()}.json",
            )
        elif self.name in {
            _StateRecordName.TRANSACTION_INTENT,
            _StateRecordName.ARCHIVE_CONSTRUCTION_INTENT,
            _StateRecordName.ARCHIVE_RETIREMENT_INTENT,
        }:
            components = ("intents", f"{self._require_record_id()}.json")
        elif self.tenant_id is None:
            raise RuntimeError("tenant record path has no tenant identity")
        elif self.name is _StateRecordName.TENANT_DESIRED:
            components = ("tenants", self.tenant_id, "desired.json")
        elif self.name is _StateRecordName.TENANT_OBSERVED:
            components = ("tenants", self.tenant_id, "observed.json")
        elif self.name in {
            _StateRecordName.TENANT_DEPLOYMENT,
            _StateRecordName.TENANT_ARCHIVE,
        }:
            if self.deployment_id is None:
                raise RuntimeError("deployment-bound record has no deployment identity")
            directory = (
                "deployments" if self.name is _StateRecordName.TENANT_DEPLOYMENT else "archives"
            )
            components = (
                "tenants",
                self.tenant_id,
                directory,
                f"{self.deployment_id}.json",
            )
        else:
            raise RuntimeError("state record path is not implemented")
        return components

    def _require_record_id(self) -> str:
        if self.record_id is None:
            raise RuntimeError("global state record has no identity")
        return self.record_id

    def validate_binding(self, document: dict[str, object]) -> None:
        """Prove that record identity agrees with its typed filesystem path."""

        if self.name is _StateRecordName.TENANT_DESIRED:
            metadata = document.get("metadata")
            if type(metadata) is not dict or metadata.get("id") != self.tenant_id:
                raise StateRecordError("desired-state identity does not match its path")
        elif self.name is _StateRecordName.TENANT_OBSERVED:
            if document.get("tenantId") != self.tenant_id:
                raise StateRecordError("observed-state identity does not match its path")
        elif self.name is _StateRecordName.TENANT_DEPLOYMENT and (
            document.get("tenantId") != self.tenant_id or document.get("id") != self.deployment_id
        ):
            raise StateRecordError("deployment identity does not match its path")
        elif self.name is _StateRecordName.TENANT_ARCHIVE and (
            document.get("tenantId") != self.tenant_id
            or document.get("deploymentId") != self.deployment_id
        ):
            raise StateRecordError("archive identity does not match its path")
        elif self.name in {
            _StateRecordName.AUTHORIZATION_JOB,
            _StateRecordName.AUTHORIZATION_CORRELATION,
        }:
            _validate_authorization_binding(self.name, self.record_id, document)
        elif self.name in {
            _StateRecordName.AUTHORIZATION_RESULT,
            _StateRecordName.EMERGENCY_RESULT,
        }:
            _validate_result_binding(self.name, self.record_id, document)
        elif (
            self.name
            in {
                _StateRecordName.TRANSACTION_INTENT,
                _StateRecordName.ARCHIVE_CONSTRUCTION_INTENT,
                _StateRecordName.ARCHIVE_RETIREMENT_INTENT,
            }
            and document.get("intentId") != self.record_id
        ):
            raise StateRecordError("intent identity does not match its path")

    @property
    def allows_replacement(self) -> bool:
        """Return whether this record kind has a committed mutable lifecycle."""

        return self.name in {
            _StateRecordName.PLATFORM_NAMESPACE,
            _StateRecordName.PLATFORM_LAUNCH,
            _StateRecordName.TENANT_DESIRED,
            _StateRecordName.TENANT_OBSERVED,
            _StateRecordName.AUTHORIZATION_JOB,
            _StateRecordName.TRANSACTION_INTENT,
            _StateRecordName.ARCHIVE_CONSTRUCTION_INTENT,
            _StateRecordName.ARCHIVE_RETIREMENT_INTENT,
        }

    @property
    def is_intent(self) -> bool:
        return self.name in {
            _StateRecordName.TRANSACTION_INTENT,
            _StateRecordName.ARCHIVE_CONSTRUCTION_INTENT,
            _StateRecordName.ARCHIVE_RETIREMENT_INTENT,
        }


def _validate_authorization_binding(
    name: _StateRecordName,
    record_id: str | None,
    document: dict[str, object],
) -> None:
    if name is _StateRecordName.AUTHORIZATION_JOB:
        if document.get("jobId") != record_id:
            raise StateRecordError("authorization-job identity does not match its path")
        return
    request = document.get("request")
    if type(request) is not dict or request.get("correlationId") != record_id:
        raise StateRecordError("authorization-correlation identity does not match its path")


def _validate_result_binding(
    name: _StateRecordName,
    record_id: str | None,
    document: dict[str, object],
) -> None:
    provenance = document.get("provenance")
    if type(provenance) is not dict:
        raise StateRecordError("operation-result provenance is not an object")
    if name is _StateRecordName.AUTHORIZATION_RESULT:
        if provenance.get("kind") != "authorization-job" or provenance.get("jobId") != record_id:
            raise StateRecordError("authorization-result identity does not match its path")
        return
    if (
        provenance.get("kind") != "emergency-administrator"
        or document.get("correlationId") != record_id
    ):
        raise StateRecordError("emergency-result identity does not match its path")


def _validate_new_result_shape(
    name: _StateRecordName,
    document: dict[str, object],
) -> None:
    if name not in {
        _StateRecordName.AUTHORIZATION_RESULT,
        _StateRecordName.EMERGENCY_RESULT,
    }:
        return
    if document["operation"] == "archive" and "archiveRecord" not in document:
        raise StateRecordError("new archive operation result requires archive authority")
    if (
        document["status"] == "succeeded"
        and document["operation"] != "delete"
        and type(document.get("manifest")) is not dict
    ):
        raise StateRecordError("new successful operation result requires its exact manifest")


def _validate_new_archive_retirement_shape(
    name: _StateRecordName,
    document: dict[str, object],
) -> None:
    if name is _StateRecordName.ARCHIVE_RETIREMENT_INTENT and (
        document.get("compatibilityVersion") != "static-retirement-v2"
    ):
        raise StateRecordError("new archive-retirement intent requires current authority")


@dataclass(frozen=True, slots=True)
class StateRevision:
    """An internal CAS token over one exact canonical record generation."""

    contract_kind: ContractKind
    byte_count: int
    sha256: str

    def __post_init__(self) -> None:
        if self.byte_count < 0 or _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("state revision is not a canonical SHA-256 token")


@dataclass(frozen=True, slots=True)
class IntentRemovalToken:
    """Exact canonical and inode generation authorized for intent removal."""

    revision: StateRevision
    metadata_generation: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.metadata_generation or any(
            type(value) is not int for value in self.metadata_generation
        ):
            raise ValueError("intent removal metadata generation is invalid")


class StoredContract:
    """A validated immutable snapshot and its storage-local revision token."""

    __slots__ = ("_document", "revision")

    def __init__(self, document: dict[str, object], revision: StateRevision) -> None:
        self._document = deepcopy(document)
        self.revision = revision

    @property
    def document(self) -> dict[str, object]:
        """Return a copy so callers cannot mutate the validated snapshot."""

        return deepcopy(self._document)


class StateRepository:
    """Own the verified state-root descriptor and tenant-state lock manager."""

    def __init__(
        self,
        root: Path,
        *,
        expected_owner: int,
        expected_directory_mode: int = 0o700,
        expected_record_mode: int = 0o600,
        tenant_release_root: Path = _DEFAULT_TENANT_RELEASE_ROOT,
    ) -> None:
        self._durable = DurableDirectory.open(
            root,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
        )
        try:
            with self._durable.open_descendant(("locks",)) as lock_directory:
                self._locks = LockManager(
                    lock_directory,
                    expected_owner=expected_owner,
                    expected_directory_mode=expected_directory_mode,
                )
        except BaseException:
            self._durable.close()
            raise
        self._expected_owner = expected_owner
        self._expected_directory_mode = expected_directory_mode
        self._expected_record_mode = expected_record_mode
        self._tenant_release_root = tenant_release_root
        self._closed = False

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._locks.close()
            self._durable.close()
            self._closed = True

    @contextmanager
    def transaction(
        self,
        *,
        mode: LockMode,
        blocking: bool = False,
    ) -> Iterator[_StateTransaction]:
        """Hold tenant-state once for a coherent one- or multi-record transaction."""

        self._require_open()
        with self._locks.acquire(
            LockName.TENANT_STATE,
            mode=mode,
            blocking=blocking,
        ):
            transaction = _StateTransaction(self, mode=mode)
            try:
                yield transaction
            finally:
                transaction._close()

    @contextmanager
    def publication_transaction(
        self,
        *,
        blocking: bool = False,
    ) -> Iterator[_StateTransaction]:
        """Hold publication before exclusive tenant-state for lifecycle mutation."""

        self._require_open()
        with self._locks.acquire_many(
            (
                LockRequest(LockName.PUBLICATION, LockMode.EXCLUSIVE),
                LockRequest(LockName.TENANT_STATE, LockMode.EXCLUSIVE),
            ),
            blocking=blocking,
        ):
            transaction = _StateTransaction(self, mode=LockMode.EXCLUSIVE)
            try:
                yield transaction
            finally:
                transaction._close()

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None:
        """Prove a repository-owned lock and optional inode are held now."""

        self._require_open()
        self._locks.require_held(name, mode=mode, descriptor=descriptor)

    def read(self, path: StateRecordPath, *, blocking: bool = False) -> StoredContract:
        with self.transaction(mode=LockMode.SHARED, blocking=blocking) as transaction:
            return transaction.read(path)

    def tenant_has_deployment_history(
        self,
        tenant_id: object,
        *,
        blocking: bool = False,
    ) -> bool:
        """Return whether any root-owned source proves a prior deployment."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.tenant_has_deployment_history(tenant_id)

    def tenant_has_identity_history(
        self,
        tenant_id: object,
        *,
        blocking: bool = False,
    ) -> bool:
        """Return whether root-owned state has ever recorded one tenant identity."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.tenant_has_identity_history(tenant_id)

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
        *,
        blocking: bool = False,
    ) -> StoredContract:
        candidate = self._encode_new(path, document)
        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction._create_immutable_bytes(path, candidate)

    def compare_and_swap(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
        *,
        blocking: bool = False,
    ) -> StoredContract:
        if not path.allows_replacement:
            raise StateRecordError("immutable state-record path cannot be replaced")
        candidate = self._encode(path, document)
        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction._compare_and_swap_bytes(path, expected_revision, candidate)

    def measure_inventory(
        self,
        *,
        limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
        blocking: bool = False,
    ) -> StateInventory:
        """Measure bounded durable-state usage under exclusive tenant-state."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.measure_inventory(limits=limits)

    def measure_authorization_records(
        self,
        *,
        limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
        blocking: bool = False,
    ) -> AuthorizationRecordInventory:
        """List bounded authorization identities under exclusive tenant-state."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.measure_authorization_records(limits=limits)

    def select_recovery_batch(
        self,
        job_ids: tuple[str, ...],
        *,
        limit: int,
        blocking: bool = False,
    ) -> tuple[str, ...]:
        """Durably rotate one bounded batch through committed job IDs."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.select_recovery_batch(job_ids, limit=limit)

    def measure_intent_records(
        self,
        *,
        limits: IntentInventoryLimits = DEFAULT_INTENT_INVENTORY_LIMITS,
        blocking: bool = False,
    ) -> IntentRecordInventory:
        """List stable active intent identities under exclusive tenant-state."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.measure_intent_records(limits=limits)

    def remove_reconciled_intent(
        self,
        path: StateRecordPath,
        expected: IntentRemovalToken,
        *,
        failure_hook: FailureHook | None = None,
        blocking: bool = False,
    ) -> None:
        """Durably clear only the exact intent generation a caller reconciled."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            transaction.remove_reconciled_intent(
                path,
                expected,
                failure_hook=failure_hook,
            )

    def inspect_audit(
        self,
        *,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
        blocking: bool = False,
    ) -> AuditState:
        """Validate the bounded audit chain under exclusive tenant-state."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.inspect_audit(limits=limits)

    def inspect_audit_correlation(
        self,
        correlation_id: object,
        *,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
        blocking: bool = False,
    ) -> AuditCorrelationSnapshot:
        """Return one bounded audit correlation under exclusive tenant-state."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.inspect_audit_correlation(correlation_id, limits=limits)

    def inspect_later_audit_transitions(
        self,
        correlation_id: object,
        *,
        maximum_transitions: int,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
        blocking: bool = False,
    ) -> tuple[AuditTransition, ...]:
        """Return capped later transition authority under exclusive tenant-state."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.inspect_later_audit_transitions(
                correlation_id,
                maximum_transitions=maximum_transitions,
                limits=limits,
            )

    def append_audit(
        self,
        document: dict[str, object],
        *,
        administrator: bool = False,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
        failure_hook: FailureHook | None = None,
        blocking: bool = False,
    ) -> AuditAppend:
        """Append one entry after verifying the complete bounded audit chain."""

        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction.append_audit(
                document,
                administrator=administrator,
                limits=limits,
                failure_hook=failure_hook,
            )

    def _read_locked(self, path: StateRecordPath) -> StoredContract:
        raw = self._durable.read_regular(
            path.components,
            expected_owner=self._expected_owner,
            expected_mode=self._expected_record_mode,
            maximum_bytes=MAX_CANONICAL_BYTES,
        )
        document = decode_contract(
            raw,
            expected_kind=path.contract_kind,
            maximum_raw_bytes=MAX_CANONICAL_BYTES,
        )
        canonical = canonical_json_bytes(document)
        if raw != canonical:
            raise StateRecordError("state record is not its exact canonical representation")
        path.validate_binding(document)
        return StoredContract(document, _revision(path.contract_kind, canonical))

    def _read_intent_locked(
        self,
        intent_id: object,
    ) -> tuple[StateRecordPath, StoredContract]:
        canonical_id = validate_uuid7(intent_id)
        raw = self._durable.read_regular(
            ("intents", f"{canonical_id}.json"),
            expected_owner=self._expected_owner,
            expected_mode=self._expected_record_mode,
            maximum_bytes=MAX_CANONICAL_BYTES,
        )
        document = decode_contract(raw, maximum_raw_bytes=MAX_CANONICAL_BYTES)
        factories = {
            ContractKind.TRANSACTION_INTENT: StateRecordPath.transaction_intent,
            ContractKind.ARCHIVE_CONSTRUCTION_INTENT: (StateRecordPath.archive_construction_intent),
            ContractKind.ARCHIVE_RETIREMENT_INTENT: StateRecordPath.archive_retirement_intent,
        }
        kind_value = document.get("kind")
        if type(kind_value) is not str:
            raise StateRecordError("intent record has no contract kind")
        try:
            kind = ContractKind(kind_value)
        except ValueError as error:
            raise StateRecordError("intent store contains an unknown contract kind") from error
        factory = factories.get(kind)
        if factory is None:
            raise StateRecordError("intent store contains another contract kind")
        path = factory(canonical_id)
        canonical = canonical_json_bytes(document)
        if raw != canonical:
            raise StateRecordError("intent record is not its exact canonical representation")
        path.validate_binding(document)
        return path, StoredContract(document, _revision(kind, canonical))

    def _encode(self, path: StateRecordPath, document: dict[str, object]) -> bytes:
        if type(document) is not dict:
            raise TypeError("state record must be a contract object")
        candidate = deepcopy(document)
        validate_contract(candidate, expected_kind=path.contract_kind)
        path.validate_binding(candidate)
        return canonical_json_bytes(candidate)

    def _encode_new(self, path: StateRecordPath, document: dict[str, object]) -> bytes:
        """Encode a newly created record under current writer requirements."""

        candidate = deepcopy(document)
        encoded = self._encode(path, candidate)
        _validate_new_result_shape(path.name, candidate)
        _validate_new_archive_retirement_shape(path.name, candidate)
        return encoded

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("state repository is closed")


class _StateTransaction:
    """Operations permitted while the repository's tenant-state lock is held."""

    def __init__(self, repository: StateRepository, *, mode: LockMode) -> None:
        self._repository = repository
        self._mode = mode
        self._active = True

    def read(self, path: StateRecordPath) -> StoredContract:
        self._require_active()
        return self._repository._read_locked(path)

    def tenant_has_deployment_history(self, tenant_id: object) -> bool:
        """Inspect every deployment-history source while state is serialized."""

        self._require_active()
        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        if canonical_id in self.measure_inventory().tenant_ids and (
            self.tenant_deployment_ids(canonical_id) or self.tenant_archive_ids(canonical_id)
        ):
            return True
        if self._tenant_has_release_history(canonical_id):
            return True
        return tenant_has_deployment_audit_history(
            self._repository._durable,
            canonical_id,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
        )

    def tenant_has_identity_history(self, tenant_id: object) -> bool:
        """Inspect current and audited identity history while state is serialized."""

        self._require_active()
        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        if canonical_id in self.measure_inventory().tenant_ids:
            return True
        return tenant_has_identity_audit_history(
            self._repository._durable,
            canonical_id,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
        )

    def _tenant_has_release_history(self, tenant_id: str) -> bool:
        release_root = self._repository._tenant_release_root / tenant_id / "releases"
        try:
            metadata = release_root.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(metadata.st_mode):
            raise StateRecordError("tenant release history is not a directory")
        try:
            with os.scandir(release_root) as entries:
                return next(entries, None) is not None
        except FileNotFoundError as error:
            raise StateRecordError("tenant release history changed while inspected") from error

    def tenant_deployment_ids(self, tenant_id: object) -> tuple[str, ...]:
        """Return the complete bounded deployment-record identity set."""

        self._require_active()
        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        deployments = self._repository._durable.open_descendant(
            ("tenants", canonical_id, "deployments")
        )
        try:
            deployments.remove_abandoned_publication_temporaries(
                expected_owner=self._repository._expected_owner,
                expected_mode=self._repository._expected_record_mode,
                maximum_entries=_MAX_RETAINED_DEPLOYMENT_RECORDS + 1,
            )
            descriptor = deployments.duplicate_descriptor()
            try:
                with os.scandir(descriptor) as entries:
                    names = tuple(sorted(entry.name for entry in entries))
            finally:
                os.close(descriptor)
        finally:
            deployments.close()
        if len(names) > _MAX_RETAINED_DEPLOYMENT_RECORDS:
            raise StateRecordError("tenant deployment history exceeds its retention bound")
        identities: list[str] = []
        for name in names:
            if not name.endswith(".json"):
                raise StateRecordError("tenant deployment history has an invalid record name")
            deployment_id = validate_uuid7(name.removesuffix(".json"))
            self.read(StateRecordPath.tenant_deployment(canonical_id, deployment_id))
            identities.append(deployment_id)
        return tuple(identities)

    def tenant_archive_ids(self, tenant_id: object) -> tuple[str, ...]:
        """Return the complete bounded archive-record deployment identity set."""

        self._require_active()
        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        archives = self._repository._durable.open_descendant(("tenants", canonical_id, "archives"))
        try:
            archives.remove_abandoned_publication_temporaries(
                expected_owner=self._repository._expected_owner,
                expected_mode=self._repository._expected_record_mode,
                maximum_entries=_MAX_RETAINED_DEPLOYMENT_RECORDS + 1,
            )
            descriptor = archives.duplicate_descriptor()
            try:
                with os.scandir(descriptor) as entries:
                    names = tuple(sorted(entry.name for entry in entries))
            finally:
                os.close(descriptor)
        finally:
            archives.close()
        if len(names) > _MAX_RETAINED_DEPLOYMENT_RECORDS:
            raise StateRecordError("tenant archive history exceeds its retention bound")
        identities: list[str] = []
        for name in names:
            if not name.endswith(".json"):
                raise StateRecordError("tenant archive history has an invalid record name")
            deployment_id = validate_uuid7(name.removesuffix(".json"))
            self.read(StateRecordPath.tenant_archive(canonical_id, deployment_id))
            identities.append(deployment_id)
        return tuple(identities)

    def deployment_for_digest(
        self,
        tenant_id: object,
        expected_digest: dict[str, object],
    ) -> dict[str, object]:
        """Resolve one retained deployment from its authorization-bound digest."""

        self._require_active()
        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        matches: list[dict[str, object]] = []
        for deployment_id in self.tenant_deployment_ids(canonical_id):
            path = StateRecordPath.tenant_deployment(canonical_id, deployment_id)
            record = self.read(path).document
            if deployment_record_digest(record).to_dict() == expected_digest:
                matches.append(record)
        if len(matches) != 1:
            raise StateRecordError("authorization-bound deployment record is not unique")
        return matches[0]

    def validate_export_bundle(
        self,
        job_id: object,
        binding: dict[str, object],
        *,
        source_manifest: dict[str, object],
        source_release_tree_digest: dict[str, object],
    ) -> None:
        """Bind one immutable export to its result and authorized source."""

        self._require_active()
        canonical_id = validate_uuid7(job_id)
        exports = self._repository._durable.open_descendant(("exports",))
        try:
            directory_fd = exports.duplicate_descriptor()
            try:
                before = validate_state_directory(
                    directory_fd,
                    expected_owner=self._repository._expected_owner,
                    expected_mode=self._repository._expected_directory_mode,
                )
                with os.scandir(directory_fd) as entries:
                    names = tuple(sorted(entry.name for entry in entries))
                after = validate_state_directory(
                    directory_fd,
                    expected_owner=self._repository._expected_owner,
                    expected_mode=self._repository._expected_directory_mode,
                )
                if names != (f"{canonical_id}.zip",) or _file_generation(
                    before
                ) != _file_generation(after):
                    raise StateRecordError(
                        "successful export spool is not the exact authorized single slot"
                    )
                file_descriptor = os.open(
                    f"{canonical_id}.zip",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
            finally:
                os.close(directory_fd)
        finally:
            exports.close()
        try:
            size = binding["size"]
            digest_binding = binding["digest"]
            if type(size) is not int or type(digest_binding) is not dict:
                raise StateRecordError("successful export bundle metadata is unsafe")
            try:
                inspection = inspect_portable_bundle_descriptor(
                    file_descriptor,
                    expected_owner=self._repository._expected_owner,
                    expected_mode=self._repository._expected_record_mode,
                )
            except PortableBundleError as error:
                raise StateRecordError("successful export bundle is not canonical") from error
            if (
                inspection.bundle_size != size
                or inspection.bundle_size > MAX_EXPORT_BYTES
                or inspection.bundle_digest.to_dict() != digest_binding
                or inspection.provenance_manifest != source_manifest
                or inspection.provenance_manifest_digest.to_dict()
                != manifest_digest(source_manifest).to_dict()
                or inspection.release_tree_digest.to_dict() != source_release_tree_digest
            ):
                raise StateRecordError(
                    "successful export bundle disagrees with its result or source authority"
                )
        finally:
            os.close(file_descriptor)

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract:
        self._require_exclusive()
        candidate = self._repository._encode_new(path, document)
        return self._create_immutable_bytes(path, candidate)

    def ensure_create_tenant_namespace(
        self,
        tenant_id: object,
        *,
        failure_hook: TenantNamespaceFailureHook | None = None,
    ) -> None:
        """Durably ensure one tenant tree only under its active create intent."""

        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        self._require_create_intent(canonical_id)
        self._admit_create_tenant_identity(canonical_id)
        tenant_root = self._repository._durable.open_descendant(("tenants",))
        try:
            root_fd = tenant_root.duplicate_descriptor()
            try:
                try:
                    os.mkdir(
                        canonical_id,
                        mode=self._repository._expected_directory_mode,
                        dir_fd=root_fd,
                    )
                except FileExistsError:
                    created = False
                else:
                    created = True
                tenant_fd = os.open(canonical_id, _DIRECTORY_OPEN_FLAGS, dir_fd=root_fd)
                try:
                    if created:
                        os.fchmod(tenant_fd, self._repository._expected_directory_mode)
                    validate_state_directory(
                        tenant_fd,
                        expected_owner=self._repository._expected_owner,
                        expected_mode=self._repository._expected_directory_mode,
                    )
                    os.fsync(tenant_fd)
                    _notify_tenant_namespace(
                        failure_hook,
                        TenantNamespaceBoundary.TENANT_DIRECTORY_SYNC,
                    )
                    os.fsync(root_fd)
                    _notify_tenant_namespace(
                        failure_hook,
                        TenantNamespaceBoundary.TENANT_ROOT_SYNC,
                    )
                    for name in _TENANT_CHILD_DIRECTORIES:
                        try:
                            os.mkdir(
                                name,
                                mode=self._repository._expected_directory_mode,
                                dir_fd=tenant_fd,
                            )
                        except FileExistsError:
                            child_created = False
                        else:
                            child_created = True
                        child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=tenant_fd)
                        try:
                            if child_created:
                                os.fchmod(
                                    child_fd,
                                    self._repository._expected_directory_mode,
                                )
                            validate_state_directory(
                                child_fd,
                                expected_owner=self._repository._expected_owner,
                                expected_mode=self._repository._expected_directory_mode,
                            )
                            os.fsync(child_fd)
                        finally:
                            os.close(child_fd)
                    os.fsync(tenant_fd)
                    _notify_tenant_namespace(
                        failure_hook,
                        TenantNamespaceBoundary.CHILD_DIRECTORIES_SYNC,
                    )
                finally:
                    os.close(tenant_fd)
            finally:
                os.close(root_fd)
        finally:
            tenant_root.close()

    def measure_create_tenant_namespace_growth(self, tenant_id: object) -> int:
        """Return the exact missing directory count for create replay admission."""

        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        self._require_create_intent(canonical_id)
        tenant_root = self._repository._durable.open_descendant(("tenants",))
        try:
            root_fd = tenant_root.duplicate_descriptor()
            try:
                try:
                    tenant_fd = os.open(
                        canonical_id,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=root_fd,
                    )
                except FileNotFoundError:
                    return 1 + len(_TENANT_CHILD_DIRECTORIES)
                try:
                    validate_state_directory(
                        tenant_fd,
                        expected_owner=self._repository._expected_owner,
                        expected_mode=self._repository._expected_directory_mode,
                    )
                    missing = 0
                    for name in _TENANT_CHILD_DIRECTORIES:
                        try:
                            child_fd = os.open(
                                name,
                                _DIRECTORY_OPEN_FLAGS,
                                dir_fd=tenant_fd,
                            )
                        except FileNotFoundError:
                            missing += 1
                            continue
                        try:
                            validate_state_directory(
                                child_fd,
                                expected_owner=self._repository._expected_owner,
                                expected_mode=self._repository._expected_directory_mode,
                            )
                        finally:
                            os.close(child_fd)
                    return missing
                finally:
                    os.close(tenant_fd)
            finally:
                os.close(root_fd)
        finally:
            tenant_root.close()

    def remove_empty_create_tenant_namespace(
        self,
        tenant_id: object,
        *,
        failure_hook: TenantNamespaceFailureHook | None = None,
    ) -> None:
        """Durably remove an uncommitted empty tree under its create intent."""

        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        self._require_create_intent(canonical_id)
        tenant_root = self._repository._durable.open_descendant(("tenants",))
        try:
            root_fd = tenant_root.duplicate_descriptor()
            try:
                try:
                    tenant_fd = os.open(
                        canonical_id,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=root_fd,
                    )
                except FileNotFoundError:
                    os.fsync(root_fd)
                    _notify_tenant_namespace(
                        failure_hook,
                        TenantNamespaceBoundary.TENANT_DIRECTORY_REMOVED,
                    )
                    return
                try:
                    validate_state_directory(
                        tenant_fd,
                        expected_owner=self._repository._expected_owner,
                        expected_mode=self._repository._expected_directory_mode,
                    )
                    with os.scandir(tenant_fd) as entries:
                        names_list: list[str] = []
                        for entry in entries:
                            names_list.append(entry.name)
                            if len(names_list) > len(_TENANT_CHILD_DIRECTORIES):
                                raise StateRecordError(
                                    "uncommitted tenant namespace contains state records"
                                )
                    names = tuple(sorted(names_list))
                    if any(name not in _TENANT_CHILD_DIRECTORIES for name in names):
                        raise StateRecordError(
                            "uncommitted tenant namespace contains state records"
                        )
                    for name in names:
                        child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=tenant_fd)
                        try:
                            validate_state_directory(
                                child_fd,
                                expected_owner=self._repository._expected_owner,
                                expected_mode=self._repository._expected_directory_mode,
                            )
                            with os.scandir(child_fd) as entries:
                                if next(entries, None) is not None:
                                    raise StateRecordError(
                                        "uncommitted tenant child directory is not empty"
                                    )
                        finally:
                            os.close(child_fd)
                    for name in names:
                        os.rmdir(name, dir_fd=tenant_fd)
                    os.fsync(tenant_fd)
                    _notify_tenant_namespace(
                        failure_hook,
                        TenantNamespaceBoundary.CHILD_DIRECTORIES_REMOVED,
                    )
                finally:
                    os.close(tenant_fd)
                os.rmdir(canonical_id, dir_fd=root_fd)
                os.fsync(root_fd)
                _notify_tenant_namespace(
                    failure_hook,
                    TenantNamespaceBoundary.TENANT_DIRECTORY_REMOVED,
                )
            finally:
                os.close(root_fd)
        finally:
            tenant_root.close()

    def ensure_create_tenant_state(
        self,
        tenant_id: object,
        manifest: dict[str, object],
        observed_state: dict[str, object],
        *,
        failure_hook: CreateStateFailureHook | None = None,
    ) -> None:
        """Durably complete one absent-to-undeployed state pair under its intent."""

        self._require_exclusive()
        canonical_id = validate_uuid7(tenant_id)
        intent = self._require_create_intent(canonical_id).document
        candidate_manifest = deepcopy(manifest)
        candidate_observed = deepcopy(observed_state)
        recovery = intent["lifecycleRecovery"]
        candidate_manifest_digest = manifest_digest(candidate_manifest).to_dict()
        if type(recovery) is not dict:  # pragma: no cover - schema validation proves this
            raise StateRecordError("create intent lifecycle recovery is malformed")
        spec = candidate_manifest["spec"]
        if type(spec) is not dict:  # pragma: no cover - schema validation proves this
            raise StateRecordError("create candidate manifest spec is malformed")
        if spec["desiredState"] != "undeployed" or "desiredDeployment" in spec:
            raise StateRecordError("create candidate manifest is not undeployed")
        if (
            intent.get("sourceManifest") is not None
            or intent["sourceManifestDigest"] is not None
            or intent["candidateManifestDigest"] != candidate_manifest_digest
            or recovery["sourceObservedState"] is not None
            or recovery["sourceRouteSet"] != "absent"
            or recovery["candidateObservedState"] != candidate_observed
            or recovery["candidateRouteSet"] != "absent"
        ):
            raise StateRecordError("create state disagrees with its active intent")

        self.ensure_create_tenant_namespace(canonical_id)
        self._require_empty_create_namespace(canonical_id)
        self._ensure_immutable_exact(
            StateRecordPath.tenant_desired(canonical_id),
            candidate_manifest,
        )
        _notify_create_state(failure_hook, CreateStateBoundary.DESIRED_STATE_SYNC)
        self._ensure_immutable_exact(
            StateRecordPath.tenant_observed(canonical_id),
            candidate_observed,
        )
        _notify_create_state(failure_hook, CreateStateBoundary.OBSERVED_STATE_SYNC)

    def _require_create_intent(self, tenant_id: str) -> StoredContract:
        self._repository.require_held(
            LockName.PUBLICATION,
            mode=LockMode.EXCLUSIVE,
        )
        inventory = self.measure_intent_records()
        matching: list[StoredContract] = []
        for identity in inventory.records:
            path, record = self.read_intent(identity.intent_id)
            document = record.document
            if (
                path.contract_kind is ContractKind.TRANSACTION_INTENT
                and document["operation"] == "create"
                and document["tenantId"] == tenant_id
            ):
                matching.append(record)
        if len(matching) != 1 or len(inventory.records) != 1:
            raise StateRecordError("create mutation requires one matching active create intent")
        intents = self._repository._durable.open_descendant(("intents",))
        try:
            descriptor = intents.duplicate_descriptor()
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            intents.close()
        return matching[0]

    def _require_empty_create_namespace(self, tenant_id: str) -> None:
        desired_name = StateRecordPath.tenant_desired(tenant_id).components[-1]
        observed_name = StateRecordPath.tenant_observed(tenant_id).components[-1]
        allowed = {*_TENANT_CHILD_DIRECTORIES, desired_name, observed_name}
        tenant_root = self._repository._durable.open_descendant(("tenants",))
        try:
            tenant_directory = tenant_root.open_descendant((tenant_id,))
            try:
                tenant_directory.remove_abandoned_publication_temporaries(
                    expected_owner=self._repository._expected_owner,
                    expected_mode=self._repository._expected_record_mode,
                    maximum_entries=len(allowed) + 1,
                )
                tenant_fd = tenant_directory.duplicate_descriptor()
                try:
                    with os.scandir(tenant_fd) as entries:
                        names_list: list[str] = []
                        for entry in entries:
                            names_list.append(entry.name)
                            if len(names_list) > len(allowed):
                                raise StateRecordError(
                                    "create tenant namespace contains unexpected state"
                                )
                    names = frozenset(names_list)
                    if not set(_TENANT_CHILD_DIRECTORIES).issubset(names) or not names.issubset(
                        allowed
                    ):
                        raise StateRecordError("create tenant namespace contains unexpected state")
                    for name in _TENANT_CHILD_DIRECTORIES:
                        child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=tenant_fd)
                        try:
                            validate_state_directory(
                                child_fd,
                                expected_owner=self._repository._expected_owner,
                                expected_mode=self._repository._expected_directory_mode,
                            )
                            with os.scandir(child_fd) as entries:
                                if next(entries, None) is not None:
                                    raise StateRecordError(
                                        "create tenant namespace contains release history"
                                    )
                        finally:
                            os.close(child_fd)
                finally:
                    os.close(tenant_fd)
            finally:
                tenant_directory.close()
        finally:
            tenant_root.close()

    def _admit_create_tenant_identity(self, tenant_id: str) -> None:
        inventory = self.measure_inventory()
        if tenant_id not in inventory.tenant_ids:
            admit_state_inventory(
                inventory,
                StateInventoryReservation(tenants=1),
            )

    def _ensure_immutable_exact(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract:
        candidate = self._repository._encode_new(path, document)
        try:
            current = self._repository._read_locked(path)
        except FileNotFoundError:
            return self._create_immutable_bytes(path, candidate)
        if current.revision != _revision(path.contract_kind, candidate):
            raise StateConflictError("existing immutable state disagrees with create intent")
        return current

    def _create_immutable_bytes(
        self,
        path: StateRecordPath,
        candidate: bytes,
    ) -> StoredContract:
        self._require_exclusive()
        self._repository._durable.create_immutable(
            path.components,
            candidate,
            mode=self._repository._expected_record_mode,
        )
        return self._repository._read_locked(path)

    def compare_and_swap(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
    ) -> StoredContract:
        self._require_exclusive()
        candidate = self._repository._encode(path, document)
        return self._compare_and_swap_bytes(path, expected_revision, candidate)

    def bind_dispatch_authority(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
        *,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> StoredContract:
        """Commit executor-owned dispatch fields without widening ordinary CAS."""

        self._require_exclusive()
        if path.name is not _StateRecordName.AUTHORIZATION_JOB:
            raise StateRecordError("dispatch authority belongs only to an authorization job")
        candidate = self._repository._encode(path, document)
        current = self._repository._read_locked(path)
        if current.revision != expected_revision:
            raise StateConflictError("authoritative state changed before commit")
        _validate_dispatch_authority_replacement(current.document, document)
        self._admit_atomic_authorization_replacement(
            path,
            candidate,
            capacity_limits=capacity_limits,
        )
        self._repository._durable.replace(
            path.components,
            candidate,
            mode=self._repository._expected_record_mode,
        )
        return self._repository._read_locked(path)

    def _admit_atomic_authorization_replacement(
        self,
        path: StateRecordPath,
        candidate: bytes,
        *,
        capacity_limits: HostCapacityLimits,
    ) -> None:
        """Admit permanent growth and the complete temporary replacement."""

        candidate_allocation = self._repository._durable.allocation_upper_bound(len(candidate))
        current_allocation = self._repository._durable.regular_allocation(
            path.components,
            expected_owner=self._repository._expected_owner,
            expected_mode=self._repository._expected_record_mode,
        )
        self.admit_inventory(
            StateInventoryReservation(
                authorization_allocated_bytes=max(0, candidate_allocation - current_allocation)
            )
        )
        namespace_allocation = self.namespace_allocation_upper_bound(1)
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                allocated_bytes=candidate_allocation + namespace_allocation,
                unique_inodes=1,
            ),
            self.measure_filesystem_capacity(),
            limits=capacity_limits,
        )

    def commit_execution_validation(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        document: dict[str, object],
        *,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> StoredContract:
        """Commit the executor-only terminal validation marker."""

        self._require_exclusive()
        if path.name is not _StateRecordName.AUTHORIZATION_JOB:
            raise StateRecordError("execution validation belongs only to an authorization job")
        candidate = self._repository._encode(path, document)
        current = self._repository._read_locked(path)
        if current.revision != expected_revision:
            raise StateConflictError("authoritative state changed before commit")
        _validate_execution_validation_replacement(current.document, document)
        self._admit_atomic_authorization_replacement(
            path,
            candidate,
            capacity_limits=capacity_limits,
        )
        self._repository._durable.replace(
            path.components,
            candidate,
            mode=self._repository._expected_record_mode,
        )
        return self._repository._read_locked(path)

    def measure_inventory(
        self,
        *,
        limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
    ) -> StateInventory:
        self._require_exclusive()
        return measure_state_inventory(
            self._repository._durable,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            limits=limits,
        )

    def measure_authorization_records(
        self,
        *,
        limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
    ) -> AuthorizationRecordInventory:
        self._require_exclusive()
        return measure_authorization_records(
            self._repository._durable,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            limits=limits,
        )

    def measure_intent_records(
        self,
        *,
        limits: IntentInventoryLimits = DEFAULT_INTENT_INVENTORY_LIMITS,
    ) -> IntentRecordInventory:
        self._require_exclusive()
        return measure_intent_records(
            self._repository._durable,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            limits=limits,
        )

    def select_recovery_batch(
        self,
        job_ids: tuple[str, ...],
        *,
        limit: int,
    ) -> tuple[str, ...]:
        """Durably rotate one bounded batch while retaining tenant-state."""

        self._require_exclusive()
        if type(limit) is not int or limit <= 0:
            raise ValueError("recovery batch limit must be a positive integer")
        canonical = tuple(sorted(validate_uuid7(job_id) for job_id in job_ids))
        if len(canonical) != len(set(canonical)):
            raise StateRecordError("recovery inventory contains duplicate job IDs")
        if not canonical:
            return ()
        try:
            raw_cursor = self._repository._durable.read_regular(
                _RECOVERY_CURSOR_COMPONENTS,
                expected_owner=self._repository._expected_owner,
                expected_mode=self._repository._expected_record_mode,
                maximum_bytes=_RECOVERY_CURSOR_MAXIMUM_BYTES,
            )
        except FileNotFoundError:
            cursor = None
        else:
            try:
                cursor = validate_uuid7(raw_cursor.decode("ascii"))
            except (UnicodeDecodeError, TypeError, ValueError) as error:
                raise StateRecordError("recovery cursor is invalid") from error

        start = 0 if cursor is None else bisect_right(canonical, cursor) % len(canonical)
        count = min(limit, len(canonical))
        batch = tuple(canonical[(start + offset) % len(canonical)] for offset in range(count))
        self._repository._durable.replace(
            _RECOVERY_CURSOR_COMPONENTS,
            batch[-1].encode("ascii"),
            mode=self._repository._expected_record_mode,
        )
        return batch

    def read_intent(self, intent_id: object) -> tuple[StateRecordPath, StoredContract]:
        self._require_exclusive()
        return self._repository._read_intent_locked(intent_id)

    def remove_reconciled_intent(
        self,
        path: StateRecordPath,
        expected: IntentRemovalToken,
        *,
        failure_hook: FailureHook | None = None,
    ) -> None:
        self._require_exclusive()
        if not path.is_intent:
            raise StateRecordError("only an intent can cross the reconciliation removal boundary")
        current = self._repository._read_locked(path)
        if current.revision != expected.revision:
            raise StateConflictError("intent changed after it was reconciled")
        inventory = self.measure_intent_records()
        generation = next(
            (
                record.metadata_generation
                for record in inventory.records
                if record.intent_id == path.record_id
            ),
            None,
        )
        if generation != expected.metadata_generation:
            raise StateConflictError("intent inode changed after it was reconciled")
        self._repository._durable.remove(
            path.components,
            failure_hook=failure_hook,
        )

    def inspect_audit(
        self,
        *,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
    ) -> AuditState:
        self._require_exclusive()
        return inspect_audit_records(
            self._repository._durable,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            limits=limits,
        )

    def inspect_audit_correlation(
        self,
        correlation_id: object,
        *,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
    ) -> AuditCorrelationSnapshot:
        self._require_exclusive()
        return inspect_audit_correlation_records(
            self._repository._durable,
            correlation_id,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            limits=limits,
        )

    def inspect_later_audit_transitions(
        self,
        correlation_id: object,
        *,
        maximum_transitions: int,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
    ) -> tuple[AuditTransition, ...]:
        self._require_exclusive()
        return inspect_later_audit_transition_records(
            self._repository._durable,
            correlation_id,
            maximum_transitions=maximum_transitions,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            limits=limits,
        )

    def append_audit(
        self,
        document: dict[str, object],
        *,
        administrator: bool = False,
        limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
        failure_hook: FailureHook | None = None,
    ) -> AuditAppend:
        self._require_exclusive()
        return append_audit_record(
            self._repository._durable,
            document,
            expected_owner=self._repository._expected_owner,
            expected_directory_mode=self._repository._expected_directory_mode,
            expected_record_mode=self._repository._expected_record_mode,
            administrator=administrator,
            limits=limits,
            failure_hook=failure_hook,
        )

    def admit_inventory(
        self,
        reservation: StateInventoryReservation,
        *,
        limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
    ) -> StateInventoryProjection:
        """Admit growth while retaining this exclusive transaction's lock."""

        inventory = self.measure_inventory(limits=limits)
        return admit_state_inventory(inventory, reservation, limits=limits)

    def allocation_upper_bound(self, byte_count: int) -> int:
        """Return a pre-write allocation ceiling for this state filesystem."""

        self._require_exclusive()
        return self._repository._durable.allocation_upper_bound(byte_count)

    def namespace_allocation_upper_bound(self, entry_count: int) -> int:
        """Return the transient directory-growth ceiling for immutable writes."""

        self._require_exclusive()
        return self._repository._durable.namespace_allocation_upper_bound(entry_count)

    def measure_filesystem_capacity(self) -> FilesystemCapacity:
        """Measure the state filesystem through the verified root descriptor."""

        self._require_exclusive()
        descriptor = self._repository._durable.duplicate_descriptor()
        try:
            return measure_filesystem_capacity_descriptor(descriptor)
        finally:
            os.close(descriptor)

    def _compare_and_swap_bytes(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        candidate: bytes,
    ) -> StoredContract:
        self._require_exclusive()
        if not path.allows_replacement:
            raise StateRecordError("immutable state-record path cannot be replaced")
        current = self._repository._read_locked(path)
        if current.revision != expected_revision:
            raise StateConflictError("authoritative state changed before commit")
        if (
            path.name is _StateRecordName.ARCHIVE_RETIREMENT_INTENT
            and current.document.get("compatibilityVersion") == "static-retirement-v2"
        ):
            candidate_document = decode_contract(
                candidate,
                expected_kind=ContractKind.ARCHIVE_RETIREMENT_INTENT,
                maximum_raw_bytes=MAX_CANONICAL_BYTES,
            )
            _validate_new_archive_retirement_shape(path.name, candidate_document)
        if path.name is _StateRecordName.AUTHORIZATION_JOB:
            candidate_document = decode_contract(
                candidate,
                expected_kind=ContractKind.AUTHORIZATION_JOB,
                maximum_raw_bytes=MAX_CANONICAL_BYTES,
            )
            _validate_authorization_phase_replacement(
                current.document,
                candidate_document,
            )
        self._repository._durable.replace(
            path.components,
            candidate,
            mode=self._repository._expected_record_mode,
        )
        return self._repository._read_locked(path)

    def _close(self) -> None:
        self._active = False

    def _require_active(self) -> None:
        if not self._active:
            raise RuntimeError("state transaction is no longer active")

    def _require_exclusive(self) -> None:
        self._require_active()
        if self._mode is not LockMode.EXCLUSIVE:
            raise RuntimeError("state mutation requires an exclusive tenant-state lock")


def _notify_tenant_namespace(
    hook: TenantNamespaceFailureHook | None,
    boundary: TenantNamespaceBoundary,
) -> None:
    if hook is not None:
        hook(boundary)


def _validate_authorization_phase_replacement(
    current: dict[str, object],
    candidate: dict[str, object],
) -> None:
    before = deepcopy(current)
    after = deepcopy(candidate)
    before.pop("phase")
    after.pop("phase")
    if before != after:
        raise StateRecordError(
            "ordinary authorization replacement changed executor-owned authority"
        )


def _validate_dispatch_authority_replacement(
    current: dict[str, object],
    candidate: dict[str, object],
) -> None:
    if (
        current["phase"] not in {"pending", "claimed", "completed", "failed"}
        or candidate["phase"] != current["phase"]
    ):
        raise StateRecordError("dispatch authority requires an unchanged dispatched job phase")
    if current["executionValidated"] is not False or candidate["executionValidated"] is not False:
        raise StateRecordError("dispatch authority cannot follow execution validation")
    before = deepcopy(current)
    after = deepcopy(candidate)
    for field in _DISPATCH_AUTHORITY_FIELDS:
        previous = before.pop(field, None)
        replacement = after.pop(field, None)
        if previous is not None and previous != replacement:
            raise StateRecordError("bound dispatch authority cannot be replaced")
    if before != after:
        raise StateRecordError("dispatch binding changed non-dispatch authority")


def _validate_execution_validation_replacement(
    current: dict[str, object],
    candidate: dict[str, object],
) -> None:
    if (
        current["executionValidated"] is not False
        or candidate["executionValidated"] is not True
        or current["phase"] not in {"completed", "failed"}
        or candidate["phase"] != current["phase"]
    ):
        raise StateRecordError("execution validation marker transition is invalid")
    before = deepcopy(current)
    after = deepcopy(candidate)
    before.pop("phase")
    after.pop("phase")
    before.pop("executionValidated")
    after.pop("executionValidated")
    if before != after:
        raise StateRecordError("execution validation changed authorization authority")


def _file_generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _notify_create_state(
    hook: CreateStateFailureHook | None,
    boundary: CreateStateBoundary,
) -> None:
    if hook is not None:
        hook(boundary)


def _revision(kind: ContractKind, canonical: bytes) -> StateRevision:
    kind_bytes = kind.value.encode("ascii")
    framed = (
        _STATE_REVISION_FORMAT
        + b"\0"
        + len(kind_bytes).to_bytes(2, "big")
        + kind_bytes
        + len(canonical).to_bytes(4, "big")
        + canonical
    )
    return StateRevision(
        contract_kind=kind,
        byte_count=len(canonical),
        sha256=hashlib.sha256(framed).hexdigest(),
    )
