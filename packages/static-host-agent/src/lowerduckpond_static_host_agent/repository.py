"""Strict, lock-protected access to canonical authoritative state records."""

from __future__ import annotations

import hashlib
import os
import re
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
    ContractKind,
    canonical_json_bytes,
    decode_contract,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.audit import (
    DEFAULT_AUDIT_LIMITS,
    AuditAppend,
    AuditLimits,
    AuditState,
)
from lowerduckpond_static_host_agent.audit import (
    append_audit as append_audit_record,
)
from lowerduckpond_static_host_agent.audit import (
    inspect_audit as inspect_audit_records,
)
from lowerduckpond_static_host_agent.capacity import (
    FilesystemCapacity,
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

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
        *,
        blocking: bool = False,
    ) -> StoredContract:
        candidate = self._encode(path, document)
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

        if type(limit) is not int or limit <= 0:
            raise ValueError("recovery batch limit must be a positive integer")
        canonical = tuple(sorted(validate_uuid7(job_id) for job_id in job_ids))
        if len(canonical) != len(set(canonical)):
            raise StateRecordError("recovery inventory contains duplicate job IDs")
        if not canonical:
            return ()
        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking):
            try:
                raw_cursor = self._durable.read_regular(
                    _RECOVERY_CURSOR_COMPONENTS,
                    expected_owner=self._expected_owner,
                    expected_mode=self._expected_record_mode,
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
            self._durable.replace(
                _RECOVERY_CURSOR_COMPONENTS,
                batch[-1].encode("ascii"),
                mode=self._expected_record_mode,
            )
            return batch

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

    def create_immutable(
        self,
        path: StateRecordPath,
        document: dict[str, object],
    ) -> StoredContract:
        self._require_exclusive()
        candidate = self._repository._encode(path, document)
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

    def _require_create_intent(self, tenant_id: str) -> None:
        inventory = self.measure_intent_records()
        matching = 0
        for identity in inventory.records:
            path, record = self.read_intent(identity.intent_id)
            document = record.document
            if (
                path.contract_kind is ContractKind.TRANSACTION_INTENT
                and document["operation"] == "create"
                and document["tenantId"] == tenant_id
            ):
                matching += 1
        if matching != 1 or len(inventory.records) != 1:
            raise StateRecordError("tenant namespace requires one matching active create intent")

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
