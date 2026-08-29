"""Strict, lock-protected access to canonical authoritative state records."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
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

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

_STATE_REVISION_FORMAT: Final = b"lowerduckpond-state-revision-v1"
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)


class StateRecordError(RuntimeError):
    """An authoritative record did not satisfy its storage contract."""


class StateConflictError(RuntimeError):
    """A compare-and-swap source revision is no longer current."""


class _StateRecordName(StrEnum):
    """The authoritative paths whose layouts are already committed by M3."""

    PLATFORM_NAMESPACE = "platform-namespace"
    PLATFORM_LAUNCH = "platform-launch"
    TENANT_DESIRED = "tenant-desired"
    TENANT_OBSERVED = "tenant-observed"
    TENANT_DEPLOYMENT = "tenant-deployment"


@dataclass(frozen=True, slots=True, init=False)
class StateRecordPath:
    """One typed path in the fixed authoritative-state layout."""

    name: _StateRecordName
    tenant_id: str | None
    deployment_id: str | None

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
    def _new(
        cls,
        name: _StateRecordName,
        *,
        tenant_id: str | None = None,
        deployment_id: str | None = None,
    ) -> Self:
        value = object.__new__(cls)
        object.__setattr__(value, "name", name)
        object.__setattr__(value, "tenant_id", tenant_id)
        object.__setattr__(value, "deployment_id", deployment_id)
        return value

    @property
    def contract_kind(self) -> ContractKind:
        return {
            _StateRecordName.PLATFORM_NAMESPACE: ContractKind.PLATFORM_NAMESPACE,
            _StateRecordName.PLATFORM_LAUNCH: ContractKind.LAUNCH_RECORD,
            _StateRecordName.TENANT_DESIRED: ContractKind.SITE,
            _StateRecordName.TENANT_OBSERVED: ContractKind.TENANT_OBSERVED_STATE,
            _StateRecordName.TENANT_DEPLOYMENT: ContractKind.DEPLOYMENT_RECORD,
        }[self.name]

    @property
    def components(self) -> tuple[str, ...]:
        if self.name is _StateRecordName.PLATFORM_NAMESPACE:
            return ("platform", "namespace.json")
        if self.name is _StateRecordName.PLATFORM_LAUNCH:
            return ("platform", "launch.json")
        if self.tenant_id is None:
            raise RuntimeError("tenant record path has no tenant identity")
        if self.name is _StateRecordName.TENANT_DESIRED:
            return ("tenants", self.tenant_id, "desired.json")
        if self.name is _StateRecordName.TENANT_OBSERVED:
            return ("tenants", self.tenant_id, "observed.json")
        if self.deployment_id is None:
            raise RuntimeError("deployment record path has no deployment identity")
        return (
            "tenants",
            self.tenant_id,
            "deployments",
            f"{self.deployment_id}.json",
        )

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


@dataclass(frozen=True, slots=True)
class StateRevision:
    """An internal CAS token over one exact canonical record generation."""

    contract_kind: ContractKind
    byte_count: int
    sha256: str

    def __post_init__(self) -> None:
        if self.byte_count < 0 or _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("state revision is not a canonical SHA-256 token")


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
        candidate = self._encode(path, document)
        with self.transaction(mode=LockMode.EXCLUSIVE, blocking=blocking) as transaction:
            return transaction._compare_and_swap_bytes(path, expected_revision, candidate)

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

    def _compare_and_swap_bytes(
        self,
        path: StateRecordPath,
        expected_revision: StateRevision,
        candidate: bytes,
    ) -> StoredContract:
        self._require_exclusive()
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
