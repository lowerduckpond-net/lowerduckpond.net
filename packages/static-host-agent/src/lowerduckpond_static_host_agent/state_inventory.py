"""Bounded durable-state inventory and pre-mutation admission."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts import MAX_CANONICAL_BYTES, ContractError, validate_uuid7

from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    validate_state_directory,
)

MEBIBYTE: Final = 1024 * 1024
_INITIAL_MAXIMUM_TENANTS: Final = 25
_INITIAL_MAXIMUM_AUTHORIZATION_RECORDS: Final = 10_000
_INITIAL_MAXIMUM_AUTHORIZATION_ALLOCATED_BYTES: Final = 64 * MEBIBYTE
_AUTHORIZATION_DIRECTORIES: Final = ("correlations", "jobs", "results")
_DIRECTORY_SCAN_MARGIN: Final = 1
_BLOCK_BYTES: Final = 512


class StateInventoryError(RuntimeError):
    """The durable-state tree could not produce one trusted bounded inventory."""


class StateAdmissionRejectedError(StateInventoryError):
    """A proposed durable-state allocation would cross an M3 ceiling."""


@dataclass(frozen=True, slots=True)
class StateInventoryLimits:
    """Initial M3 tenant and authorization-store ceilings from ADR 0017."""

    maximum_tenants: int = _INITIAL_MAXIMUM_TENANTS
    maximum_authorization_records: int = _INITIAL_MAXIMUM_AUTHORIZATION_RECORDS
    maximum_authorization_allocated_bytes: int = _INITIAL_MAXIMUM_AUTHORIZATION_ALLOCATED_BYTES

    def __post_init__(self) -> None:
        values = (
            self.maximum_tenants,
            self.maximum_authorization_records,
            self.maximum_authorization_allocated_bytes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("state-inventory limits must be nonnegative integers")
        if (
            self.maximum_tenants > _INITIAL_MAXIMUM_TENANTS
            or self.maximum_authorization_records > _INITIAL_MAXIMUM_AUTHORIZATION_RECORDS
            or self.maximum_authorization_allocated_bytes
            > _INITIAL_MAXIMUM_AUTHORIZATION_ALLOCATED_BYTES
        ):
            raise ValueError("state-inventory limits cannot weaken the committed M3 boundaries")


@dataclass(frozen=True, slots=True)
class StateInventory:
    """One stable inventory of tenant identities and authorization records."""

    tenant_ids: tuple[str, ...]
    authorization_jobs: int
    authorization_results: int
    authorization_correlations: int
    authorization_allocated_bytes: int

    def __post_init__(self) -> None:
        if tuple(sorted(set(self.tenant_ids))) != self.tenant_ids:
            raise StateInventoryError("tenant inventory must contain sorted unique identities")
        try:
            if any(validate_uuid7(value) != value for value in self.tenant_ids):
                raise StateInventoryError("tenant inventory contains a noncanonical identity")
        except ContractError as error:
            raise StateInventoryError("tenant inventory contains an invalid identity") from error
        values = (
            self.authorization_jobs,
            self.authorization_results,
            self.authorization_correlations,
            self.authorization_allocated_bytes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise StateInventoryError("state inventory counts must be nonnegative integers")

    @property
    def tenant_count(self) -> int:
        return len(self.tenant_ids)

    @property
    def authorization_record_count(self) -> int:
        return (
            self.authorization_jobs + self.authorization_results + self.authorization_correlations
        )


@dataclass(frozen=True, slots=True)
class StateInventoryReservation:
    """Worst-case durable-state growth reserved before mutation."""

    tenants: int = 0
    authorization_records: int = 0
    authorization_allocated_bytes: int = 0

    def __post_init__(self) -> None:
        values = (
            self.tenants,
            self.authorization_records,
            self.authorization_allocated_bytes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("state-inventory reservation must be nonnegative")


@dataclass(frozen=True, slots=True)
class StateInventoryProjection:
    """The projected usage accepted by the durable-state boundary."""

    tenants: int
    authorization_records: int
    authorization_allocated_bytes: int


@dataclass(frozen=True, slots=True)
class _DirectoryEntry:
    name: str
    metadata: os.stat_result


DEFAULT_STATE_INVENTORY_LIMITS: Final = StateInventoryLimits()


def admit_state_inventory(
    inventory: StateInventory,
    reservation: StateInventoryReservation,
    *,
    limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
) -> StateInventoryProjection:
    """Reject a reservation before any tenant or authorization-state mutation."""

    projected_tenants = inventory.tenant_count + reservation.tenants
    projected_records = inventory.authorization_record_count + reservation.authorization_records
    projected_bytes = (
        inventory.authorization_allocated_bytes + reservation.authorization_allocated_bytes
    )
    if projected_tenants > limits.maximum_tenants:
        raise StateAdmissionRejectedError("tenant reservation would cross the host ceiling")
    if projected_records > limits.maximum_authorization_records:
        raise StateAdmissionRejectedError(
            "authorization reservation would cross the record ceiling"
        )
    if projected_bytes > limits.maximum_authorization_allocated_bytes:
        raise StateAdmissionRejectedError(
            "authorization reservation would cross the allocated-byte ceiling"
        )
    return StateInventoryProjection(
        tenants=projected_tenants,
        authorization_records=projected_records,
        authorization_allocated_bytes=projected_bytes,
    )


def measure_state_inventory(
    root: DurableDirectory,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: StateInventoryLimits = DEFAULT_STATE_INVENTORY_LIMITS,
) -> StateInventory:
    """Measure fixed state directories through the already verified root descriptor."""

    tenant_ids = _measure_tenants(
        root,
        expected_owner=expected_owner,
        expected_directory_mode=expected_directory_mode,
        maximum_tenants=limits.maximum_tenants,
    )
    authorization_root = root.open_descendant(("authorization",))
    try:
        root_entries = _stable_directory_entries(
            authorization_root,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            maximum_entries=len(_AUTHORIZATION_DIRECTORIES),
        )
        if tuple(entry.name for entry in root_entries) != _AUTHORIZATION_DIRECTORIES:
            raise StateInventoryError("authorization layout contains an unexpected entry")

        counts: dict[str, int] = {}
        allocated_bytes = 0
        remaining_records = limits.maximum_authorization_records
        for directory_name in _AUTHORIZATION_DIRECTORIES:
            directory = authorization_root.open_descendant((directory_name,))
            try:
                entries = _stable_directory_entries(
                    directory,
                    expected_owner=expected_owner,
                    expected_directory_mode=expected_directory_mode,
                    maximum_entries=remaining_records,
                )
                for entry in entries:
                    _validate_authorization_record(
                        entry,
                        expected_owner=expected_owner,
                        expected_record_mode=expected_record_mode,
                    )
                    allocated_bytes += entry.metadata.st_blocks * _BLOCK_BYTES
                counts[directory_name] = len(entries)
                remaining_records -= len(entries)
            finally:
                directory.close()
    finally:
        authorization_root.close()

    inventory = StateInventory(
        tenant_ids=tenant_ids,
        authorization_jobs=counts["jobs"],
        authorization_results=counts["results"],
        authorization_correlations=counts["correlations"],
        authorization_allocated_bytes=allocated_bytes,
    )
    admit_state_inventory(inventory, StateInventoryReservation(), limits=limits)
    return inventory


def _measure_tenants(
    root: DurableDirectory,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    maximum_tenants: int,
) -> tuple[str, ...]:
    tenant_root = root.open_descendant(("tenants",))
    try:
        entries = _stable_directory_entries(
            tenant_root,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            maximum_entries=maximum_tenants,
        )
    finally:
        tenant_root.close()
    tenant_ids: list[str] = []
    for entry in entries:
        if not stat.S_ISDIR(entry.metadata.st_mode):
            raise StateInventoryError("tenant inventory entry is not a directory")
        _validate_directory_metadata(
            entry.metadata,
            expected_owner=expected_owner,
            expected_mode=expected_directory_mode,
        )
        tenant_ids.append(_identifier_from_name(entry.name, suffix=""))
    return tuple(tenant_ids)


def _validate_authorization_record(
    entry: _DirectoryEntry,
    *,
    expected_owner: int,
    expected_record_mode: int,
) -> None:
    _identifier_from_name(entry.name, suffix=".json")
    metadata = entry.metadata
    if not stat.S_ISREG(metadata.st_mode):
        raise StateInventoryError("authorization record is not a regular file")
    if metadata.st_size > MAX_CANONICAL_BYTES:
        raise StateInventoryError("authorization record exceeds its canonical byte ceiling")
    if metadata.st_blocks < 0:
        raise StateInventoryError("authorization record has invalid block accounting")
    _validate_regular_metadata(
        metadata,
        expected_owner=expected_owner,
        expected_mode=expected_record_mode,
    )


def _identifier_from_name(name: str, *, suffix: str) -> str:
    if suffix and not name.endswith(suffix):
        raise StateInventoryError("state record name has an unexpected suffix")
    identifier = name[: -len(suffix)] if suffix else name
    try:
        canonical = validate_uuid7(identifier)
    except ContractError as error:
        raise StateInventoryError("state entry name is not a canonical UUIDv7") from error
    if canonical != identifier:
        raise StateInventoryError("state entry name is not canonical")
    return canonical


def _stable_directory_entries(
    directory: DurableDirectory,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    maximum_entries: int,
) -> tuple[_DirectoryEntry, ...]:
    descriptor = directory.duplicate_descriptor()
    try:
        before = validate_state_directory(
            descriptor,
            expected_owner=expected_owner,
            expected_mode=expected_directory_mode,
        )
        names = _bounded_names(descriptor, maximum_entries=maximum_entries)
        entries = tuple(
            _DirectoryEntry(
                name=name,
                metadata=os.stat(name, dir_fd=descriptor, follow_symlinks=False),
            )
            for name in names
        )
        after_names = _bounded_names(descriptor, maximum_entries=maximum_entries)
        after = validate_state_directory(
            descriptor,
            expected_owner=expected_owner,
            expected_mode=expected_directory_mode,
        )
        if names != after_names or _metadata_generation(before) != _metadata_generation(after):
            raise StateInventoryError("state directory changed while it was inventoried")
        for entry in entries:
            current = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
            if _metadata_generation(entry.metadata) != _metadata_generation(current):
                raise StateInventoryError("state entry changed while it was inventoried")
        return entries
    finally:
        os.close(descriptor)


def _bounded_names(descriptor: int, *, maximum_entries: int) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(descriptor) as iterator:
        for entry in iterator:
            names.append(entry.name)
            if len(names) > maximum_entries:
                raise StateAdmissionRejectedError("state directory exceeds its entry ceiling")
    return tuple(sorted(names))


def _validate_directory_metadata(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
) -> None:
    if metadata.st_uid != expected_owner or stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise StateInventoryError("state directory has unexpected ownership or mode")


def _validate_regular_metadata(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
) -> None:
    if (
        metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_nlink != 1
    ):
        raise StateInventoryError("authorization record has unexpected ownership or mode")


def _metadata_generation(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
