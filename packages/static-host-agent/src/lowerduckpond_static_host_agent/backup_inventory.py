"""Classify bounded static authority without reconciling it during capture."""

from __future__ import annotations

import os
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractKind,
    canonical_json_bytes,
    decode_contract,
    platform_state_digest,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.archive_quarantine import decode_archive_quarantine
from lowerduckpond_static_host_agent.audit import AuditState, inspect_audit_readonly
from lowerduckpond_static_host_agent.backup_descriptor import (
    MAX_BACKUP_DEPLOYMENTS,
    MAX_BACKUP_INTENTS,
    MAX_BACKUP_TENANTS,
)
from lowerduckpond_static_host_agent.backup_identity import (
    GENESIS_PATH,
    LINEAGE_PATH,
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    decode_lineage,
)
from lowerduckpond_static_host_agent.backup_lineage import require_initial_lineage_prefix
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.repository import StateRecordPath
from lowerduckpond_static_host_agent.state_inventory import DEFAULT_STATE_INVENTORY_LIMITS

_ROOT_NAMES: Final = frozenset(
    {
        "platform",
        "tenants",
        "authorization",
        "audit",
        "intents",
        "locks",
        "intake",
        "exports",
    }
)
_PLATFORM_NAMES: Final = frozenset(
    {
        "namespace.json",
        "launch.json",
        "audit-lineage.json",
        "archive-quarantine.json",
    }
)
_TEMPORARY_MARGIN: Final = 64
_MAX_QUARANTINE_BYTES: Final = 32 * 1024 * 1024
_BLOCK_BYTES: Final = 512


@dataclass(frozen=True)
class BackupTenant:
    tenant_id: str
    desired: dict[str, object] | None
    observed: dict[str, object] | None
    deployments: tuple[dict[str, object], ...]
    archives: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class BackupState:
    namespace: dict[str, object]
    launch: dict[str, object] | None
    lineage: dict[str, object]
    audit: AuditState
    tenants: tuple[BackupTenant, ...]
    intents: tuple[dict[str, object], ...]


def _names(
    root: DurableDirectory,
    path: tuple[str, ...],
    owner: int,
    maximum: int,
) -> tuple[str, ...]:
    with root.open_descendant(path) if path else nullcontext(root) as directory:
        temporaries = directory.publication_temporaries(
            expected_owner=owner,
            expected_mode=0o600,
            maximum_entries=maximum + _TEMPORARY_MARGIN,
        )
        descriptor = directory.duplicate_descriptor()
        try:
            names = []
            count = 0
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    count += 1
                    if count > maximum + _TEMPORARY_MARGIN:
                        raise BackupIdentityError("backup state directory exceeds its bound")
                    if entry.name not in temporaries:
                        names.append(entry.name)
                    if len(names) > maximum:
                        raise BackupIdentityError("backup state inventory exceeds its bound")
            return tuple(sorted(names))
        finally:
            os.close(descriptor)


def _read(root: DurableDirectory, path: tuple[str, ...], owner: int, maximum: int) -> bytes:
    return root.read_regular(
        path,
        expected_owner=owner,
        expected_mode=0o600,
        maximum_bytes=maximum,
    )


def _record(root: DurableDirectory, path: StateRecordPath, owner: int) -> dict[str, object]:
    raw = _read(root, path.components, owner, MAX_CANONICAL_BYTES)
    document = decode_contract(raw, expected_kind=path.contract_kind)
    if canonical_json_bytes(document) != raw:
        raise BackupIdentityError("backup state contract is not canonical")
    path.validate_binding(document)
    return document


def _identifier(name: str) -> str:
    if not name.endswith(".json"):
        raise BackupIdentityError("backup state record has an unclassified name")
    return validate_uuid7(name.removesuffix(".json"))


def _intents(root: DurableDirectory, owner: int) -> tuple[dict[str, object], ...]:
    paths = {
        ContractKind.TRANSACTION_INTENT.value: StateRecordPath.transaction_intent,
        ContractKind.EMERGENCY_DELETION_INTENT.value: StateRecordPath.emergency_deletion_intent,
        ContractKind.ARCHIVE_CONSTRUCTION_INTENT.value: StateRecordPath.archive_construction_intent,
        ContractKind.ARCHIVE_RETIREMENT_INTENT.value: StateRecordPath.archive_retirement_intent,
    }
    records = []
    for name in _names(root, ("intents",), owner, MAX_BACKUP_INTENTS):
        identifier = _identifier(name)
        raw = _read(root, ("intents", name), owner, MAX_CANONICAL_BYTES)
        document = decode_contract(raw)
        kind = document["kind"]
        if type(kind) is not str or kind not in paths:
            raise BackupIdentityError("backup intent kind is unclassified")
        path = paths[kind](identifier)
        path.validate_binding(document)
        if canonical_json_bytes(document) != raw:
            raise BackupIdentityError("backup intent is not canonical")
        records.append(document)
    return tuple(records)


def _authorization(root: DurableDirectory, owner: int) -> None:
    expected = ("correlations", "jobs", "results")
    if _names(root, ("authorization",), owner, len(expected)) != expected:
        raise BackupIdentityError("backup authorization namespace is incomplete")
    count = 0
    allocated = 0
    limit = DEFAULT_STATE_INVENTORY_LIMITS
    for directory_name in expected:
        parent = ("authorization", directory_name)
        names = _names(root, parent, owner, limit.maximum_authorization_records - count)
        count += len(names)
        for name in names:
            identifier = _identifier(name)
            if directory_name == "jobs":
                path = StateRecordPath.authorization_job(identifier)
            elif directory_name == "correlations":
                path = StateRecordPath.authorization_correlation(identifier)
            else:
                raw = _read(root, (*parent, name), owner, MAX_CANONICAL_BYTES)
                document = decode_contract(raw, expected_kind=ContractKind.OPERATION_RESULT)
                provenance = document["provenance"]
                assert type(provenance) is dict  # noqa: S101 - contract proves shape
                path = (
                    StateRecordPath.emergency_result(identifier)
                    if provenance["kind"] == "emergency-administrator"
                    else StateRecordPath.authorization_result(identifier)
                )
            _record(root, path, owner)
            with root.open_descendant(parent) as directory:
                descriptor = directory.duplicate_descriptor()
                try:
                    allocated += (
                        os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_blocks
                        * _BLOCK_BYTES
                    )
                finally:
                    os.close(descriptor)
            if allocated > limit.maximum_authorization_allocated_bytes:
                raise BackupIdentityError("backup authorization allocation exceeds its bound")


def _tenant(
    root: DurableDirectory,
    owner: int,
    identifier: str,
    *,
    interrupted: bool,
) -> BackupTenant:
    parent = ("tenants", identifier)
    names = _names(root, parent, owner, 4)
    allowed = {"desired.json", "observed.json", "deployments", "archives"}
    if not set(names) <= allowed or (not interrupted and set(names) != allowed):
        raise BackupIdentityError("backup tenant namespace lacks classified authority")
    desired = (
        _record(root, StateRecordPath.tenant_desired(identifier), owner)
        if "desired.json" in names
        else None
    )
    observed = (
        _record(root, StateRecordPath.tenant_observed(identifier), owner)
        if "observed.json" in names
        else None
    )
    inventories: dict[str, tuple[dict[str, object], ...]] = {}
    for name in ("deployments", "archives"):
        records = []
        if name in names:
            for filename in _names(root, (*parent, name), owner, MAX_BACKUP_DEPLOYMENTS):
                deployment = _identifier(filename)
                path = (
                    StateRecordPath.tenant_deployment(identifier, deployment)
                    if name == "deployments"
                    else StateRecordPath.tenant_archive(identifier, deployment)
                )
                records.append(_record(root, path, owner))
        inventories[name] = tuple(records)
    return BackupTenant(
        identifier, desired, observed, inventories["deployments"], inventories["archives"]
    )


def _locks(root: DurableDirectory, owner: int, lineage: dict[str, object]) -> None:
    required = {lock.filename for lock in LockName} | {GENESIS_PATH[-1]}
    allowed = required | {"authorization-recovery.cursor"}
    names = set(_names(root, ("locks",), owner, len(allowed)))
    if not required <= names <= allowed:
        raise BackupIdentityError("backup lock namespace is unclassified")
    for lock in LockName:
        _read(root, ("locks", lock.filename), owner, 0)
    if decode_lineage(_read(root, GENESIS_PATH, owner, MAX_IDENTITY_BYTES)) != lineage:
        raise BackupIdentityError("backup lineage genesis disagrees with primary")
    if "authorization-recovery.cursor" in names:
        validate_uuid7(
            _read(root, ("locks", "authorization-recovery.cursor"), owner, 36).decode("ascii")
        )


def capture_state_inventory(
    state_root: Path,
    *,
    locks: LockManager,
    expected_owner: int,
    repository_genesis: dict[str, object],
) -> BackupState:
    """Repository proof is obtained before these shared leases; never repair here."""

    locks.require_held(LockName.PUBLICATION, mode=LockMode.SHARED)
    locks.require_held(LockName.TENANT_STATE, mode=LockMode.SHARED)
    with DurableDirectory.open(
        state_root,
        expected_owner=expected_owner,
        expected_directory_mode=0o700,
    ) as root:
        if set(_names(root, (), expected_owner, len(_ROOT_NAMES))) != _ROOT_NAMES:
            raise BackupIdentityError("backup state root has unclassified or missing stores")
        platform = set(_names(root, ("platform",), expected_owner, len(_PLATFORM_NAMES)))
        if not {"namespace.json", "audit-lineage.json"} <= platform <= _PLATFORM_NAMES:
            raise BackupIdentityError("backup platform authority is unclassified")
        namespace = _record(root, StateRecordPath.platform_namespace(), expected_owner)
        lineage = decode_lineage(_read(root, LINEAGE_PATH, expected_owner, MAX_IDENTITY_BYTES))
        if (
            lineage != repository_genesis
            or lineage["namespaceDigest"] != platform_state_digest(namespace).to_dict()
        ):
            raise BackupIdentityError("backup lineage differs from verified repository proof")
        _locks(root, expected_owner, lineage)
        if "archive-quarantine.json" in platform:
            decode_archive_quarantine(
                _read(
                    root,
                    ("platform", "archive-quarantine.json"),
                    expected_owner,
                    _MAX_QUARANTINE_BYTES,
                )
            )
        launch = (
            _record(root, StateRecordPath.platform_launch(), expected_owner)
            if "launch.json" in platform
            else None
        )
        intents = _intents(root, expected_owner)
        _authorization(root, expected_owner)
        interrupted = {record["tenantId"] for record in intents}
        tenants = tuple(
            _tenant(root, expected_owner, validate_uuid7(name), interrupted=name in interrupted)
            for name in _names(root, ("tenants",), expected_owner, MAX_BACKUP_TENANTS)
        )
        audit = inspect_audit_readonly(
            root,
            expected_owner=expected_owner,
            expected_directory_mode=0o700,
            expected_record_mode=0o600,
        )
        require_initial_lineage_prefix(root, expected_owner, lineage, audit)
        return BackupState(namespace, launch, lineage, audit, tenants, intents)
