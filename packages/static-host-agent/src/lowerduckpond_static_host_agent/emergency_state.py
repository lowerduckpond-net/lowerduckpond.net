"""Exact root-administrator state removal after its permanent deletion tombstone."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import suppress
from typing import cast

from lowerduckpond_static_contracts import ContractKind, validate_contract

from lowerduckpond_static_host_agent.delete_state import _names, _sync
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)


class EmergencyStateError(RuntimeError):
    """Emergency state no longer matches its separately recorded administrator authority."""


def verify_emergency_state(
    repository: StateRepository,
    transaction: _StateTransaction,
    intent: dict[str, object],
    *,
    committed: bool,
) -> tuple[StateRecordPath, ...]:
    """Require every remaining record to be an exact member of the recorded snapshot."""
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)
    validate_contract(intent, expected_kind=ContractKind.EMERGENCY_DELETION_INTENT)
    tenant = str(intent["tenantId"])
    root = repository._durable.open_descendant(("tenants",))
    try:
        try:
            directory = root.open_descendant((tenant,))
        except FileNotFoundError:
            if not committed:
                raise EmergencyStateError("emergency source disappeared before tombstone") from None
            _sync(root)
            return ()
        try:
            names = _names(directory, {"desired.json", "observed.json", "deployments", "archives"})
            expected = {
                StateRecordPath.tenant_desired(tenant): intent["sourceManifest"],
                StateRecordPath.tenant_observed(tenant): intent["sourceObservedState"],
            }
            records = cast(list[dict[str, object]], intent["deploymentRecords"])
            archive = intent["archiveRecord"]
            expected.update(
                {StateRecordPath.tenant_deployment(tenant, value["id"]): value for value in records}
            )
            if type(archive) is dict:
                expected[StateRecordPath.tenant_archive(tenant, archive["deploymentId"])] = archive
            present: set[StateRecordPath] = set()
            for name, path in (
                ("desired.json", StateRecordPath.tenant_desired(tenant)),
                ("observed.json", StateRecordPath.tenant_observed(tenant)),
            ):
                if name in names:
                    present.add(path)
            for category in ("deployments", "archives"):
                allowed = {
                    path.components[-1]: path
                    for path in expected
                    if path.components[-2] == category
                }
                if category not in names:
                    continue
                child = directory.open_descendant((category,))
                try:
                    present.update(allowed[name] for name in _names(child, set(allowed)))
                    _sync(child)
                finally:
                    child.close()
            if (not committed and present != set(expected)) or any(
                transaction.read(path).document != expected[path] for path in present
            ):
                raise EmergencyStateError("emergency source records changed")
            _sync(directory)
            return tuple(sorted(present, key=lambda path: path.components))
        finally:
            directory.close()
    finally:
        root.close()


def remove_emergency_state(
    repository: StateRepository,
    transaction: _StateTransaction,
    intent: dict[str, object],
    *,
    hook: Callable[[str], None],
) -> None:
    if (
        transaction.read(StateRecordPath.emergency_deletion_intent(intent["intentId"])).document
        != intent
        or transaction.inspect_audit_correlation(intent["correlationId"]).entry
        != intent["auditEntry"]
    ):
        raise EmergencyStateError("emergency removal has no exact durable tombstone")
    paths = verify_emergency_state(repository, transaction, intent, committed=True)
    for path in paths:
        repository._durable.remove(path.components)
        hook("state-record-removed")
    root = repository._durable.open_descendant(("tenants",))
    try:
        try:
            directory = root.open_descendant((str(intent["tenantId"]),))
        except FileNotFoundError:
            _sync(root)
            return
        try:
            descriptor = directory.duplicate_descriptor()
            try:
                for name in ("archives", "deployments"):
                    with suppress(FileNotFoundError):
                        os.rmdir(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                    hook("state-directory-removed")
            finally:
                os.close(descriptor)
        finally:
            directory.close()
        descriptor = root.duplicate_descriptor()
        try:
            os.rmdir(str(intent["tenantId"]), dir_fd=descriptor)
            os.fsync(descriptor)
            hook("tenant-removed")
        finally:
            os.close(descriptor)
    finally:
        root.close()
