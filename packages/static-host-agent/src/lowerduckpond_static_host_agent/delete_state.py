"""Descriptor-relative removal of exactly tombstoned ordinary tenant state."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import suppress
from typing import cast

from lowerduckpond_static_contracts import ContractKind, deployment_record_digest, validate_contract

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)


class DeleteStateError(RuntimeError):
    """Deletion cannot prove every remaining namespace entry belongs to its tombstone."""


def validate_delete_namespace(
    repository: StateRepository,
    transaction: _StateTransaction,
    job: StoredContract,
    intent: dict[str, object],
) -> None:
    """Refuse unexpected or altered records before committing a deletion tombstone."""
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)
    directory = repository._durable.open_descendant(("tenants", str(intent["tenantId"])))
    try:
        _remaining_records(transaction, directory, job.document, intent)
    finally:
        directory.close()


def remove_deleted_state(  # noqa: PLR0913 - exact immutable authority and root namespace
    repository: StateRepository,
    transaction: _StateTransaction,
    job: StoredContract,
    intent: dict[str, object],
    audit: dict[str, object],
    *,
    hook: Callable[[str], None] | None = None,
) -> None:
    """Remove records only after the matching permanent deletion event has committed."""
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)
    document = job.document
    request = cast(dict[str, object], document["request"])
    expected = cast(dict[str, object], document["expectedSource"])
    validate_contract(intent, expected_kind=ContractKind.TRANSACTION_INTENT)
    validate_contract(audit, expected_kind=ContractKind.AUDIT_ENTRY)
    if (
        request["operation"] != "delete"
        or intent["operation"] != "delete"
        or intent["tenantId"] != request["tenantId"]
        or intent["correlationId"] != request["correlationId"]
        or intent["sourceManifestDigest"] != expected["manifestDigest"]
        or transaction.read(StateRecordPath.transaction_intent(intent["intentId"])).document
        != intent
        or transaction.inspect_audit_correlation(request["correlationId"]).entry != audit
        or audit["operation"] != "delete"
        or audit["resultStatus"] != "succeeded"
        or audit["operatorPrincipal"] != document["operatorPrincipal"]
        or audit["tenantId"] != request["tenantId"]
        or audit.get("deletionEvidence") != expected["deletionEvidence"]
    ):
        raise DeleteStateError("tenant removal has no exact committed ordinary tombstone")
    tenant = str(request["tenantId"])
    root = repository._durable.open_descendant(("tenants",))
    try:
        try:
            directory = root.open_descendant((tenant,))
        except FileNotFoundError:
            _sync(root)
            return
        try:
            paths = _remaining_records(transaction, directory, document, intent)
            for path in paths:
                repository._durable.remove(path.components)
                if hook is not None:
                    hook("state-record-removed")
            for name in ("archives", "deployments"):
                descriptor = directory.duplicate_descriptor()
                try:
                    with suppress(FileNotFoundError):
                        os.rmdir(name, dir_fd=descriptor)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if hook is not None:
                    hook("state-directory-removed")
        finally:
            directory.close()
        descriptor = root.duplicate_descriptor()
        try:
            os.rmdir(tenant, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if hook is not None:
            hook("tenant-removed")
    finally:
        root.close()


def _remaining_records(
    transaction: _StateTransaction,
    directory: DurableDirectory,
    job: dict[str, object],
    intent: dict[str, object],
) -> tuple[StateRecordPath, ...]:
    request = cast(dict[str, object], job["request"])
    tenant = str(request["tenantId"])
    desired = StateRecordPath.tenant_desired(tenant)
    observed = StateRecordPath.tenant_observed(tenant)
    allowed = {desired.components[-1], observed.components[-1], "archives", "deployments"}
    names = _names(directory, allowed)
    recovery = cast(dict[str, object], intent["lifecycleRecovery"])
    paths: list[StateRecordPath] = []
    for path, expected in (
        (desired, intent["sourceManifest"]),
        (observed, recovery["sourceObservedState"]),
    ):
        if path.components[-1] in names:
            if transaction.read(path).document != expected:
                raise DeleteStateError("tenant state changed after deletion was prepared")
            paths.append(path)
    authority = cast(dict[str, object], job["sourceAuthority"])
    archive = authority["archiveRecord"]
    expected_source = cast(dict[str, object], job["expectedSource"])
    source_spec = cast(dict[str, object], cast(dict[str, object], authority["manifest"])["spec"])
    selected = source_spec.get("desiredDeployment")
    for category, field in (
        ("archives", "dispatchArchiveDeploymentIds"),
        ("deployments", "dispatchDeploymentIds"),
    ):
        ids = job.get(field)
        if type(ids) is not list or any(type(value) is not str for value in ids):
            raise DeleteStateError("deletion record history is unavailable")
        if category not in names:
            continue
        child = directory.open_descendant((category,))
        try:
            present = _names(child, {str(value) + ".json" for value in ids})
            for name in sorted(present):
                identity = name.removesuffix(".json")
                path = (
                    StateRecordPath.tenant_archive(tenant, identity)
                    if category == "archives"
                    else StateRecordPath.tenant_deployment(tenant, identity)
                )
                record = transaction.read(path).document
                if category == "archives" and record != archive:
                    raise DeleteStateError("archive record changed after deletion authority")
                if (
                    category == "deployments"
                    and type(selected) is dict
                    and identity == selected["id"]
                    and deployment_record_digest(record).to_dict()
                    != expected_source["deploymentDigest"]
                ):
                    raise DeleteStateError("selected deployment changed after deletion authority")
                paths.append(path)
            _sync(child)
        finally:
            child.close()
    _sync(directory)
    return tuple(paths)


def _names(directory: DurableDirectory, allowed: set[str]) -> set[str]:
    descriptor = directory.duplicate_descriptor()
    try:
        names: set[str] = set()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if entry.name not in allowed:
                    raise DeleteStateError(
                        "deletion encountered state outside its bounded authority"
                    )
                names.add(entry.name)
        return names
    finally:
        os.close(descriptor)


def _sync(directory: DurableDirectory) -> None:
    descriptor = directory.duplicate_descriptor()
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
