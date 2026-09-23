"""Local administrator tombstone commitment after separately proven route removal."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes

from lowerduckpond_static_host_agent.archive_commit import _missing_exact
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    HostCapacityLimits,
    ReleaseCapacityUsage,
    admit_release_capacity,
)
from lowerduckpond_static_host_agent.emergency_state import (
    remove_emergency_state,
    verify_emergency_state,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore
from lowerduckpond_static_host_agent.repository import (
    IntentRemovalToken,
    StateRecordPath,
    StateRepository,
    StoredContract,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_commit import _audit_needs_append
from lowerduckpond_static_host_agent.state_inventory import StateInventoryReservation


class EmergencyDeletionError(RuntimeError):
    """Administrator deletion cannot prove its exact recorded recovery path."""


def verify_emergency_releases(
    store: DeploymentReleaseStore,
    transaction: _StateTransaction,
    intent: dict[str, object],
    *,
    committed: bool,
) -> None:
    tenant = str(intent["tenantId"])
    records = cast(list[dict[str, object]], intent["deploymentRecords"])
    actual = dict(store.published_inventory(publication_lock=transaction).tenant_releases).get(
        tenant, ()
    )
    expected = tuple(str(record["id"]) for record in records)
    if not set(actual).issubset(expected) or (not committed and actual != expected):
        raise EmergencyDeletionError("emergency releases exceed their recorded authority")
    for record in records:
        if (
            record["id"] in actual
            and store.measure(tenant, record["id"], publication_lock=transaction).digest.to_dict()
            != record["releaseTreeDigest"]
        ):
            raise EmergencyDeletionError("emergency release content changed")


def admit_emergency_transition(  # noqa: PLR0913 - complete remaining allocation
    transaction: _StateTransaction,
    intent: dict[str, object],
    limits: HostCapacityLimits,
    *,
    preparing: bool,
    audit_missing: bool,
    result_missing: bool,
) -> None:
    audit = cast(dict[str, object], intent["auditEntry"])
    result = cast(dict[str, object], intent["result"])
    if audit_missing:
        transaction.admit_audit_append(audit, administrator=True)
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
        allocated += transaction.allocation_upper_bound(DEFAULT_AUDIT_LIMITS.maximum_segment_bytes)
    count = len(writes) + int(audit_missing)
    if count:
        admit_release_capacity(
            ReleaseCapacityUsage(()),
            CapacityReservation(
                allocated + transaction.namespace_allocation_upper_bound(count), count
            ),
            transaction.measure_filesystem_capacity(),
            limits=limits,
        )


def finalize_emergency_transition(  # noqa: PLR0913 - explicit permanent evidence and interruption boundaries
    repository: StateRepository,
    transaction: _StateTransaction,
    spool: ExportSpool,
    store: DeploymentReleaseStore,
    prepared: StoredContract,
    *,
    limits: HostCapacityLimits,
    verify_absence: Callable[[], None],
    hook: Callable[[str], None],
) -> dict[str, object]:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE)
    transaction.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)
    document = prepared.document
    tenant, identity = str(document["tenantId"]), str(document["intentId"])
    result = cast(dict[str, object], document["result"])
    audit = cast(dict[str, object], document["auditEntry"])
    retirement = cast(dict[str, object] | None, document["retirementIntent"])
    path = StateRecordPath.emergency_deletion_intent(identity)
    if transaction.read(path).revision != prepared.revision:
        raise EmergencyDeletionError("emergency authority changed")
    inventory = transaction.measure_intent_records()
    expected = {identity} if retirement is None else {identity, str(retirement["intentId"])}
    if not {value.intent_id for value in inventory.records}.issubset(expected):
        raise EmergencyDeletionError("emergency transaction has unrelated journals")
    audit_missing = _audit_needs_append(transaction.inspect_audit(), audit)
    result_missing = _missing_exact(transaction, StateRecordPath.emergency_result(identity), result)
    if not result_missing and audit_missing:
        raise EmergencyDeletionError("emergency result precedes its tombstone")
    verify_emergency_state(repository, transaction, document, committed=not audit_missing)
    verify_emergency_releases(store, transaction, document, committed=not audit_missing)
    admit_emergency_transition(
        transaction,
        document,
        limits,
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
        hook("retirement-sync")
    if audit_missing:
        transaction.append_audit(audit, administrator=True)
    hook("audit-sync")
    for record in cast(list[dict[str, object]], document["deploymentRecords"]):
        store.remove_release(
            tenant,
            record["id"],
            expected_release_tree_digest=cast(dict[str, object], record["releaseTreeDigest"]),
            publication_lock=transaction,
        )
        hook("release-removed")
    remove_emergency_state(repository, transaction, document, hook=hook)
    if tenant in transaction.measure_inventory().tenant_ids or tenant in dict(
        store.published_inventory(publication_lock=transaction).tenant_releases
    ):
        raise EmergencyDeletionError("emergency deletion retained local tenant authority")
    verify_absence()
    if result_missing:
        transaction.create_immutable(StateRecordPath.emergency_result(identity), result)
    hook("result-sync")
    original = next(value for value in inventory.records if value.intent_id == identity)
    transaction.remove_reconciled_intent(
        path, IntentRemovalToken(prepared.revision, original.metadata_generation)
    )
    hook("intent-removed")
    return result
