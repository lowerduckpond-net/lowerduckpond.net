"""Independent settled-state and running-runtime proofs before service admission."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, platform_state_digest

from lowerduckpond_static_host_agent.backup_capture import _releases, _tenant_row
from lowerduckpond_static_host_agent.backup_descriptor import LAUNCH_DIGEST_FORMAT
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.backup_inventory import BackupState, capture_state_inventory
from lowerduckpond_static_host_agent.caddy_admin import (
    _running_caddy_service_identity,
    verify_running_caddy,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartPhase,
    CaddyStartupStore,
    start_target,
)
from lowerduckpond_static_host_agent.emergency_remote import verify_emergency_terminal
from lowerduckpond_static_host_agent.execution import (
    _capture_replay_authority,
    _require_same_authority,
    _validate_handler_result_state,
    _validate_request_integrity,
    _validate_result_audit,
    _validate_result_binding,
)
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_mapping import _read_runtime_mapping
from lowerduckpond_static_host_agent.host_restore_paths import RestorePaths
from lowerduckpond_static_host_agent.host_restore_startup import require_restore_startup
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)
from lowerduckpond_static_host_agent.route_snapshot import (
    snapshot_tenant_authority,
    snapshot_tenant_routes,
)


def verify_authorization(repository: StateRepository, *, settled: bool) -> None:
    """Read every job/correlation/result join before mutation and after finalizers.

    Before reconciliation, operation-specific intents may own result-first or
    audit-first commits. Their exact candidate proof belongs to their existing
    finalizer. Settled state allows no such incomplete relationship.
    """
    emergency = []
    with repository.publication_transaction() as transaction:
        inventory = transaction.measure_authorization_records()
        for identity in set(inventory.result_ids) - set(inventory.job_ids):
            # The shared results namespace also holds independently authorized
            # administrator deletion receipts, keyed by correlation identity.
            transaction.read(StateRecordPath.emergency_result(identity))
            audit = transaction.inspect_audit_correlation(identity).entry
            if audit is None:
                raise HostRestoreError("restore_emergency_result_missing_audit")
            emergency.append(audit)
        correlations: set[str] = set()
        for identity in inventory.job_ids:
            job = transaction.read(StateRecordPath.authorization_job(identity)).document
            _validate_request_integrity(job)
            request = cast(dict[str, object], job["request"])
            correlation_id = str(request["correlationId"])
            correlation = transaction.read(
                StateRecordPath.authorization_correlation(correlation_id)
            ).document
            _require_same_authority(job, correlation)
            if (
                correlation_id in correlations
                or correlation["jobId"] != identity
                or correlation["requestDigest"] != job["requestDigest"]
            ):
                raise HostRestoreError("restore_job_correlation_mismatch")
            correlations.add(correlation_id)
            if identity not in inventory.result_ids:
                if job["phase"] not in {"pending", "claimed"}:
                    raise HostRestoreError("restore_terminal_job_missing_result")
                if settled and transaction.inspect_audit_correlation(correlation_id).entry:
                    raise HostRestoreError("restore_job_audit_missing_result")
                continue
            result = transaction.read(StateRecordPath.authorization_result(identity)).document
            _validate_result_binding(job, result)
            if settled:
                latest = _validate_result_audit(transaction, job, result)
                if job["phase"] != ("completed" if result["status"] == "succeeded" else "failed"):
                    raise HostRestoreError("restore_job_terminal_phase_incomplete")
                if job["compatibilityVersion"] == "static-job-v2":
                    authority = _capture_replay_authority(
                        transaction,
                        job,
                        result,
                        validation_was_committed=job["executionValidated"] is True,
                        audit_is_latest_for_tenant=latest,
                    )
                    _validate_handler_result_state(
                        transaction,
                        job,
                        result,
                        authority=authority,
                        audit_is_latest_for_tenant=latest,
                    )
        if correlations != set(inventory.correlation_ids):
            raise HostRestoreError("restore_correlation_has_no_job")
    for audit in emergency:
        verify_emergency_terminal(repository, audit)


def _same_state(transaction: _StateTransaction, state: BackupState) -> None:
    """Join the read-only capture with the exclusive ordinary route validator."""
    if (
        transaction.measure_intent_records().records
        or transaction.read(StateRecordPath.platform_namespace()).document != state.namespace
        or transaction.measure_inventory().tenant_ids
        != tuple(tenant.tenant_id for tenant in state.tenants)
    ):
        raise HostRestoreError("restore_state_changed_during_proof")
    try:
        launch = transaction.read(StateRecordPath.platform_launch()).document
    except FileNotFoundError:
        launch = None
    if launch != state.launch:
        raise HostRestoreError("restore_launch_changed_during_proof")
    for tenant in state.tenants:
        identity = tenant.tenant_id
        if (
            transaction.read(StateRecordPath.tenant_desired(identity)).document != tenant.desired
            or transaction.read(StateRecordPath.tenant_observed(identity)).document
            != tenant.observed
            or tuple(
                transaction.read(StateRecordPath.tenant_deployment(identity, value)).document
                for value in transaction.tenant_deployment_ids(identity)
            )
            != tenant.deployments
            or tuple(
                transaction.read(StateRecordPath.tenant_archive(identity, value)).document
                for value in transaction.tenant_archive_ids(identity)
            )
            != tenant.archives
        ):
            raise HostRestoreError("restore_tenant_changed_during_proof")


def verify_settled_state(  # noqa: PLR0913 - complete installed/candidate root policy
    repository: StateRepository,
    root: Path,
    content: Path,
    inputs: RestoreInputs,
    lineage: dict[str, object],
    *,
    owner: int,
    content_group: int,
) -> dict[str, object]:
    verify_authorization(repository, settled=True)
    with (
        repository._locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
        repository._locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED),
    ):
        state = capture_state_inventory(
            root,
            locks=repository._locks,
            expected_owner=owner,
            repository_genesis=lineage,
        )
        if state.intents:
            raise HostRestoreError("restore_local_intents_remain")
        releases = _releases(content, state, repository._locks, owner, content_group)
    with repository.publication_transaction() as transaction:
        _same_state(transaction, state)
        if (
            state.namespace != inputs.document["namespace"]
            or state.launch != inputs.document["launch"]
        ):
            raise HostRestoreError("restore_platform_policy_changed")
        authority = snapshot_tenant_authority(transaction)
        for tenant in authority.tenants:
            manifest = tenant.manifest
            spec = cast(dict[str, object], manifest["spec"])
            if spec["desiredState"] in {"active", "suspended"} and tenant.deployment is not None:
                tenant_id = str(cast(dict[str, object], manifest["metadata"])["id"])
                if tenant.deployment["id"] not in {
                    row["deploymentId"] for row in releases.get(tenant_id, [])
                }:
                    raise HostRestoreError("restore_selected_release_missing")
        document = {
            "namespaceDigest": platform_state_digest(state.namespace).to_dict(),
            "launchDigest": None
            if state.launch is None
            else framed_digest(LAUNCH_DIGEST_FORMAT, canonical_json_bytes(state.launch)),
            "tenants": [
                _tenant_row(tenant, releases.get(tenant.tenant_id, [])) for tenant in state.tenants
            ],
            "audit": {
                "entryCount": state.audit.entry_count,
                "terminalEntryDigest": state.audit.terminal_digest,
            },
        }
    return {
        "stateDigest": framed_digest(
            "lowerduckpond-host-restore-state-v1",
            canonical_json_bytes(document, maximum_bytes=MAX_RESTORE_BYTES),
        ),
        "tenantCount": len(state.tenants),
        "audit": document["audit"],
    }


def verify_installed_runtime(  # noqa: PLR0913 - selection proof and native running boundary
    store: RestoreStore,
    repository: StateRepository,
    paths: RestorePaths,
    inputs: RestoreInputs,
    *,
    caddy_uid: int,
    running: bool = True,
) -> dict[str, object]:
    journal = store.read()
    mapping = _read_runtime_mapping(store, private_preparation=False)
    if journal is None or mapping is None:
        raise HostRestoreError("restore_runtime_mapping_missing")
    with (
        CaddyRuntime.open(
            paths.caddy,
            paths.state / "locks/publication.lock",
            expected_owner=store.owner,
            expected_group=paths.caddy_group,
            validation_uid=caddy_uid,
            validation_gid=paths.caddy_group,
            expected_binary_sha256=str(inputs.caddy["binarySha256"]),
            expected_lock_owner=store.owner,
            expected_lock_group=store.owner,
        ) as runtime,
        CaddyStartupStore.open(paths.caddy / "intents", expected_owner=store.owner) as startup,
        repository.publication_transaction() as transaction,
        runtime.using_held_publication_lock(repository),
    ):
        selected = runtime.open_active_verified()
        try:
            if (
                selected.generation.manifest != mapping.manifest
                or runtime.read_generation_route_snapshot(selected.generation_id)
                != snapshot_tenant_routes(transaction)
            ):
                raise HostRestoreError("restore_running_routes_changed")
            if not running:
                return {"runtimeMapping": mapping.digest}
            before = _running_caddy_service_identity()
            intent = startup.read()
            if intent is not None and (
                intent.phase is not CaddyStartPhase.CANDIDATE_STARTING
                or intent.invocation_id != before[1]
            ):
                raise HostRestoreError("restore_running_startup_invocation_mismatch")
            if journal.phase is not RestorePhase.COMPLETE or intent is not None:
                require_restore_startup(
                    intent,
                    start_target(selected.generation_id, mapping.manifest.to_bytes()),
                    before[1],
                    root=paths.recovery,
                    owner=store.owner,
                )
            verify_running_caddy(selected.generation)
            if _running_caddy_service_identity() != before:
                raise HostRestoreError("restore_running_invocation_changed")
            return {"runtimeMapping": mapping.digest, "invocationId": before[1]}
        finally:
            selected.generation.close()
