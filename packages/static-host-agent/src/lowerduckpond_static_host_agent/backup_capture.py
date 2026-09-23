"""Assemble recovery evidence while both static capture leases remain held."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import (
    archive_record_digest,
    canonical_json_bytes,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.backup_caddy import capture_caddy_evidence
from lowerduckpond_static_host_agent.backup_descriptor import (
    ARTIFACT_DIGEST_FORMAT,
    BACKUP_SCHEMA,
    INTENT_DIGEST_FORMAT,
    LAUNCH_DIGEST_FORMAT,
    OBSERVED_DIGEST_FORMAT,
    encode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.backup_inventory import (
    BackupState,
    BackupTenant,
    capture_state_inventory,
)
from lowerduckpond_static_host_agent.backup_sources import (
    measure_backup_sources,
    source_policy_digest,
)
from lowerduckpond_static_host_agent.capacity import DEFAULT_HOST_CAPACITY_LIMITS
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.release_store import DeploymentReleaseStore


def _candidates(state: BackupState) -> dict[str, str]:
    candidates = {}
    for intent in state.intents:
        if intent["kind"] != "TransactionIntent" or intent["operation"] not in {
            "deploy",
            "import",
            "restore",
        }:
            continue
        candidate = intent["candidateManifest"]
        assert type(candidate) is dict  # noqa: S101 - validated contract
        spec = candidate["spec"]
        assert type(spec) is dict  # noqa: S101 - validated contract
        deployment = spec.get("desiredDeployment")
        if type(deployment) is not dict:
            raise BackupIdentityError("backup transition candidate has no deployment")
        tenant_id = validate_uuid7(intent["tenantId"])
        if tenant_id in candidates:
            raise BackupIdentityError("backup has ambiguous deployment candidates")
        candidates[tenant_id] = validate_uuid7(deployment["id"])
    return candidates


def _release_authority(state: BackupState) -> dict[tuple[str, str], object]:
    records = {
        (tenant.tenant_id, cast(str, record["id"])): record["releaseTreeDigest"]
        for tenant in state.tenants
        for record in tenant.deployments
    }
    for intent in state.intents:
        if intent["kind"] != "EmergencyDeletionIntent":
            continue
        for record in cast(list[dict[str, object]], intent["deploymentRecords"]):
            key = (validate_uuid7(intent["tenantId"]), validate_uuid7(record["id"]))
            digest = record["releaseTreeDigest"]
            if key in records and records[key] != digest:
                raise BackupIdentityError("backup release authority conflicts with deletion intent")
            records[key] = digest
    return records


def _releases(
    content: Path,
    state: BackupState,
    locks: LockManager,
    owner: int,
    content_group: int,
) -> dict[str, list[dict[str, object]]]:
    root = content / "sites"
    candidates = _candidates(state)
    authority = _release_authority(state)
    tenants = {tenant.tenant_id for tenant in state.tenants} | {
        validate_uuid7(intent["tenantId"]) for intent in state.intents
    }
    result: dict[str, list[dict[str, object]]] = {}
    with DeploymentReleaseStore(
        root,
        root / ".staging",
        expected_owner=owner,
        expected_release_group=content_group,
        expected_staging_group=owner,
    ) as store:
        inventory = store.capture_published_inventory(
            publication_lock=locks,
            transition_candidates=candidates,
        )
        allocated = inventory.namespace_usage.allocated_bytes
        inodes = inventory.namespace_usage.unique_inodes
        for tenant_id, deployment_ids in inventory.tenant_releases:
            if tenant_id not in tenants:
                raise BackupIdentityError("backup contains an unbound release tenant")
            rows: list[dict[str, object]] = []
            for deployment_id in deployment_ids:
                key = tenant_id, deployment_id
                expected = authority.get(key)
                if expected is None and candidates.get(tenant_id) != deployment_id:
                    raise BackupIdentityError("backup release lacks record or candidate authority")
                measurement = store.measure(tenant_id, deployment_id, publication_lock=locks)
                digest = measurement.digest.to_dict()
                if expected is not None and expected != digest:
                    raise BackupIdentityError("backup release digest disagrees with its record")
                rows.append({"deploymentId": deployment_id, "treeDigest": digest})
                allocated += measurement.allocated_bytes
                inodes += measurement.unique_inode_count
                if (
                    allocated > DEFAULT_HOST_CAPACITY_LIMITS.maximum_allocated_bytes
                    or inodes > DEFAULT_HOST_CAPACITY_LIMITS.maximum_unique_inodes
                ):
                    raise BackupIdentityError("backup releases exceed host capacity policy")
            result[tenant_id] = rows
    return result


def _tenant_row(tenant: BackupTenant, releases: list[dict[str, object]]) -> dict[str, object]:
    return {
        "tenantId": tenant.tenant_id,
        "desiredDigest": None
        if tenant.desired is None
        else manifest_digest(tenant.desired).to_dict(),
        "observedDigest": None
        if tenant.observed is None
        else framed_digest(
            OBSERVED_DIGEST_FORMAT,
            canonical_json_bytes(tenant.observed),
        ),
        "deployments": [
            {
                "deploymentId": record["id"],
                "recordDigest": deployment_record_digest(record).to_dict(),
            }
            for record in tenant.deployments
        ],
        "archives": [
            {
                "deploymentId": record["deploymentId"],
                "recordDigest": archive_record_digest(record).to_dict(),
            }
            for record in tenant.archives
        ],
        "releases": releases,
    }


def _require_source_layout(roots: Mapping[str, Path], owner: int) -> None:
    # Imported lazily: restore runtime proofs reuse the backup descriptor types.
    from lowerduckpond_static_host_agent.host_restore_history import (  # noqa: PLC0415
        require_backup_provenance,
    )
    from lowerduckpond_static_host_agent.host_restore_journal import (  # noqa: PLC0415
        HostRestoreError,
    )

    try:
        require_backup_provenance(roots["recovery"], owner=owner)
    except HostRestoreError as error:
        raise BackupIdentityError("backup recovery provenance is invalid") from error
    with DurableDirectory.open(
        roots["content"],
        expected_owner=owner,
        expected_directory_mode=0o711,
    ) as content:
        descriptor = content.duplicate_descriptor()
        try:
            names = set()
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if entry.name not in {"fixture", "sites", "lost+found"}:
                        raise BackupIdentityError("backup content source is unclassified")
                    names.add(entry.name)
            if names - {"lost+found"} != {"fixture", "sites"}:
                raise BackupIdentityError("backup content source is incomplete")
        finally:
            os.close(descriptor)


def build_capture_descriptor(  # noqa: PLR0913 - explicit input and privilege bindings
    roots: Mapping[str, Path],
    workspace: Path,
    caddy_root: Path,
    *,
    locks: LockManager,
    expected_owner: int,
    content_group: int,
    artifact_sha256: str,
    repository_genesis: dict[str, object],
    capture_id: str,
    captured_at: str,
) -> bytes:
    """The caller must retain these same leases until Restic has completed."""

    authority = describe_backup_authority(
        roots,
        workspace,
        locks=locks,
        expected_owner=expected_owner,
        content_group=content_group,
        repository_genesis=repository_genesis,
    )
    caddy = capture_caddy_evidence(
        caddy_root,
        locks=locks,
        expected_owner=expected_owner,
        expected_group=content_group,
    )
    return encode_backup_descriptor(
        {
            **authority,
            "schema": BACKUP_SCHEMA,
            "captureId": capture_id,
            "capturedAt": captured_at,
            "sourcePolicyDigest": source_policy_digest(),
            "artifactDigest": {
                "format": ARTIFACT_DIGEST_FORMAT,
                "algorithm": "sha256",
                "value": artifact_sha256,
            },
            "caddy": caddy.to_dict(),
        }
    )


def describe_backup_authority(  # noqa: PLR0913 - original and restored boundary use identical checks
    roots: Mapping[str, Path],
    workspace: Path,
    *,
    locks: LockManager,
    expected_owner: int,
    content_group: int,
    repository_genesis: dict[str, object],
) -> dict[str, object]:
    """Measure only snapshot authority; never infer excluded runtime payloads.

    Recovery compares this complete observation with the original descriptor
    BEFORE changing any restored bytes. The same implementation used for capture
    checks types, schemas, audit, retained releases, namespace and tree digests.
    """

    locks.require_held(LockName.PUBLICATION, mode=LockMode.SHARED)
    locks.require_held(LockName.TENANT_STATE, mode=LockMode.SHARED)
    _require_source_layout(roots, expected_owner)
    state = capture_state_inventory(
        roots["state"],
        locks=locks,
        expected_owner=expected_owner,
        repository_genesis=repository_genesis,
    )
    releases = _releases(roots["content"], state, locks, expected_owner, content_group)
    tree = measure_backup_sources(
        roots,
        workspace,
        locks=locks,
        expected_owner=expected_owner,
        content_group=content_group,
    )
    tenants = {tenant.tenant_id: tenant for tenant in state.tenants}
    for tenant_id in releases.keys() - tenants.keys():
        # An emergency intent can remain after its tenant directory is removed.
        # Preserve its surviving release evidence and explicit record absence.
        tenants[tenant_id] = BackupTenant(tenant_id, None, None, (), ())
    return {
        "lineage": state.lineage,
        "namespaceDigest": platform_state_digest(state.namespace).to_dict(),
        "launchDigest": None
        if state.launch is None
        else framed_digest(LAUNCH_DIGEST_FORMAT, canonical_json_bytes(state.launch)),
        "audit": {
            "entryCount": state.audit.entry_count,
            "segmentCount": state.audit.segment_count,
            "terminalEntryDigest": state.audit.terminal_digest,
        },
        "authority": {
            "treeDigest": tree.digest,
            "entryCount": tree.entries,
            "contentBytes": tree.content_bytes,
        },
        "tenants": [
            _tenant_row(tenants[identifier], releases.get(identifier, []))
            for identifier in sorted(tenants)
        ],
        "intents": [
            {
                "intentId": intent["intentId"],
                "tenantId": intent["tenantId"],
                "kind": intent["kind"],
                "digest": framed_digest(INTENT_DIGEST_FORMAT, canonical_json_bytes(intent)),
            }
            for intent in state.intents
        ],
    }
