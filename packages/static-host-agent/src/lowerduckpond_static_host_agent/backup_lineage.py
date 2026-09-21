"""Initialize a lineage once, or verify its original audit prefix without reset."""

from __future__ import annotations

import os
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractKind,
    audit_entry_digest,
    canonical_json_bytes,
    decode_contract,
    platform_state_digest,
)
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState, inspect_audit
from lowerduckpond_static_host_agent.backup_identity import (
    LINEAGE_PATH,
    LINEAGE_SCHEMA,
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    RepositoryIdentity,
    decode_lineage,
    validate_lineage,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, FailureHook
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName


def _read(root: DurableDirectory, path: tuple[str, ...], owner: int, limit: int) -> bytes:
    return root.read_regular(path, expected_owner=owner, expected_mode=0o600, maximum_bytes=limit)


def _require_initial_prefix(
    root: DurableDirectory, owner: int, lineage: dict[str, object], audit: AuditState
) -> None:
    count = lineage["initialEntryCount"]
    assert type(count) is int  # noqa: S101 - validated lineage
    if count > audit.entry_count:
        raise BackupIdentityError("audit history predates its lineage boundary")
    if not count:
        return
    sequence = 0
    for number in range(audit.segment_count):
        raw = _read(root, ("audit", f"segment-{number:020d}.jsonl"), owner, 8 * 1024 * 1024)
        for line in raw.splitlines(keepends=True):
            sequence += 1
            if sequence == count:
                document = decode_contract(line, expected_kind=ContractKind.AUDIT_ENTRY)
                if audit_entry_digest(document).to_dict() != lineage["initialTerminalEntryDigest"]:
                    raise BackupIdentityError("audit history forks its lineage boundary")
                return
    raise BackupIdentityError("audit lineage boundary is unavailable")


def lineage_for_repository(  # noqa: PLR0913 - explicit privilege and failure boundaries
    root_path: Path,
    identity: RepositoryIdentity,
    *,
    snapshot_tags: tuple[tuple[str, tuple[str, ...]], ...],
    initialize: bool,
    expected_owner: int,
    failure_hook: FailureHook | None = None,
) -> dict[str, object]:
    """Caller holds repository serialization and the selected artifact lease.

    Network inventory is obtained before this exclusive state transaction.
    Initialization is an explicit migration action, never a missing-file repair
    performed by verification. An existing record always wins unchanged.
    """
    with (
        DurableDirectory.open(
            root_path, expected_owner=expected_owner, expected_directory_mode=0o700
        ) as root,
        root.open_descendant(("locks",)) as directory,
        LockManager(
            directory, expected_owner=expected_owner, expected_directory_mode=0o700
        ) as locks,
        locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE, blocking=True),
    ):
        namespace_raw = _read(
            root, ("platform", "namespace.json"), expected_owner, MAX_CANONICAL_BYTES
        )
        namespace = decode_contract(namespace_raw, expected_kind=ContractKind.PLATFORM_NAMESPACE)
        if canonical_json_bytes(namespace) != namespace_raw:
            raise BackupIdentityError("platform namespace is not canonical")
        namespace_digest = platform_state_digest(namespace).to_dict()
        try:
            lineage = decode_lineage(_read(root, LINEAGE_PATH, expected_owner, MAX_IDENTITY_BYTES))
        except FileNotFoundError:
            if not initialize:
                raise BackupIdentityError("audit lineage has not been initialized") from None
            lineage = None
        _require_snapshot_history(snapshot_tags, identity, lineage)
        audit = inspect_audit(
            root,
            expected_owner=expected_owner,
            expected_directory_mode=0o700,
            expected_record_mode=0o600,
        )
        if lineage is not None:
            if (
                lineage["repository"] != identity.document()
                or lineage["namespaceDigest"] != namespace_digest
            ):
                raise BackupIdentityError("audit lineage binding changed")
            _require_initial_prefix(root, expected_owner, lineage, audit)
            _sync_platform(root)
            return lineage
        # Inspection above validates the complete pre-migration chain. An archive
        # directory/index is rejected by that reader rather than authorizing a
        # new lineage over a missing prefix. No audit bytes are rewritten.
        now = time.time_ns() // 1_000_000
        lineage = validate_lineage(
            {
                "schema": LINEAGE_SCHEMA,
                "lineageId": generate_uuid7(clock=lambda: now, entropy=_entropy),
                "repository": identity.document(),
                "repositoryBinding": identity.binding(),
                "namespaceDigest": namespace_digest,
                "initializedAt": datetime.fromtimestamp(now / 1000, UTC).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "initialEntryCount": audit.entry_count,
                "initialTerminalEntryDigest": audit.terminal_digest,
            }
        )
        with root.open_descendant(("platform",)) as platform:
            platform.remove_abandoned_publication_temporaries(
                expected_owner=expected_owner, expected_mode=0o600, maximum_entries=64
            )
        root.create_immutable(
            LINEAGE_PATH, canonical_json_bytes(lineage), mode=0o600, failure_hook=failure_hook
        )
        return lineage


def _sync_platform(root: DurableDirectory) -> None:
    # A previous process may have died after immutable rename but before the
    # directory sync. Re-observation must close that durability gap before use.
    with root.open_descendant(("platform",)) as platform:
        descriptor = platform.duplicate_descriptor()
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


def _require_snapshot_history(
    snapshots: tuple[tuple[str, tuple[str, ...]], ...],
    identity: RepositoryIdentity,
    lineage: dict[str, object] | None,
) -> None:
    for hostname, tags in snapshots:
        reserved = tuple(
            tag
            for tag in tags
            if tag.startswith(("lineage-", "repository-", "rotation-", "capture-"))
        )
        protected = "lowerduckpond-audit-archive" in tags
        if not reserved and not protected:
            continue  # Unmodified pre-M3.11 scheduled/diagnostic backups.
        if lineage is None:
            raise BackupIdentityError("repository history requires an existing audit lineage")
        expected_lineage = f"lineage-{lineage['lineageId']}"
        expected_repository = f"repository-{identity.binding()['value']}"
        if (
            hostname != identity.node_name
            or tuple(tag for tag in tags if tag.startswith("lineage-")) != (expected_lineage,)
            or tuple(tag for tag in tags if tag.startswith("repository-")) != (expected_repository,)
        ):
            raise BackupIdentityError("repository history conflicts with the audit lineage")
