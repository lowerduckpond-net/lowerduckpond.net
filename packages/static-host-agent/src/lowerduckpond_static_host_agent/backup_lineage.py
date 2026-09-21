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
    canonical_json_bytes,
    decode_contract,
    platform_state_digest,
)
from lowerduckpond_static_domain import generate_uuid7

from lowerduckpond_static_host_agent.audit import AuditState, audit_prefix_terminal, inspect_audit
from lowerduckpond_static_host_agent.backup_identity import (
    GENESIS_PATH,
    LINEAGE_PATH,
    LINEAGE_SCHEMA,
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    RepositoryIdentity,
    decode_lineage,
    validate_lineage,
)
from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    FailureHook,
    StatePathError,
    validate_regular_state_file,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, LockOrderError


def _read(root: DurableDirectory, path: tuple[str, ...], owner: int, limit: int) -> bytes:
    return root.read_regular(path, expected_owner=owner, expected_mode=0o600, maximum_bytes=limit)


def require_initial_lineage_prefix(
    root: DurableDirectory, owner: int, lineage: dict[str, object], audit: AuditState
) -> None:
    count = lineage["initialEntryCount"]
    assert type(count) is int  # noqa: S101 - validated lineage
    if count > audit.entry_count:
        raise BackupIdentityError("audit history predates its lineage boundary")
    if not count:
        return
    terminal = audit_prefix_terminal(
        root, count, expected_owner=owner, expected_directory_mode=0o700, expected_record_mode=0o600
    )
    if terminal != lineage["initialTerminalEntryDigest"]:
        raise BackupIdentityError("audit history forks its lineage boundary")


def lineage_for_repository(  # noqa: PLR0913 - explicit privilege and failure boundaries
    root_path: Path,
    identity: RepositoryIdentity,
    *,
    snapshot_tags: tuple[tuple[str, tuple[str, ...]], ...],
    initialize: bool,
    expected_owner: int,
    repository_genesis: dict[str, object] | None,
    commit: bool = True,
    failure_hook: FailureHook | None = None,
    genesis_failure_hook: FailureHook | None = None,
) -> dict[str, object]:
    """Caller holds repository serialization and the selected artifact lease.

    Network inventory is obtained before this exclusive state transaction.
    Initialization is an explicit migration action, never a missing-file repair
    performed by verification. Preparation persists only the local candidate;
    commit requires independently restored repository evidence. Network I/O
    belongs between those transactions, never under tenant-state.
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
        _require_current_state_lease(directory, locks, expected_owner)
        namespace_raw = _read(
            root, ("platform", "namespace.json"), expected_owner, MAX_CANONICAL_BYTES
        )
        namespace = decode_contract(namespace_raw, expected_kind=ContractKind.PLATFORM_NAMESPACE)
        if canonical_json_bytes(namespace) != namespace_raw:
            raise BackupIdentityError("platform namespace is not canonical")
        namespace_digest = platform_state_digest(namespace).to_dict()
        genesis = _optional_lineage(root, GENESIS_PATH, expected_owner)
        published = _optional_lineage(root, LINEAGE_PATH, expected_owner)
        if published is not None and (genesis is None or published != genesis):
            raise BackupIdentityError("audit lineage genesis is missing or inconsistent")
        if published is None and not initialize:
            raise BackupIdentityError("audit lineage has not been initialized")
        require_repository_history(snapshot_tags, identity, genesis)
        if repository_genesis is not None:
            validate_lineage(repository_genesis)
            if genesis != repository_genesis:
                raise BackupIdentityError("repository history requires the existing audit lineage")
        elif published is not None or commit:
            raise BackupIdentityError("repository lineage evidence is missing")
        audit = inspect_audit(
            root,
            expected_owner=expected_owner,
            expected_directory_mode=0o700,
            expected_record_mode=0o600,
        )
        if genesis is not None:
            if (
                genesis["repository"] != identity.document()
                or genesis["namespaceDigest"] != namespace_digest
            ):
                raise BackupIdentityError("audit lineage binding changed")
            require_initial_lineage_prefix(root, expected_owner, genesis, audit)
            # This immutable independent anchor is published and synced first.
            # Missing primary bytes can only be copied from this exact identity.
            _sync_directory(root, "locks")
            if published is None and commit:
                _publish_primary(root, genesis, expected_owner, failure_hook)
            else:
                _sync_directory(root, "platform")
            return genesis
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
        _remove_temporaries(root, "locks", expected_owner)
        root.create_immutable(
            GENESIS_PATH,
            canonical_json_bytes(lineage),
            mode=0o600,
            failure_hook=genesis_failure_hook,
        )
        return lineage


def _optional_lineage(
    root: DurableDirectory, path: tuple[str, ...], owner: int
) -> dict[str, object] | None:
    try:
        return decode_lineage(_read(root, path, owner, MAX_IDENTITY_BYTES))
    except FileNotFoundError:
        return None


def _remove_temporaries(root: DurableDirectory, name: str, owner: int) -> None:
    with root.open_descendant((name,)) as directory:
        directory.remove_abandoned_publication_temporaries(
            expected_owner=owner, expected_mode=0o600, maximum_entries=64
        )


def _publish_primary(
    root: DurableDirectory, lineage: dict[str, object], owner: int, failure_hook: FailureHook | None
) -> None:
    _remove_temporaries(root, "platform", owner)
    root.create_immutable(
        LINEAGE_PATH, canonical_json_bytes(lineage), mode=0o600, failure_hook=failure_hook
    )


def _require_current_state_lease(
    directory: DurableDirectory, locks: LockManager, owner: int
) -> None:
    # A blocking acquisition can finish on the old inode after its name was
    # replaced. Prove that the current no-follow inode is the one actually held
    # before trusting any state or publishing lineage.
    parent = directory.duplicate_descriptor()
    try:
        current = os.open(
            LockName.TENANT_STATE.filename,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent,
        )
        try:
            metadata = validate_regular_state_file(
                current, expected_owner=owner, expected_mode=0o600
            )
            if metadata.st_size != 0:
                raise StatePathError("audit lineage state lock is not empty")
            locks.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE, descriptor=current)
        except LockOrderError as error:
            raise StatePathError("audit lineage state lock identity changed") from error
        finally:
            os.close(current)
    finally:
        os.close(parent)


def _sync_directory(root: DurableDirectory, name: str) -> None:
    # A previous process may have died after immutable rename but before the
    # directory sync. Re-observation must close that durability gap before use.
    with root.open_descendant((name,)) as directory:
        descriptor = directory.duplicate_descriptor()
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _entropy(length: int) -> bytes:
    return secrets.token_bytes(length)


def require_repository_history(
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
        protected = bool({"lowerduckpond-audit-archive", "lowerduckpond-audit-lineage"} & set(tags))
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
