"""Empty-history namespace bootstrap for the explicit M3.11 production transaction."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from lowerduckpond_static_contracts import ContractKind, canonical_json_bytes, decode_contract

from lowerduckpond_static_host_agent.backup_coordinator import _require_current_root
from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    FailureHook,
    StatePathError,
    validate_regular_state_file,
)
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, LockRequest

ROOTS = frozenset(
    {"platform", "tenants", "authorization", "audit", "intents", "locks", "intake", "exports"}
)
AUTHORIZATION = frozenset({"jobs", "results", "correlations"})
NAMESPACE = ("platform", "namespace.json")
MAX_NAMESPACE_BYTES = 1024


def _names(directory: DurableDirectory, allowed: frozenset[str]) -> frozenset[str]:
    descriptor = directory.duplicate_descriptor()
    try:
        names: set[str] = set()
        with os.scandir(descriptor) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > len(allowed) or entry.name not in allowed:
                    raise StatePathError("production namespace requires empty tenant history")
                names.add(entry.name)
        return frozenset(names)
    finally:
        os.close(descriptor)


@contextmanager
def _transaction(path: Path, owner: int, mode: LockMode) -> Iterator[DurableDirectory]:
    with (
        DurableDirectory.open(path, expected_owner=owner, expected_directory_mode=0o700) as root,
        root.open_descendant(("locks",)) as lock_root,
        LockManager(lock_root, expected_owner=owner, expected_directory_mode=0o700) as locks,
        locks.acquire_many(tuple(LockRequest(name, mode) for name in LockName)),
    ):
        _require_current_root(root, path)
        descriptor = lock_root.duplicate_descriptor()
        try:
            with root.open_descendant(("locks",)) as named_locks:
                named = named_locks.duplicate_descriptor()
                try:
                    opened_metadata, named_metadata = os.fstat(descriptor), os.fstat(named)
                    if (opened_metadata.st_dev, opened_metadata.st_ino) != (
                        named_metadata.st_dev,
                        named_metadata.st_ino,
                    ):
                        raise StatePathError("production namespace lock directory changed")
                finally:
                    os.close(named)
            for name in LockName:
                current = os.open(
                    name.filename,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=descriptor,
                )
                try:
                    metadata = validate_regular_state_file(
                        current, expected_owner=owner, expected_mode=0o600
                    )
                    if metadata.st_size:
                        raise StatePathError("production namespace lock is not empty")
                    locks.require_held(name, mode=mode, descriptor=current)
                finally:
                    os.close(current)
        finally:
            os.close(descriptor)
        yield root


def _inspect(root: DurableDirectory, *, temporary: str | None = None) -> frozenset[str]:
    if _names(root, ROOTS) != ROOTS:
        raise StatePathError("production namespace requires the complete static layout")
    platform_names = frozenset({"namespace.json"})
    if temporary is not None:
        platform_names |= {temporary}
    actual_platform = frozenset[str]()
    for name in ROOTS:
        with root.open_descendant((name,)) as directory:
            if name == "platform":
                actual_platform = _names(directory, platform_names)
            elif name == "locks":
                if _names(directory, frozenset(lock.filename for lock in LockName)) != frozenset(
                    lock.filename for lock in LockName
                ):
                    raise StatePathError("production namespace requires original kernel locks")
            elif name == "authorization":
                if _names(directory, AUTHORIZATION) != AUTHORIZATION:
                    raise StatePathError("production authorization layout is incomplete")
                for child in AUTHORIZATION:
                    with directory.open_descendant((child,)) as records:
                        _names(records, frozenset())
            else:
                _names(directory, frozenset())
    return actual_platform


def _read(root: DurableDirectory, path: tuple[str, ...], owner: int) -> bytes:
    return root.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_NAMESPACE_BYTES
    )


def _validate(raw: bytes) -> None:
    if len(raw) > MAX_NAMESPACE_BYTES:
        raise ValueError("production namespace exceeds its bound")
    document = decode_contract(raw, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    if canonical_json_bytes(document) != raw:
        raise ValueError("production namespace must retain its original canonical bytes")


def inspect_empty_history(path: Path, *, expected_owner: int) -> bytes | None:
    """Read-only pre-lineage observation; missing or interrupted state is not empty.

    This inspects only the static tree. The production controller must separately
    verify completion, selected artifact, publication, releases, routes, provider
    policy and backup identity. A post-lineage host uses the protected verifier,
    never this pre-migration check.
    """
    with _transaction(path, expected_owner, LockMode.SHARED) as root:
        names = _inspect(root)
        if not names:
            return None
        raw = _read(root, NAMESPACE, expected_owner)
        _validate(raw)
        return raw


def initialize_namespace(
    path: Path,
    original: bytes,
    *,
    expected_owner: int,
    failure_hook: FailureHook | None = None,
) -> bool:
    """Publish only the original authorized namespace before lineage initialization.

    The caller must first persist these exact bytes (including the actual initial
    timestamp) in its qualified migration transaction and drain old processes.
    This primitive neither authorizes a rollout nor manufactures a timestamp.
    It has no CLI or automatic Ansible callsite. False means the original record
    was already published; even its inode and modification time remain intact.
    """
    _validate(original)
    temporary = ".ldp-state-" + hashlib.sha256(original).hexdigest()[:32]
    with _transaction(path, expected_owner, LockMode.EXCLUSIVE) as root:
        names = _inspect(root, temporary=temporary)
        if "namespace.json" in names:
            if names != {"namespace.json"} or _read(root, NAMESPACE, expected_owner) != original:
                raise StatePathError("production namespace differs from the original transaction")
            created = False
        else:
            if temporary in names:
                retained = _read(root, ("platform", temporary), expected_owner)
                if not original.startswith(retained):
                    raise StatePathError("interrupted namespace differs from the original bytes")
                # Only this transaction's content-addressed partial publication
                # can be retired. The read-only preflight never cleans it up.
                root.remove(("platform", temporary))
            root.create_immutable(
                NAMESPACE,
                original,
                failure_hook=failure_hook,
                temporary_name_source=lambda: temporary,
            )
            created = True
        # Close a previous death after rename and before parent sync.
        with root.open_descendant(("platform",)) as directory:
            descriptor = directory.duplicate_descriptor()
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _require_current_root(root, path)
        return created
