"""Verify restored authority against capture before granting mutation permission."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, platform_state_digest

from lowerduckpond_static_host_agent.backup_capture import describe_backup_authority
from lowerduckpond_static_host_agent.backup_descriptor import (
    LAUNCH_DIGEST_FORMAT,
    decode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName


def require_trusted_policy(
    descriptor: dict[str, object],
    *,
    repository_genesis: dict[str, object],
    artifact_sha256: str,
    namespace: dict[str, object],
    launch: dict[str, object] | None,
) -> None:
    if (
        descriptor["lineage"] != repository_genesis
        or cast(dict[str, str], descriptor["artifactDigest"])["value"] != artifact_sha256
        or descriptor["namespaceDigest"] != platform_state_digest(namespace).to_dict()
        or descriptor["launchDigest"]
        != (
            None
            if launch is None
            else framed_digest(LAUNCH_DIGEST_FORMAT, canonical_json_bytes(launch))
        )
    ):
        raise HostRestoreError("restore_trusted_input_mismatch")


def validate_restored_authority(  # noqa: PLR0913 - independent original/trusted/restored bindings
    raw: bytes,
    roots: Mapping[str, Path],
    workspace: Path,
    *,
    owner: int,
    content_group: int,
    repository_genesis: dict[str, object],
    artifact_sha256: str,
    namespace: dict[str, object],
    launch: dict[str, object] | None,
) -> dict[str, object]:
    """No restored content is authoritative solely because Restic restored it.

    These leases refer to inert, validated candidate lock files on a private
    tree. They are discarded and recreated before any installed worker starts.
    Original backup evidence, including kernel-lock bytes and prior recovery
    provenance, is measured first so recreating locks cannot conceal corruption.
    """
    descriptor = decode_backup_descriptor(raw)
    require_trusted_policy(
        descriptor,
        repository_genesis=repository_genesis,
        artifact_sha256=artifact_sha256,
        namespace=namespace,
        launch=launch,
    )
    with (
        LockManager(roots["state"] / "locks", expected_owner=owner) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
        locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED),
    ):
        measured = describe_backup_authority(
            roots,
            workspace,
            locks=locks,
            expected_owner=owner,
            content_group=content_group,
            repository_genesis=repository_genesis,
        )
    if any(descriptor[name] != value for name, value in measured.items()):
        raise HostRestoreError("restore_authority_mismatch")
    return measured
