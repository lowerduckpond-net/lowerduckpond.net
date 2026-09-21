"""Bounded Restic discovery and one immutable repository lineage anchor."""

from __future__ import annotations

import os
import re
import selectors
import subprocess
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from lowerduckpond_static_contracts import ContractError, canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_identity import (
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    RepositoryIdentity,
    canonical_locator,
    decode_lineage,
)

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOTS = 8_192
METADATA_TIMEOUT_SECONDS = 300
LINEAGE_TAG = "lowerduckpond-audit-lineage"
LINEAGE_FILE = "audit-lineage-genesis.json"
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ENVIRONMENT = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_DEFAULT_REGION",
    "RESTIC_PASSWORD",
    "RESTIC_REPOSITORY",
    "RESTIC_CACHE_DIR",
)
_LEASE_DESCRIPTORS: ContextVar[tuple[int, ...]] = ContextVar("restic_backup_leases", default=())


@contextmanager
def inherit_restic_leases(descriptors: tuple[int, ...]) -> Iterator[None]:
    """Keep caller-validated lease inodes held if the coordinating process dies.

    The caller owns the descriptors and retains them until every child is reaped.
    Nested capture adds its static leases to repository/selection exclusion.
    """

    inherited = (*_LEASE_DESCRIPTORS.get(), *descriptors)
    if len(set(inherited)) != len(inherited):
        raise BackupIdentityError("backup lease descriptors are ambiguous")
    for descriptor in descriptors:
        os.fstat(descriptor)
    token = _LEASE_DESCRIPTORS.set(inherited)
    try:
        yield
    finally:
        _LEASE_DESCRIPTORS.reset(token)


@dataclass(frozen=True)
class RepositorySnapshot:
    snapshot_id: str
    hostname: str
    tags: tuple[str, ...]


def restic_metadata(
    arguments: tuple[str, ...], environment: Mapping[str, str], limit: int
) -> bytes:
    """Only fixed config/snapshot reads; never leak provider output into logs."""
    if arguments not in {("cat", "config"), ("snapshots", "--json")}:
        raise BackupIdentityError("unsupported repository discovery operation")
    return _restic(arguments, environment, limit)


def _restic(
    arguments: tuple[str, ...],
    environment: Mapping[str, str],
    limit: int,
    payload: bytes | None = None,
) -> bytes:
    with tempfile.TemporaryFile() as source:
        if payload is not None:
            source.write(payload)
            source.seek(0)
        return _run_restic(arguments, environment, limit, source if payload is not None else None)


def _run_restic(
    arguments: tuple[str, ...],
    environment: Mapping[str, str],
    limit: int,
    source: BinaryIO | None,
    *,
    timeout_seconds: int | None = None,
) -> bytes:
    with subprocess.Popen(  # noqa: S603 - fixed executable and validated internal arguments
        ("/usr/bin/restic", *arguments),
        stdin=source if source is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        pass_fds=_LEASE_DESCRIPTORS.get(),
        env={
            "PATH": "/usr/bin:/bin",
            **{key: environment[key] for key in _ENVIRONMENT if key in environment},
        },
    ) as process:
        assert process.stdout is not None  # noqa: S101 - PIPE supplied above
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        output = bytearray()
        deadline = time.monotonic() + (
            METADATA_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(descriptor, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise BackupIdentityError("repository discovery exceeded its deadline")
                    try:
                        chunk = os.read(descriptor, min(65536, limit + 1 - len(output)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > limit:
                        raise BackupIdentityError("repository discovery exceeds its output bound")
            if process.wait(timeout=max(0.0, deadline - time.monotonic())):
                raise BackupIdentityError("repository discovery failed")
            return bytes(output)
        except subprocess.TimeoutExpired as error:
            raise BackupIdentityError("repository discovery exceeded its deadline") from error
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def discover_repository(
    environment: Mapping[str, str],
) -> tuple[RepositoryIdentity, tuple[RepositorySnapshot, ...]]:
    try:
        config = decode_json_object(restic_metadata(("cat", "config"), environment, 16 * 1024))
        locator = environment["RESTIC_REPOSITORY"]
        if locator.startswith("/"):
            locator = str(Path(locator).resolve(strict=True))
        config_id = config["id"]
        if type(config_id) is not str:
            raise BackupIdentityError("invalid Restic repository identity")
        identity = RepositoryIdentity(
            config_id, environment["LOWERDUCKPOND_BACKUP_NODE_NAME"], canonical_locator(locator)
        )
        if type(config.get("version")) is not int or config["version"] != 2:  # noqa: PLR2004
            raise BackupIdentityError("unsupported Restic repository format")
        raw = restic_metadata(("snapshots", "--json"), environment, MAX_SNAPSHOT_BYTES)
        document = decode_json_object(
            b'{"snapshots":' + raw + b"}", maximum_bytes=MAX_SNAPSHOT_BYTES + 16
        )
        if set(document) != {"snapshots"}:
            raise BackupIdentityError("repository snapshot output is not one JSON array")
        entries = document["snapshots"]
        if type(entries) is not list or len(entries) > MAX_SNAPSHOTS:
            raise BackupIdentityError("repository snapshot inventory exceeds its bound")
        snapshots: list[RepositorySnapshot] = []
        seen: set[str] = set()
        for entry in entries:
            if type(entry) is not dict:
                raise BackupIdentityError("invalid repository snapshot metadata")
            snapshot_id = entry.get("id")
            hostname = entry.get("hostname")
            tags = entry.get("tags", [])
            if (
                type(snapshot_id) is not str
                or _HEX.fullmatch(snapshot_id) is None
                or snapshot_id in seen
                or type(hostname) is not str
                or type(tags) is not list
                or len(tags) > 64  # noqa: PLR2004
                or any(type(tag) is not str or len(tag) > 256 for tag in tags)  # noqa: PLR2004
                or len(tags) != len(set(tags))
            ):
                raise BackupIdentityError("invalid repository snapshot metadata")
            seen.add(snapshot_id)
            snapshots.append(RepositorySnapshot(snapshot_id, hostname, tuple(tags)))
        return identity, tuple(snapshots)
    except (ContractError, KeyError, TypeError, ValueError, OSError) as error:
        raise BackupIdentityError("repository discovery is unavailable or malformed") from error


def repository_genesis(
    identity: RepositoryIdentity,
    snapshots: tuple[RepositorySnapshot, ...],
    environment: Mapping[str, str],
) -> dict[str, object] | None:
    """Verify the unique permanent anchor, not just its existence or tags."""
    candidates = [snapshot for snapshot in snapshots if LINEAGE_TAG in snapshot.tags]
    if not candidates:
        return None
    if len(candidates) != 1:
        raise BackupIdentityError("repository lineage evidence is ambiguous")
    snapshot = candidates[0]
    raw = _restic(
        ("dump", snapshot.snapshot_id, "/" + LINEAGE_FILE), environment, MAX_IDENTITY_BYTES
    )
    record = decode_lineage(raw)
    if (
        record["repository"] != identity.document()
        or snapshot.hostname != identity.node_name
        or set(snapshot.tags) != set(lineage_tags(record))
    ):
        raise BackupIdentityError("repository lineage binding changed")
    listing = _restic(("ls", "--json", snapshot.snapshot_id), environment, 32 * 1024)
    entries = [decode_json_object(line) for line in listing.splitlines()]
    if len(entries) != 2:  # noqa: PLR2004 - snapshot header and one file
        raise BackupIdentityError("repository lineage tree is invalid")
    header, node = entries
    if (
        header.get("struct_type") != "snapshot"
        or header.get("id") != snapshot.snapshot_id
        or node.get("struct_type") != "node"
        or node.get("path") != "/" + LINEAGE_FILE
        or node.get("type") != "file"
        or type(node.get("size")) is not int
        or node["size"] != len(raw)
    ):
        raise BackupIdentityError("repository lineage tree is invalid")
    return record


def lineage_tags(record: dict[str, object]) -> tuple[str, ...]:
    binding = record["repositoryBinding"]
    assert isinstance(binding, dict)  # noqa: S101 - validated canonical record
    return LINEAGE_TAG, f"lineage-{record['lineageId']}", f"repository-{binding['value']}"


def publish_repository_genesis(
    identity: RepositoryIdentity, record: dict[str, object], environment: Mapping[str, str]
) -> tuple[dict[str, object], tuple[RepositorySnapshot, ...]]:
    """Caller discovered no anchor while holding repository serialization.

    A lost response fails this attempt. The next invocation discovers and
    verifies the committed snapshot before considering another write.
    """
    raw = canonical_json_bytes(record)
    if decode_lineage(raw)["repository"] != identity.document():
        raise BackupIdentityError("repository lineage binding changed")
    tags = tuple(argument for tag in lineage_tags(record) for argument in ("--tag", tag))
    _restic(
        (
            "backup",
            "--json",
            "--stdin",
            "--stdin-filename",
            LINEAGE_FILE,
            "--host",
            identity.node_name,
            *tags,
        ),
        environment,
        32 * 1024,
        raw,
    )
    observed, snapshots = discover_repository(environment)
    if observed != identity:
        raise BackupIdentityError("repository identity changed during initialization")
    restored = repository_genesis(identity, snapshots, environment)
    if restored != record:
        raise BackupIdentityError("repository lineage publication was not verified")
    return restored, snapshots
