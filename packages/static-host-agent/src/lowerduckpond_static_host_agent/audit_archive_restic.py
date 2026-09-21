"""Exact-ID protected snapshot restoration and independently checked retention selection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from lowerduckpond_static_contracts import ContractError, decode_json_object

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent.audit_archive_workspace import restore_payload
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import (
    LINEAGE_TAG,
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOTS,
    RepositorySnapshot,
    _restic,
    _run_restic,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory

SNAPSHOT_SOURCE: Final = "/var/cache/lowerduckpond-backup/audit/snapshot"
MAX_TREE_METADATA_BYTES: Final = 64 * 1024
MAINTENANCE_TIMEOUT_SECONDS: Final = 30 * 60
_MAX_SOURCE_OR_TAG_ENTRIES: Final = 64
_PROTECTED_TAGS: Final = frozenset({formats.ARCHIVE_TAG, LINEAGE_TAG})
_PAYLOAD_MODE: Final = 0o600


@dataclass(frozen=True, slots=True)
class VerifiedAuditSnapshot:
    snapshot_id: str
    descriptor: dict[str, object]
    descriptor_bytes: bytes
    segment: bytes
    witness: bytes


def _payload_size(node: dict[str, object], maximum: int, owner: int, group: int) -> int:
    size = node.get("size")
    content = node.get("content")
    if (
        node.get("type") != "file"
        or type(size) is not int
        or not 0 < size <= maximum
        or any(type(node.get(field)) is not int for field in ("uid", "gid", "mode", "links"))
        or node.get("uid") != owner
        or node.get("gid") != group
        or node.get("mode") != _PAYLOAD_MODE
        or node.get("links") != 1
        or any(
            node.get(field)
            for field in (
                "extended_attributes",
                "generic_attributes",
                "linktarget",
                "linktarget_raw",
                "subtree",
                "error",
                "device",
            )
        )
        or type(content) is not list
        or not content
        or len(content) > MAX_TREE_METADATA_BYTES // 64
    ):
        raise BackupIdentityError("protected audit snapshot payload has unsafe metadata")
    for blob in content:
        formats.full_snapshot_id(blob)
    return size


def _snapshot_tree(
    snapshot: RepositorySnapshot, environment: Mapping[str, str], *, owner: int, group: int
) -> dict[str, int]:
    # `ls --json` omits hard-link and extended-attribute metadata. Walk the
    # content-addressed tree records, with an exact fixed path at every level.
    raw = _restic(("cat", "snapshot", snapshot.snapshot_id), environment, MAX_TREE_METADATA_BYTES)
    header = decode_json_object(raw, maximum_bytes=MAX_TREE_METADATA_BYTES)
    if (
        header.get("hostname") != snapshot.hostname
        or header.get("paths") != [SNAPSHOT_SOURCE]
        or snapshot.paths != (SNAPSHOT_SOURCE,)
        or _string_inventory(header.get("tags")) != tuple(sorted(snapshot.tags))
    ):
        raise BackupIdentityError("protected audit snapshot tree has another identity")
    tree = formats.full_snapshot_id(header.get("tree"))
    source = PurePosixPath(SNAPSHOT_SOURCE)
    parents = source.parts[1:]
    consumed = len(raw)
    seen: set[str] = set()
    sizes: dict[str, int] = {}
    for depth in range(len(parents) + 1):
        if tree in seen or consumed >= MAX_TREE_METADATA_BYTES:
            raise BackupIdentityError("protected audit snapshot tree exceeds its fixed shape")
        seen.add(tree)
        raw = _restic(("cat", "blob", tree), environment, MAX_TREE_METADATA_BYTES - consumed)
        consumed += len(raw)
        document = decode_json_object(raw, maximum_bytes=MAX_TREE_METADATA_BYTES)
        nodes = document.get("nodes")
        expected = (
            {parents[depth]} if depth < len(parents) else {"descriptor.json", "segment.jsonl"}
        )
        if set(document) != {"nodes"} or type(nodes) is not list or len(nodes) != len(expected):
            raise BackupIdentityError("protected audit snapshot omits or adds payload paths")
        for node in nodes:
            if type(node) is not dict or type(node.get("name")) is not str:
                raise BackupIdentityError("protected audit snapshot has malformed tree metadata")
            name = node["name"]
            if name not in expected:
                raise BackupIdentityError("protected audit snapshot omits or adds payload paths")
            expected.remove(name)
            if depth < len(parents):
                if node.get("type") != "dir" or any(
                    node.get(field)
                    for field in ("linktarget", "linktarget_raw", "error", "content")
                ):
                    raise BackupIdentityError(
                        "protected audit snapshot has unsafe structural parents"
                    )
                tree = formats.full_snapshot_id(node.get("subtree"))
            else:
                maximum = (
                    formats.MAX_DESCRIPTOR_BYTES
                    if name == "descriptor.json"
                    else formats.MAX_SEGMENT_BYTES
                )
                sizes[str(source / name)] = _payload_size(node, maximum, owner, group)
    return sizes


def verify_audit_snapshot(  # noqa: PLR0913 - repository, lineage, workspace and inode boundaries
    snapshot: RepositorySnapshot,
    identity: RepositoryIdentity,
    lineage_id: str,
    environment: Mapping[str, str],
    workspace: DurableDirectory,
    *,
    expected_owner: int,
    expected_group: int,
) -> VerifiedAuditSnapshot:
    formats.full_snapshot_id(snapshot.snapshot_id)
    if snapshot.hostname != identity.node_name or "scheduled" in snapshot.tags:
        raise BackupIdentityError("protected audit snapshot has an invalid retention binding")
    try:
        sizes = _snapshot_tree(snapshot, environment, owner=expected_owner, group=expected_group)
        raw = restore_payload(
            workspace,
            "descriptor.json",
            _restic(
                ("dump", snapshot.snapshot_id, SNAPSHOT_SOURCE + "/descriptor.json"),
                environment,
                formats.MAX_DESCRIPTOR_BYTES,
            ),
            expected_owner,
        )
        descriptor = formats.decode_rotation(raw)
        if (
            descriptor["lineageId"] != lineage_id
            or descriptor["repositoryBinding"] != identity.binding()
            or tuple(sorted(snapshot.tags)) != formats.required_archive_tags(descriptor)
            or sizes[SNAPSHOT_SOURCE + "/descriptor.json"] != len(raw)
        ):
            raise BackupIdentityError("protected audit descriptor has another snapshot binding")
        segment = restore_payload(
            workspace,
            "segment.jsonl",
            _restic(
                ("dump", snapshot.snapshot_id, SNAPSHOT_SOURCE + "/segment.jsonl"),
                environment,
                formats.MAX_SEGMENT_BYTES,
            ),
            expected_owner,
        )
        if sizes[SNAPSHOT_SOURCE + "/segment.jsonl"] != len(segment):
            raise BackupIdentityError("protected audit snapshot tree and restored bytes disagree")
        evidence = formats.verify_segment(descriptor, segment)
        witness = restore_payload(workspace, "witness.json", evidence.witness, expected_owner)
        return VerifiedAuditSnapshot(snapshot.snapshot_id, descriptor, raw, segment, witness)
    except ContractError as error:
        raise BackupIdentityError("protected audit snapshot metadata is malformed") from error


def ordinary_retention_ids(
    identity: RepositoryIdentity,
    snapshots: tuple[RepositorySnapshot, ...],
    protected_ids: frozenset[str],
    environment: Mapping[str, str],
) -> tuple[str, ...]:
    """Ask fixed Restic 7/5/12 policy, then classify every retained/removed ID."""
    eligible = {
        snapshot.snapshot_id: snapshot
        for snapshot in snapshots
        if snapshot.hostname == identity.node_name and "scheduled" in snapshot.tags
    }
    if any(
        snapshot_id in protected_ids or _PROTECTED_TAGS.intersection(snapshot.tags)
        for snapshot_id, snapshot in eligible.items()
    ):
        raise BackupIdentityError("ordinary retention inventory contains protected evidence")
    if any(not snapshot.paths for snapshot in eligible.values()):
        raise BackupIdentityError("ordinary retention inventory lacks source-path bindings")
    raw = _restic(
        (
            "forget",
            "--json",
            "--dry-run",
            "--host",
            identity.node_name,
            "--tag",
            "scheduled",
            "--group-by",
            "host,paths",
            "--keep-daily",
            "7",
            "--keep-weekly",
            "5",
            "--keep-monthly",
            "12",
        ),
        environment,
        MAX_SNAPSHOT_BYTES,
    )
    if not raw:
        if eligible:
            raise BackupIdentityError("ordinary retention omitted its snapshot inventory")
        return ()
    try:
        document = decode_json_object(
            b'{"groups":' + raw + b"}", maximum_bytes=MAX_SNAPSHOT_BYTES + 16
        )
        groups = document.get("groups")
        if set(document) != {"groups"} or type(groups) is not list or len(groups) > MAX_SNAPSHOTS:
            raise BackupIdentityError("ordinary retention output exceeds its group boundary")
        seen: set[str] = set()
        removals: set[str] = set()
        for group in groups:
            kept, removed = _retention_group(group, identity.node_name, eligible)
            if seen.intersection(kept | removed):
                raise BackupIdentityError("ordinary retention repeats a snapshot across groups")
            seen.update(kept | removed)
            removals.update(removed)
        if seen != set(eligible):
            raise BackupIdentityError(
                "ordinary retention did not classify every scheduled snapshot"
            )
        return tuple(sorted(removals))
    except ContractError as error:
        raise BackupIdentityError("ordinary retention JSON is malformed") from error


def _string_inventory(value: object) -> tuple[str, ...]:
    if (
        type(value) is not list
        or len(value) > _MAX_SOURCE_OR_TAG_ENTRIES
        or any(type(item) is not str for item in value)
        or len(value) != len(set(value))
    ):
        raise BackupIdentityError("ordinary retention has malformed source or tag metadata")
    return tuple(sorted(value))


def _retention_records(
    records: object, paths: tuple[str, ...], eligible: dict[str, RepositorySnapshot]
) -> set[str]:
    if records is None:
        return set()  # Restic encodes an empty Go slice as null.
    if type(records) is not list or len(records) > MAX_SNAPSHOTS:
        raise BackupIdentityError("ordinary retention output exceeds its snapshot bound")
    result: set[str] = set()
    for record in records:
        if type(record) is not dict:
            raise BackupIdentityError("ordinary retention snapshot is malformed")
        snapshot_id = formats.full_snapshot_id(record.get("id"))
        if snapshot_id not in eligible or snapshot_id in result:
            raise BackupIdentityError("ordinary retention selected unknown or repeated authority")
        snapshot = eligible[snapshot_id]
        if (
            tuple(sorted(snapshot.paths)) != paths
            or _string_inventory(record.get("paths")) != paths
            or record.get("hostname") != snapshot.hostname
            or _string_inventory(record.get("tags")) != tuple(sorted(snapshot.tags))
        ):
            raise BackupIdentityError(
                "ordinary retention changed a snapshot's source or tag binding"
            )
        result.add(snapshot_id)
    return result


def _retention_group(
    group: object, hostname: str, eligible: dict[str, RepositorySnapshot]
) -> tuple[set[str], set[str]]:
    if (
        type(group) is not dict
        or group.get("host") != hostname
        or set(group) != {"tags", "host", "paths", "keep", "remove", "reasons"}
        or group["tags"] not in (None, [])
    ):
        raise BackupIdentityError("ordinary retention group has invalid node or grouping metadata")
    paths = _string_inventory(group["paths"])
    kept = _retention_records(group["keep"], paths, eligible)
    removed = _retention_records(group["remove"], paths, eligible)
    if not paths or not kept or kept.intersection(removed):
        raise BackupIdentityError("ordinary retention group lacks disjoint retained authority")
    return kept, removed


def forget_exact_ids(ids: tuple[str, ...], environment: Mapping[str, str]) -> None:
    if len(ids) > MAX_SNAPSHOTS or ids != tuple(sorted(set(ids))):
        raise BackupIdentityError("ordinary retention deletion set is ambiguous")
    if ids:
        for snapshot_id in ids:
            formats.full_snapshot_id(snapshot_id)
        _restic(("forget", "--quiet", *ids), environment, 32 * 1024)


def prune_repository(environment: Mapping[str, str]) -> None:
    _run_restic(
        ("prune", "--quiet"),
        environment,
        32 * 1024,
        None,
        timeout_seconds=MAINTENANCE_TIMEOUT_SECONDS,
    )


def check_repository(environment: Mapping[str, str]) -> None:
    _run_restic(
        ("check", "--quiet"),
        environment,
        32 * 1024,
        None,
        timeout_seconds=MAINTENANCE_TIMEOUT_SECONDS,
    )
