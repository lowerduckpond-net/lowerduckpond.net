from __future__ import annotations

import copy
import json
import os
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent import audit_archive_restic as adapter
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.durable import DurableDirectory
from test_audit_archive_formats import IDENTITY, LINEAGE, descriptor, entry

SNAPSHOT = "a" * 64
type Repository = tuple[RepositorySnapshot, dict[tuple[str, ...], Any], list[tuple[str, ...]]]


@pytest.fixture
def repository(
    monkeypatch: pytest.MonkeyPatch,
) -> Repository:
    segment = canonical_json_bytes(entry())
    record = descriptor(segment)
    snapshot = RepositorySnapshot(
        SNAPSHOT,
        IDENTITY.node_name,
        formats.required_archive_tags(record),
        (adapter.SNAPSHOT_SOURCE,),
    )
    parents = PurePosixPath(adapter.SNAPSHOT_SOURCE).parts[1:]
    trees = [f"{i + 1:064x}" for i in range(len(parents) + 1)]
    responses: dict[tuple[str, ...], Any] = {
        ("cat", "snapshot", SNAPSHOT): {
            "hostname": snapshot.hostname,
            "paths": list(snapshot.paths),
            "tags": list(snapshot.tags),
            "tree": trees[0],
        },
        ("dump", SNAPSHOT, adapter.SNAPSHOT_SOURCE + "/descriptor.json"): canonical_json_bytes(
            record
        ),
        ("dump", SNAPSHOT, adapter.SNAPSHOT_SOURCE + "/segment.jsonl"): segment,
    }
    for index, name in enumerate(parents):
        responses[("cat", "blob", trees[index])] = {
            "nodes": [{"name": name, "type": "dir", "subtree": trees[index + 1], "content": None}]
        }
    responses[("cat", "blob", trees[-1])] = {
        "nodes": [
            {
                "name": name,
                "type": "file",
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "mode": 0o600,
                "links": 1,
                "size": len(data),
                "content": ["b" * 64],
            }
            for name, data in (
                ("descriptor.json", canonical_json_bytes(record)),
                ("segment.jsonl", segment),
            )
        ]
    }
    calls: list[tuple[str, ...]] = []

    def restic(arguments: tuple[str, ...], _environment: Mapping[str, str], limit: int) -> bytes:
        calls.append(arguments)
        value = responses[arguments]
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        if len(raw) > limit:
            raise BackupIdentityError("test child exceeded bounded output")
        return raw

    monkeypatch.setattr(adapter, "_restic", restic)
    return snapshot, responses, calls


def verify(snapshot: RepositorySnapshot, path: Path) -> adapter.VerifiedAuditSnapshot:
    path.chmod(0o700)
    with DurableDirectory.open(
        path, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as work:
        return adapter.verify_audit_snapshot(
            snapshot,
            IDENTITY,
            LINEAGE,
            {},
            work,
            expected_owner=os.geteuid(),
            expected_group=os.getegid(),
        )


def test_exact_full_tree_then_independent_payloads_generate_bound_witness(
    repository: Repository, tmp_path: Path
) -> None:
    snapshot, _, calls = repository
    result = verify(snapshot, tmp_path)
    assert result.segment == canonical_json_bytes(entry())
    assert result.witness == formats.inspect_segment(result.segment).witness
    assert (tmp_path / "descriptor.json").read_bytes() == result.descriptor_bytes
    assert (tmp_path / "witness.json").read_bytes() == result.witness
    assert calls[-2:] == [
        ("dump", SNAPSHOT, adapter.SNAPSHOT_SOURCE + "/descriptor.json"),
        ("dump", SNAPSHOT, adapter.SNAPSHOT_SOURCE + "/segment.jsonl"),
    ]
    assert all(SNAPSHOT in args or args[:2] == ("cat", "blob") for args in calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("type", "symlink"),
        ("links", 2),
        ("links", None),
        ("links", True),
        ("uid", -1),
        ("gid", -1),
        ("mode", 0o644),
        ("size", 0),
        ("size", True),
        ("size", formats.MAX_SEGMENT_BYTES + 1),
        ("content", []),
        ("content", ["abbrev"]),
        ("subtree", "b" * 64),
        ("linktarget", "/private"),
        ("linktarget_raw", "eA=="),
        ("extended_attributes", [{"name": "user.unknown", "value": "eA=="}]),
        ("generic_attributes", {"unknown": "x"}),
        ("error", "partial file"),
        ("device", 1),
    ],
)
def test_payload_inode_metadata_fails_before_any_restore(
    repository: Repository, tmp_path: Path, field: str, value: object
) -> None:
    snapshot, responses, calls = repository
    tree = next(value for key, value in reversed(responses.items()) if key[:2] == ("cat", "blob"))
    tree["nodes"][0][field] = value
    with pytest.raises(BackupIdentityError):
        verify(snapshot, tmp_path)
    assert not any(args[0] == "dump" for args in calls)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "missing",
        "duplicate",
        "path-escape",
        "parent-symlink",
        "cycle",
        "oversize",
        "snapshot-path",
        "snapshot-host",
        "snapshot-tags",
    ],
)
def test_untrusted_tree_shape_or_snapshot_identity_cannot_choose_paths(
    repository: Repository, tmp_path: Path, fault: str
) -> None:
    snapshot, responses, calls = repository
    tree_keys = [key for key in responses if key[:2] == ("cat", "blob")]
    leaf = responses[tree_keys[-1]]["nodes"]
    first = responses[tree_keys[0]]["nodes"][0]
    header = responses[("cat", "snapshot", SNAPSHOT)]
    if fault == "extra":
        leaf.append(copy.deepcopy(leaf[0]))
    elif fault == "missing":
        leaf.pop()
    elif fault == "duplicate":
        leaf[1] = copy.deepcopy(leaf[0])
    elif fault == "path-escape":
        leaf[0]["name"] = "../descriptor.json"
    elif fault == "parent-symlink":
        first["type"] = "symlink"
    elif fault == "cycle":
        first["subtree"] = tree_keys[0][2]
    elif fault == "oversize":
        header["unknown"] = "x" * adapter.MAX_TREE_METADATA_BYTES
    elif fault == "snapshot-path":
        header["paths"] = ["/elsewhere"]
    elif fault == "snapshot-host":
        header["hostname"] = "other-node"
    else:
        header["tags"].append("scheduled")
    with pytest.raises(BackupIdentityError):
        verify(snapshot, tmp_path)
    assert not any(args[0] == "dump" for args in calls)


@pytest.mark.parametrize("fault", ["descriptor", "segment", "size", "noncanonical"])
def test_restored_bytes_must_agree_with_tree_descriptor_and_full_chain(
    repository: Repository, tmp_path: Path, fault: str
) -> None:
    snapshot, responses, _ = repository
    key = (
        "dump",
        SNAPSHOT,
        adapter.SNAPSHOT_SOURCE + ("/segment.jsonl" if fault == "segment" else "/descriptor.json"),
    )
    if fault == "size":
        tree = next(
            value for key, value in reversed(responses.items()) if key[:2] == ("cat", "blob")
        )
        tree["nodes"][0]["size"] += 1
    elif fault == "noncanonical":
        responses[key] = b" " + responses[key]
    else:
        responses[key] = (
            responses[key].replace(b"2026", b"2025") if fault == "descriptor" else b"{}\n"
        )
        if fault == "descriptor":
            document = json.loads(responses[key])
            document["lineageId"] = "0198d17f-6f4a-7000-8000-000000000099"
            responses[key] = canonical_json_bytes(document)
    with pytest.raises(BackupIdentityError):
        verify(snapshot, tmp_path)
