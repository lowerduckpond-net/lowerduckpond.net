from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Mapping
from pathlib import PurePosixPath
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object
from lowerduckpond_static_host_agent import host_restore_snapshot as snapshot
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, RepositoryIdentity
from lowerduckpond_static_host_agent.backup_restic import RepositorySnapshot
from lowerduckpond_static_host_agent.backup_snapshot import STATIC_BACKUP_TAG
from lowerduckpond_static_host_agent.backup_sources import SOURCE_PATHS, STAGED_PATHS
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - pytest fixture
from test_backup_capture import Capture
from test_backup_capture import capture as capture  # noqa: PLC0414 - real descriptor fixture
from test_backup_capture import fixture as fixture  # noqa: PLC0414


@pytest.fixture
def restic(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> tuple[snapshot.RestoreSnapshot, dict[str, dict[str, object]]]:
    descriptor = capture.descriptor()
    raw = canonical_json_bytes(descriptor, maximum_bytes=256 * 1024)
    identity = RepositoryIdentity("a" * 64, "source-node", "/private/backup")
    selected = snapshot.RestoreSnapshot(
        identity,
        RepositorySnapshot(
            "d" * 64,
            "source-node",
            (
                "scheduled",
                STATIC_BACKUP_TAG,
                "scope-" + "e" * 64,
                f"capture-{descriptor['captureId']}",
                f"lineage-{capture.state.lineage['lineageId']}",
                f"repository-{identity.binding()['value']}",
            ),
            (*SOURCE_PATHS.values(), *STAGED_PATHS.values()),
        ),
        raw,
        capture.state.lineage,
    )
    paths: dict[str, dict[str, object]] = {}

    def directory(path: str, mode: int = 0o755) -> None:
        if path == "/" or path in paths:
            return
        directory(str(PurePosixPath(path).parent))
        paths[path] = {
            "name": PurePosixPath(path).name,
            "type": "dir",
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "mode": (1 << 31) | mode,
            "content": None,
        }

    for label, installed in SOURCE_PATHS.items():
        root = capture.roots[label]
        for local in (root, *root.rglob("*")):
            relative = local.relative_to(root)
            if str(relative) in {"intake", "exports", "sites/.staging"}:
                continue
            target = str(PurePosixPath(installed) / relative)
            metadata = local.stat()
            if local.is_dir():
                directory(target, stat.S_IMODE(metadata.st_mode))
            else:
                directory(str(PurePosixPath(target).parent))
                paths[target] = {
                    "name": local.name,
                    "type": "file",
                    "uid": os.geteuid(),
                    "gid": os.getegid(),
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "links": 1,
                    "size": metadata.st_size,
                    "content": ["f" * 64] if metadata.st_size else [],
                }
    for label, installed in STAGED_PATHS.items():
        directory(str(PurePosixPath(installed).parent))
        paths[installed] = {
            "name": PurePosixPath(installed).name,
            "type": "file",
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "mode": 0o600,
            "links": 1,
            "size": len(raw) if label == "descriptor" else 5,
            "content": ["f" * 64],
        }
    trees = {
        hashlib.sha256(path.encode()).hexdigest(): path
        for path in ("/", *paths)
        if path == "/" or paths[path]["type"] == "dir"
    }

    def read(arguments: tuple[str, ...], _environment: object, limit: int) -> bytes:
        if arguments == ("dump", "d" * 64, STAGED_PATHS["descriptor"]):
            result = raw
        elif arguments == ("cat", "snapshot", "d" * 64):
            result = canonical_json_bytes(
                {
                    "hostname": "source-node",
                    "paths": list(selected.snapshot.paths),
                    "tags": list(selected.snapshot.tags),
                    "tree": hashlib.sha256(b"/").hexdigest(),
                }
            )
        else:
            assert arguments[:2] == ("cat", "blob")
            parent = trees[arguments[2]]
            nodes = []
            for path, value in paths.items():
                if str(PurePosixPath(path).parent) == parent:
                    node = dict(value)
                    if node["type"] == "dir":
                        node["subtree"] = hashlib.sha256(path.encode()).hexdigest()
                    nodes.append(node)
            result = canonical_json_bytes({"nodes": nodes}, maximum_bytes=limit)
        assert len(result) <= limit
        return result

    monkeypatch.setattr(snapshot, "_restic", read)
    monkeypatch.setattr(
        snapshot, "discover_repository", lambda env: (identity, (selected.snapshot,))
    )
    monkeypatch.setattr(snapshot, "repository_genesis", lambda *args: capture.state.lineage)
    return selected, paths


def inspect(selected: snapshot.RestoreSnapshot) -> dict[str, object]:
    return snapshot.inspect_restore_tree(
        selected,
        {},
        owner=os.geteuid(),
        group=os.getegid(),
        fragments=dict.fromkeys((*SOURCE_PATHS, *STAGED_PATHS), 4096),
    )


def test_full_identity_and_complete_tree_are_proven_before_any_restore_allocation(
    restic: tuple[snapshot.RestoreSnapshot, dict[str, dict[str, object]]],
) -> None:
    selected, _ = restic
    assert snapshot.select_restore_snapshot("d" * 64, {}) == selected
    result = inspect(selected)
    assert result["snapshotId"] == "d" * 64
    assert set(cast(dict[str, object], result["sourceUsage"])) == set(SOURCE_PATHS) | set(
        STAGED_PATHS
    )
    with pytest.raises(HostRestoreError):
        snapshot.select_restore_snapshot("dddddddd", {})


@pytest.mark.parametrize("field", ["paths", "tags"])
@pytest.mark.parametrize(
    "change", ["reorder", "duplicate", "missing", "extra", "different", "non-string", "not-list"]
)
def test_header_membership_is_order_independent_but_exact(
    restic: tuple[snapshot.RestoreSnapshot, dict[str, dict[str, object]]],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    change: str,
) -> None:
    selected, _ = restic
    original = cast(
        Callable[[tuple[str, ...], Mapping[str, str], int], bytes], vars(snapshot)["_restic"]
    )

    def changed_header(
        arguments: tuple[str, ...], environment: Mapping[str, str], limit: int
    ) -> bytes:
        raw = original(arguments, environment, limit)
        if arguments != ("cat", "snapshot", selected.snapshot.snapshot_id):
            return raw
        header = decode_json_object(raw)
        values = cast(list[object], header[field])
        replacements: dict[str, object] = {
            "reorder": values[::-1],
            "duplicate": [*values[:-1], values[0]],
            "missing": values[:-1],
            "extra": [*values, "unexpected"],
            "different": [*values[:-1], "unexpected"],
            "non-string": [*values[:-1], 1],
            "not-list": None,
        }
        header[field] = replacements[change]
        return canonical_json_bytes(header)

    monkeypatch.setattr(snapshot, "_restic", changed_header)
    if change == "reorder":
        assert inspect(selected)["snapshotId"] == selected.snapshot.snapshot_id
    else:
        with pytest.raises(HostRestoreError, match="restore_snapshot_header_mismatch"):
            inspect(selected)


@pytest.mark.parametrize("size_present", [False, True])
@pytest.mark.parametrize("content", ["empty", "nonempty", "missing", "null"])
def test_empty_file_zero_size_encoding_cannot_hide_content(
    restic: tuple[snapshot.RestoreSnapshot, dict[str, dict[str, object]]],
    size_present: bool,
    content: str,
) -> None:
    selected, paths = restic
    node = next(node for node in paths.values() if node["type"] == "file" and node["size"] == 0)
    if not size_present:
        del node["size"]
    if content == "nonempty":
        node["content"] = ["f" * 64]
    elif content == "missing":
        del node["content"]
    elif content == "null":
        node["content"] = None
    if content == "empty":
        assert inspect(selected)["snapshotId"] == selected.snapshot.snapshot_id
    else:
        with pytest.raises(HostRestoreError):
            inspect(selected)


@pytest.mark.parametrize(
    "fault",
    ["link", "hardlink", "xattr", "owner", "mode", "size", "missing", "excluded", "unknown"],
)
def test_snapshot_hostile_nodes_and_hidden_transients_fail_before_materialization(
    restic: tuple[snapshot.RestoreSnapshot, dict[str, dict[str, object]]],
    fault: str,
) -> None:
    selected, paths = restic
    file = SOURCE_PATHS["state"] + "/platform/namespace.json"
    node = paths[file]
    if fault == "link":
        node["type"] = "symlink"
        node["linktarget"] = "/etc/shadow"
    elif fault == "hardlink":
        node["links"] = 2
    elif fault == "xattr":
        node["extended_attributes"] = [{"name": "security.capability", "value": "unsafe"}]
    elif fault == "owner":
        node["uid"] = os.geteuid() + 1
    elif fault == "mode":
        node["mode"] = 0o660
    elif fault == "size":
        node["size"] = 32 * 1024 * 1024 + 1
    elif fault == "missing":
        del paths[file]
    elif fault == "excluded":
        target = SOURCE_PATHS["state"] + "/intake"
        paths[target] = {**node, "name": "intake"}
    else:
        paths["/etc-shadow"] = {**node, "name": "etc-shadow"}
    with pytest.raises((HostRestoreError, BackupIdentityError)):
        inspect(selected)
