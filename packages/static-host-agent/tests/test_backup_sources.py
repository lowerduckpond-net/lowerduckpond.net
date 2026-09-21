from __future__ import annotations

import os
import stat
from io import BytesIO
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent import backup_sources as sources
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.locks import LockOrderError


@pytest.mark.parametrize("directory", [False, True])
def test_private_state_accepts_executor_group_without_granting_group_access(
    directory: bool,
) -> None:
    walker = sources._Walk(owner=0, content_group=991, stream=BytesIO())
    kind = stat.S_IFDIR if directory else stat.S_IFREG
    mode = 0o700 if directory else 0o600

    def metadata(group: int, permissions: int) -> os.stat_result:
        return os.stat_result((kind | permissions, 1, 10, 1, 0, group, 0, 0, 0, 0))

    for group in (0, 991):
        walker.validate(metadata(group, mode), ("state", "record"), directory=directory, device=10)
    with pytest.raises(BackupIdentityError, match="unsafe"):
        walker.validate(metadata(992, mode), ("state", "record"), directory=directory, device=10)
    with pytest.raises(BackupIdentityError, match="unsafe"):
        walker.validate(
            metadata(991, mode | 0o040), ("state", "record"), directory=directory, device=10
        )


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    # Component tests use a deterministic capacity observation. This workspace's
    # virtual filesystem reports zero inodes; installed fixtures prove real ext4.
    def capacity(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            device=os.fstat(descriptor).st_dev,
            fragment_size=4096,
            total_blocks=32_000_000,
            available_blocks=25_000_000,
            total_inodes=2_000_000,
            available_inodes=1_000_000,
        )

    monkeypatch.setattr(sources, "measure_filesystem_capacity_descriptor", capacity)
    roots = {name: tmp_path / name for name in sources.SOURCE_PATHS}
    for name, path in roots.items():
        path.mkdir(mode=0o711 if name == "content" else 0o700)
    (tmp_path / "workspace").mkdir(mode=0o700)
    (roots["state"] / "locks").mkdir(mode=0o700)
    with LockManager.initialize(roots["state"] / "locks", expected_owner=os.geteuid()):
        pass
    for excluded in (
        roots["state"] / "intake",
        roots["state"] / "exports",
        roots["content"] / "sites",
    ):
        excluded.mkdir(mode=0o710 if excluded.name == "sites" else 0o700)
    (roots["content"] / "sites/.staging").mkdir(mode=0o700)
    fixture = roots["content"] / "fixture"
    fixture.mkdir(mode=0o750)
    (fixture / "index.html").write_bytes(b"original fixture")
    (fixture / "index.html").chmod(0o640)
    return roots


def _capture(roots: dict[str, Path]) -> sources.BackupTree:
    with (
        LockManager(roots["state"] / "locks", expected_owner=os.geteuid()) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
        locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED),
    ):
        return sources.measure_backup_sources(
            roots,
            roots["state"].parent / "workspace",
            locks=locks,
            expected_owner=os.geteuid(),
            content_group=os.getegid(),
        )


def test_tree_digest_binds_paths_modes_and_bytes_but_not_excluded_secrets(
    roots: dict[str, Path],
) -> None:
    original = _capture(roots)
    for excluded in (
        roots["state"] / "intake",
        roots["state"] / "exports",
        roots["content"] / "sites/.staging",
    ):
        (excluded / "canary").write_bytes(b"must never enter a backup")
    temporary = roots["state"] / (".ldp-state-" + "a" * 32)
    temporary.write_bytes(b"unpublished sensitive bytes")
    temporary.chmod(0o600)
    assert _capture(roots) == original
    assert temporary.exists()
    fixture = roots["content"] / "fixture/index.html"
    fixture.write_bytes(b"changed fixture")
    changed = _capture(roots)
    assert changed.digest != original.digest
    fixture.write_bytes(b"original fixture")
    fixture.chmod(0o644)
    assert _capture(roots).digest != original.digest
    fixture.chmod(0o640)
    fixture.rename(fixture.with_name("renamed.html"))
    assert _capture(roots).digest != original.digest


def test_tenant_content_with_temporary_looking_name_remains_authoritative(
    roots: dict[str, Path],
) -> None:
    before = _capture(roots)
    content = roots["content"] / "fixture" / (".ldp-state-" + "a" * 32)
    content.write_bytes(b"ordinary tenant content")
    content.chmod(0o644)
    after = _capture(roots)
    assert after.entries == before.entries + 1
    assert after.content_bytes == before.content_bytes + len(content.read_bytes())
    assert after.digest != before.digest


@pytest.mark.parametrize(
    "damage", ["symlink", "hardlink", "fifo", "mode", "xattr", "bad-temporary"]
)
def test_unsafe_authority_is_rejected_without_copy_or_cleanup(
    roots: dict[str, Path],
    damage: str,
) -> None:
    path = roots["state"] / "record"
    if damage == "symlink":
        path.symlink_to(roots["content"] / "fixture/index.html")
    elif damage == "fifo":
        os.mkfifo(path, 0o600)
    else:
        if damage == "bad-temporary":
            path = path.with_name(".ldp-state-invalid")
        path.write_bytes(b"private state")
        path.chmod(0o644 if damage == "mode" else 0o600)
        if damage == "hardlink":
            (roots["state"].parent / "outside-link").hardlink_to(path)
        if damage == "xattr":
            os.setxattr(path, "user.unclassified", b"private")
    with pytest.raises(BackupIdentityError):
        _capture(roots)
    assert path.exists()


@pytest.mark.parametrize(
    "bound",
    ["MAX_TREE_ENTRIES", "MAX_TREE_BYTES", "MAX_INVENTORY_BYTES", "MAX_FILE_BYTES", "MAX_DEPTH"],
)
def test_capture_enforces_each_fixed_resource_bound(
    roots: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    bound: str,
) -> None:
    monkeypatch.setattr(sources, bound, 1)
    with pytest.raises(BackupIdentityError):
        _capture(roots)
    assert not list((roots["state"].parent / "workspace").iterdir())


def test_mid_read_mutation_never_returns_a_tree_digest(
    roots: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = roots["content"] / "fixture/index.html"
    inode = path.stat().st_ino
    original = os.read
    changed = False

    def mutate(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original(descriptor, size)
        if not changed and os.fstat(descriptor).st_ino == inode:
            path.write_bytes(b"replacement fixture")
            changed = True
        return chunk

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(BackupIdentityError):
        _capture(roots)
    assert changed


def test_capture_preserves_real_capacity_policy_when_inode_observation_is_unavailable(
    roots: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            device=os.fstat(descriptor).st_dev,
            fragment_size=4096,
            total_blocks=32_000_000,
            available_blocks=25_000_000,
            total_inodes=0,
            available_inodes=0,
        )

    monkeypatch.setattr(sources, "measure_filesystem_capacity_descriptor", unavailable)
    with pytest.raises(CapacityRejectedError, match="available inodes"):
        _capture(roots)
    assert not list((roots["state"].parent / "workspace").iterdir())


@pytest.mark.parametrize("held", [LockName.PUBLICATION, LockName.TENANT_STATE])
def test_capture_requires_both_static_leases(roots: dict[str, Path], held: LockName) -> None:
    with (
        LockManager(roots["state"] / "locks", expected_owner=os.geteuid()) as locks,
        locks.acquire(held, mode=LockMode.SHARED),
        pytest.raises(LockOrderError),
    ):
        sources.measure_backup_sources(
            roots,
            roots["state"].parent / "workspace",
            locks=locks,
            expected_owner=os.geteuid(),
            content_group=os.getegid(),
        )
