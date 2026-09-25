"""Production namespace migration preserves history and the original attempt."""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import ContractError, canonical_json_bytes
from lowerduckpond_static_host_agent import production_namespace as migration
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, StatePathError
from lowerduckpond_static_host_agent.locks import LockManager, LockOrderError

CRASH_STATUS = 86
NAMESPACE = canonical_json_bytes(
    {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": "2026-09-25T00:00:00Z",
    }
)


@pytest.fixture
def state(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    for name in migration.ROOTS:
        (root / name).mkdir(mode=0o700)
    for name in migration.AUTHORIZATION:
        (root / "authorization" / name).mkdir(mode=0o700)
    with LockManager.initialize(root / "locks", expected_owner=os.geteuid()):
        pass
    return root


def snapshot(root: Path) -> dict[str, tuple[int, int, bytes | None]]:
    return {
        str(path.relative_to(root)): (
            path.lstat().st_ino,
            path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in root.rglob("*")
        if not path.is_symlink() and not path.is_fifo()
    }


def initialize(root: Path) -> bool:
    return migration.initialize_namespace(root, NAMESPACE, expected_owner=os.geteuid())


def inspect(root: Path) -> bytes | None:
    return migration.inspect_empty_history(root, expected_owner=os.geteuid())


def test_readonly_preflight_and_retry_preserve_original_identity(state: Path) -> None:
    original = snapshot(state)
    assert inspect(state) is None
    assert snapshot(state) == original
    assert initialize(state)
    initialized = snapshot(state)
    assert inspect(state) == NAMESPACE
    assert not initialize(state)
    assert snapshot(state) == initialized
    assert set(initialized) - set(original) == {"platform/namespace.json"}
    for key, value in original.items():
        if key != "platform":
            assert initialized[key] == value


@pytest.mark.parametrize(
    "name",
    [
        "tenants/original",
        "audit/segment-00000000000000000000.jsonl",
        "platform/launch.json",
        "platform/archive-quarantine.json",
        "platform/audit-lineage.json",
        "locks/audit-lineage-genesis.json",
        "locks/authorization-recovery.cursor",
        "authorization/jobs/job.json",
        "authorization/results/result.json",
        "authorization/correlations/correlation.json",
        "intake/pending",
        "exports/pending",
        "intents/pending",
        "emergency",
    ],
)
def test_no_history_or_interrupted_identity_can_authorize_namespace_reset(
    state: Path, name: str
) -> None:
    (state / name).write_bytes(b"original retained authority")
    original = snapshot(state)
    for command in (inspect, initialize):
        with pytest.raises(StatePathError):
            command(state)
        assert snapshot(state) == original


@pytest.mark.parametrize("name", ["intake", "authorization/results", "platform", "audit"])
@pytest.mark.parametrize("fault", ["missing", "mode", "symlink"])
def test_empty_means_verified_present_directories_not_missing_or_unsafe_storage(
    state: Path, name: str, fault: str
) -> None:
    path = state / name
    if fault == "mode":
        path.chmod(0o755)
    else:
        path.rmdir()
        if fault == "symlink":
            replacement = state.parent / "replacement"
            replacement.mkdir(mode=0o700)
            path.symlink_to(replacement, target_is_directory=True)
    for command in (inspect, initialize):
        with pytest.raises((StatePathError, OSError)):
            command(state)
    assert not (state / "platform/namespace.json").exists()


@pytest.mark.parametrize("fault", ["different", "symlink", "hardlink", "mode", "fifo"])
def test_existing_namespace_must_be_the_exact_safe_original(state: Path, fault: str) -> None:
    assert initialize(state)
    path = state / "platform/namespace.json"
    if fault == "different":
        path.write_bytes(NAMESPACE.replace(b"T00:00:00Z", b"T01:00:00Z"))
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "hardlink":
        os.link(path, state.parent / "outside")
    else:
        path.unlink()
        if fault == "fifo":
            os.mkfifo(path)
        else:
            other = state.parent / "outside"
            other.write_bytes(NAMESPACE)
            other.chmod(0o600)
            path.symlink_to(other)
    before = path.lstat()
    with pytest.raises((StatePathError, OSError)):
        initialize(state)
    after = path.lstat()
    assert (before.st_ino, before.st_mtime_ns, before.st_mode) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_mode,
    )


@pytest.mark.parametrize(
    "raw",
    [NAMESPACE.rstrip(b"\n"), NAMESPACE + b"\n", b"{}\n", b"x" * 1025],
)
def test_only_the_original_canonical_namespace_can_be_supplied(state: Path, raw: bytes) -> None:
    before = snapshot(state)
    with pytest.raises((ValueError, ContractError)):
        migration.initialize_namespace(state, raw, expected_owner=os.geteuid())
    assert snapshot(state) == before


@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
def test_process_death_resumes_only_original_bytes(
    state: Path, boundary: DurabilityBoundary
) -> None:
    child = os.fork()
    if child == 0:

        def die(current: DurabilityBoundary) -> None:
            if current == boundary:
                os._exit(CRASH_STATUS)

        migration.initialize_namespace(
            state, NAMESPACE, expected_owner=os.geteuid(), failure_hook=die
        )
        os._exit(87)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == CRASH_STATUS
    published = (state / "platform/namespace.json").exists()
    before = snapshot(state)
    with pytest.raises(StatePathError):
        migration.initialize_namespace(
            state,
            NAMESPACE.replace(b"T00:00:00Z", b"T01:00:00Z"),
            expected_owner=os.geteuid(),
        )
    assert snapshot(state) == before
    if not published:
        before = snapshot(state)
        with pytest.raises(StatePathError):
            inspect(state)
        assert snapshot(state) == before
    assert initialize(state) is not published
    assert inspect(state) == NAMESPACE
    assert list((state / "platform").iterdir()) == [state / "platform/namespace.json"]


@pytest.mark.parametrize("fault", ["partial", "foreign-name", "foreign-bytes", "hardlink"])
def test_only_owned_partial_publication_can_be_retired(state: Path, fault: str) -> None:
    name = ".ldp-state-" + hashlib.sha256(NAMESPACE).hexdigest()[:32]
    if fault == "foreign-name":
        name = ".ldp-state-" + "a" * 32
    path = state / "platform" / name
    raw = b"foreign authority" if fault == "foreign-bytes" else NAMESPACE[:20]
    path.write_bytes(raw)
    path.chmod(0o600)
    if fault == "hardlink":
        os.link(path, state.parent / "other")
    if fault == "partial":
        assert initialize(state)
        assert not path.exists()
        assert inspect(state) == NAMESPACE
    else:
        before = snapshot(state)
        with pytest.raises(StatePathError):
            initialize(state)
        assert snapshot(state) == before


@pytest.mark.parametrize("replace_directory", [False, True])
def test_lock_replacement_during_acquisition_cannot_initialize(
    state: Path, monkeypatch: pytest.MonkeyPatch, *, replace_directory: bool
) -> None:
    original = fcntl.flock
    replaced = False

    def replace(descriptor: int, operation: int) -> None:
        nonlocal replaced
        original(descriptor, operation)
        if not replaced and operation & fcntl.LOCK_EX:
            replaced = True
            if replace_directory:
                (state / "locks").rename(state.parent / "old-locks")
                (state / "locks").mkdir(mode=0o700)
                with LockManager.initialize(state / "locks", expected_owner=os.geteuid()):
                    pass
            else:
                path = state / "locks/intake.lock"
                path.unlink()
                path.touch(mode=0o600)

    monkeypatch.setattr(fcntl, "flock", replace)
    with pytest.raises((StatePathError, LockOrderError)):
        initialize(state)
    assert not (state / "platform/namespace.json").exists()
