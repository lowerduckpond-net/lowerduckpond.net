from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import DurabilityBoundary, LockManager, StateRepository
from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.backup_identity import (
    BINDING_FORMAT,
    GENESIS_PATH,
    LINEAGE_PATH,
    MAX_IDENTITY_BYTES,
    BackupIdentityError,
    RepositoryIdentity,
    canonical_locator,
    decode_lineage,
    framed_digest,
)
from lowerduckpond_static_host_agent.backup_lineage import lineage_for_repository
from lowerduckpond_static_host_agent.durable import FailureHook, StatePathError

FIXTURES = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
IDENTITY = RepositoryIdentity("a" * 64, "source-node", "s3:https://nyc3.example.test/backups/m3")


@pytest.fixture
def state(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    for name in ("audit", "platform", "locks"):
        (root / name).mkdir(mode=0o700)
    with LockManager.initialize(root / "locks", expected_owner=os.geteuid()):
        pass
    namespace = root / "platform/namespace.json"
    namespace.write_bytes(
        canonical_json_bytes(json.loads((FIXTURES / "platform-namespace.json").read_bytes()))
    )
    namespace.chmod(0o600)
    _append(root, 0)
    return root


def _append(root: Path, sequence: int) -> None:
    entry = json.loads((FIXTURES / "audit-entry.json").read_bytes())
    with StateRepository(root, expected_owner=os.geteuid()) as repository:
        audit = repository.inspect_audit()
        entry["sequence"] = sequence
        entry["previousEntryDigest"] = audit.terminal_digest
        entry["correlationId"] = f"0198d17f-6f4a-7000-8000-{sequence + 1:012x}"
        repository.append_audit(entry)


def _remote(root: Path) -> dict[str, object] | None:
    path = root.parent / "repository-genesis.json"
    return decode_lineage(path.read_bytes()) if path.exists() else None


def _lineage(
    root: Path,
    *,
    initialize: bool = True,
    identity: RepositoryIdentity = IDENTITY,
    failure_hook: FailureHook | None = None,
    genesis_failure_hook: FailureHook | None = None,
) -> dict[str, object]:
    # State-layer tests use a separate durable repository stand-in. Real Restic
    # and the coordinator are covered independently; it survives local tree loss.
    remote = _remote(root)
    if remote is None and initialize:
        remote = lineage_for_repository(
            root,
            identity,
            snapshot_tags=(),
            initialize=True,
            expected_owner=os.geteuid(),
            repository_genesis=None,
            commit=False,
            genesis_failure_hook=genesis_failure_hook,
        )
        (root.parent / "repository-genesis.json").write_bytes(canonical_json_bytes(remote))
    return lineage_for_repository(
        root,
        identity,
        snapshot_tags=(),
        initialize=initialize,
        expected_owner=os.geteuid(),
        repository_genesis=remote,
        failure_hook=failure_hook,
    )


def test_binding_golden_uses_64_bit_framing_and_excludes_mutable_configuration() -> None:
    payload = canonical_json_bytes(IDENTITY.document())
    framed = BINDING_FORMAT.encode() + b"\0" + len(payload).to_bytes(8, "big") + payload
    assert IDENTITY.binding() == {
        "format": BINDING_FORMAT,
        "algorithm": "sha256",
        "value": hashlib.sha256(framed).hexdigest(),
    }
    assert framed_digest("lowerduckpond-audit-lineage-v1", payload) != IDENTITY.binding()
    assert set(IDENTITY.document()) == {"schema", "configId", "nodeName", "locator"}


@pytest.mark.parametrize(
    "locator",
    [
        "s3:NYC3.example.test/backups/m3/",
        "s3:https://nyc3.example.test:443/backups/m3",
        "s3://nyc3.example.test/backups/m3",
    ],
)
def test_equivalent_s3_locators_bind_one_location(locator: str) -> None:
    assert canonical_locator(locator) == IDENTITY.locator


@pytest.mark.parametrize(
    "locator",
    [
        "s3:https://key:secret@nyc3.example.test/backups",
        "s3:http://nyc3.example.test/backups",
        "s3:https://nyc3.example.test/backups?credential=secret",
        "s3:https://nyc3.example.test/backups#fragment",
        "s3:https://nyc3.example.test/backups/%2e%2e",
        "s3:https://nyc3.example.test/backups/../other",
        "s3:https://nyc3.example.test/backups//m3",
        "s3:https://nyc3.example.test/backups/./m3",
        "s3:https://nyc3.example.test/",
        "rclone:remote:backups",
        "relative/path",
        "/",
        "//host/path",
        "s3:https://nyc3.example.test\n/backups",
    ],
)
def test_ambiguous_or_secret_bearing_locators_are_rejected(locator: str) -> None:
    with pytest.raises(BackupIdentityError):
        canonical_locator(locator)


def test_init_preserves_audit_and_reapplication_keeps_original_identity(state: Path) -> None:
    audit_path = state / "audit/segment-00000000000000000000.jsonl"
    before = audit_path.read_bytes()
    first = _lineage(state)
    path = state.joinpath(*LINEAGE_PATH)
    raw = path.read_bytes()
    inode = path.stat().st_ino
    assert first["initialEntryCount"] == 1
    assert audit_path.read_bytes() == before
    assert decode_lineage(raw) == first
    _append(state, 1)
    assert _lineage(state, initialize=False) == first
    assert _lineage(state) == first
    assert path.stat().st_ino == inode and path.read_bytes() == raw


def test_verify_does_not_initialize_missing_identity(state: Path) -> None:
    with pytest.raises(BackupIdentityError, match="not been initialized"):
        _lineage(state, initialize=False)
    assert not state.joinpath(*LINEAGE_PATH).exists()


def test_state_lock_replaced_during_acquisition_never_publishes_lineage(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = fcntl.flock
    path = state / "locks/tenant-state.lock"

    def replace_after_lock(descriptor: int, operation: int) -> None:
        original(descriptor, operation)
        if operation == fcntl.LOCK_EX:
            path.rename(path.with_suffix(".old"))
            path.write_bytes(b"")
            path.chmod(0o600)

    monkeypatch.setattr(fcntl, "flock", replace_after_lock)
    with pytest.raises(StatePathError, match="lock identity changed"):
        _lineage(state)
    assert not state.joinpath(*LINEAGE_PATH).exists()


@pytest.mark.parametrize("field", ["config", "node", "location"])
def test_identity_changes_never_rebind_existing_lineage(state: Path, field: str) -> None:
    _lineage(state)
    path = state.joinpath(*LINEAGE_PATH)
    before = path.read_bytes()
    changed = RepositoryIdentity(
        "b" * 64 if field == "config" else IDENTITY.config_id,
        "new-node" if field == "node" else IDENTITY.node_name,
        IDENTITY.locator + "-other" if field == "location" else IDENTITY.locator,
    )
    with pytest.raises(BackupIdentityError, match="binding changed"):
        _lineage(state, identity=changed)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "boundary",
    [
        DurabilityBoundary.WRITE,
        DurabilityBoundary.FILE_SYNC,
        DurabilityBoundary.RENAME,
        DurabilityBoundary.DIRECTORY_SYNC,
    ],
)
@pytest.mark.parametrize("process_exit", [False, True])
@pytest.mark.parametrize("phase", ["genesis", "primary"])
def test_every_initialization_interruption_resumes_one_published_identity(
    state: Path, boundary: DurabilityBoundary, process_exit: bool, phase: str
) -> None:
    path = state.joinpath(*LINEAGE_PATH)

    def interrupt(observed: DurabilityBoundary) -> None:
        if observed is boundary:
            if process_exit:
                os._exit(23)
            raise InterruptedError("injected failure")

    def attempt() -> None:
        _lineage(
            state,
            failure_hook=interrupt if phase == "primary" else None,
            genesis_failure_hook=interrupt if phase == "genesis" else None,
        )

    if process_exit:
        pid = os.fork()
        if pid == 0:
            attempt()
            os._exit(0)
        assert os.waitpid(pid, 0)[1] == 23 << 8
    else:
        with pytest.raises(InterruptedError):
            attempt()
    published = path.read_bytes() if path.exists() else None
    anchor = state.joinpath(*GENESIS_PATH)
    genesis = anchor.read_bytes() if anchor.exists() else None
    recovered = _lineage(state)
    assert recovered["initialEntryCount"] == 1
    assert _lineage(state, initialize=False) == recovered
    if published is not None:
        assert path.read_bytes() == published
    if genesis is not None:
        assert anchor.read_bytes() == path.read_bytes() == genesis
    assert not list((state / "platform").glob(".ldp-state-*"))
    assert not list((state / "locks").glob(".ldp-state-*"))


@pytest.mark.parametrize(
    "tag",
    ["lowerduckpond-audit-archive", "lineage-unknown", "repository-unknown", "rotation-unknown"],
)
def test_repository_history_forbids_initializing_a_replacement_lineage(
    state: Path, tag: str
) -> None:
    with pytest.raises(BackupIdentityError, match="existing audit lineage"):
        lineage_for_repository(
            state,
            IDENTITY,
            snapshot_tags=(("source-node", (tag,)),),
            initialize=True,
            expected_owner=os.geteuid(),
            repository_genesis=_remote(state),
        )
    assert not state.joinpath(*LINEAGE_PATH).exists()


def test_existing_lineage_requires_exact_repository_and_node_tags(state: Path) -> None:
    record = _lineage(state)
    tags = (
        f"lineage-{record['lineageId']}",
        f"repository-{IDENTITY.binding()['value']}",
        "lowerduckpond-audit-archive",
    )
    assert (
        lineage_for_repository(
            state,
            IDENTITY,
            snapshot_tags=(("source-node", tags),),
            initialize=False,
            expected_owner=os.geteuid(),
            repository_genesis=_remote(state),
        )
        == record
    )
    for host, changed in (
        ("other", tags),
        ("source-node", tags[1:]),
        ("source-node", (*tags, "lineage-other")),
    ):
        with pytest.raises(BackupIdentityError, match="conflicts"):
            lineage_for_repository(
                state,
                IDENTITY,
                snapshot_tags=((host, changed),),
                initialize=True,
                expected_owner=os.geteuid(),
                repository_genesis=_remote(state),
            )


@pytest.mark.parametrize("damage", ["truncated", "forked", "archive-index"])
def test_missing_or_changed_audit_prefix_cannot_be_repaired_by_initializing(
    state: Path, damage: str
) -> None:
    _lineage(state)
    segment = state / "audit/segment-00000000000000000000.jsonl"
    if damage == "truncated":
        segment.unlink()
    elif damage == "forked":
        segment.unlink()
        entry = json.loads((FIXTURES / "audit-entry.json").read_bytes())
        entry["correlationId"] = "0198d17f-6f4a-7000-8000-111111111111"
        with StateRepository(state, expected_owner=os.geteuid()) as repository:
            repository.append_audit(entry)
    else:
        (state / "audit/archive").mkdir(mode=0o700)
    with pytest.raises((BackupIdentityError, AuditError)):
        _lineage(state)


@pytest.mark.parametrize(
    "damage",
    [
        "extra",
        "bool",
        "version",
        "digest",
        "uuid",
        "duplicate",
        "spaces",
        "oversize",
        "mode",
        "symlink",
        "hardlink",
    ],
)
def test_hostile_lineage_bytes_or_inode_never_authorize_reinitialization(
    state: Path, damage: str
) -> None:
    document = _lineage(state)
    path = state.joinpath(*LINEAGE_PATH)
    raw = path.read_bytes()
    if damage == "extra":
        document["extra"] = None
    elif damage == "bool":
        document["initialEntryCount"] = True
    elif damage == "version":
        document["schema"] = "lowerduckpond-audit-lineage-v2"
    elif damage == "digest":
        document["repositoryBinding"] = framed_digest("lowerduckpond-audit-lineage-v1", b"other")
    elif damage == "uuid":
        document["lineageId"] = "0198d17f-6f4a-4000-8000-111111111111"
    elif damage == "duplicate":
        path.write_bytes(raw[:-2] + b',"initialEntryCount":1}\n')
    elif damage == "spaces":
        path.write_bytes(b" " + raw)
    elif damage == "oversize":
        path.write_bytes(b" " * (MAX_IDENTITY_BYTES + 1))
    elif damage == "mode":
        path.chmod(0o644)
    elif damage == "symlink":
        path.rename(path.with_suffix(".original"))
        path.symlink_to(path.with_suffix(".original"))
    elif damage == "hardlink":
        path.with_suffix(".linked").hardlink_to(path)
    if damage in {"extra", "bool", "version", "digest", "uuid"}:
        path.write_bytes(canonical_json_bytes(document))
    with pytest.raises((BackupIdentityError, StatePathError)):
        _lineage(state)


def test_missing_primary_before_any_snapshot_resumes_the_original_genesis(state: Path) -> None:
    original = _lineage(state)
    primary = state.joinpath(*LINEAGE_PATH)
    anchor = state.joinpath(*GENESIS_PATH)
    raw = primary.read_bytes()
    assert anchor.read_bytes() == raw
    inode = anchor.stat().st_ino
    primary.unlink()
    with pytest.raises(BackupIdentityError, match="not been initialized"):
        _lineage(state, initialize=False)
    assert not primary.exists()
    _append(state, 1)
    assert _lineage(state) == original
    assert primary.read_bytes() == anchor.read_bytes() == raw
    assert anchor.stat().st_ino == inode


@pytest.mark.parametrize("damage", ["missing", "corrupt", "conflict", "symlink", "mode"])
def test_missing_or_inconsistent_genesis_never_rebinds_primary(state: Path, damage: str) -> None:
    _lineage(state)
    primary = state.joinpath(*LINEAGE_PATH)
    original = primary.read_bytes()
    anchor = state.joinpath(*GENESIS_PATH)
    if damage == "missing":
        anchor.unlink()
    elif damage == "corrupt":
        anchor.write_bytes(b"{}\n")
    elif damage == "conflict":
        record = json.loads(anchor.read_bytes())
        record["lineageId"] = "0198d17f-6f4a-7000-8000-111111111111"
        anchor.write_bytes(canonical_json_bytes(record))
    elif damage == "symlink":
        anchor.unlink()
        anchor.symlink_to(primary)
    elif damage == "mode":
        anchor.chmod(0o644)
    with pytest.raises((BackupIdentityError, StatePathError)):
        _lineage(state)
    assert primary.read_bytes() == original


def test_repository_history_prevents_reset_when_both_local_identity_records_are_lost(
    state: Path,
) -> None:
    original = _lineage(state)
    state.joinpath(*LINEAGE_PATH).unlink()
    state.joinpath(*GENESIS_PATH).unlink()
    tags = (f"lineage-{original['lineageId']}", f"repository-{IDENTITY.binding()['value']}")
    with pytest.raises(BackupIdentityError, match="existing audit lineage"):
        lineage_for_repository(
            state,
            IDENTITY,
            snapshot_tags=((IDENTITY.node_name, tags),),
            initialize=True,
            expected_owner=os.geteuid(),
            repository_genesis=_remote(state),
        )
    assert not state.joinpath(*LINEAGE_PATH).exists()
    assert not state.joinpath(*GENESIS_PATH).exists()


def test_old_scheduled_restore_without_both_records_cannot_create_new_genesis(state: Path) -> None:
    original = _lineage(state)
    state.joinpath(*LINEAGE_PATH).unlink()
    state.joinpath(*GENESIS_PATH).unlink()
    with pytest.raises(BackupIdentityError, match="existing audit lineage"):
        _lineage(state)
    assert _remote(state) == original
    assert not state.joinpath(*LINEAGE_PATH).exists()
    assert not state.joinpath(*GENESIS_PATH).exists()


def test_primary_publication_requires_restored_repository_evidence(state: Path) -> None:
    candidate = lineage_for_repository(
        state,
        IDENTITY,
        snapshot_tags=(),
        initialize=True,
        expected_owner=os.geteuid(),
        repository_genesis=None,
        commit=False,
    )
    assert state.joinpath(*GENESIS_PATH).exists()
    assert not state.joinpath(*LINEAGE_PATH).exists()
    with pytest.raises(BackupIdentityError, match="repository lineage evidence is missing"):
        lineage_for_repository(
            state,
            IDENTITY,
            snapshot_tags=(),
            initialize=True,
            expected_owner=os.geteuid(),
            repository_genesis=None,
        )
    assert not state.joinpath(*LINEAGE_PATH).exists()
    assert candidate == decode_lineage(state.joinpath(*GENESIS_PATH).read_bytes())
