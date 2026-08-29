from __future__ import annotations

import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from multiprocessing import get_context
from multiprocessing.connection import Connection
from pathlib import Path
from threading import Event

import pytest
from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractError,
    ContractKind,
    canonical_json_bytes,
)
from lowerduckpond_static_host_agent import (
    LockManager,
    LockMode,
    StateAlreadyExistsError,
    StateConflictError,
    StatePathError,
    StateRecordError,
    StateRecordPath,
    StateRepository,
    StateRevision,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_OTHER_TENANT_ID = "0198d17f-6f4a-7000-8000-000000000001"
_DEPLOYMENT_ID = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_OTHER_DEPLOYMENT_ID = "0198d17f-6f4a-7000-8000-000000000002"
_JOB_ID = "0198d17f-6f4a-7000-8000-000000000002"
_INTENT_ID = "0198d17f-6f4a-7000-8000-000000000003"
_ARCHIVE_CONSTRUCTION_INTENT_ID = "0198d17f-6f4a-7000-8000-000000000004"
_ARCHIVE_RETIREMENT_INTENT_ID = "0198d17f-6f4a-7000-8000-000000000005"
_DIRECTORY_MODE = 0o700
_RECORD_MODE = 0o600
_PROCESS_TIMEOUT_SECONDS = 10


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(_DIRECTORY_MODE)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root)
    _mkdir(root / "platform")
    _mkdir(root / "tenants")
    _mkdir(root / "tenants" / _TENANT_ID)
    _mkdir(root / "tenants" / _TENANT_ID / "deployments")
    _mkdir(root / "tenants" / _TENANT_ID / "archives")
    _mkdir(root / "authorization")
    _mkdir(root / "authorization" / "jobs")
    _mkdir(root / "authorization" / "results")
    _mkdir(root / "authorization" / "correlations")
    _mkdir(root / "intents")
    _mkdir(root / "locks")
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _repository(root: Path) -> StateRepository:
    return StateRepository(root, expected_owner=os.geteuid())


def _write_record(root: Path, path: StateRecordPath, document: dict[str, object]) -> Path:
    parent = root
    for component in path.components[:-1]:
        parent /= component
        if not parent.exists():
            _mkdir(parent)
    target = root.joinpath(*path.components)
    target.write_bytes(canonical_json_bytes(document))
    target.chmod(_RECORD_MODE)
    return target


def _process_compare_and_swap(
    task: tuple[str, StateRevision, str],
    ready: Event,
    release: Event,
    connection: Connection,
) -> None:
    root, revision, slug = task
    candidate = _fixture("site.json")
    metadata = candidate["metadata"]
    assert type(metadata) is dict
    metadata["slug"] = slug
    ready.set()
    if not release.wait(_PROCESS_TIMEOUT_SECONDS):
        connection.send("timeout")
        connection.close()
        return
    try:
        with _repository(Path(root)) as repository:
            repository.compare_and_swap(
                StateRecordPath.tenant_desired(_TENANT_ID),
                revision,
                candidate,
                blocking=True,
            )
    except StateConflictError:
        connection.send("conflict")
    else:
        connection.send("committed")
    finally:
        connection.close()


def test_typed_paths_pin_the_committed_authoritative_layout() -> None:
    assert StateRecordPath.platform_namespace().components == ("platform", "namespace.json")
    assert StateRecordPath.platform_launch().components == ("platform", "launch.json")
    assert StateRecordPath.tenant_desired(_TENANT_ID).components == (
        "tenants",
        _TENANT_ID,
        "desired.json",
    )
    assert StateRecordPath.tenant_observed(_TENANT_ID).components == (
        "tenants",
        _TENANT_ID,
        "observed.json",
    )
    assert StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID).components == (
        "tenants",
        _TENANT_ID,
        "deployments",
        f"{_DEPLOYMENT_ID}.json",
    )
    assert StateRecordPath.tenant_archive(_TENANT_ID, _DEPLOYMENT_ID).components == (
        "tenants",
        _TENANT_ID,
        "archives",
        f"{_DEPLOYMENT_ID}.json",
    )
    assert StateRecordPath.authorization_job(_JOB_ID).components == (
        "authorization",
        "jobs",
        f"{_JOB_ID}.json",
    )
    assert StateRecordPath.authorization_result(_JOB_ID).components == (
        "authorization",
        "results",
        f"{_JOB_ID}.json",
    )
    assert StateRecordPath.emergency_result(_INTENT_ID).components == (
        "authorization",
        "results",
        f"{_INTENT_ID}.json",
    )
    assert StateRecordPath.authorization_correlation(_INTENT_ID).components == (
        "authorization",
        "correlations",
        f"{_INTENT_ID}.json",
    )
    assert StateRecordPath.transaction_intent(_INTENT_ID).components == (
        "intents",
        f"{_INTENT_ID}.json",
    )
    assert StateRecordPath.archive_construction_intent(
        _ARCHIVE_CONSTRUCTION_INTENT_ID
    ).components == ("intents", f"{_ARCHIVE_CONSTRUCTION_INTENT_ID}.json")
    assert StateRecordPath.archive_retirement_intent(_ARCHIVE_RETIREMENT_INTENT_ID).components == (
        "intents",
        f"{_ARCHIVE_RETIREMENT_INTENT_ID}.json",
    )


@pytest.mark.parametrize(
    "tenant_id",
    ["../escape", _TENANT_ID.upper(), f"{_TENANT_ID}/child", "not-a-uuid"],
)
def test_typed_paths_reject_noncanonical_or_escaping_identifiers(tenant_id: str) -> None:
    with pytest.raises(ContractError):
        StateRecordPath.tenant_desired(tenant_id)


@pytest.mark.parametrize(
    ("path", "fixture"),
    [
        (StateRecordPath.platform_namespace(), "platform-namespace.json"),
        (StateRecordPath.platform_launch(), "launch-record.json"),
        (StateRecordPath.tenant_desired(_TENANT_ID), "site.json"),
        (StateRecordPath.tenant_observed(_TENANT_ID), "tenant-observed-state.json"),
        (
            StateRecordPath.tenant_deployment(_TENANT_ID, _DEPLOYMENT_ID),
            "deployment-record.json",
        ),
        (
            StateRecordPath.tenant_archive(_TENANT_ID, _DEPLOYMENT_ID),
            "archive-record.json",
        ),
        (StateRecordPath.authorization_job(_JOB_ID), "authorization-job.json"),
        (StateRecordPath.authorization_result(_JOB_ID), "operation-result.json"),
        (
            StateRecordPath.authorization_correlation("0198d17f-6f4a-7000-8000-000000000001"),
            "authorization-job.json",
        ),
        (StateRecordPath.transaction_intent(_INTENT_ID), "transaction-intent.json"),
        (
            StateRecordPath.archive_construction_intent(_ARCHIVE_CONSTRUCTION_INTENT_ID),
            "archive-construction-intent.json",
        ),
        (
            StateRecordPath.archive_retirement_intent(_ARCHIVE_RETIREMENT_INTENT_ID),
            "archive-retirement-intent.json",
        ),
    ],
)
def test_reader_accepts_only_typed_canonical_contracts(
    tmp_path: Path,
    path: StateRecordPath,
    fixture: str,
) -> None:
    root = _state_root(tmp_path)
    document = _fixture(fixture)
    _write_record(root, path, document)

    with _repository(root) as repository:
        stored = repository.read(path)

    assert stored.document == document
    assert stored.revision.contract_kind is path.contract_kind
    assert stored.revision.byte_count == len(canonical_json_bytes(document))


def test_state_revision_has_a_pinned_domain_separated_representation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    document = _fixture("site.json")
    canonical = canonical_json_bytes(document)
    _write_record(root, path, document)

    with _repository(root) as repository:
        revision = repository.read(path).revision

    kind = ContractKind.SITE.value.encode("ascii")
    framed = (
        b"lowerduckpond-state-revision-v1\0"
        + len(kind).to_bytes(2, "big")
        + kind
        + len(canonical).to_bytes(4, "big")
        + canonical
    )
    assert revision.sha256 == hashlib.sha256(framed).hexdigest()


def test_emergency_result_binds_its_correlation_identity_to_the_result_path(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    result = _fixture("operation-result.json")
    del result["manifest"]
    result["operation"] = "delete"
    result["provenance"] = {
        "kind": "emergency-administrator",
        "operatorPrincipal": "operator@example.test",
        "reason": "verified operator recovery",
    }
    path = StateRecordPath.emergency_result("0198d17f-6f4a-7000-8000-000000000001")

    with _repository(root) as repository:
        created = repository.create_immutable(path, result)
        reread = repository.read(path)

    assert created.document == reread.document == result


def test_reader_rejects_schema_valid_but_noncanonical_bytes(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    document = _fixture("site.json")
    target = root.joinpath(*path.components)
    target.write_bytes(json.dumps(document, indent=2).encode())
    target.chmod(_RECORD_MODE)

    with _repository(root) as repository, pytest.raises(StateRecordError, match="canonical"):
        repository.read(path)


def test_reader_rejects_duplicate_members_before_trusting_state(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.platform_namespace()
    target = root.joinpath(*path.components)
    target.write_bytes(
        b'{"apiVersion":"hosting.lowerduckpond.net/v1alpha1",'
        b'"kind":"PlatformNamespace","kind":"PlatformNamespace",'
        b'"tenantOriginSuffix":"lowerduckpond.com"}\n'
    )
    target.chmod(_RECORD_MODE)

    with _repository(root) as repository, pytest.raises(ContractError):
        repository.read(path)


@pytest.mark.parametrize(
    ("wrong_path", "fixture"),
    [
        (StateRecordPath.tenant_desired(_OTHER_TENANT_ID), "site.json"),
        (
            StateRecordPath.tenant_observed(_OTHER_TENANT_ID),
            "tenant-observed-state.json",
        ),
        (
            StateRecordPath.tenant_deployment(_OTHER_TENANT_ID, _DEPLOYMENT_ID),
            "deployment-record.json",
        ),
        (
            StateRecordPath.tenant_deployment(_TENANT_ID, _OTHER_DEPLOYMENT_ID),
            "deployment-record.json",
        ),
        (
            StateRecordPath.tenant_archive(_OTHER_TENANT_ID, _DEPLOYMENT_ID),
            "archive-record.json",
        ),
        (
            StateRecordPath.tenant_archive(_TENANT_ID, _OTHER_DEPLOYMENT_ID),
            "archive-record.json",
        ),
        (StateRecordPath.authorization_job(_INTENT_ID), "authorization-job.json"),
        (StateRecordPath.authorization_result(_INTENT_ID), "operation-result.json"),
        (
            StateRecordPath.authorization_correlation(_JOB_ID),
            "authorization-job.json",
        ),
        (StateRecordPath.transaction_intent(_JOB_ID), "transaction-intent.json"),
        (
            StateRecordPath.archive_construction_intent(_JOB_ID),
            "archive-construction-intent.json",
        ),
        (
            StateRecordPath.archive_retirement_intent(_JOB_ID),
            "archive-retirement-intent.json",
        ),
    ],
)
def test_reader_rejects_a_valid_contract_stored_under_another_identity(
    tmp_path: Path,
    wrong_path: StateRecordPath,
    fixture: str,
) -> None:
    root = _state_root(tmp_path)
    _write_record(root, wrong_path, _fixture(fixture))

    with _repository(root) as repository, pytest.raises(StateRecordError, match="identity"):
        repository.read(wrong_path)


@pytest.mark.parametrize("unsafe_shape", ["mode", "hardlink", "symlink", "oversized"])
def test_reader_rejects_unsafe_final_inode_shapes(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    target = _write_record(root, path, _fixture("site.json"))
    if unsafe_shape == "mode":
        target.chmod(0o640)
    elif unsafe_shape == "hardlink":
        os.link(target, root / "linked-record.json")
    elif unsafe_shape == "symlink":
        outside = root / "outside.json"
        target.rename(outside)
        target.symlink_to(outside)
    else:
        target.write_bytes(b"x" * (MAX_CANONICAL_BYTES + 1))

    with _repository(root) as repository, pytest.raises(StatePathError):
        repository.read(path)


def test_repository_rejects_unsafe_root_and_intermediate_directory_modes(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    root.chmod(0o750)
    with pytest.raises(StatePathError, match="directory"):
        _repository(root)

    root.chmod(_DIRECTORY_MODE)
    (root / "tenants").chmod(0o750)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    _write_record(root, path, _fixture("site.json"))
    with _repository(root) as repository, pytest.raises(StatePathError, match="directory"):
        repository.read(path)


def test_reader_revalidates_the_open_root_directory_mode(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    _write_record(root, path, _fixture("site.json"))

    with _repository(root) as repository:
        root.chmod(0o750)
        with pytest.raises(StatePathError, match="directory"):
            repository.read(path)


def test_reader_revalidates_the_open_lock_directory_mode(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    _write_record(root, path, _fixture("site.json"))

    with _repository(root) as repository:
        (root / "locks").chmod(0o750)
        with pytest.raises(StatePathError, match="directory"):
            repository.read(path)


def test_immutable_create_validates_then_publishes_exact_canonical_bytes(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    document = _fixture("site.json")

    with _repository(root) as repository:
        created = repository.create_immutable(path, document)
        with pytest.raises(StateAlreadyExistsError):
            repository.create_immutable(path, deepcopy(document))

    target = root.joinpath(*path.components)
    assert created.document == document
    assert target.read_bytes() == canonical_json_bytes(document)
    assert stat.S_IMODE(target.stat().st_mode) == _RECORD_MODE
    assert list(target.parent.glob(".ldp-state-*")) == []


def test_compare_and_swap_commits_only_the_expected_generation(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    original = _fixture("site.json")
    updated = deepcopy(original)
    updated_metadata = updated["metadata"]
    assert type(updated_metadata) is dict
    updated_metadata["slug"] = "new-duck-repair"

    with _repository(root) as repository:
        created = repository.create_immutable(path, original)
        committed = repository.compare_and_swap(path, created.revision, updated)
        with pytest.raises(StateConflictError):
            repository.compare_and_swap(path, created.revision, original)
        current = repository.read(path)

    assert committed.document == updated
    assert committed.revision != created.revision
    assert current.document == updated
    assert current.revision == committed.revision


def test_invalid_compare_and_swap_candidate_cannot_mutate_current_state(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    original = _fixture("site.json")
    invalid = deepcopy(original)
    invalid["unknown"] = True

    with _repository(root) as repository:
        created = repository.create_immutable(path, original)
        with pytest.raises(ContractError):
            repository.compare_and_swap(path, created.revision, invalid)
        current = repository.read(path)

    assert current.document == original
    assert current.revision == created.revision


def test_stored_document_copies_cannot_mutate_the_validated_snapshot(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    document = _fixture("site.json")

    with _repository(root) as repository:
        stored = repository.create_immutable(path, document)

    first = stored.document
    first["kind"] = "mutated"
    assert stored.document == document


def test_blocking_concurrent_compare_and_swap_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    original = _fixture("site.json")
    with _repository(root) as repository:
        revision = repository.create_immutable(path, original).revision

    def update(slug: str) -> str:
        candidate = deepcopy(original)
        metadata = candidate["metadata"]
        assert type(metadata) is dict
        metadata["slug"] = slug
        try:
            with _repository(root) as repository:
                repository.compare_and_swap(
                    path,
                    revision,
                    candidate,
                    blocking=True,
                )
        except StateConflictError:
            return "conflict"
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(update, ["candidate-a", "candidate-b"]))

    assert sorted(outcomes) == ["committed", "conflict"]
    with _repository(root) as repository:
        current = repository.read(path)
    metadata = current.document["metadata"]
    assert type(metadata) is dict
    assert metadata["slug"] in {"candidate-a", "candidate-b"}


def test_transaction_can_read_a_coherent_multi_record_snapshot(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    desired_path = StateRecordPath.tenant_desired(_TENANT_ID)
    observed_path = StateRecordPath.tenant_observed(_TENANT_ID)
    _write_record(root, desired_path, _fixture("site.json"))
    _write_record(root, observed_path, _fixture("tenant-observed-state.json"))

    with (
        _repository(root) as repository,
        repository.transaction(mode=LockMode.SHARED) as transaction,
    ):
        desired = transaction.read(desired_path)
        observed = transaction.read(observed_path)

    assert desired.document["kind"] == "Site"
    assert observed.document["kind"] == "TenantObservedState"


def test_shared_and_expired_transactions_cannot_mutate_state(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    document = _fixture("site.json")

    with _repository(root) as repository:
        with (
            repository.transaction(mode=LockMode.SHARED) as transaction,
            pytest.raises(RuntimeError, match="exclusive"),
        ):
            transaction.create_immutable(path, document)
        with pytest.raises(RuntimeError, match="no longer active"):
            transaction.read(path)


def test_process_concurrent_compare_and_swap_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    path = StateRecordPath.tenant_desired(_TENANT_ID)
    with _repository(root) as repository:
        revision = repository.create_immutable(path, _fixture("site.json")).revision

    context = get_context("spawn")
    release = context.Event()
    read_ends: list[Connection] = []
    processes = []
    for slug in ("process-a", "process-b"):
        receiving, sending = context.Pipe(duplex=False)
        ready = context.Event()
        process = context.Process(
            target=_process_compare_and_swap,
            args=((str(root), revision, slug), ready, release, sending),
        )
        process.start()
        sending.close()
        assert ready.wait(_PROCESS_TIMEOUT_SECONDS)
        read_ends.append(receiving)
        processes.append(process)
    release.set()
    try:
        outcomes = []
        for connection in read_ends:
            assert connection.poll(_PROCESS_TIMEOUT_SECONDS)
            outcomes.append(connection.recv())
        assert sorted(outcomes) == ["committed", "conflict"]
        for process in processes:
            process.join(_PROCESS_TIMEOUT_SECONDS)
            assert process.exitcode == 0
    finally:
        for connection in read_ends:
            connection.close()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(_PROCESS_TIMEOUT_SECONDS)


def test_closed_repository_rejects_new_transactions(tmp_path: Path) -> None:
    repository = _repository(_state_root(tmp_path))
    repository.close()

    with pytest.raises(RuntimeError, match="closed"), repository.transaction(mode=LockMode.SHARED):
        pass
