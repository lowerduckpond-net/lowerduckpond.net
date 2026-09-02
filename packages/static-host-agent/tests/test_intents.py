from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import manifest_digest
from lowerduckpond_static_host_agent import (
    DurabilityBoundary,
    IntentDiscovery,
    IntentDiscoveryError,
    IntentInventoryLimits,
    LockManager,
    StateAdmissionRejectedError,
    StateConflictError,
    StateInventoryError,
    StateRecordError,
    StateRecordPath,
    StateRepository,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_DIRECTORY_MODE = 0o700
_RECORD_MODE = 0o600
_INTENT_FILES = (
    "transaction-intent.json",
    "archive-construction-intent.json",
    "archive-retirement-intent.json",
)


def _load(name: str) -> dict[str, object]:
    document = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(document) is dict
    return document


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir()
    root.chmod(_DIRECTORY_MODE)
    for name in ("intents", "locks"):
        directory = root / name
        directory.mkdir()
        directory.chmod(_DIRECTORY_MODE)
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _repository(root: Path) -> StateRepository:
    return StateRepository(root, expected_owner=os.geteuid())


def _path(document: dict[str, object]) -> StateRecordPath:
    factories = {
        "TransactionIntent": StateRecordPath.transaction_intent,
        "ArchiveConstructionIntent": StateRecordPath.archive_construction_intent,
        "ArchiveRetirementIntent": StateRecordPath.archive_retirement_intent,
    }
    return factories[str(document["kind"])](document["intentId"])


def _matching_delete_transaction() -> dict[str, object]:
    document = _load("transaction-intent.json")
    observed = _load("tenant-observed-state.json")
    document["operation"] = "delete"
    document["candidateManifest"] = None
    document["candidateManifestDigest"] = None
    source_manifest = document["sourceManifest"]
    assert type(source_manifest) is dict
    source_spec = source_manifest["spec"]
    assert type(source_spec) is dict
    source_spec["desiredState"] = "archived"
    document["sourceManifestDigest"] = manifest_digest(source_manifest).to_dict()
    observed["desiredManifestDigest"] = document["sourceManifestDigest"]
    observed["observedState"] = "archived"
    observed["activeDeploymentId"] = None
    observed["runtimeGenerationId"] = None
    document["lifecycleRecovery"] = {
        "sourceObservedState": observed,
        "sourceRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000004",
        "sourceRouteSet": "absent",
        "candidateObservedState": None,
        "candidateRuntimeGenerationId": "0198d17f-6f4a-7000-8000-000000000006",
        "candidateRouteSet": "absent",
    }
    return document


def test_empty_intent_store_has_an_empty_recovery_plan(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with _repository(root) as repository:
        plan = IntentDiscovery(repository).discover()

    assert plan.intents == ()
    assert plan.recovery_order == ()


@pytest.mark.parametrize("filename", _INTENT_FILES)
def test_each_intent_kind_is_discovered_with_its_exact_revision(
    tmp_path: Path,
    filename: str,
) -> None:
    root = _state_root(tmp_path)
    document = _load(filename)
    path = _path(document)

    with _repository(root) as repository:
        created = repository.create_immutable(path, document)
        plan = IntentDiscovery(repository).discover()

    assert len(plan.intents) == 1
    assert plan.intents[0].path == path
    assert plan.intents[0].record.revision == created.revision
    assert plan.recovery_order == (path,)


def test_related_lifecycle_intent_is_recovered_before_retirement(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    transaction = _matching_delete_transaction()
    retirement = _load("archive-retirement-intent.json")
    transaction_path = _path(transaction)
    retirement_path = _path(retirement)

    with _repository(root) as repository:
        repository.create_immutable(transaction_path, transaction)
        repository.create_immutable(retirement_path, retirement)
        plan = IntentDiscovery(repository).discover()

    assert plan.recovery_order == (transaction_path, retirement_path)


def test_unrelated_lifecycle_and_remote_intents_fail_closed(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    transaction = _load("transaction-intent.json")
    construction = _load("archive-construction-intent.json")

    with _repository(root) as repository:
        repository.create_immutable(_path(transaction), transaction)
        repository.create_immutable(_path(construction), construction)
        with pytest.raises(IntentDiscoveryError, match="transition"):
            IntentDiscovery(repository).discover()


def test_duplicate_or_competing_remote_authority_fails_closed(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    construction = _load("archive-construction-intent.json")
    retirement = _load("archive-retirement-intent.json")

    with _repository(root) as repository:
        repository.create_immutable(_path(construction), construction)
        repository.create_immutable(_path(retirement), retirement)
        with pytest.raises(IntentDiscoveryError, match="cannot coexist"):
            IntentDiscovery(repository).discover()


def test_two_lifecycle_intents_with_the_same_authority_kind_fail_closed(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    first = _load("transaction-intent.json")
    second = deepcopy(first)
    second["intentId"] = "0198d17f-6f4a-7000-8000-000000000099"

    with _repository(root) as repository:
        repository.create_immutable(_path(first), first)
        repository.create_immutable(_path(second), second)
        with pytest.raises(IntentDiscoveryError, match="same authority kind"):
            IntentDiscovery(repository).discover()


def test_intent_inventory_is_bounded_before_record_reads(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    document = _load("transaction-intent.json")

    with _repository(root) as repository:
        repository.create_immutable(_path(document), document)
        with pytest.raises(StateAdmissionRejectedError, match="entry ceiling"):
            IntentDiscovery(
                repository,
                limits=IntentInventoryLimits(maximum_records=0),
            ).discover()


def test_abandoned_safe_intent_temporary_is_recovered(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    temporary = root / "intents/.ldp-state-0123456789abcdef0123456789abcdef"
    temporary.write_bytes(b"interrupted")
    temporary.chmod(_RECORD_MODE)

    with _repository(root) as repository:
        plan = IntentDiscovery(repository).discover()

    assert plan.intents == ()
    assert not temporary.exists()


def test_another_contract_kind_in_the_intent_store_is_rejected(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    job = _load("authorization-job.json")
    path = root / "intents" / f"{job['jobId']}.json"
    path.write_text(json.dumps(job, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(_RECORD_MODE)

    with _repository(root) as repository, pytest.raises(StateRecordError, match="another"):
        IntentDiscovery(repository).discover()


@pytest.mark.parametrize("unsafe_shape", ["mode", "symlink", "hardlink"])
def test_unsafe_intent_inode_shape_is_rejected(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    root = _state_root(tmp_path)
    document = _load("transaction-intent.json")
    path = _path(document)

    with _repository(root) as repository:
        repository.create_immutable(path, document)

    target = root.joinpath(*path.components)
    if unsafe_shape == "mode":
        target.chmod(0o640)
    elif unsafe_shape == "symlink":
        outside = tmp_path / "outside"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
    else:
        os.link(target, tmp_path / "second-link")

    with _repository(root) as repository, pytest.raises(StateInventoryError):
        IntentDiscovery(repository).discover()


def test_reconciled_intent_removal_requires_the_discovered_revision(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    document = _load("transaction-intent.json")
    path = _path(document)

    with _repository(root) as repository:
        created = repository.create_immutable(path, document)
        discovered = IntentDiscovery(repository).discover().intents[0]
        updated_document = deepcopy(document)
        updated_document["phase"] = "state-committed"
        updated = repository.compare_and_swap(path, created.revision, updated_document)
        with pytest.raises(StateConflictError, match="changed"):
            repository.remove_reconciled_intent(path, discovered.removal_token)
        current = IntentDiscovery(repository).discover().intents[0]
        assert current.record.revision == updated.revision
        repository.remove_reconciled_intent(path, current.removal_token)
        plan = IntentDiscovery(repository).discover()

    assert plan.intents == ()


def test_recovery_removal_refuses_a_non_intent_path(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    document = _load("transaction-intent.json")

    with _repository(root) as repository:
        created = repository.create_immutable(_path(document), document)
        discovered = IntentDiscovery(repository).discover().intents[0]
        assert discovered.record.revision == created.revision
        with pytest.raises(StateRecordError, match="only an intent"):
            repository.remove_reconciled_intent(
                StateRecordPath.platform_launch(),
                discovered.removal_token,
            )


def test_recreated_identical_intent_rejects_the_stale_removal_token(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    document = _load("transaction-intent.json")
    path = _path(document)

    with _repository(root) as repository:
        repository.create_immutable(path, document)
        stale = IntentDiscovery(repository).discover().intents[0]
        repository.remove_reconciled_intent(path, stale.removal_token)
        repository.create_immutable(path, document)
        current = IntentDiscovery(repository).discover().intents[0]
        assert current.record.revision == stale.record.revision
        assert current.removal_token != stale.removal_token
        with pytest.raises(StateConflictError, match="inode changed"):
            repository.remove_reconciled_intent(path, stale.removal_token)
        assert repository.read(path).document == document


@pytest.mark.parametrize(
    "boundary",
    [DurabilityBoundary.REMOVE, DurabilityBoundary.DIRECTORY_SYNC],
)
def test_removal_failure_exposes_only_the_complete_old_or_absent_state(
    tmp_path: Path,
    boundary: DurabilityBoundary,
) -> None:
    root = _state_root(tmp_path)
    document = _load("transaction-intent.json")
    path = _path(document)

    def fail_at(observed: DurabilityBoundary) -> None:
        if observed is boundary:
            raise RuntimeError("injected intent-removal failure")

    with _repository(root) as repository:
        created = repository.create_immutable(path, document)
        discovered = IntentDiscovery(repository).discover().intents[0]
        assert discovered.record.revision == created.revision
        with pytest.raises(RuntimeError, match="injected"):
            repository.remove_reconciled_intent(
                path,
                discovered.removal_token,
                failure_hook=fail_at,
            )
        plan = IntentDiscovery(repository).discover()

    assert plan.intents == ()


def test_intent_limit_cannot_be_weakened() -> None:
    with pytest.raises(ValueError, match="cannot weaken"):
        IntentInventoryLimits(maximum_records=3)
