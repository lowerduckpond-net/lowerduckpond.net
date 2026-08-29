from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    DurabilityBoundary,
    DurableDirectory,
    LockManager,
    LockMode,
    StateAdmissionRejectedError,
    StateBusyError,
    StateInventory,
    StateInventoryError,
    StateInventoryLimits,
    StateInventoryReservation,
    StatePathError,
    StateRecordPath,
    StateRepository,
    admit_state_inventory,
)

_TENANT_ID = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_OTHER_TENANT_ID = "0198d17f-6f4a-7000-8000-000000000001"
_JOB_ID = "0198d17f-6f4a-7000-8000-000000000002"
_CORRELATION_ID = "0198d17f-6f4a-7000-8000-000000000003"
_DIRECTORY_MODE = 0o700
_RECORD_MODE = 0o600
_EXPECTED_TENANTS = 2
_EXPECTED_AUTHORIZATION_RECORDS = 3
_UNSAFE_TEMPORARY_COUNT = 2
_TENANT_CEILING = 25
_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_CRASH_EXIT_STATUS = 91


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(_DIRECTORY_MODE)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root)
    for components in (
        ("platform",),
        ("tenants",),
        ("authorization",),
        ("authorization", "correlations"),
        ("authorization", "jobs"),
        ("authorization", "results"),
        ("intents",),
        ("audit",),
        ("locks",),
    ):
        _mkdir(root.joinpath(*components))
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _repository(root: Path) -> StateRepository:
    return StateRepository(root, expected_owner=os.geteuid())


def _tenant(root: Path, tenant_id: str) -> Path:
    path = root / "tenants" / tenant_id
    _mkdir(path)
    return path


def _record(path: Path, data: bytes = b"{}\n") -> int:
    path.write_bytes(data)
    path.chmod(_RECORD_MODE)
    return path.stat().st_blocks * 512


def _crash_during_authorization_publication(root: str) -> None:
    def crash(boundary: DurabilityBoundary) -> None:
        if boundary is DurabilityBoundary.WRITE:
            os._exit(_CRASH_EXIT_STATUS)

    with DurableDirectory.open(
        Path(root),
        expected_owner=os.geteuid(),
        expected_directory_mode=_DIRECTORY_MODE,
    ) as directory:
        directory.create_immutable(
            ("authorization", "jobs", f"{_JOB_ID}.json"),
            b"partial",
            mode=_RECORD_MODE,
            failure_hook=crash,
        )


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def test_empty_inventory_is_measured_through_the_repository_lock(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with _repository(root) as repository:
        inventory = repository.measure_inventory()

    assert inventory == StateInventory((), 0, 0, 0, 0)


def test_inventory_recovers_a_publication_temporary_left_by_process_exit(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    process = get_context("spawn").Process(
        target=_crash_during_authorization_publication,
        args=(str(root),),
    )
    process.start()
    process.join(timeout=10)
    assert process.exitcode == _CRASH_EXIT_STATUS
    temporary_directory = root / "authorization" / "jobs"
    assert len(list(temporary_directory.glob(".ldp-state-*"))) == 1

    with _repository(root) as repository:
        inventory = repository.measure_inventory()

    assert inventory.authorization_record_count == 0
    assert list(temporary_directory.glob(".ldp-state-*")) == []


@pytest.mark.parametrize("unsafe_shape", ["name", "hardlink"])
def test_inventory_refuses_to_remove_an_unsafe_reserved_temporary(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    root = _state_root(tmp_path)
    filename = ".ldp-state-" + ("not-random" if unsafe_shape == "name" else "a" * 32)
    temporary = root / "authorization" / "jobs" / filename
    _record(temporary, b"partial")
    if unsafe_shape == "hardlink":
        os.link(temporary, root / "unsafe-link")

    with _repository(root) as repository, pytest.raises(StatePathError):
        repository.measure_inventory()

    assert temporary.exists()


def test_temporary_recovery_bounds_the_complete_directory_walk(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    directory = root / "authorization" / "jobs"
    for index in range(_UNSAFE_TEMPORARY_COUNT):
        _record(directory / f".ldp-state-{index:032x}", b"partial")

    with (
        _repository(root) as repository,
        pytest.raises(StatePathError, match="recovery ceiling"),
    ):
        repository.measure_inventory(limits=StateInventoryLimits(maximum_authorization_records=0))

    assert len(list(directory.glob(".ldp-state-*"))) == _UNSAFE_TEMPORARY_COUNT


def test_inventory_counts_exact_tenants_records_and_allocated_blocks(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _tenant(root, _TENANT_ID)
    _tenant(root, _OTHER_TENANT_ID)
    allocated = sum(
        (
            _record(root / "authorization" / "jobs" / f"{_JOB_ID}.json"),
            _record(root / "authorization" / "results" / f"{_JOB_ID}.json"),
            _record(root / "authorization" / "correlations" / f"{_CORRELATION_ID}.json"),
        )
    )

    with _repository(root) as repository:
        inventory = repository.measure_inventory()

    assert inventory.tenant_ids == tuple(sorted((_TENANT_ID, _OTHER_TENANT_ID)))
    assert inventory.tenant_count == _EXPECTED_TENANTS
    assert inventory.authorization_jobs == 1
    assert inventory.authorization_results == 1
    assert inventory.authorization_correlations == 1
    assert inventory.authorization_record_count == _EXPECTED_AUTHORIZATION_RECORDS
    assert inventory.authorization_allocated_bytes == allocated


@pytest.mark.parametrize(
    "name",
    ["not-a-uuid", _TENANT_ID.upper(), "../escape", f"{_TENANT_ID}.json"],
)
def test_inventory_rejects_noncanonical_tenant_names(tmp_path: Path, name: str) -> None:
    root = _state_root(tmp_path)
    if "/" in name:
        (root / "tenants" / "not-a-uuid").symlink_to(root)
    else:
        _tenant(root, name)

    with _repository(root) as repository, pytest.raises(StateInventoryError):
        repository.measure_inventory()


@pytest.mark.parametrize("shape", ["mode", "symlink", "hardlink", "oversized"])
def test_inventory_rejects_unsafe_authorization_records(tmp_path: Path, shape: str) -> None:
    root = _state_root(tmp_path)
    target = root / "authorization" / "jobs" / f"{_JOB_ID}.json"
    _record(target)
    if shape == "mode":
        target.chmod(0o640)
    elif shape == "symlink":
        outside = root / "outside.json"
        target.rename(outside)
        target.symlink_to(outside)
    elif shape == "hardlink":
        os.link(target, root / "outside.json")
    else:
        target.write_bytes(b"x" * (16 * 1024 + 1))

    with _repository(root) as repository, pytest.raises(StateInventoryError):
        repository.measure_inventory()


def test_inventory_rejects_unknown_authorization_layout_entries(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    _mkdir(root / "authorization" / "unexpected")

    with _repository(root) as repository, pytest.raises(StateAdmissionRejectedError):
        repository.measure_inventory()


def test_inventory_rejects_a_record_count_beyond_the_configured_scan_bound(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    _record(root / "authorization" / "jobs" / f"{_JOB_ID}.json")

    with (
        _repository(root) as repository,
        pytest.raises(StateAdmissionRejectedError, match="entry ceiling"),
    ):
        repository.measure_inventory(limits=StateInventoryLimits(maximum_authorization_records=0))


@pytest.mark.parametrize(
    ("tenant_count", "accepted"),
    [(_TENANT_CEILING, True), (_TENANT_CEILING + 1, False)],
)
def test_tenant_inventory_accepts_the_exact_ceiling_and_rejects_one_over(
    tmp_path: Path,
    tenant_count: int,
    accepted: bool,
) -> None:
    root = _state_root(tmp_path)
    for index in range(tenant_count):
        _tenant(root, f"0198d17f-6f4a-7000-8000-{index:012x}")

    with _repository(root) as repository:
        if accepted:
            assert repository.measure_inventory().tenant_count == tenant_count
        else:
            with pytest.raises(StateAdmissionRejectedError, match="entry ceiling"):
                repository.measure_inventory()


@pytest.mark.parametrize(
    ("inventory", "reservation", "message"),
    [
        (
            StateInventory((_TENANT_ID,), 0, 0, 0, 0),
            StateInventoryReservation(tenants=1),
            "tenant",
        ),
        (
            StateInventory((), 1, 0, 0, 4096),
            StateInventoryReservation(authorization_records=1),
            "record",
        ),
        (
            StateInventory((), 0, 0, 1, 4096),
            StateInventoryReservation(authorization_allocated_bytes=4096),
            "allocated-byte",
        ),
    ],
)
def test_admission_accepts_exact_bound_and_rejects_one_over(
    inventory: StateInventory,
    reservation: StateInventoryReservation,
    message: str,
) -> None:
    if reservation.tenants:
        limits = StateInventoryLimits(maximum_tenants=2)
        one_over = StateInventoryReservation(tenants=2)
    elif reservation.authorization_records:
        limits = StateInventoryLimits(maximum_authorization_records=2)
        one_over = StateInventoryReservation(authorization_records=2)
    else:
        limits = StateInventoryLimits(maximum_authorization_allocated_bytes=8192)
        one_over = StateInventoryReservation(authorization_allocated_bytes=4097)

    projection = admit_state_inventory(inventory, reservation, limits=limits)
    assert projection.tenants <= limits.maximum_tenants
    assert projection.authorization_records <= limits.maximum_authorization_records
    assert projection.authorization_allocated_bytes <= limits.maximum_authorization_allocated_bytes
    with pytest.raises(StateAdmissionRejectedError, match=message):
        admit_state_inventory(inventory, one_over, limits=limits)


def test_policy_overrides_can_tighten_but_cannot_weaken_recorded_ceilings() -> None:
    StateInventoryLimits(
        maximum_tenants=24,
        maximum_authorization_records=9999,
        maximum_authorization_allocated_bytes=64 * 1024 * 1024 - 1,
    )

    with pytest.raises(ValueError, match="weaken"):
        StateInventoryLimits(maximum_tenants=26)
    with pytest.raises(ValueError, match="weaken"):
        StateInventoryLimits(maximum_authorization_records=10_001)
    with pytest.raises(ValueError, match="weaken"):
        StateInventoryLimits(maximum_authorization_allocated_bytes=64 * 1024 * 1024 + 1)


def test_shared_transaction_cannot_measure_mutation_admission_inventory(tmp_path: Path) -> None:
    root = _state_root(tmp_path)

    with (
        _repository(root) as repository,
        repository.transaction(mode=LockMode.SHARED) as transaction,
        pytest.raises(RuntimeError, match="exclusive"),
    ):
        transaction.measure_inventory()


def test_admission_retains_exclusive_lock_for_the_callers_following_mutation(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)

    with (
        _repository(root) as repository,
        repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
    ):
        projection = transaction.admit_inventory(StateInventoryReservation(authorization_records=1))

        def compete() -> str:
            try:
                with _repository(root) as competing:
                    competing.measure_inventory()
            except StateBusyError:
                return "busy"
            return "acquired"

        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(compete).result() == "busy"
        transaction.create_immutable(
            StateRecordPath.authorization_job(_JOB_ID),
            _fixture("authorization-job.json"),
        )

    assert projection.authorization_records == 1


def test_inventory_rejects_tenant_directory_metadata_drift(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    tenant = _tenant(root, _TENANT_ID)
    tenant.chmod(0o750)

    with _repository(root) as repository, pytest.raises(StateInventoryError, match="ownership"):
        repository.measure_inventory()


def test_record_mode_check_uses_only_permission_bits(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    target = root / "authorization" / "jobs" / f"{_JOB_ID}.json"
    _record(target)
    assert stat.S_IMODE(target.stat().st_mode) == _RECORD_MODE

    with _repository(root) as repository:
        assert repository.measure_inventory().authorization_jobs == 1
