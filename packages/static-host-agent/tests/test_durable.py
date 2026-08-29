from __future__ import annotations

import os
import stat
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    DurabilityBoundary,
    DurableDirectory,
    StateAlreadyExistsError,
    StatePathError,
)

_STATE_MODE = 0o600
_CRASH_EXIT_STATUS = 91
_PROCESS_TIMEOUT_SECONDS = 10


def _raise_at(expected: DurabilityBoundary) -> Callable[[DurabilityBoundary], None]:
    def hook(actual: DurabilityBoundary) -> None:
        if actual is expected:
            raise InjectedFailureError(expected)

    return hook


class InjectedFailureError(RuntimeError):
    pass


def _crash_during_write(root: str, boundary_value: str, replace: bool) -> None:
    boundary = DurabilityBoundary(boundary_value)

    def crash(actual: DurabilityBoundary) -> None:
        if actual is boundary:
            os._exit(_CRASH_EXIT_STATUS)

    with DurableDirectory.open(Path(root)) as directory:
        if replace:
            directory.replace(("record.json",), b"complete-new-state", failure_hook=crash)
        else:
            directory.create_immutable(
                ("record.json",),
                b"complete-new-state",
                failure_hook=crash,
            )


def test_immutable_create_publishes_exact_bytes_and_mode(tmp_path: Path) -> None:
    with DurableDirectory.open(tmp_path) as directory:
        directory.create_immutable(("record.json",), b'{"value":1}', mode=0o600)

    record = tmp_path / "record.json"
    assert record.read_bytes() == b'{"value":1}'
    assert stat.S_IMODE(record.stat().st_mode) == _STATE_MODE
    assert record.stat().st_nlink == 1
    assert list(tmp_path.glob(".ldp-state-*")) == []


def test_immutable_create_never_replaces_an_existing_record(tmp_path: Path) -> None:
    record = tmp_path / "record.json"
    record.write_bytes(b"established")

    with (
        DurableDirectory.open(tmp_path) as directory,
        pytest.raises(StateAlreadyExistsError),
    ):
        directory.create_immutable(("record.json",), b"attacker-controlled")

    assert record.read_bytes() == b"established"
    assert list(tmp_path.glob(".ldp-state-*")) == []


@pytest.mark.parametrize(
    ("boundary", "is_published"),
    [
        (DurabilityBoundary.WRITE, False),
        (DurabilityBoundary.FILE_SYNC, False),
        (DurabilityBoundary.RENAME, True),
        (DurabilityBoundary.DIRECTORY_SYNC, True),
    ],
)
def test_immutable_create_failure_exposes_only_absence_or_complete_state(
    tmp_path: Path,
    boundary: DurabilityBoundary,
    is_published: bool,
) -> None:
    with DurableDirectory.open(tmp_path) as directory, pytest.raises(InjectedFailureError):
        directory.create_immutable(
            ("record.json",),
            b"complete-new-state",
            failure_hook=_raise_at(boundary),
            temporary_name_source=lambda: f".ldp-state-test-{boundary.value}",
        )

    record = tmp_path / "record.json"
    assert record.exists() is is_published
    if is_published:
        assert record.read_bytes() == b"complete-new-state"
    assert list(tmp_path.glob(".ldp-state-test-*")) == []


@pytest.mark.parametrize(
    ("boundary", "expected"),
    [
        (DurabilityBoundary.WRITE, b"complete-old-state"),
        (DurabilityBoundary.FILE_SYNC, b"complete-old-state"),
        (DurabilityBoundary.RENAME, b"complete-new-state"),
        (DurabilityBoundary.DIRECTORY_SYNC, b"complete-new-state"),
    ],
)
def test_atomic_replace_failure_exposes_one_complete_generation(
    tmp_path: Path,
    boundary: DurabilityBoundary,
    expected: bytes,
) -> None:
    record = tmp_path / "record.json"
    record.write_bytes(b"complete-old-state")

    with DurableDirectory.open(tmp_path) as directory, pytest.raises(InjectedFailureError):
        directory.replace(
            ("record.json",),
            b"complete-new-state",
            failure_hook=_raise_at(boundary),
            temporary_name_source=lambda: f".ldp-state-test-{boundary.value}",
        )

    assert record.read_bytes() == expected
    assert list(tmp_path.glob(".ldp-state-test-*")) == []


@pytest.mark.parametrize(
    ("boundary", "expected"),
    [
        (DurabilityBoundary.WRITE, b"complete-old-state"),
        (DurabilityBoundary.FILE_SYNC, b"complete-old-state"),
        (DurabilityBoundary.RENAME, b"complete-new-state"),
        (DurabilityBoundary.DIRECTORY_SYNC, b"complete-new-state"),
    ],
)
def test_process_exit_during_replace_leaves_one_complete_generation(
    tmp_path: Path,
    boundary: DurabilityBoundary,
    expected: bytes,
) -> None:
    record = tmp_path / "record.json"
    record.write_bytes(b"complete-old-state")
    process = get_context("spawn").Process(
        target=_crash_during_write,
        args=(str(tmp_path), boundary.value, True),
    )
    process.start()
    process.join(_PROCESS_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(_PROCESS_TIMEOUT_SECONDS)
        pytest.fail("durability subprocess did not terminate")

    assert process.exitcode == _CRASH_EXIT_STATUS
    assert record.read_bytes() == expected


@pytest.mark.parametrize(
    ("boundary", "is_published"),
    [
        (DurabilityBoundary.WRITE, False),
        (DurabilityBoundary.FILE_SYNC, False),
        (DurabilityBoundary.RENAME, True),
        (DurabilityBoundary.DIRECTORY_SYNC, True),
    ],
)
def test_process_exit_during_immutable_create_never_exposes_partial_state(
    tmp_path: Path,
    boundary: DurabilityBoundary,
    is_published: bool,
) -> None:
    process = get_context("spawn").Process(
        target=_crash_during_write,
        args=(str(tmp_path), boundary.value, False),
    )
    process.start()
    process.join(_PROCESS_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(_PROCESS_TIMEOUT_SECONDS)
        pytest.fail("durability subprocess did not terminate")

    assert process.exitcode == _CRASH_EXIT_STATUS
    record = tmp_path / "record.json"
    assert record.exists() is is_published
    if is_published:
        assert record.read_bytes() == b"complete-new-state"


def test_temporary_name_collision_cannot_remove_an_established_record(tmp_path: Path) -> None:
    collision = tmp_path / ".ldp-state-collision"
    collision.write_bytes(b"established")

    with DurableDirectory.open(tmp_path) as directory, pytest.raises(FileExistsError):
        directory.create_immutable(
            ("record.json",),
            b"new",
            temporary_name_source=lambda: collision.name,
        )

    assert collision.read_bytes() == b"established"
    assert not (tmp_path / "record.json").exists()


@pytest.mark.parametrize("temporary_name", ["record.json", ".unreserved-temporary"])
def test_temporary_names_are_confined_to_the_internal_namespace(
    tmp_path: Path,
    temporary_name: str,
) -> None:
    with DurableDirectory.open(tmp_path) as directory, pytest.raises(StatePathError):
        directory.create_immutable(
            ("record.json",),
            b"new",
            temporary_name_source=lambda: temporary_name,
        )


def test_remove_syncs_and_obeys_missing_policy(tmp_path: Path) -> None:
    record = tmp_path / "record.json"
    record.write_bytes(b"state")
    boundaries: list[DurabilityBoundary] = []

    with DurableDirectory.open(tmp_path) as directory:
        directory.remove(("record.json",), failure_hook=boundaries.append)
        directory.remove(("record.json",), missing_ok=True)
        with pytest.raises(FileNotFoundError):
            directory.remove(("record.json",))

    assert boundaries == [DurabilityBoundary.REMOVE, DurabilityBoundary.DIRECTORY_SYNC]


@pytest.mark.parametrize(
    "components",
    [(), ("",), (".",), ("..",), ("nested/name",), ("/absolute",), ("nul\x00byte",)],
)
def test_fixed_state_paths_reject_unsafe_components(
    tmp_path: Path,
    components: tuple[str, ...],
) -> None:
    with DurableDirectory.open(tmp_path) as directory, pytest.raises(StatePathError):
        directory.create_immutable(components, b"state")


def test_descriptor_traversal_refuses_a_symlinked_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "tenant").symlink_to(outside, target_is_directory=True)

    with DurableDirectory.open(root) as directory, pytest.raises(StatePathError):
        directory.create_immutable(("tenant", "record.json"), b"state")

    assert list(outside.iterdir()) == []


def test_open_refuses_a_symlinked_state_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(StatePathError):
        DurableDirectory.open(linked_root)


def test_concurrent_immutable_creation_has_exactly_one_winner(tmp_path: Path) -> None:
    def create(candidate: int) -> tuple[str, bytes]:
        payload = f"candidate-{candidate}".encode()
        try:
            with DurableDirectory.open(tmp_path) as directory:
                directory.create_immutable(("record.json",), payload)
        except StateAlreadyExistsError:
            return "existing", payload
        return "created", payload

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(create, range(8)))

    winners = [payload for outcome, payload in outcomes if outcome == "created"]
    assert len(winners) == 1
    assert (tmp_path / "record.json").read_bytes() == winners[0]
    assert list(tmp_path.glob(".ldp-state-*")) == []


def test_closed_directory_rejects_operations(tmp_path: Path) -> None:
    directory = DurableDirectory.open(tmp_path)
    directory.close()

    with pytest.raises(RuntimeError, match="closed"):
        directory.create_immutable(("record.json",), b"state")
