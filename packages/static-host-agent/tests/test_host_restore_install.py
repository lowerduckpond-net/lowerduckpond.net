from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.host_restore_gate import close_gate, restore_admission
from lowerduckpond_static_host_agent.host_restore_install import (
    RootSwap,
    install_roots,
    prepare_root_install,
    verify_installed_roots,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from test_host_restore_journal import journal as journal  # noqa: PLC0414 - shared fixture
from test_host_restore_journal import root as root  # noqa: PLC0414 - shared fixture


@pytest.fixture
def swaps(root: Path, journal: RestoreJournal, tmp_path: Path) -> dict[str, RootSwap]:
    result = {}
    for name in ("state", "content", "caddy"):
        parent = tmp_path / name
        parent.mkdir(mode=0o700)
        swap = RootSwap(name, parent / "live", journal.restore_id, 0o700, os.getegid())
        swap.destination.mkdir(mode=0o700)
        swap.container.mkdir(mode=0o700)
        swap.candidate.mkdir(mode=0o700)
        (swap.destination / "history").write_bytes(b"original destination")
        (swap.candidate / "history").write_bytes(b"verified snapshot")
        result[name] = swap
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        close_gate(store, journal.restore_id)
        store.begin(journal)
        for phase in PHASES[1 : PHASES.index(RestorePhase.RUNTIME_PREPARED) + 1]:
            journal = store.advance(journal, phase, {"evidence": phase.value})
    return result


@pytest.mark.parametrize("name", ["state", "content", "caddy"])
@pytest.mark.parametrize(
    "boundary", ["prior-renamed", "prior-synced", "candidate-renamed", "candidate-synced"]
)
def test_process_exit_between_root_renames_preserves_both_trees_and_gate(
    root: Path, swaps: dict[str, RootSwap], name: str, boundary: str
) -> None:
    def crash(actual_name: str, actual_boundary: str) -> None:
        if (actual_name, actual_boundary) == (name, boundary):
            os._exit(73)

    child = os.fork()
    if child == 0:
        with RestoreStore.locked(root, owner=os.geteuid()) as store:
            install_roots(store, swaps, failure_hook=crash)
        os._exit(74)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 73  # noqa: PLR2004 - owned hard-exit boundary
    assert not restore_admission(root, owner=os.geteuid(), caddy=True)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        first = install_roots(store, swaps)
        assert install_roots(store, swaps) == first
    for swap in swaps.values():
        assert (swap.destination / "history").read_bytes() == b"verified snapshot"
        assert (
            swap.destination.parent / swap.retained_name / "history"
        ).read_bytes() == b"original destination"
        assert not swap.candidate.exists()


@pytest.mark.parametrize("damage", ["candidate", "destination", "retained", "symlink"])
def test_root_swap_refuses_unbound_inodes_without_merging_or_deleting(
    root: Path, swaps: dict[str, RootSwap], damage: str
) -> None:
    swap = swaps["caddy"]
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        prepare_root_install(store, swaps)
        if damage == "retained":
            (swap.destination.parent / swap.retained_name).mkdir(mode=0o700)
        else:
            path = swap.candidate if damage in {"candidate", "symlink"} else swap.destination
            path.rename(path.with_name("preserved-evidence"))
            if damage == "symlink":
                path.symlink_to(path.with_name("preserved-evidence"), target_is_directory=True)
            else:
                path.mkdir(mode=0o700)
                (path / "unrelated").write_bytes(b"must survive")
        with pytest.raises(HostRestoreError):
            install_roots(store, swaps)
    assert not restore_admission(root, owner=os.geteuid(), caddy=True)
    assert (swaps["state"].destination / "history").read_bytes() == b"original destination"
    assert (swaps["content"].destination / "history").read_bytes() == b"original destination"


@pytest.mark.parametrize("damage", ["none", "destination", "prior", "candidate", "receipt"])
def test_installed_phase_verifies_roots_without_reinstalling(
    root: Path, swaps: dict[str, RootSwap], damage: str
) -> None:
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        receipt = install_roots(store, swaps)
        current = store.read()
        assert current is not None
        store.advance(current, RestorePhase.INSTALLED, {"roots": receipt})
        assert verify_installed_roots(store, swaps) == receipt
        swap = swaps["state"]
        if damage in {"destination", "prior"}:
            path = swap.destination if damage == "destination" else swap.container / "prior"
            path.rename(path.with_name("retained-original"))
            path.mkdir(mode=0o700)
        elif damage == "candidate":
            swap.candidate.mkdir(mode=0o700)
        elif damage == "receipt":
            (root / "root-install.json").unlink()
        else:
            return
        before = sorted(str(path.relative_to(root.parent)) for path in root.parent.rglob("*"))
        with pytest.raises((HostRestoreError, FileNotFoundError)):
            verify_installed_roots(store, swaps)
        assert (
            sorted(str(path.relative_to(root.parent)) for path in root.parent.rglob("*")) == before
        )
