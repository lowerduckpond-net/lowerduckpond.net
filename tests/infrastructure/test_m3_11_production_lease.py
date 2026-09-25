"""Real process death and contention never transfer a live rollout's authority."""

from __future__ import annotations

import os
import select
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import m3_11_production_lease as lease

OWNER = os.geteuid()
CRASH_STATUS = 86
WORKER = """
import os,sys
from pathlib import Path
from scripts import m3_11_production_lease as lease
path=Path(sys.argv[1])
context=(lease.controller(path,owner=os.geteuid(),drain=lambda:None)
         if len(sys.argv)==2 else lease.action(path,owner=os.geteuid(),token=sys.argv[2]))
with context as token:
    print(token or 'action',flush=True)
    sys.stdin.read(1)
"""


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    path = tmp_path / "lease"
    path.mkdir(mode=0o700)
    return path


@contextmanager
def worker(path: Path, token: str | None = None) -> Iterator[tuple[subprocess.Popen[str], str]]:
    command = [sys.executable, "-c", WORKER, str(path)]
    if token is not None:
        command.append(token)
    with subprocess.Popen(  # noqa: S603 - fixed test program and owned fixture path/token
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    ) as p:
        try:
            assert p.stdout is not None
            assert select.select([p.stdout], [], [], 5)[0], "lease worker did not become ready"
            value = p.stdout.readline().strip()
            assert value
            yield p, value
        finally:
            if p.poll() is None:
                p.terminate()
            p.wait(timeout=5)


def test_live_owner_and_action_are_exclusive(directory: Path) -> None:
    with worker(directory) as (_, token):
        with (
            pytest.raises(BlockingIOError),
            lease.controller(
                directory, owner=OWNER, drain=lambda: pytest.fail("busy owner was stolen")
            ),
        ):
            pytest.fail("second owner admitted")
        with (
            worker(directory, token),
            pytest.raises(BlockingIOError),
            lease.action(directory, owner=OWNER, token=token),
        ):
            pytest.fail("concurrent command admitted")
        with lease.action(directory, owner=OWNER, token=token):
            pass


def test_owner_death_fences_late_commands_and_takeover_changes_token(directory: Path) -> None:
    with worker(directory) as (process, old):
        process.kill()
        process.wait(timeout=5)
        with (
            pytest.raises(ValueError, match="no longer present"),
            lease.action(directory, owner=OWNER, token=old),
        ):
            pytest.fail("dead controller admitted")
        drained: list[bytes] = []
        with lease.controller(
            directory, owner=OWNER, drain=lambda: drained.append((directory / "token").read_bytes())
        ) as current:
            assert current != old and drained == [lease.REVOKED]
            with (
                pytest.raises(ValueError, match="superseded"),
                lease.action(directory, owner=OWNER, token=old),
            ):
                pytest.fail("delayed old command admitted")
            with lease.action(directory, owner=OWNER, token=current):
                pass
        assert drained == [lease.REVOKED, lease.REVOKED]


def test_orphan_action_blocks_new_owner_after_controller_death(directory: Path) -> None:
    with worker(directory) as (owner, token), worker(directory, token) as (action, _):
        owner.kill()
        owner.wait(timeout=5)
        with (
            pytest.raises(BlockingIOError),
            lease.controller(
                directory, owner=OWNER, drain=lambda: pytest.fail("live action was skipped")
            ),
        ):
            pytest.fail("takeover overlapped an orphan action")
        assert action.poll() is None
        action.kill()
        action.wait(timeout=5)
        with lease.controller(directory, owner=OWNER, drain=lambda: None) as new:
            assert new != token


def test_failed_descendant_drain_never_publishes_new_authority(directory: Path) -> None:
    def refuse() -> None:
        raise ValueError("descendants remain")

    with (
        pytest.raises(ValueError, match="descendants remain"),
        lease.controller(directory, owner=OWNER, drain=refuse),
    ):
        pytest.fail("undrained owner admitted")
    assert (directory / "token").read_bytes() == lease.REVOKED


@pytest.mark.parametrize("token", ["", "a" * 63, "A" * 64, "0" * 64, "b" * 64])
def test_wrong_token_never_admits_action(directory: Path, token: str) -> None:
    with (
        worker(directory),
        pytest.raises(ValueError),
        lease.action(directory, owner=OWNER, token=token),
    ):
        pytest.fail("foreign token admitted")


@pytest.mark.parametrize("name", ["owner", "action", "token"])
@pytest.mark.parametrize("fault", ["symlink", "hardlink", "mode", "directory", "oversized"])
def test_hostile_lease_metadata_is_refused(directory: Path, name: str, fault: str) -> None:
    with lease.controller(directory, owner=OWNER, drain=lambda: None):
        pass
    path = directory / name
    if fault in {"symlink", "directory"}:
        path.unlink()
        if fault == "symlink":
            path.symlink_to(directory.parent / "elsewhere")
        else:
            path.mkdir(mode=0o600)
    elif fault == "hardlink":
        os.link(path, directory.parent / "linked")
    elif fault == "mode":
        path.chmod(0o644)
    else:
        path.write_bytes(b"x" * 66)
    with (
        pytest.raises((ValueError, OSError)),
        lease.controller(
            directory, owner=OWNER, drain=lambda: pytest.fail("unsafe metadata admitted")
        ),
    ):
        pytest.fail("unsafe lease admitted")


@pytest.mark.parametrize("name", ["owner", "action"])
def test_missing_original_lock_cannot_be_recreated(directory: Path, name: str) -> None:
    with lease.controller(directory, owner=OWNER, drain=lambda: None):
        pass
    (directory / name).unlink()
    with (
        pytest.raises(ValueError, match="disappeared"),
        lease.controller(directory, owner=OWNER, drain=lambda: None),
    ):
        pytest.fail("missing original lock replaced")
    assert not (directory / name).exists()


def test_partial_token_after_actual_process_death_is_revoked_before_drain(directory: Path) -> None:
    program = """
import os,sys
from pathlib import Path
from scripts import m3_11_production_lease as lease
original=os.pwrite
def die(fd, raw, offset):
    original(fd, raw[:8], offset)
    os._exit(86)
os.pwrite=die
with lease.controller(Path(sys.argv[1]),owner=os.geteuid(),drain=lambda:None):
    raise AssertionError('unexpected admission')
"""
    result = subprocess.run(  # noqa: S603 - fixed crash program and owned test directory
        [sys.executable, "-c", program, str(directory)], check=False, timeout=5
    )
    assert result.returncode == CRASH_STATUS
    assert (directory / "token").read_bytes() == b"0" * 8
    inodes = {name: (directory / name).stat().st_ino for name in lease.NAMES}
    with (
        lease.controller(directory, owner=OWNER, drain=lambda: None) as token,
        lease.action(directory, owner=OWNER, token=token),
    ):
        pass
    assert {name: (directory / name).stat().st_ino for name in lease.NAMES} == inodes


@pytest.mark.parametrize("names", [("owner",), ("owner", "action")])
def test_partial_initialization_preserves_original_locks(
    directory: Path, names: tuple[str, ...]
) -> None:
    for name in names:
        (directory / name).touch(mode=0o600)
    inodes = {name: (directory / name).stat().st_ino for name in names}
    with lease.controller(directory, owner=OWNER, drain=lambda: None):
        assert {name: (directory / name).stat().st_ino for name in names} == inodes


@pytest.mark.parametrize("name", ["owner", "action", "token"])
def test_replacement_of_a_pinned_file_is_detected(directory: Path, name: str) -> None:
    with (
        pytest.raises(ValueError, match="file changed"),
        lease.controller(directory, owner=OWNER, drain=lambda: None) as token,
        lease.action(directory, owner=OWNER, token=token),
    ):
        path = directory / name
        original = path.read_bytes()
        path.rename(directory.parent / "retained")
        path.touch(mode=0o600)
        path.write_bytes(original)


def test_unknown_files_are_not_removed(directory: Path) -> None:
    path = directory / "unexpected"
    path.write_bytes(b"retained")
    with (
        pytest.raises(ValueError, match="unknown"),
        lease.controller(directory, owner=OWNER, drain=lambda: None),
    ):
        pytest.fail("unclassified state admitted")
    assert path.read_bytes() == b"retained"
