from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from config.ansible.molecule.m3_8.restore_convergence import run


@pytest.mark.parametrize("outcome", ["success", "failure", "timeout"])
def test_convergence_reaps_launcher_and_stops_children_before_releasing_fixture(
    tmp_path: Path, outcome: str
) -> None:
    lock = tmp_path / "child.lock"
    lock.touch(mode=0o600)
    script = """
import fcntl, os, sys, time
descriptor = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(descriptor, fcntl.LOCK_EX)
child = os.fork()
if child == 0:
    time.sleep(60)
    os._exit(0)
print('child holds fixture lease', flush=True)
if sys.argv[2] == 'timeout':
    time.sleep(60)
sys.exit(7 if sys.argv[2] == 'failure' else 0)
"""
    path = tmp_path / "converge.log"
    with path.open("wb") as log:
        arguments = [sys.executable, "-I", "-c", script, str(lock), outcome]
        if outcome == "timeout":
            with pytest.raises(subprocess.TimeoutExpired):
                run(arguments, cwd=tmp_path, environment=dict(os.environ), log=log, timeout=1)
        else:
            assert run(
                arguments, cwd=tmp_path, environment=dict(os.environ), log=log, timeout=5
            ) == (7 if outcome == "failure" else 0)
    assert path.read_text() == "child holds fixture lease\n"
    # The child inherited the lease, so wrapper exit alone cannot release it.
    with lock.open("rb") as stream:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                assert time.monotonic() < deadline, "convergence child survived cleanup"
                time.sleep(0.01)
