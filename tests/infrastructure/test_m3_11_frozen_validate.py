"""Exercise the actual isolated process and permanent Python audit boundary."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.m3_11_private_inputs import write_private


@pytest.mark.parametrize(
    "operation",
    [
        "outside-write",
        "outside-unlink",
        "rename",
        "socket",
        "shell",
        "write-debugfs",
        "other-image",
        "allowed-scratch",
    ],
)
def test_isolated_proof_can_only_read_originals_and_write_new_scratch(
    tmp_path: Path, operation: str
) -> None:
    original = tmp_path / "original"
    original.write_bytes(b"unchanged original")
    code = """
import os, socket, subprocess, sys
from pathlib import Path
from scripts.m3_11_frozen_validate import readonly
base, operation = Path(sys.argv[1]), sys.argv[2]
scratch, original = base / 'scratch', base / 'original'
readonly(original, scratch)
scratch.mkdir(mode=0o700)
try:
    if operation == 'outside-write': original.write_bytes(b'changed')
    elif operation == 'outside-unlink': original.unlink()
    elif operation == 'rename': original.rename(scratch / 'moved')
    elif operation == 'socket': socket.socket()
    elif operation == 'shell': subprocess.run(['/bin/true'], check=True)
    elif operation == 'write-debugfs':
        subprocess.run(['/usr/sbin/debugfs', '-w', 'stat /static', str(original)], check=True)
    elif operation == 'other-image':
        subprocess.run(['/usr/sbin/debugfs', '-R', 'stat /static', str(base/'another')], check=True)
    else:
        (scratch / 'tmp').mkdir(mode=0o700)
        copied = scratch / 'tmp' / 'copy'
        copied.write_bytes(original.read_bytes())
        copied.unlink()
except RuntimeError:
    assert operation != 'allowed-scratch'
    print('denied')
else:
    assert operation == 'allowed-scratch'
    print('allowed')
"""
    completed = subprocess.run(  # noqa: S603 - fixed synthetic subprocess, no provider surface
        [sys.executable, "-B", "-c", code, str(tmp_path), operation],
        check=True,
        capture_output=True,
        timeout=60,
    )
    assert completed.stdout == (b"allowed\n" if operation == "allowed-scratch" else b"denied\n")
    assert original.read_bytes() == b"unchanged original"


def test_real_entry_creates_new_private_scratch_and_never_reuses_it(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    evidence, selection = tmp_path / "evidence.json", tmp_path / "selection.json"
    write_private(evidence, {"image_path": str(tmp_path / "image")})
    write_private(selection, {"synthetic": True})
    scratch = tmp_path / "proof"
    # Native archive/state semantics have their own retained-byte and synthetic
    # tests. Here only the expensive parser is replaced; the actual entry/audit
    # hook, private input parser, argv and scratch lifecycle remain active.
    code = """
import sys
from scripts import m3_11_frozen_local as local
from scripts import m3_11_frozen_validate as child
def verification(evidence, selection, *, scratch):
    assert scratch.is_dir() and (scratch / 'tmp').is_dir()
    assert scratch.stat().st_mode & 0o777 == 0o700
    assert selection == {'synthetic': True}
    return {'status': 'synthetic-parser-boundary'}
local.verify_local = verification
sys.argv = [sys.argv[0], *sys.argv[1:]]
child.main()
"""
    args = [sys.executable, "-B", "-c", code, str(evidence), str(selection), str(scratch)]
    first = subprocess.run(args, check=True, capture_output=True, timeout=60)  # noqa: S603
    assert b"synthetic-parser-boundary" in first.stdout
    second = subprocess.run(args, check=False, capture_output=True, timeout=60)  # noqa: S603
    assert second.returncode != 0 and b"not new and absolute" in second.stderr
