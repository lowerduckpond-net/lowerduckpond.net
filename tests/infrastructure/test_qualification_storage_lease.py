"""Independent local attempts cannot overlap on the same versioned archive bucket."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.qualification_storage_lease import FD_ENV, lease_path, require_inherited, storage_lease

ROOT = Path(__file__).resolve().parents[2]
TARGET = {"SPACES_REGION": "ams3", "SPACES_ARCHIVE_BUCKET": "fixture-archives"}


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


def test_archive_target_excludes_backup_bucket_from_lease_identity(isolated: Path) -> None:
    assert lease_path(TARGET) == lease_path({**TARGET, "SPACES_BACKUP_BUCKET": "other-backups"})
    with storage_lease(TARGET):
        with pytest.raises(BlockingIOError), storage_lease(TARGET):
            pytest.fail("second writer acquired the same bucket")
        with storage_lease({**TARGET, "SPACES_ARCHIVE_BUCKET": "separate-archives"}):
            pass
    with storage_lease(TARGET):
        pass


def test_lease_survives_real_uv_child_and_blocks_unrelated_process(isolated: Path) -> None:
    script = """
import sys, os
from pathlib import Path
from scripts.qualification_storage_lease import storage_lease, require_inherited
Path.home = lambda: Path(sys.argv[1])
if sys.argv[2] == 'inherited':
    require_inherited(os.environ)
else:
    try:
        with storage_lease(os.environ):
            raise AssertionError('competing process acquired the archive')
    except BlockingIOError:
        pass
"""
    uv = shutil.which("uv")
    assert uv
    with storage_lease(TARGET) as fd:
        for inherited in (False, True):
            environment = {**os.environ, **TARGET}
            if inherited:
                environment[FD_ENV] = str(fd)
            result = subprocess.run(  # noqa: S603 - fixed local interpreter; no provider access
                [
                    uv,
                    "run",
                    "--frozen",
                    "python",
                    "-c",
                    script,
                    str(isolated),
                    "inherited" if inherited else "competing",
                ],
                cwd=ROOT,
                env=environment,
                pass_fds=(fd,) if inherited else (),
                capture_output=True,
                check=False,
                timeout=20,
            )
            assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "mode", "directory"])
def test_unsafe_lease_path_fails_closed(isolated: Path, damage: str) -> None:
    path = lease_path(TARGET)
    original = isolated / "original"
    original.write_bytes(b"do not alter")
    original.chmod(0o600)
    if damage == "symlink":
        path.symlink_to(original)
    elif damage == "hardlink":
        path.hardlink_to(original)
    elif damage == "directory":
        path.mkdir()
    else:
        path.touch(mode=0o644)
    with pytest.raises((ValueError, OSError)), storage_lease(TARGET):
        pytest.fail("unsafe lease was adopted")
    assert original.read_bytes() == b"do not alter"


def test_inherited_descriptor_cannot_authorize_another_bucket(isolated: Path) -> None:
    with storage_lease(TARGET) as fd:
        foreign = {**TARGET, FD_ENV: str(fd), "SPACES_ARCHIVE_BUCKET": "other-archives"}
        lease_path(foreign).touch(mode=0o600)
        with pytest.raises(ValueError):
            require_inherited(foreign)
