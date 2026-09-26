"""The legacy mode-0666 backing file is safe only behind verified private ancestry."""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_retirement_probe as probe


@pytest.mark.parametrize(
    "fault", [None, "no-private-parent", "writable-parent", "symlink", "hardlink", "size", "owner"]
)
def test_fixed_backing_image_requires_private_root_owned_single_link_ancestry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str | None,
) -> None:
    root = tmp_path / "root"
    parent = root / "restore-disks"
    root.mkdir(mode=0o700)
    parent.mkdir(mode=0o700)
    path = parent / "var-lib.ext4"
    with path.open("xb") as stream:
        stream.truncate(8 * 1024 * 1024 * 1024)
    path.chmod(0o666)
    if fault == "no-private-parent":
        root.chmod(0o755)
        parent.chmod(0o755)
    elif fault == "writable-parent":
        parent.chmod(0o777)
    elif fault == "symlink":
        parent.rename(root / "real-disks")
        parent.symlink_to(root / "real-disks")
    elif fault == "hardlink":
        (parent / "second-link").hardlink_to(path)
    elif fault == "size":
        path.write_bytes(b"not an 8-GiB filesystem")
    image_inode = path.stat().st_ino
    real_open, real_stat = os.open, os.fstat

    def opened(path: str, flags: int, *, dir_fd: int | None = None) -> int:
        return real_open(str(tmp_path) if path == "/" else path, flags, dir_fd=dir_fd)

    def metadata(fd: int) -> os.stat_result:
        original = real_stat(fd)
        values = list(original)
        # Translate this private test root's owner, leaving real modes/link counts.
        values[4] = 1 if fault == "owner" and original.st_ino == image_inode else 0
        return os.stat_result(values)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "fstat", metadata)
    monkeypatch.setattr(signal, "alarm", Mock())
    monkeypatch.setattr(sys, "argv", ["probe", "image", "/root/restore-disks/var-lib.ext4"])
    if fault:
        with pytest.raises((OSError, ValueError)):
            probe.main()
        assert not capsys.readouterr().out
    else:
        probe.main()
        result = json.loads(capsys.readouterr().out)
        assert result["mode"] == 0o666  # noqa: PLR2004 - actual legacy fixture mode
        assert result["links"] == 1
        assert result["inode"] == image_inode
        assert result["size"] == 8 * 1024 * 1024 * 1024
