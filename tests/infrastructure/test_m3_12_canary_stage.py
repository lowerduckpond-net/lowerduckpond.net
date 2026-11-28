"""The bootstrap stage can consume reviewed bytes but never select them."""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.m3_12_canary_stage import ReviewedStage, run


def _private(path: Path, raw: bytes) -> str:
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "fault", ["none", "wrong-installer", "wrong-artifact", "wrong-verifier", "wrong-selector"]
)
def test_stage_review_and_selector(tmp_path: Path, fault: str) -> None:
    transfer = tmp_path / "transfer"
    transfer.mkdir(mode=0o700)
    install = tmp_path / "install"
    install.mkdir()
    pre = "a" * 64
    actual = install / (pre if fault != "wrong-selector" else "b" * 64)
    actual.mkdir()
    current = install / "current"
    current.symlink_to(actual)
    _private(install / "selection.lock", b"")
    archive = _private(transfer / "artifact.tar", b"exact archive bytes")
    source = _private(
        transfer / "installer.py",
        b"""
import subprocess, sys
from pathlib import Path
archive, digest, root, verify, state, flag = sys.argv[1:]
assert flag == "--stage-only"
assert Path(archive).read_bytes() == b"exact archive bytes"
subprocess.run([verify], check=True)
(Path(root) / digest).mkdir()
print("changed")
""",
    )
    verifier = tmp_path / "verifier"
    verifier_hash = _private(verifier, b"#!/bin/sh\nexit 0\n")
    reviewed = ReviewedStage(pre, archive, source, verifier_hash)
    if fault not in {"none", "wrong-selector"}:
        reviewed = replace(reviewed, **{fault.removeprefix("wrong-"): "e" * 64})
    kwargs = {"owner": os.geteuid(), "install": install, "state": tmp_path / "state"}
    if fault == "none":
        assert run(reviewed, transfer, verifier=verifier, **kwargs) is True  # type: ignore[arg-type]
        assert (install / archive).is_dir()
    else:
        with pytest.raises(ValueError, match=r"canary-stage-(digest|predecessor)-changed"):
            run(reviewed, transfer, verifier=verifier, **kwargs)  # type: ignore[arg-type]
        assert not (install / archive).exists()
    assert current.resolve(strict=True) == actual
    assert {p.name for p in transfer.iterdir()} == {"artifact.tar", "installer.py"}
    assert not (tmp_path / "state").exists()
