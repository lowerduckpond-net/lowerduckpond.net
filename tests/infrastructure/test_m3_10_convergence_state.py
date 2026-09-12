from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
CANDIDATE = "c" * 64


@pytest.fixture
def state(tmp_path: Path) -> tuple[Path, Path]:
    parent = tmp_path / "state"
    parent.mkdir(mode=0o711)
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / CANDIDATE).mkdir()
    (installed / "current").symlink_to(installed / CANDIDATE)
    script = tmp_path / "state-check"
    source = (ROOT / "scripts/m3-10-convergence-state").read_text()
    script.write_text(
        source.replace("/var/lib/lowerduckpond", str(parent))
        .replace("/opt/lowerduckpond/static-host-agent", str(installed))
        .replace("== 0:", f"== {os.geteuid()}:")
    )
    return script, parent / "convergence/m3-10"


def run(state: tuple[Path, Path], action: str, artifact: str = CANDIDATE) -> int:
    return subprocess.run(  # noqa: S603 - fixed copied program in private fixture
        ["/bin/bash", str(state[0]), action, artifact], capture_output=True, check=False
    ).returncode


def test_completion_requires_a_recorded_selected_artifact(state: tuple[Path, Path]) -> None:
    assert run(state, "check") != 0
    assert run(state, "record", "d" * 64) != 0
    assert run(state, "record") == 0
    assert run(state, "check") == 0
    assert run(state, "check", "d" * 64) != 0
    assert run(state, "clear") == 0
    assert run(state, "check") != 0
    assert run(state, "clear") == 0


@pytest.mark.parametrize("drift", ["mode", "extra-bytes", "symlink", "directory"])
def test_completion_rejects_untrusted_or_ambiguous_records(
    state: tuple[Path, Path], drift: str
) -> None:
    assert run(state, "record") == 0
    marker = state[1]
    if drift == "mode":
        marker.chmod(0o644)
    elif drift == "extra-bytes":
        marker.chmod(0o600)
        marker.write_text(CANDIDATE + "\n\n")
        marker.chmod(0o400)
    elif drift == "symlink":
        target = marker.with_name("target")
        marker.rename(target)
        marker.symlink_to(target)
    else:
        marker.parent.chmod(0o755)
    assert run(state, "check") != 0
