"""Prepare the actual deployed M3.10 source before the rollout fixture converges."""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR = "22147a64e9b39e7965201cf2d96e07aeaa6d3ca1"
REPOSITORY = "/var/cache/lowerduckpond-backup/rollout-fixture-repository"


def prepare(directory: Path) -> tuple[Path, Path]:
    """No current site converge may seed dependencies into the old baseline."""
    git = shutil.which("git")
    if git is None:
        raise ValueError("rollout predecessor Git is unavailable")
    previous = directory / "production-predecessor"
    previous.mkdir(mode=0o700)
    archive = directory / "production-predecessor.tar"
    with archive.open("xb") as stream:
        subprocess.run(  # noqa: S603 - fixed Git revision and repository archive
            [git, "--no-replace-objects", "-C", str(ROOT), "archive", "--format=tar", PREDECESSOR],
            stdout=stream,
            stderr=subprocess.PIPE,
            check=True,
        )
    with tarfile.open(archive) as source:
        source.extractall(previous, filter="data")
    variables = directory / "production-predecessor-variables.json"
    variables.write_text(
        json.dumps(
            {"backup_node_name": "lowerduckpond-production-01", "backup_repository": REPOSITORY}
        )
        + "\n"
    )
    return previous, variables
