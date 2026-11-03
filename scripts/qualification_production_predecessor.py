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
SCENARIO = Path("config/ansible/molecule/m3_8")
HARNESS_COPIES = (
    "molecule.yml",
    "resolve_operator_transport.py",
    "prepare_archive_storage.py",
    "Dockerfile.minio.j2",
)


def adapt_harness(previous: Path) -> None:
    """Use today's owned fixture plumbing, never today's production roles/code."""
    converge = previous / SCENARIO / "converge.yml"
    source = converge.read_text()
    for literal, group in (
        ("lowerduckpond-ubuntu-2604", "hosting_nodes"),
        ("lowerduckpond-m3-10-minio", "archive_fixture"),
    ):
        argument = "          - " + literal + "\n"
        if source.count(argument) != 1:
            raise ValueError("historical rollout harness argument changed")
        owned = "{{ groups['" + group + "'] | first }}"
        source = source.replace(argument, f"          - {json.dumps(owned)}\n")
    converge.write_text(source)
    for name in HARNESS_COPIES:
        shutil.copyfile(ROOT / SCENARIO / name, previous / SCENARIO / name)


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
    adapt_harness(previous)
    variables = directory / "production-predecessor-variables.json"
    variables.write_text(
        json.dumps(
            {"backup_node_name": "lowerduckpond-production-01", "backup_repository": REPOSITORY}
        )
        + "\n"
    )
    return previous, variables
