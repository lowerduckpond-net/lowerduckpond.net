from __future__ import annotations

import json
import os
import subprocess
import tarfile
from collections import Counter
from pathlib import Path

from lowerduckpond_static_host_agent import ARCHIVE_SANDBOX_STATIC_PROPERTIES

REPOSITORY_ROOT = Path(__file__).parents[2]
BUILDER = (REPOSITORY_ROOT / "scripts/build-static-host-agent").resolve()
INSTALLER = (
    REPOSITORY_ROOT
    / "config/ansible/roles/static_host_agent/files/install-static-host-agent-artifact"
).resolve()
VERIFIER = (
    REPOSITORY_ROOT
    / "config/ansible/roles/static_host_agent/files/verify-static-host-agent-artifact"
).resolve()
ARCHIVE_ROOT_MODE = 0o555
ARCHIVE_FILE_MODE = 0o444
WORKER_UNIT_TEMPLATE = (
    REPOSITORY_ROOT
    / "config/ansible/roles/static_host_agent/templates/lowerduckpond-static-worker@.service.j2"
)


def run(*arguments: str | os.PathLike[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- every executable is a reviewed absolute path.
        [os.fspath(argument) for argument in arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )


def test_host_agent_artifact_is_locked_reproducible_and_installable(tmp_path: Path) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    first_build = run(BUILDER, first)
    second_build = run(BUILDER, second)
    assert first_build.returncode == 0, first_build.stderr
    assert second_build.returncode == 0, second_build.stderr
    digest = first_build.stdout.strip()
    assert second_build.stdout.strip() == digest
    assert first.read_bytes() == second.read_bytes()
    assert first.with_suffix(".tar.sha256").read_text(encoding="ascii") == f"{digest}\n"

    with tarfile.open(first, mode="r:") as archive:
        members = archive.getmembers()
        assert all(
            member.name == "artifact" or member.name.startswith("artifact/") for member in members
        )
        assert all(member.isdir() or member.isreg() for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        assert all(
            member.mode == (ARCHIVE_ROOT_MODE if member.isdir() else ARCHIVE_FILE_MODE)
            for member in members
        )

    install_root = tmp_path / "install"
    install_root.mkdir()
    installed = run(INSTALLER, first, digest, install_root, VERIFIER)
    assert installed.returncode == 0, installed.stderr
    assert installed.stdout == "changed\n"
    repeated = run(INSTALLER, first, digest, install_root, VERIFIER)
    assert repeated.returncode == 0, repeated.stderr
    assert repeated.stdout == "unchanged\n"

    selected = (install_root / "current").resolve(strict=True)
    assert selected == install_root / digest
    manifest = json.loads((selected / "artifact-manifest.json").read_bytes())
    assert manifest["format"] == "lowerduckpond-static-host-agent-artifact-v1"
    assert manifest["python"] == "3.14"
    assert run(VERIFIER, selected).returncode == 0


def test_installer_refuses_drift_in_an_existing_version(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.tar"
    build = run(BUILDER, artifact)
    assert build.returncode == 0, build.stderr
    digest = build.stdout.strip()
    install_root = tmp_path / "install"
    install_root.mkdir()
    assert run(INSTALLER, artifact, digest, install_root, VERIFIER).returncode == 0

    selected = install_root / digest
    victim = next((selected / "site-packages").rglob("*.py"))
    victim.chmod(0o644)
    victim.write_bytes(victim.read_bytes() + b"\n")
    victim.chmod(ARCHIVE_FILE_MODE)

    refused = run(INSTALLER, artifact, digest, install_root, VERIFIER)
    assert refused.returncode != 0
    assert "content drifted" in refused.stderr


def test_dark_worker_unit_consumes_the_reviewed_sandbox_contract() -> None:
    lines = Counter(WORKER_UNIT_TEMPLATE.read_text(encoding="utf-8").splitlines())
    expected = Counter(f"{key}={value}" for key, value in ARCHIVE_SANDBOX_STATIC_PROPERTIES)
    for property_line, count in expected.items():
        assert lines[property_line] == count
    assert lines["TemporaryFileSystem=/workspace:rw,size=64M,nr_inodes=4096,mode=0700"] == 1
