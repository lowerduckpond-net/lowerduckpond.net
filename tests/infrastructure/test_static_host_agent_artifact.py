from __future__ import annotations

import ast
import json
import os
import shlex
import subprocess
import sys
import tarfile
from collections import Counter
from pathlib import Path

from lowerduckpond_static_host_agent import ARCHIVE_SANDBOX_STATIC_PROPERTIES

REPOSITORY_ROOT = Path(__file__).parents[2]
BUILDER = (REPOSITORY_ROOT / "scripts/build-static-host-agent").resolve()
PREFLIGHT = (REPOSITORY_ROOT / "scripts/preflight-m3-dark-host-production").resolve()
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


def verifier_for_test(tmp_path: Path) -> Path:
    """Run the production verifier with the artifact's pinned Python runtime."""
    implementation = tmp_path / "verify-static-host-agent-artifact-implementation"
    source = VERIFIER.read_text(encoding="utf-8")
    source = source.replace("#!/usr/bin/python3 -I", f"#!{sys.executable} -I", 1)
    implementation.write_text(source, encoding="utf-8")
    implementation.chmod(0o755)

    verifier = tmp_path / "verify-static-host-agent-artifact"
    verifier.write_text(
        f'#!/bin/sh\nexec {shlex.quote(os.fspath(implementation))} --current-owner "$@"\n',
        encoding="utf-8",
    )
    verifier.chmod(0o755)
    return verifier


def test_host_agent_artifact_is_locked_reproducible_and_installable(
    tmp_path: Path,
) -> None:
    for helper in (INSTALLER, VERIFIER):
        ast.parse(helper.read_text(encoding="utf-8"), feature_version=(3, 12))

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
    verifier = verifier_for_test(tmp_path)
    installed = run(INSTALLER, first, digest, install_root, verifier)
    assert installed.returncode == 0, installed.stderr
    assert installed.stdout == "changed\n"
    repeated = run(INSTALLER, first, digest, install_root, verifier)
    assert repeated.returncode == 0, repeated.stderr
    assert repeated.stdout == "unchanged\n"

    selected = (install_root / "current").resolve(strict=True)
    assert selected == install_root / digest
    manifest = json.loads((selected / "artifact-manifest.json").read_bytes())
    assert manifest["format"] == "lowerduckpond-static-host-agent-artifact-v1"
    assert manifest["python"] == "3.14"
    assert run(verifier, selected).returncode == 0


def test_installer_refuses_drift_in_an_existing_version(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.tar"
    build = run(BUILDER, artifact)
    assert build.returncode == 0, build.stderr
    digest = build.stdout.strip()
    install_root = tmp_path / "install"
    install_root.mkdir()
    verifier = verifier_for_test(tmp_path)
    assert run(INSTALLER, artifact, digest, install_root, verifier).returncode == 0

    selected = install_root / digest
    victim = next((selected / "site-packages").rglob("*.py"))
    victim.chmod(0o644)
    victim.write_bytes(victim.read_bytes() + b"\n")
    victim.chmod(ARCHIVE_FILE_MODE)

    refused = run(INSTALLER, artifact, digest, install_root, verifier)
    assert refused.returncode != 0
    assert "content drifted" in refused.stderr


def test_preflight_extraction_preserves_reviewed_modes_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact.tar"
    build = run(BUILDER, artifact)
    assert build.returncode == 0, build.stderr

    preflight = PREFLIGHT.read_text(encoding="utf-8")
    assert 'tar --extract --same-permissions --file "${first_artifact}"' in preflight

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    original_umask = os.umask(0o077)
    try:
        extraction = run(
            "tar",
            "--extract",
            "--same-permissions",
            "--file",
            artifact,
            "--directory",
            extracted,
            "--strip-components=1",
        )
    finally:
        os.umask(original_umask)
    assert extraction.returncode == 0, extraction.stderr
    assert (extracted / "site-packages").stat().st_mode & 0o777 == ARCHIVE_ROOT_MODE

    extracted.chmod(ARCHIVE_ROOT_MODE)
    verifier = verifier_for_test(tmp_path)
    verified = run(verifier, extracted)
    assert verified.returncode == 0, verified.stderr


def test_dark_worker_unit_consumes_the_reviewed_sandbox_contract() -> None:
    lines = Counter(WORKER_UNIT_TEMPLATE.read_text(encoding="utf-8").splitlines())
    expected = Counter(f"{key}={value}" for key, value in ARCHIVE_SANDBOX_STATIC_PROPERTIES)
    # This trusted root-owned entry point begins as ldp-provisioner and needs
    # exactly one sudo transition into the fixed UUID-only executor. Sudo/PAM
    # needs AF_UNIX sockets, pipe2, and resource-limit operations, while the
    # private network namespace and cgroup/rlimit ceilings remain fixed. The
    # archive helper itself retains the reviewed no-new-privileges policy.
    expected["NoNewPrivileges=true"] -= 1
    expected["NoNewPrivileges=false"] += 1
    expected["CapabilityBoundingSet="] -= 1
    expected["CapabilityBoundingSet=CAP_SETGID CAP_SETUID"] += 1
    expected["RestrictAddressFamilies=~AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET"] -= 1
    expected["RestrictAddressFamilies=AF_UNIX"] += 1
    expected["SystemCallFilter=~@network-io"] -= 1
    expected["SystemCallFilter=~@resources"] -= 1
    expected["SystemCallFilter=~prlimit64"] -= 1
    expected["SystemCallFilter=~pipe pipe2 mknod mknodat"] -= 1
    expected["SystemCallFilter=~mknod mknodat"] += 1
    expected["SystemCallFilter=~clone clone3 fork vfork"] -= 1
    for property_line, count in expected.items():
        assert lines[property_line] == count
    assert lines["TemporaryFileSystem=/workspace:rw,size=64M,nr_inodes=4096,mode=0700"] == 1
    assert lines["BindReadOnlyPaths=/usr"] == 1
    assert lines["BindReadOnlyPaths=/lib"] == 1
    assert lines["BindReadOnlyPaths=/lib64"] == 1
    assert lines["BindReadOnlyPaths=/etc/lowerduckpond/static-publication.json"] == 1
