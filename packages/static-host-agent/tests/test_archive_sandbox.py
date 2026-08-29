from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    ARCHIVE_SANDBOX_STATIC_PROPERTIES,
    ArchiveSandboxError,
    archive_sandbox_policy,
)

_EXPECTED_RESOURCE_PROPERTIES = {
    "CPUQuota": "100%",
    "LimitCPU": "120",
    "LimitNOFILE": "1024",
    "MemoryMax": "256M",
    "MemorySwapMax": "0",
    "RuntimeMaxSec": "5min",
    "TasksMax": "32",
}
_EXPECTED_ISOLATION_PROPERTIES = {
    "CapabilityBoundingSet": "",
    "DevicePolicy": "closed",
    "IPAddressDeny": "any",
    "MemoryDenyWriteExecute": "true",
    "NoNewPrivileges": "true",
    "PrivateDevices": "true",
    "PrivateNetwork": "true",
    "PrivateTmp": "true",
    "ProtectHome": "true",
    "ProtectSystem": "strict",
    "RestrictAddressFamilies": "AF_UNIX",
    "RestrictNamespaces": "true",
    "SystemCallArchitectures": "native",
    "SystemCallFilter": "@system-service",
}


def test_archive_sandbox_commits_exact_resource_and_isolation_backstops() -> None:
    properties = dict(ARCHIVE_SANDBOX_STATIC_PROPERTIES)

    assert len(properties) == len(ARCHIVE_SANDBOX_STATIC_PROPERTIES)
    assert {name: properties[name] for name in _EXPECTED_RESOURCE_PROPERTIES} == (
        _EXPECTED_RESOURCE_PROPERTIES
    )
    assert {name: properties[name] for name in _EXPECTED_ISOLATION_PROPERTIES} == (
        _EXPECTED_ISOLATION_PROPERTIES
    )


def test_archive_sandbox_exposes_only_one_input_and_one_output_tree() -> None:
    policy = archive_sandbox_policy(
        Path("/var/lib/lowerduckpond/intake/artifact.zip"),
        Path("/var/lib/lowerduckpond/releases/staging"),
    )

    assert policy.properties[-2:] == (
        ("ReadOnlyPaths", "/var/lib/lowerduckpond/intake/artifact.zip"),
        ("ReadWritePaths", "/var/lib/lowerduckpond/releases/staging"),
    )
    assert policy.artifact != policy.staging_parent


@pytest.mark.parametrize(
    ("artifact", "staging"),
    [
        ("relative.zip", "/var/lib/lowerduckpond/staging"),
        ("/", "/var/lib/lowerduckpond/staging"),
        ("/var/lib/artifact zip", "/var/lib/lowerduckpond/staging"),
        ("/var/lib/artifact:zip", "/var/lib/lowerduckpond/staging"),
        ("/var/lib/archive", "/var/lib/archive/staging"),
        ("/var/lib/archive/artifact.zip", "/var/lib/archive"),
    ],
)
def test_archive_sandbox_rejects_ambiguous_or_overlapping_paths(
    artifact: str,
    staging: str,
) -> None:
    with pytest.raises(ArchiveSandboxError):
        archive_sandbox_policy(Path(artifact), Path(staging))


def test_archive_sandbox_properties_form_a_valid_systemd_unit(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"")
    staging = tmp_path / "staging"
    staging.mkdir()
    policy = archive_sandbox_policy(artifact, staging)
    service = tmp_path / "lowerduckpond-archive-sandbox-test.service"
    properties = "\n".join(f"{name}={value}" for name, value in policy.properties)
    service.write_text(
        "[Unit]\n"
        "Description=Lower Duck Pond archive sandbox static verification\n\n"
        "[Service]\n"
        f"{properties}\n"
        "ExecStart=/bin/true\n",
        encoding="utf-8",
    )

    completed = subprocess.run(  # noqa: S603 - fixed executable and generated unit
        ["/usr/bin/systemd-analyze", "verify", "--recursive-errors=no", os.fspath(service)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "SYSTEMD_LOG_LEVEL": "err"},
    )

    assert completed.returncode == 0, completed.stderr
