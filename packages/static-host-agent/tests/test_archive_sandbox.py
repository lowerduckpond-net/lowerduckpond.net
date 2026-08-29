from __future__ import annotations

import os
import subprocess
from pathlib import Path

import lowerduckpond_static_host_agent.archive_sandbox as archive_sandbox_module
import pytest
from lowerduckpond_static_host_agent import (
    ARCHIVE_SANDBOX_STATIC_PROPERTIES,
    ArchiveSandboxError,
    archive_sandbox_policy,
)

_EXPECTED_RESOURCE_PROPERTIES = {
    "CPUQuota": "100%",
    "LimitCPU": "120",
    "LimitCORE": "0",
    "LimitNOFILE": "1024",
    "MemoryMax": "256M",
    "MemorySwapMax": "0",
    "RuntimeMaxSec": "5min",
    "TimeoutStartSec": "5min",
    "TasksMax": "32",
    "Type": "exec",
}
_EXPECTED_ISOLATION_PROPERTIES = {
    "CapabilityBoundingSet": "",
    "DevicePolicy": "closed",
    "IPAddressDeny": "any",
    "InaccessiblePaths": "/proc",
    "MemoryDenyWriteExecute": "true",
    "NoNewPrivileges": "true",
    "PrivateDevices": "true",
    "PrivateIPC": "true",
    "PrivateNetwork": "true",
    "ProtectHome": "true",
    "ProtectSystem": "strict",
    "RestrictAddressFamilies": "~AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET",
    "RestrictNamespaces": "true",
    "StandardError": "null",
    "StandardInput": "null",
    "StandardOutput": "null",
    "SystemCallArchitectures": "native",
    "TemporaryFileSystem": "/:ro",
}
_EXPECTED_SYSTEM_CALL_FILTERS = (
    "@system-service",
    "~@network-io",
    "~@keyring",
    "~@resources",
    "~prlimit64",
    "~sync syncfs",
    "~inotify_init inotify_init1 inotify_add_watch",
    "~io_uring_setup io_uring_register io_uring_enter",
    "~clone clone3 fork vfork",
    "~kill tkill tgkill rt_sigqueueinfo rt_tgsigqueueinfo pidfd_send_signal",
    "~ptrace process_vm_readv process_vm_writev pidfd_getfd process_madvise process_mrelease",
)
_BOUND_PATH_COUNT = 3


def test_archive_sandbox_commits_exact_resource_and_isolation_backstops() -> None:
    properties = {
        name: value
        for name, value in ARCHIVE_SANDBOX_STATIC_PROPERTIES
        if name != "SystemCallFilter"
    }
    filters = tuple(
        value for name, value in ARCHIVE_SANDBOX_STATIC_PROPERTIES if name == "SystemCallFilter"
    )

    assert {name: properties[name] for name in _EXPECTED_RESOURCE_PROPERTIES} == (
        _EXPECTED_RESOURCE_PROPERTIES
    )
    assert {name: properties[name] for name in _EXPECTED_ISOLATION_PROPERTIES} == (
        _EXPECTED_ISOLATION_PROPERTIES
    )
    assert filters == _EXPECTED_SYSTEM_CALL_FILTERS


def test_archive_sandbox_exposes_only_runtime_one_input_and_one_output_tree(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"")
    staging = tmp_path / "staging"
    staging.mkdir()
    policy = archive_sandbox_policy(
        runtime,
        artifact,
        staging,
    )

    assert policy.properties[-3:] == (
        ("BindReadOnlyPaths", os.fspath(runtime)),
        ("BindReadOnlyPaths", os.fspath(artifact)),
        ("BindPaths", os.fspath(staging)),
    )
    assert len({policy.runtime_root, policy.artifact, policy.staging_parent}) == _BOUND_PATH_COUNT


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
    tmp_path: Path,
    artifact: str,
    staging: str,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    with pytest.raises(ArchiveSandboxError):
        archive_sandbox_policy(runtime, Path(artifact), Path(staging))


def test_archive_sandbox_rejects_symlinked_path_components(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"")
    staging = tmp_path / "staging"
    staging.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(staging, target_is_directory=True)

    with pytest.raises(ArchiveSandboxError, match=r"symbolic link|unavailable"):
        archive_sandbox_policy(runtime, artifact, alias)


def test_archive_sandbox_rejects_runtime_or_artifact_aliases(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"")
    staging = runtime / "staging"
    staging.mkdir()

    with pytest.raises(ArchiveSandboxError, match="disjoint and unaliased"):
        archive_sandbox_policy(runtime, artifact, staging)


def test_archive_sandbox_rejects_a_mount_point_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"")
    staging = tmp_path / "staging"
    staging.mkdir()
    runtime_identity = (runtime.stat().st_dev, runtime.stat().st_ino)
    real_mount_id = archive_sandbox_module._mount_id

    def mounted_runtime(descriptor: int) -> int:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == runtime_identity:
            return real_mount_id(descriptor) + 1
        return real_mount_id(descriptor)

    monkeypatch.setattr(archive_sandbox_module, "_mount_id", mounted_runtime)

    with pytest.raises(ArchiveSandboxError, match="mount point"):
        archive_sandbox_policy(runtime, artifact, staging)


def test_archive_sandbox_properties_form_a_valid_systemd_unit(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"")
    staging = tmp_path / "staging"
    staging.mkdir()
    policy = archive_sandbox_policy(runtime, artifact, staging)
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
        env={**os.environ, "SYSTEMD_LOG_LEVEL": "warning"},
    )

    assert completed.returncode == 0, completed.stderr
    assert "RuntimeMaxSec= has no effect" not in completed.stderr
