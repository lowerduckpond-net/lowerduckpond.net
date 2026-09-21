from __future__ import annotations

import fcntl
import shlex
import subprocess
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).parents[2] / "config/ansible/roles/backup/templates"
COMMANDS = (
    "backup",
    "backup-maintenance",
    "backup-state-identity",
    "backup-audit-protection",
    "latest-backup-snapshot",
    "restic-check",
    "restore-smoke-test",
)
OLD = "a" * 64
NEW = "b" * 64


def command_prefix(name: str, root: Path) -> str:
    source = (TEMPLATES / f"{name}.j2").read_text()
    start = source.index("exec 9<")
    guard = source.index("echo backup_configuration_scope_changed", start)
    end = source.index("\nfi\n", guard) + len("\nfi\n")
    prefix = source[start:end]
    prefix = prefix.replace("{{ backup_activation_scope | quote }}", shlex.quote(OLD))
    prefix = prefix.replace("/etc/lowerduckpond/backup.env", str(root / "backup.env"))
    prefix = prefix.replace(
        "/var/cache/lowerduckpond-backup/repository.lock", str(root / "repository.lock")
    )
    return (
        f"set -euo pipefail\nlock_path={shlex.quote(str(root / 'repository.lock'))}\n"
        f"{prefix}\n: > {shlex.quote(str(root / 'authorized'))}\n"
    )


@pytest.mark.parametrize("name", COMMANDS)
def test_queued_command_cannot_use_configuration_activated_after_its_policy_was_loaded(
    tmp_path: Path, name: str
) -> None:
    lock = tmp_path / "repository.lock"
    lock.write_bytes(b"")
    (tmp_path / "backup.env").write_text(f"LOWERDUCKPOND_BACKUP_ACTIVATION_SCOPE={OLD}\n")
    with lock.open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX)
        process = subprocess.Popen(  # noqa: S603 - owned exact installed prefix with private paths
            ["/usr/bin/bash", "-c", command_prefix(name, tmp_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"},
        )
        try:
            # The old policy is already in the child argv; lock serialization
            # orders activation before it can source any active configuration.
            (tmp_path / "backup.env").write_text(f"LOWERDUCKPOND_BACKUP_ACTIVATION_SCOPE={NEW}\n")
            fcntl.flock(lease, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode != 0
            assert stdout == b"" and stderr == b"backup_configuration_scope_changed\n"
            assert not (tmp_path / "authorized").exists()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    assert lock.read_bytes() == b""


@pytest.mark.parametrize("name", COMMANDS)
def test_current_command_requires_existing_lock_and_never_truncates_it(
    tmp_path: Path, name: str
) -> None:
    (tmp_path / "backup.env").write_text(f"LOWERDUCKPOND_BACKUP_ACTIVATION_SCOPE={OLD}\n")
    arguments = ["/usr/bin/bash", "-c", command_prefix(name, tmp_path)]
    result = subprocess.run(  # noqa: S603 - owned exact installed prefix
        arguments, check=False, capture_output=True, env={"PATH": "/usr/bin:/bin"}
    )
    assert result.returncode != 0
    assert not (tmp_path / "repository.lock").exists()
    assert not (tmp_path / "authorized").exists()
    (tmp_path / "repository.lock").write_bytes(b"existing inode bytes")
    before = (tmp_path / "repository.lock").stat().st_ino
    result = subprocess.run(  # noqa: S603 - owned exact installed prefix
        arguments, check=False, capture_output=True, env={"PATH": "/usr/bin:/bin"}
    )
    # Root agents perform full inode validation after this prefix. Its only
    # mutation capability here is the owned authorization marker.
    assert result.returncode == 0
    assert (tmp_path / "authorized").exists()
    assert (tmp_path / "repository.lock").stat().st_ino == before
    assert (tmp_path / "repository.lock").read_bytes() == b"existing inode bytes"
    assert (tmp_path / "repository.lock").stat().st_nlink == 1
