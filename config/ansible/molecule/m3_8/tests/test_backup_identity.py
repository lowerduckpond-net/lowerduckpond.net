"""Real Restic and installed root boundaries for the first M3.11 migration slice."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import test_lifecycle as support
from independent_fixture import require_owned_fixture
from testinfra.host import Host

COMMAND = "/usr/local/libexec/lowerduckpond/backup-state-identity"
LINEAGE = f"{support.STATE_ROOT}/platform/audit-lineage.json"
UNIT = "lowerduckpond-backup-identity.service"
PRIVATE_MODE = 0o600


def _run(host: Host, code: str) -> str:
    result = host.run("/usr/bin/python3 -I -B -c %s", code)
    assert result.rc == 0, result.stderr
    return result.stdout


def _restic(host: Host, arguments: str) -> str:
    # Fixed test-authored arguments only; neither config nor credentials are printed.
    result = host.run(
        "/bin/bash -c %s",
        "set -euo pipefail; exec 9<>/var/cache/lowerduckpond-backup/repository.lock; "
        "flock --exclusive 9; set -a; source /etc/lowerduckpond/backup.env; set +a; "
        f"/usr/bin/restic {arguments}",
    )
    assert result.rc == 0, "fixture Restic operation failed"
    return result.stdout


def test_installed_backup_identity_migration_and_repository_fencing(
    host: Host, tmp_path: Path
) -> None:
    require_owned_fixture()
    assert support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    created = support._submit(
        tmp_path,
        *connection,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=f"m3-identity-{uuid.uuid7().hex[-12:]}",
            quotas={"storageMiB": 1, "entries": 10},
        ),
    )
    assert created["status"] == "succeeded"
    assert not host.file(LINEAGE).exists
    assert host.run("%s --verify", COMMAND).rc != 0
    initialized = host.run("systemctl start %s", UNIT)
    assert initialized.rc == 0, host.run("journalctl -u %s --no-pager -n 20", UNIT).stdout
    original = host.file(LINEAGE).content
    record = json.loads(original)
    assert record["initialEntryCount"] > 0
    assert host.file(LINEAGE).user == "root" and host.file(LINEAGE).mode == PRIVATE_MODE
    assert host.run("%s --verify", COMMAND).rc == 0
    assert host.run("systemctl start %s", UNIT).rc == 0
    assert host.file(LINEAGE).content == original
    denied = host.run("runuser -u ldp-provisioner -- %s --initialize", COMMAND)
    assert denied.rc != 0
    assert host.run("/usr/local/libexec/lowerduckpond/backup-identity-agent --initialize").rc != 0
    _assert_lock_exclusion(host)
    _assert_repository_change_refused(host)

    # A second supported operation advances audit history while the immutable
    # pre-migration prefix remains verifiable without changing lineage bytes.
    deleted = support._submit(
        tmp_path,
        *connection,
        support._request("delete", str(uuid.uuid7()), tenantId=created["tenantId"]),
    )
    assert deleted["status"] == "succeeded"
    assert host.run("%s --verify", COMMAND).rc == 0
    assert host.file(LINEAGE).content == original

    # Dedicated diagnostic snapshot: exercise real full-ID discovery and restore,
    # without claiming this small snapshot is a coherent platform backup.
    output = _restic(
        host,
        f"backup --json --host {record['repository']['nodeName']} "
        f"--tag lineage-{record['lineageId']} "
        f"--tag repository-{record['repositoryBinding']['value']} {LINEAGE}",
    )
    summary = json.loads(output.splitlines()[-1])
    snapshot = summary["snapshot_id"]
    assert len(snapshot) == 64 and all(value in "0123456789abcdef" for value in snapshot)  # noqa: PLR2004
    destination = host.run("mktemp -d /var/cache/lowerduckpond-backup/identity-restore.XXXXXXXX")
    assert destination.rc == 0
    restore = destination.stdout.strip()
    _restic(host, f"restore {snapshot} --target {restore}")
    assert host.file(restore + LINEAGE).content == original
    _run(
        host,
        f"""
from pathlib import Path
path = Path({LINEAGE!r})
saved = path.read_bytes()
path.unlink()
try:
    import subprocess
    result = subprocess.run([{COMMAND!r}, '--initialize'], capture_output=True)
    assert result.returncode != 0
    assert not path.exists()
finally:
    path.write_bytes(saved)
    path.chmod(0o600)
""",
    )
    assert host.run("%s --verify", COMMAND).rc == 0


def _assert_repository_change_refused(host: Host) -> None:
    _run(
        host,
        f"""
import pathlib, re, subprocess
path = pathlib.Path('/etc/lowerduckpond/backup.env')
original = path.read_bytes()
lineage = pathlib.Path({LINEAGE!r}).read_bytes()
try:
    changed, count = re.subn(rb'^LOWERDUCKPOND_BACKUP_NODE_NAME=.*$',
        b'LOWERDUCKPOND_BACKUP_NODE_NAME=unrelated-node', original, flags=re.MULTILINE)
    assert count == 1
    path.write_bytes(changed)
    outcome = subprocess.run([{COMMAND!r}, '--initialize'], capture_output=True)
    assert outcome.returncode != 0
    assert pathlib.Path({LINEAGE!r}).read_bytes() == lineage
finally:
    path.write_bytes(original)
""",
    )


def _assert_lock_exclusion(host: Host) -> None:
    _run(
        host,
        f"""
import fcntl, os, pathlib, subprocess, time
for path in (
    '/var/cache/lowerduckpond-backup/repository.lock',
    '/opt/lowerduckpond/static-host-agent/selection.lock',
    '/var/lib/lowerduckpond/static/locks/tenant-state.lock',
):
    with open(path, 'rb') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX)
        child = subprocess.Popen([{COMMAND!r}, '--verify'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Confirm a live child cannot finish while an outer/inner lease is
            # held; completion afterward proves the installed command resumes.
            time.sleep(1)
            assert child.poll() is None, path
            fcntl.flock(lease, fcntl.LOCK_UN)
            stdout, stderr = child.communicate(timeout=30)
            assert child.returncode == 0, stderr
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
""",
    )
