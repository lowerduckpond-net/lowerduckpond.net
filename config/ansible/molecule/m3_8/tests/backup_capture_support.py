"""Real installed capture with a test-process pause inside the production leases."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
from collections.abc import Callable

import test_backup_identity as identity
import test_export_import as exports
import test_lifecycle as support
import test_transport_recovery as recovery
from testinfra.host import Host

DESCRIPTOR = "/var/cache/lowerduckpond-backup/staging/static-recovery.json"
BACKUP_UNIT = "lowerduckpond-backup.service"


def capture_process() -> subprocess.Popen[str]:
    # The artifact is never modified. The diagnostic process substitutes only
    # the call boundary, then calls the original Restic writer/readback while
    # both production shared locks remain held. The installed service itself is
    # exercised separately, including health, credentials and resource limits.
    script = """
import fcntl, grp, os, select, subprocess, sys
from pathlib import Path
selection = os.open('/opt/lowerduckpond/static-host-agent/selection.lock', os.O_RDONLY)
fcntl.flock(selection, fcntl.LOCK_SH)
selected = Path('/opt/lowerduckpond/static-host-agent/current').resolve(strict=True)
subprocess.run(['/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact',
                str(selected)], check=True, capture_output=True)
sys.path.insert(0, str(selected / 'site-packages'))
from lowerduckpond_static_host_agent import backup_coordinator as coordinator
from lowerduckpond_static_host_agent.backup_restic import inherit_restic_leases
original = coordinator.create_coherent_snapshot
def captured(raw, environment):
    print('captured', flush=True)
    assert select.select([sys.stdin], [], [], 90)[0], 'capture coordination timed out'
    assert sys.stdin.readline() == 'continue\\n'
    return original(raw, environment)
coordinator.create_coherent_snapshot = captured
with inherit_restic_leases((9, selection)):
    snapshot = coordinator.capture_backup(coordinator.CapturePaths(), os.environ,
        artifact_sha256=selected.name, expected_owner=0,
        content_group=grp.getgrnam('caddy').gr_gid)
print(snapshot, flush=True)
"""
    shell = (
        "set -euo pipefail; umask 077; "
        "exec 9<>/var/cache/lowerduckpond-backup/repository.lock; flock --exclusive 9; "
        "set -a; source /etc/lowerduckpond/backup.env; set +a; "
        "trap 'rm -f /var/cache/lowerduckpond-backup/staging/mariadb.sql.gz' EXIT; "
        "/usr/bin/env --ignore-environment PATH=/usr/bin:/bin "
        "/usr/sbin/runuser --user ldp-backup -- /usr/bin/mariadb-dump "
        "--all-databases --single-transaction --quick --routines --events --triggers "
        "| gzip --best > /var/cache/lowerduckpond-backup/staging/mariadb.sql.gz; "
        f"/usr/bin/python3 -I -B -c {shlex.quote(script)}"
    )
    docker = shutil.which("docker")
    assert docker is not None
    return subprocess.Popen(  # noqa: S603 - owned fixture, fixed root diagnostic
        [docker, "exec", "-i", "--user", "root", support.CONTAINER, "/bin/bash", "-c", shell],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def await_writer(host: Host, name: str = "tenant-state") -> None:
    script = f"""
import os, time
from pathlib import Path
metadata = os.stat({support.STATE_ROOT + "/locks/" + name + ".lock"!r})
identity = (os.major(metadata.st_dev), os.minor(metadata.st_dev), metadata.st_ino)
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    for line in Path('/proc/locks').read_text().splitlines():
        fields = line.split()
        if fields[1:5] != ['->', 'FLOCK', 'ADVISORY', 'WRITE']:
            continue
        major, minor, inode = fields[6].split(':')
        if (int(major, 16), int(minor, 16), int(inode)) == identity:
            raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit('writer did not wait on backup capture')
"""
    identity._run(host, script)


def finish_capture(process: subprocess.Popen[str]) -> str:
    exports._continue_capture(process)
    output, error = process.communicate(timeout=120)
    assert process.returncode == 0, error
    snapshot = output.strip()
    assert len(snapshot) == 64 and all(value in "0123456789abcdef" for value in snapshot)  # noqa: PLR2004
    return snapshot


def race(host: Host, start: Callable[[], None], *, lock: str = "tenant-state") -> dict[str, object]:
    process = capture_process()
    try:
        exports._await_capture_line(process, "captured")
        raw = host.file(DESCRIPTOR).content
        start()
        await_writer(host, lock)
        assert process.poll() is None
        snapshot = finish_capture(process)
        return restore_and_measure(host, snapshot, expected=raw)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)


def race_job(host: Host, job: str) -> tuple[dict[str, object], dict[str, object]]:
    unit = f"lowerduckpond-static-worker@{job}.service"

    def start() -> None:
        result = host.run("systemctl start --no-block %s", unit)
        assert result.rc == 0, result.stderr

    descriptor = race(host, start)
    result = recovery._await_result(host, job)
    assert result["status"] == "succeeded", result
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state = host.run("systemctl show --property=ActiveState --value %s", unit)
        if state.stdout.strip() == "inactive":
            break
        time.sleep(0.1)
    else:
        raise AssertionError("mutation did not finish after capture released its locks")
    assert host.run("systemctl show --property=Result --value %s", unit).stdout.strip() == "success"
    recovery._await_authorization_quiescent(host, job)
    return result, descriptor


def restore_and_measure(
    host: Host, snapshot: str, *, expected: bytes | None = None
) -> dict[str, object]:
    raw = identity._restic(host, f"dump {snapshot} {DESCRIPTOR}").encode()
    if expected is not None:
        assert raw == expected
    document = json.loads(raw)
    assert document["schema"] == "lowerduckpond-static-backup-v1"
    entries = json.loads(identity._restic(host, f"snapshots --json {snapshot}"))
    assert len(entries) == 1 and entries[0]["id"] == snapshot
    assert set(entries[0]["tags"]) >= {
        "scheduled",
        "lowerduckpond-static-backup",
        f"capture-{document['captureId']}",
        f"lineage-{document['lineage']['lineageId']}",
        f"repository-{document['lineage']['repositoryBinding']['value']}",
    }
    destination = host.run("mktemp -d /var/cache/lowerduckpond-backup/coherent-restore.XXXXXXXX")
    assert destination.rc == 0
    restore = destination.stdout.strip()
    identity._restic(host, f"restore {snapshot} --target {restore}")
    script = exports._selected_python(
        host,
        f"""
import grp, gzip, json, shutil
from pathlib import Path
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_sources import measure_backup_sources, SOURCE_PATHS
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
destination = Path({restore!r})
raw = (destination / {DESCRIPTOR.lstrip("/")!r}).read_bytes()
document = decode_backup_descriptor(raw)
roots = {{name: destination / path.lstrip('/') for name, path in SOURCE_PATHS.items()}}
with (DurableDirectory.open(roots['state'] / 'locks', expected_owner=0,
                           expected_directory_mode=0o700) as directory,
      LockManager(directory, expected_owner=0) as locks,
      locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED, blocking=True),
      locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED, blocking=True)):
    tree = measure_backup_sources(roots, Path('/var/cache/lowerduckpond-backup/workspace'),
                                 locks=locks, expected_owner=0,
                                 content_group=grp.getgrnam('caddy').gr_gid)
    assert document['authority'] == {{'treeDigest': tree.digest, 'entryCount': tree.entries,
                                     'contentBytes': tree.content_bytes}}
for excluded in ('var/lib/lowerduckpond/static/intake', 'var/lib/lowerduckpond/static/exports',
                 'srv/lowerduckpond/sites/.staging', 'srv/lowerduckpond/lost+found',
                 'etc/caddy', 'var/lib/caddy'):
    assert not (destination / excluded).exists(), excluded
assert not list(roots['state'].rglob('.ldp-state-*'))
assert not list(roots['recovery'].rglob('.ldp-state-*'))
database = destination / 'var/cache/lowerduckpond-backup/staging/mariadb.sql.gz'
with gzip.open(database, 'rb') as source:
    assert b'MariaDB' in source.read(4096)
print(json.dumps(document))
shutil.rmtree(destination)
""",
    )
    restored = json.loads(identity._run(host, script))
    assert restored == document
    return document
