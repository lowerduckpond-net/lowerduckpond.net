"""Coordinate real installed lifecycle workers with captured export snapshots."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import test_export_import as exports
import test_lifecycle as support
import test_transport_recovery as recovery
from testinfra.host import Host


def _archived_capture(host: Host, tenant: str) -> subprocess.Popen[str]:
    script = exports._selected_python(
        host,
        f"""
import json
import select
from pathlib import Path
from lowerduckpond_static_host_agent import StateRepository, StateRecordPath
from lowerduckpond_static_host_agent.archive_bundle import (
    RemoteArchiveBundleSource, fetch_archive_bundle,
)
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockMode
with (StateRepository(Path({support.STATE_ROOT!r}), expected_owner=0) as repository,
      ExportSpool(Path({support.STATE_ROOT!r}), expected_owner=0) as spool):
    with spool.construction(blocking=True):
        with repository.transaction(mode=LockMode.EXCLUSIVE, blocking=True) as transaction:
            manifest = transaction.read(StateRecordPath.tenant_desired({tenant!r})).document
            identifiers = transaction.tenant_archive_ids({tenant!r})
            assert len(identifiers) == 1
            record = transaction.read(
                StateRecordPath.tenant_archive({tenant!r}, identifiers[0])).document
        inspection = fetch_archive_bundle(
            RemoteArchiveBundleSource(load_archive_configuration().remote_store()), spool,
            record, manifest, job_id='root-installed-capture-proof', expected_owner=0)
        print('captured', flush=True)
        assert select.select([sys.stdin], [], [], 90)[0], 'capture coordination timed out'
        assert sys.stdin.readline() == 'continue\\n'
        print(json.dumps({{'manifest': inspection.provenance_manifest,
                          'digest': inspection.bundle_digest.to_dict()}}), flush=True)
""",  # noqa: S608 - Python select, no SQL
    )
    docker = shutil.which("docker")
    assert docker is not None
    return subprocess.Popen(  # noqa: S603 - fixed disposable host and installed code
        [
            docker,
            "exec",
            "-i",
            "--user",
            "root",
            support.CONTAINER,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            script,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def exercise_capture_exclusion(
    host: Host, request: dict[str, object], *, archived: bool, ansible_overlap: bool = False
) -> dict[str, object]:
    tenant = str(request["tenantId"])
    original = support._read_state(host, f"{support.STATE_ROOT}/tenants/{tenant}/desired.json")
    job = support._issue_without_handoff(host, request)
    process = (
        _archived_capture(host, tenant) if archived else exports._capture_process(host, tenant)
    )
    try:
        exports._await_capture_line(process, "captured")
        if not archived:
            exports._continue_capture(process)
            exports._await_capture_line(process, "unlocked")
        started = host.run("systemctl start --no-block lowerduckpond-static-worker@%s.service", job)
        assert started.rc == 0, started.stderr
        blocked = host.run(
            "/usr/bin/python3 -I -B -c %s",
            f"""
import os
import time
from pathlib import Path
metadata = os.stat({support.STATE_ROOT + "/locks/export.lock"!r})
identity = (os.major(metadata.st_dev), os.minor(metadata.st_dev), metadata.st_ino)
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    for line in Path('/proc/locks').read_text().splitlines():
        fields = line.split()
        if fields[1:5] != ['->', 'FLOCK', 'ADVISORY', 'WRITE']:
            continue
        major, minor, inode = fields[6].split(':')
        if (int(major, 16), int(minor, 16), int(inode)) != identity:
            continue
        try:
            groups = Path('/proc/' + fields[5] + '/cgroup').read_text().splitlines()
        except FileNotFoundError:
            continue
        unit = {"lowerduckpond-static-worker@" + job + ".service"!r}
        if any(unit in group.split(':', 2)[-1].split('/') for group in groups):
            raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit('lifecycle worker did not wait for export capture')
""",
        )
        assert blocked.rc == 0, blocked.stderr
        assert not host.file(f"{support.STATE_ROOT}/authorization/results/{job}.json").exists
        assert (
            support._read_state(host, f"{support.STATE_ROOT}/tenants/{tenant}/desired.json")
            == original
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            ansible = executor.submit(support._run_ansible_reapply) if ansible_overlap else None
            if ansible is not None:
                # The worker is verifiably blocked on capture while convergence is running.
                time.sleep(5)
                assert not ansible.done()
            exports._continue_capture(process)
            output, error = process.communicate(timeout=30)
            assert process.returncode == 0, error
            assert json.loads(output)["manifest"] == original
            result = recovery._await_result(host, job)
            assert result["status"] == "succeeded", result
            recovery._await_authorization_quiescent(host, job)
            if ansible is not None:
                reapplied = ansible.result(timeout=600)
                assert reapplied.returncode == 0, reapplied.stdout + reapplied.stderr
        return result
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
