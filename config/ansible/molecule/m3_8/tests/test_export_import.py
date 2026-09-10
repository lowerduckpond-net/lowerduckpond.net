from __future__ import annotations

import json
import os
import select
import shutil
import stat
import subprocess
import time
import uuid
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import test_lifecycle as support
import test_transport_recovery as recovery
from lowerduckpond_static_contracts import MAX_DEPLOY_ARTIFACT_BYTES, manifest_digest
from lowerduckpond_static_host_agent.portable_bundle import inspect_portable_bundle
from lowerduckpond_static_operator import client
from testinfra.host import Host

_CONTENT_BYTES = 100 * 1024 * 1024
_ENTRY_COUNT = 5_000
_FILE_BYTES = 4 * 1024 * 1024
_INDEX = b"full-size installed M3.9 content\n"
_WORKER_MEMORY_BYTES = 256 * 1024 * 1024


def _full_size_deployment() -> bytes:
    stream = BytesIO()
    remaining = _CONTENT_BYTES - len(_INDEX)
    with zipfile.ZipFile(stream, mode="w") as archive:
        for index in range(_ENTRY_COUNT):
            name = "index.html" if index == 0 else f"file-{index:04d}.bin"
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            if index == 0:
                content = _INDEX
            else:
                size = min(remaining, _FILE_BYTES)
                # Moderate compression fills the complete content quota while
                # leaving room for ZIP metadata in the bounded upload envelope.
                random_bytes = size // 2
                content = os.urandom(random_bytes) + bytes(size - random_bytes)
            archive.writestr(member, content)
            if index != 0:
                remaining -= len(content)
    assert remaining == 0
    payload = stream.getvalue()
    assert len(payload) <= MAX_DEPLOY_ARTIFACT_BYTES
    return payload


def _assert_worker_budget(host: Host, result: dict[str, object]) -> None:
    provenance = result["provenance"]
    assert isinstance(provenance, dict)
    job_id = str(provenance["jobId"])
    unit = f"lowerduckpond-static-worker@{job_id}.service"
    checked = host.run(
        "/usr/bin/systemctl show --property=Result --property=MemoryMax "
        "--property=MemorySwapMax --property=LimitCPU --property=CPUQuotaPerSecUSec %s",
        unit,
    )
    assert checked.rc == 0, checked.stderr
    properties = dict(line.split("=", 1) for line in checked.stdout.splitlines())
    assert properties["Result"] == "success"
    assert int(properties["MemoryMax"]) == _WORKER_MEMORY_BYTES
    assert properties["MemorySwapMax"] == "0"
    assert properties["LimitCPU"] == "120"
    assert properties["CPUQuotaPerSecUSec"] == "1s"


def _assert_empty_spool(host: Host) -> None:
    checked = host.run(
        "/usr/bin/python3 -I -B -c %s",
        "from pathlib import Path; "
        f"assert not list(Path({support.STATE_ROOT + '/exports'!r}).iterdir())",
    )
    assert checked.rc == 0, checked.stderr


def test_installed_full_size_export_import_round_trip(host: Host, tmp_path: Path) -> None:  # noqa: PLR0915
    support._await_persisted_admission_burst(host)
    operator_host, identity, ssh = support._operator_inputs(tmp_path)
    slug = f"m3-nine-{str(uuid.uuid7()).replace('-', '')[-12:]}"
    created = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=slug,
            quotas={"storageMiB": 100, "entries": _ENTRY_COUNT},
        ),
    )
    tenant_id = str(created["tenantId"])
    deployed = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request("deploy", str(uuid.uuid7()), tenantId=tenant_id),
        artifact=_full_size_deployment(),
    )
    assert deployed["status"] == "succeeded"
    support._assert_route(host, str(deployed["canonicalOrigin"]), status=200, body=_INDEX)
    _assert_worker_budget(host, deployed)
    desired_path = f"{support.STATE_ROOT}/tenants/{tenant_id}/desired.json"
    observed_path = f"{support.STATE_ROOT}/tenants/{tenant_id}/observed.json"
    first_bytes: bytes | None = None
    for number, source_state in enumerate(("active", "active", "suspended")):
        if source_state == "suspended":
            suspended = support._submit(
                tmp_path,
                operator_host,
                identity,
                ssh,
                support._request("suspend", str(uuid.uuid7()), tenantId=tenant_id),
            )
            assert support._lifecycle(suspended) == "suspended"
        desired_before = support._read_state(host, desired_path)
        observed_before = support._read_state(host, observed_path)
        export_request = support._request("export", str(uuid.uuid7()), tenantId=tenant_id)
        destination = tmp_path / f"export-{number}.zip"
        exported = support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            export_request,
            export_path=destination,
        )
        assert exported["status"] == "succeeded"
        assert support._lifecycle(exported) == source_state
        assert support._read_state(host, desired_path) == desired_before
        assert support._read_state(host, observed_path) == observed_before
        _assert_worker_budget(host, exported)
        inspection = inspect_portable_bundle(destination, expected_owner=os.geteuid())
        assert inspection.provenance_manifest == desired_before
        assert len(inspection.content_paths) == _ENTRY_COUNT
        assert inspection.content_bytes == _CONTENT_BYTES
        content = destination.read_bytes()
        if number == 0:
            first_bytes = content
        elif number == 1:
            assert content == first_bytes
        _assert_empty_spool(host)
        retired_destination = tmp_path / f"retired-{number}.zip"
        assert (
            support._submit(
                tmp_path,
                operator_host,
                identity,
                ssh,
                dict(export_request),
                export_path=retired_destination,
            )
            == exported
        )
        assert not retired_destination.exists()
        if number == 1:
            continue
        if number == 0:
            limited = support._submit(
                tmp_path,
                operator_host,
                identity,
                ssh,
                support._request(
                    "create",
                    str(uuid.uuid7()),
                    slug=f"{slug}-limited",
                    quotas={"storageMiB": 1, "entries": _ENTRY_COUNT},
                ),
            )
            limited_id = str(limited["tenantId"])
            rejected = support._submit(
                tmp_path,
                operator_host,
                identity,
                ssh,
                support._request("import", str(uuid.uuid7()), tenantId=limited_id),
                artifact=content,
            )
            assert rejected["status"] == "failed"
            assert rejected["errorCode"] == "capacity_exceeded"
            assert support._read_state(
                host, f"{support.STATE_ROOT}/tenants/{limited_id}/desired.json"
            ) == support._manifest(limited)
            support._assert_route(host, str(limited["canonicalOrigin"]), status=404)
        target = support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            support._request(
                "create",
                str(uuid.uuid7()),
                slug=f"{slug}-copy-{number}",
                quotas={"storageMiB": 100, "entries": _ENTRY_COUNT},
            ),
        )
        target_id = str(target["tenantId"])
        imported = support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            support._request("import", str(uuid.uuid7()), tenantId=target_id),
            artifact=content,
        )
        assert imported["status"] == "succeeded"
        assert support._lifecycle(imported) == "active"
        assert imported["tenantId"] == target_id
        assert imported["canonicalOrigin"] == target["canonicalOrigin"]
        assert support._desired_deployment(imported) != support._desired_deployment(exported)
        support._assert_route(host, str(imported["canonicalOrigin"]), status=200, body=_INDEX)
        _assert_worker_budget(host, imported)
        deployment_id = support._desired_deployment(imported)
        record = support._read_state(
            host, f"{support.STATE_ROOT}/tenants/{target_id}/deployments/{deployment_id}.json"
        )
        provenance = record["importProvenance"]
        assert isinstance(provenance, dict)
        assert provenance["manifest"] == desired_before
    _assert_empty_spool(host)


def _selected_python(host: Host, body: str) -> str:
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0, selected.stderr
    return (
        f"import sys; sys.path.insert(0, {(selected.stdout.strip() + '/site-packages')!r})\n{body}"
    )


def test_installed_unacknowledged_retry_conflict_and_expiry(
    host: Host, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    support._await_persisted_admission_burst(host)
    operator_host, identity, ssh = support._operator_inputs(tmp_path)
    created = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=f"m3-retain-{str(uuid.uuid7())[-12:]}",
            quotas={"storageMiB": 100, "entries": _ENTRY_COUNT},
        ),
    )
    tenant_id = str(created["tenantId"])
    undeployed_request = support._request("export", str(uuid.uuid7()), tenantId=tenant_id)
    undeployed_path = tmp_path / "undeployed.zip"
    rejected = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        undeployed_request,
        export_path=undeployed_path,
    )
    assert rejected["status"] == "failed"
    assert rejected["errorCode"] == "invalid_request"
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(undeployed_request),
            export_path=undeployed_path,
        )
        == rejected
    )
    assert not undeployed_path.exists()
    _assert_empty_spool(host)
    deployed = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request("deploy", str(uuid.uuid7()), tenantId=tenant_id),
        artifact=support._deployment_zip(b"retained download\n"),
    )
    assert deployed["status"] == "succeeded"
    for expire in (False, True):
        request = support._request("export", str(uuid.uuid7()), tenantId=tenant_id)
        destination = tmp_path / f"unacknowledged-{expire}.zip"
        with monkeypatch.context() as patch:
            patch.setattr(client, "acknowledge_export", lambda **_kwargs: None)
            exported = support._submit(
                tmp_path,
                operator_host,
                identity,
                ssh,
                request,
                export_path=destination,
            )
            retry_path = tmp_path / f"unacknowledged-retry-{expire}.zip"
            assert (
                support._submit(
                    tmp_path,
                    operator_host,
                    identity,
                    ssh,
                    dict(request),
                    export_path=retry_path,
                )
                == exported
            )
        assert destination.read_bytes() == retry_path.read_bytes()
        conflict_path = tmp_path / f"conflict-{expire}.zip"
        conflict = support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            support._request("export", str(uuid.uuid7()), tenantId=tenant_id),
            export_path=conflict_path,
        )
        assert conflict["errorCode"] == "conflict"
        assert not conflict_path.exists()
        provenance = exported["provenance"]
        assert isinstance(provenance, dict)
        job_id = str(provenance["jobId"])
        job_path = f"{support.STATE_ROOT}/authorization/jobs/{job_id}.json"
        original_job = support._read_state(host, job_path)
        assert original_job["exportDelivery"] == "unacknowledged"
        if expire:
            script = _selected_python(
                host,
                f"""
from datetime import datetime, timedelta
from pathlib import Path
from lowerduckpond_static_host_agent import StateRepository
from lowerduckpond_static_host_agent.export_delivery import ExportDelivery
from lowerduckpond_static_host_agent.export_spool import ExportSpool
root = Path({support.STATE_ROOT!r})
deadline = datetime.fromisoformat({original_job["acceptedAt"]!r}) + timedelta(hours=24)
with (
    StateRepository(root, expected_owner=0) as repository,
    ExportSpool(root, expected_owner=0) as spool,
):
    ExportDelivery(repository, spool, now=lambda: deadline).reconcile(blocking=True)
""",
            )
            checked = host.run("/usr/bin/python3 -I -B -c %s", script)
            assert checked.rc == 0, checked.stderr
        else:
            client.acknowledge_export(
                host=operator_host,
                identity_path=identity,
                result=exported,
                ssh_executable=ssh,
            )
        retired_job = support._read_state(host, job_path)
        assert retired_job["acceptedAt"] == original_job["acceptedAt"]
        assert retired_job["exportDelivery"] == ("expired" if expire else "acknowledged")
        _assert_empty_spool(host)
        retired_path = tmp_path / f"retired-{expire}.zip"
        assert (
            support._submit(
                tmp_path,
                operator_host,
                identity,
                ssh,
                dict(request),
                export_path=retired_path,
            )
            == exported
        )
        assert not retired_path.exists()


def _capture_process(host: Host, tenant_id: str) -> subprocess.Popen[str]:
    script = _selected_python(
        host,
        f"""
import json
import select
from pathlib import Path
from lowerduckpond_static_contracts import manifest_digest, deployment_record_digest
from lowerduckpond_static_host_agent import StateRepository, StateRecordPath
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.export_snapshot import (
    capture_export_snapshot, ExportCaptureBoundary,
)
from lowerduckpond_static_host_agent.export_handler import ExportLifecycleHandler
from lowerduckpond_static_host_agent.locks import LockMode

def pause(message):
    print(message, flush=True)
    assert select.select([sys.stdin], [], [], 90)[0], 'capture coordination timed out'
    assert sys.stdin.readline() == 'continue\\n'

def captured(boundary):
    if boundary == ExportCaptureBoundary.SNAPSHOT_VERIFIED:
        pause('captured')

class Gate:
    def require_enabled(self):
        pass

root = Path({support.STATE_ROOT!r})
with (
    StateRepository(root, expected_owner=0) as repository,
    ExportSpool(root, expected_owner=0) as spool,
):
    with spool.construction(blocking=True):
        with repository.transaction(mode=LockMode.SHARED, blocking=True) as transaction:
            manifest = transaction.read(StateRecordPath.tenant_desired({tenant_id!r})).document
            deployment = transaction.read(StateRecordPath.tenant_deployment(
                {tenant_id!r}, manifest['spec']['desiredDeployment']['id'])).document
            snapshot = capture_export_snapshot(
                spool, transaction, release_root=Path({support.RELEASE_ROOT!r}),
                tenant_id={tenant_id!r}, expected_manifest_digest=manifest_digest(manifest),
                expected_deployment_digest=deployment_record_digest(deployment),
                expected_owner=0, hook=captured,
            )
        pause('unlocked')
        inspection = ExportLifecycleHandler(
            repository, spool, Gate(), release_root=Path({support.RELEASE_ROOT!r}),
            expected_owner=0,
        )._build(snapshot)
        assert inspection.provenance_manifest == manifest
        content = (snapshot.content / 'index.html').read_text()
        print(json.dumps({{'manifest': manifest, 'content': content}}), flush=True)
""",  # noqa: S608 - Python select, no SQL
    )
    docker = shutil.which("docker")
    assert docker is not None
    return subprocess.Popen(  # noqa: S603 - disposable fixture and fixed root helper
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


def _await_capture_line(process: subprocess.Popen[str], expected: str) -> None:
    assert process.stdout is not None
    assert select.select([process.stdout], [], [], 30)[0], f"missing {expected} boundary"
    actual = process.stdout.readline().strip()
    if actual != expected:
        _output, error = process.communicate(timeout=10)
        raise AssertionError(f"capture returned {actual!r}: {error}")


def _continue_capture(process: subprocess.Popen[str]) -> None:
    assert process.stdin is not None
    process.stdin.write("continue\n")
    process.stdin.flush()


def _await_blocked_tenant_writer(host: Host) -> None:
    script = f"""
import os
import time
from pathlib import Path
metadata = os.stat({support.STATE_ROOT + "/locks/tenant-state.lock"!r})
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
raise SystemExit('mutation did not wait on the shared capture lock')
"""
    checked = host.run("/usr/bin/python3 -I -B -c %s", script)
    assert checked.rc == 0, checked.stderr


def _race_capture(
    host: Host,
    *,
    tenant_id: str,
    job_id: str,
    expected_content: bytes,
    removes_deployment: str | None = None,
) -> dict[str, object]:
    original = support._read_state(host, f"{support.STATE_ROOT}/tenants/{tenant_id}/desired.json")
    process = _capture_process(host, tenant_id)
    try:
        _await_capture_line(process, "captured")
        unit = f"lowerduckpond-static-worker@{job_id}.service"
        started = host.run("systemctl start --no-block %s", unit)
        assert started.rc == 0, started.stderr
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            state = host.run("systemctl show --property=ActiveState --value %s", unit)
            assert state.rc == 0, state.stderr
            if state.stdout.strip() in {"active", "activating"}:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("competing mutation never started")
        _await_blocked_tenant_writer(host)
        # The actual worker must not commit while capture still holds shared tenant-state.
        absent = host.run(
            "test ! -e %s", f"{support.STATE_ROOT}/authorization/results/{job_id}.json"
        )
        assert absent.rc == 0
        assert (
            support._read_state(host, f"{support.STATE_ROOT}/tenants/{tenant_id}/desired.json")
            == original
        )
        _continue_capture(process)
        _await_capture_line(process, "unlocked")
        result = recovery._await_result(host, job_id)
        assert result["status"] == "succeeded", result
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = host.run("systemctl show --property=ActiveState --value %s", unit)
            assert state.rc == 0, state.stderr
            if state.stdout.strip() == "inactive":
                break
            time.sleep(0.1)
        else:
            raise AssertionError("competing mutation did not exit")
        completed = host.run("systemctl show --property=Result --value %s", unit)
        assert completed.rc == 0 and completed.stdout.strip() == "success", completed.stderr
        if removes_deployment is not None:
            absent_release = host.run(
                "test ! -e %s",
                f"{support.RELEASE_ROOT}/{tenant_id}/releases/{removes_deployment}",
            )
            assert absent_release.rc == 0
        _continue_capture(process)
        output, error = process.communicate(timeout=30)
        assert process.returncode == 0, error
        captured = json.loads(output)
        assert captured["manifest"] == original
        assert captured["content"].encode() == expected_content
        recovery._await_authorization_quiescent(host, job_id)
        return result
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)


def test_installed_capture_races_core_mutations_and_release_cleanup(
    host: Host, tmp_path: Path
) -> None:
    support._await_persisted_admission_burst(host)
    operator_host, identity, ssh = support._operator_inputs(tmp_path)
    slug = f"m3-races-{str(uuid.uuid7())[-12:]}"
    created = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=slug,
            quotas={"storageMiB": 100, "entries": _ENTRY_COUNT},
        ),
    )
    tenant_id = str(created["tenantId"])
    first_content = b"first race generation\n"
    second_content = b"second race generation\n"
    first = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request("deploy", str(uuid.uuid7()), tenantId=tenant_id),
        artifact=support._deployment_zip(first_content),
    )
    first_deployment = support._desired_deployment(first)
    stopped = host.run("systemctl stop lowerduckpond-static-reconcile.timer")
    assert stopped.rc == 0, stopped.stderr
    try:
        recovery._await_authorization_quiescent(host)
        job = recovery._issue_artifact_without_handoff(
            host,
            support._request("deploy", str(uuid.uuid7()), tenantId=tenant_id),
            support._deployment_zip(second_content),
        )
        second = _race_capture(
            host, tenant_id=tenant_id, job_id=job, expected_content=first_content
        )
        second_deployment = support._desired_deployment(second)
        observed_path = f"{support.STATE_ROOT}/tenants/{tenant_id}/observed.json"
        before_rename: dict[str, object] | None = None
        for operation in ("suspend", "resume", "rename", "reconcile", "rollback"):
            fields: dict[str, object] = {"tenantId": tenant_id}
            if operation == "rename":
                fields["slug"] = f"{slug}-renamed"
                before_rename = support._read_state(host, observed_path)
            if operation == "reconcile":
                assert before_rename is not None
                support._replace_state(host, observed_path, before_rename)
            if operation == "rollback":
                fields["deploymentId"] = first_deployment
            request = support._request(operation, str(uuid.uuid7()), **fields)
            job = support._issue_without_handoff(host, request)
            result = _race_capture(
                host,
                tenant_id=tenant_id,
                job_id=job,
                expected_content=second_content,
                removes_deployment=second_deployment if operation == "rollback" else None,
            )
            assert support._lifecycle(result) == (
                "suspended" if operation == "suspend" else "active"
            )
            if operation == "reconcile":
                repaired = support._read_state(host, observed_path)
                assert (
                    repaired["desiredManifestDigest"]
                    == manifest_digest(support._manifest(result)).to_dict()
                )
        _assert_empty_spool(host)
    finally:
        recovery._start_reconcile_timer(host)
