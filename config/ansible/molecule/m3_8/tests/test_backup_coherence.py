"""Independently owned backup/mutation/Restic-restore qualification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import backup_capture_support as captures
import test_backup_identity as identity
import test_deletion as deletion
import test_export_import as exports
import test_lifecycle as support
import test_transport_recovery as recovery
from independent_fixture import require_owned_fixture
from testinfra.host import Host


def _start_backup(host: Host, *, succeeds: bool = True) -> None:
    result = host.run("systemctl start %s", captures.BACKUP_UNIT)
    assert (result.rc == 0) is succeeds, host.run(
        "journalctl -u %s --no-pager -n 20", captures.BACKUP_UNIT
    ).stdout


def _latest(host: Host) -> str:
    snapshots = json.loads(
        identity._restic(host, "snapshots --json --tag lowerduckpond-static-backup")
    )
    return str(max(snapshots, key=lambda snapshot: snapshot["time"])["id"])


def _service_boundaries(host: Host) -> None:
    unit = host.run("systemctl cat %s", captures.BACKUP_UNIT).stdout
    for line in (
        "TimeoutStartSec=30min",
        "MemoryMax=512M",
        "MemorySwapMax=0",
        "TasksMax=32",
        "LimitNOFILE=1024",
        "CPUQuota=100%",
        "InaccessiblePaths=-/etc/lowerduckpond/archive",
        "InaccessiblePaths=-/run/lowerduckpond-archive",
    ):
        assert line in unit
    command = "/usr/local/libexec/lowerduckpond/backup-capture-agent"
    assert host.run("runuser -u ldp-provisioner -- %s", command).rc != 0
    assert host.run("%s", command).rc != 0  # no inherited repository lease
    assert host.run("runuser -u ldp-provisioner -- cat /etc/lowerduckpond/backup.env").rc != 0
    success = "/var/lib/lowerduckpond/backup-status/backup-last-success"
    original = host.file(success).content
    path = f"{support.STATE_ROOT}/platform/unknown-backup-authority.json"
    created = host.run("install -m 0600 /dev/null %s", path)
    assert created.rc == 0
    try:
        _start_backup(host, succeeds=False)
        assert host.file(success).content == original
        assert host.file("/var/lib/lowerduckpond/backup-status/backup-last-failure").exists
        assert not host.file("/var/cache/lowerduckpond-backup/staging/mariadb.sql.gz").exists
    finally:
        assert host.run("rm -- %s", path).rc == 0
    _start_backup(host)
    assert host.file(success).content != original


def _source_exclusion_canaries(host: Host) -> None:
    script = """
import grp, os
from pathlib import Path
names = (
    '/var/lib/lowerduckpond/static/intake/backup-secret-canary',
    '/var/lib/lowerduckpond/static/exports/backup-secret-canary',
    '/var/lib/lowerduckpond/static/.ldp-state-' + 'a' * 32,
    '/var/lib/lowerduckpond/static/platform/.ldp-state-' + 'b' * 32,
    '/var/lib/lowerduckpond/recovery/.ldp-state-' + 'c' * 32,
    '/srv/lowerduckpond/fixture/.ldp-state-' + 'd' * 32,
)
for name in names:
    path = Path(name)
    path.write_bytes(b'disposable-backup-canary')
    path.chmod(0o640 if name.startswith('/srv/') else 0o600)
    if name.startswith('/srv/'):
        os.chown(path, 0, grp.getgrnam('caddy').gr_gid)
"""
    identity._run(host, script)
    try:
        _start_backup(host)
        captures.restore_and_measure(host, _latest(host))
        # Shared capture is a reader; it cannot remove valid abandoned temporaries.
        assert host.file(f"{support.STATE_ROOT}/.ldp-state-" + "a" * 32).exists
    finally:
        identity._run(
            host,
            script.split("for name in names:", maxsplit=1)[0]
            + "for name in names: Path(name).unlink(missing_ok=True)",
        )


def _ansible_fixture_write(host: Host, tmp_path: Path) -> None:
    fixture = "/srv/lowerduckpond/fixture/index.html"
    original = host.file(fixture).content
    replacement = tmp_path / "fixture.html"
    replacement.write_bytes(original + b"\n<!-- backup writer overlap -->\n")
    uv = shutil.which("uv")
    assert uv is not None

    def apply() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed owned fixture and Ansible file action
            [
                uv,
                "run",
                "ansible",
                "all",
                "-i",
                support.CONTAINER + ",",
                "-c",
                "community.docker.docker",
                "-u",
                "root",
                "-m",
                "ansible.builtin.copy",
                "-a",
                json.dumps(
                    {
                        "src": str(replacement),
                        "dest": fixture,
                        "owner": "root",
                        "group": "caddy",
                        "mode": "0640",
                    }
                ),
                "-e",
                "ansible_python_interpreter=/usr/local/libexec/lowerduckpond/configure-static-python",
            ],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
            env={**os.environ, "ANSIBLE_PIPELINING": "true"},
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        work = []

        def start() -> None:
            work.append(executor.submit(apply))

        captures.race(host, start, lock="publication")
        result = work[0].result(timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        assert host.file(fixture).content == replacement.read_bytes()
        replacement.write_bytes(original)
        result = apply()
        assert result.returncode == 0, result.stdout + result.stderr


def _repair_overlap(host: Host, request: dict[str, object], job: str) -> None:
    index = f"{support.STATE_ROOT}/authorization/correlations/{request['correlationId']}.json"
    original = host.file(index).content
    assert host.run("rm -- %s", index).rc == 0
    script = exports._selected_python(
        host,
        f"""
from pathlib import Path
from lowerduckpond_static_host_agent import StateRepository
from lowerduckpond_static_host_agent.correlations import CorrelationAdmission
with StateRepository(Path({support.STATE_ROOT!r}), expected_owner=0) as repository:
    outcome = CorrelationAdmission(repository).reconcile(blocking=True)
    assert outcome.repaired_records == 1
""",
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        work = []

        def start() -> None:
            work.append(executor.submit(identity._run, host, script))

        captures.race(host, start)
        work[0].result(timeout=30)
    assert host.file(index).content == original
    assert support._execute_issued_job(host, job)["status"] == "succeeded"
    recovery._await_authorization_quiescent(host, job)


def test_installed_coherent_backup_restore_and_writer_exclusion(  # noqa: PLR0915
    host: Host, tmp_path: Path
) -> None:
    require_owned_fixture()
    assert support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)

    def submit(
        operation: str, *, artifact: bytes | None = None, **fields: object
    ) -> dict[str, object]:
        result = support._submit(
            tmp_path,
            *connection,
            support._request(operation, str(uuid.uuid7()), **fields),
            artifact=artifact,
        )
        assert result["status"] == "succeeded", result
        return result

    tenants = [
        str(
            submit(
                "create",
                slug=f"m3-backup-{uuid.uuid7().hex[-12:]}",
                quotas={"storageMiB": 1, "entries": 10},
            )["tenantId"]
        )
        for _ in range(4)
    ]
    active, suspended, archived, undeployed = tenants
    first = submit("deploy", tenantId=active, artifact=support._deployment_zip(b"first"))
    first_deployment = support._desired_deployment(first)
    submit("deploy", tenantId=active, artifact=support._deployment_zip(b"second"))
    for tenant in (suspended, archived):
        submit("deploy", tenantId=tenant, artifact=support._deployment_zip(b"other tenant"))
    submit("suspend", tenantId=suspended)
    submit("archive", tenantId=archived)
    portable = tmp_path / "source.zip"
    exported = support._submit(
        tmp_path,
        *connection,
        support._request("export", str(uuid.uuid7()), tenantId=active),
        export_path=portable,
    )
    assert exported["status"] == "succeeded"
    assert host.run("systemctl start %s", identity.UNIT).rc == 0
    # Exactly the command, source-scope configuration and first matching backup change.
    support._assert_ansible_reapply_result(
        support._run_ansible_reapply(backup_recovery_enabled=True), expected_changes=3
    )
    support._assert_ansible_reapply_result(
        support._run_ansible_reapply(backup_recovery_enabled=True)
    )
    descriptor = captures.restore_and_measure(host, _latest(host))
    assert {tenant["tenantId"] for tenant in descriptor["tenants"]} == set(tenants)
    _service_boundaries(host)
    assert host.run("systemctl stop lowerduckpond-static-reconcile.timer").rc == 0
    try:
        recovery._await_authorization_quiescent(host)
        _source_exclusion_canaries(host)

        def race(
            operation: str, *, artifact: bytes | None = None, **fields: object
        ) -> dict[str, object]:
            request = support._request(operation, str(uuid.uuid7()), **fields)
            job = (
                support._issue_without_handoff(host, request)
                if artifact is None
                else recovery._issue_artifact_without_handoff(host, request, artifact)
            )
            result, _descriptor = captures.race_job(host, job)
            if operation == "export":
                assert (
                    support._submit(
                        tmp_path, *connection, request, export_path=tmp_path / "raced-export.zip"
                    )
                    == result
                )
            return result

        created = race(
            "create",
            slug=f"m3-backup-race-{uuid.uuid7().hex[-12:]}",
            quotas={"storageMiB": 1, "entries": 10},
        )
        tenants.append(str(created["tenantId"]))
        third = race("deploy", tenantId=active, artifact=support._deployment_zip(b"third"))
        fourth = race("deploy", tenantId=active, artifact=support._deployment_zip(b"fourth"))
        assert not host.file(f"{support.RELEASE_ROOT}/{active}/releases/{first_deployment}").exists
        race("rollback", tenantId=active, deploymentId=support._desired_deployment(third))
        assert not host.file(
            f"{support.RELEASE_ROOT}/{active}/releases/{support._desired_deployment(fourth)}"
        ).exists
        for operation in ("suspend", "resume", "rename", "reconcile", "export"):
            fields = (
                {"slug": f"m3-backup-renamed-{uuid.uuid7().hex[-12:]}"}
                if operation == "rename"
                else {}
            )
            race(operation, tenantId=active, **fields)
        race("import", tenantId=undeployed, artifact=portable.read_bytes())
        race("archive", tenantId=active)
        race("restore", tenantId=active)
        race("delete", tenantId=archived)
        tenants.remove(archived)
        with ThreadPoolExecutor(max_workers=1) as executor:
            work = []

            def emergency() -> None:
                work.append(
                    executor.submit(deletion._emergency, host, suspended, str(uuid.uuid7()))
                )

            captures.race(host, emergency, lock="publication")
            assert work[0].result(timeout=90)["status"] == "succeeded"
        tenants.remove(suspended)
        request = support._request("reconcile", str(uuid.uuid7()), tenantId=active)
        job = support._issue_without_handoff(host, request)
        _repair_overlap(host, request, job)
        _ansible_fixture_write(host, tmp_path)

        with ThreadPoolExecutor(max_workers=1) as executor:
            starts = []

            def restart_caddy() -> None:
                starts.append(executor.submit(host.run, "systemctl restart caddy.service"))

            captures.race(host, restart_caddy, lock="publication")
            started = starts[0].result(timeout=90)
            assert started.rc == 0, started.stderr
        assert host.service("caddy").is_running
        for tenant in tenants:
            manifest = support._read_state(
                host, f"{support.STATE_ROOT}/tenants/{tenant}/desired.json"
            )
            if manifest["spec"].get("desiredDeployment") is not None:
                submit("archive", tenantId=tenant)
            submit("delete", tenantId=tenant)
        exports._assert_empty_spool(host)
        _start_backup(host)
        assert captures.restore_and_measure(host, _latest(host))["tenants"] == []
    finally:
        recovery._start_reconcile_timer(host)
