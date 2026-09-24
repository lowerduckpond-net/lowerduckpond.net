"""Shared source preparation; every registry case owns its complete journey."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import audit_rotation_support as rotation
import backup_capture_support as captures
import test_archive_lifecycle as archives
import test_backup_coherence as backups
import test_backup_identity as identity
import test_export_import as exports
import test_lifecycle as support
import test_transport_recovery as recovery
from independent_fixture import require_owned_fixture
from lowerduckpond_static_operator import client
from restore_fixture import RECOVERY, UNIT, Fixture, checked
from testinfra.host import Host

from config.ansible.molecule.default.tests.test_host import _run_installed_boundary_probe
from scripts import qualification_restore as owned
from scripts.m3_11_live_storage import LiveStorage
from scripts.qualification_case import private_document


def activate_source(host: Host, *, archived_prefix: bool) -> None:
    """Require full source convergence and idempotence on its final configuration."""
    assert support._initialize_namespace(host)
    assert host.run("systemctl start %s", identity.UNIT).rc == 0
    reapplied = support._run_ansible_reapply(
        backup_recovery_enabled=True, audit_rotation_enabled=archived_prefix
    )
    # Activation changes the installation; the separate convergence must be
    # idempotent. Do not couple this fixture to a count of Ansible task labels.
    assert reapplied.returncode == 0, "source activation failed"
    support._assert_ansible_reapply_result(
        support._run_ansible_reapply(
            backup_recovery_enabled=True, audit_rotation_enabled=archived_prefix
        )
    )
    environment = dict(os.environ)
    receipt = owned.source_idempotence_receipt(environment, archived_prefix=archived_prefix)
    path = owned.directory(environment).parent / "source-idempotence.json"
    with path.open("x", encoding="ascii") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")


def source(
    host: Host,
    tmp_path: Path,
    *,
    archived_prefix: bool = False,
    full_history: bool = True,
    live_storage: LiveStorage | None = None,
) -> tuple[Fixture, list[str], dict[str, object]]:
    if live_storage is None:
        require_owned_fixture()
    else:
        live_storage.require_source(os.environ)
    activate_source(host, archived_prefix=archived_prefix)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    tenants = []
    replay: dict[str, object] = {}
    # Negative evidence needs active content and one exact archive. Positive
    # reconstruction and TLS keep all four states and the prior retained release.
    content_history = (b"retained release\n", b"selected release\n")
    for number in range(4) if full_history else (0, 2):
        request = support._request(
            "create",
            str(uuid.uuid7()),
            slug=f"restore-{uuid.uuid7().hex[-12:]}",
            quotas={"storageMiB": 1, "entries": 10},
        )
        created = support._submit(tmp_path, *connection, request)
        assert created["status"] == "succeeded"
        tenant = str(created["tenantId"])
        tenants.append(tenant)
        if number == 3:  # noqa: PLR2004 - fourth fixture remains undeployed
            replay = {"request": request, "result": created}
            continue
        for content in content_history if full_history else content_history[1:]:
            result = support._submit(
                tmp_path,
                *connection,
                support._request("deploy", str(uuid.uuid7()), tenantId=tenant),
                artifact=support._deployment_zip(content),
            )
            assert result["status"] == "succeeded"
        if number in (1, 2):
            result = support._submit(
                tmp_path,
                *connection,
                support._request(
                    "suspend" if number == 1 else "archive", str(uuid.uuid7()), tenantId=tenant
                ),
            )
            assert result["status"] == "succeeded"
    assert host.run("systemctl stop lowerduckpond-static-reconcile.timer").rc == 0
    assert host.run("systemctl stop lowerduckpond-audit-rotate.timer").rc == 0
    recovery._await_authorization_quiescent(host)
    if archived_prefix:
        rotation.close_full_segment(host)
        rotation.run_bounded_rotation(host)
        assert not host.file(
            f"{support.STATE_ROOT}/audit/segment-00000000000000000000.jsonl"
        ).exists
    export_request = support._request("export", str(uuid.uuid7()), tenantId=tenants[0])
    with patch.object(client, "acknowledge_export", return_value=None):
        exported = support._submit(
            tmp_path, *connection, export_request, export_path=tmp_path / "unacknowledged.zip"
        )
    assert exported["status"] == "succeeded"
    replay["exportJob"] = exported["provenance"]["jobId"]
    missing = support._request("deploy", str(uuid.uuid7()), tenantId=tenants[0])
    missing_job = recovery._issue_artifact_without_handoff(
        host, missing, support._deployment_zip(b"excluded upload\n")
    )
    backups._start_backup(host)
    snapshot = backups._latest(host)
    descriptor = captures.restore_and_measure(host, snapshot)
    assert {item["tenantId"] for item in descriptor["tenants"]} == set(tenants)
    fixture = Fixture(host, snapshot, live_storage=live_storage)
    replay["missingJob"] = missing_job
    replay["missingCorrelation"] = missing["correlationId"]
    replay["descriptor"] = descriptor
    return fixture, tenants, replay


def gate_closed(fixture: Fixture) -> None:
    destination = fixture.destination
    assert destination.file(owned.GATE).exists
    assert destination.run("nft list table inet lowerduckpond_restore").rc == 0
    for unit in (
        "lowerduckpond-static-reconcile.timer",
        "lowerduckpond-backup.timer",
        "lowerduckpond-backup-maintenance.timer",
        "lowerduckpond-audit-rotate.timer",
        "lowerduckpond-archive-cleanup.socket",
    ):
        assert not destination.service(unit).is_running
    assert (
        destination.run(
            "runuser -u ldp-provisioner -- /usr/local/sbin/restore-static-host --status"
        ).rc
        != 0
    )
    # A real peer in the same run-owned Docker network cannot reach origin web
    # ports, even while loopback Caddy is healthy during certificate issuance.
    address = fixture.address(fixture.destination_id)
    checked(
        fixture.acme,
        f"""
import socket
for port in (80, 443):
    try:
        connection = socket.create_connection(({address!r}, port), timeout=1)
    except OSError:
        continue
    connection.close()
    raise AssertionError('recovery exposed public web ingress')
""",
    )
    owned.source_fenced(fixture.environment)


def wait_failed(fixture: Fixture) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = fixture.destination.run(
            "systemctl show --property=ActiveState --value %s", UNIT
        ).stdout.strip()
        if state == "failed":
            gate_closed(fixture)
            assert fixture.status()["phase"] != "complete"
            assert not fixture.destination.service("caddy").is_running
            return
        time.sleep(0.25)
    raise AssertionError("invalid restore did not fail within its existing boundary")


def finish(fixture: Fixture, tenants: list[str], replay: dict[str, object]) -> None:
    fixture.wait({"complete"}, seconds=300)
    destination = fixture.destination
    assert fixture.status()["activationPending"] is False
    assert not destination.file(owned.GATE).exists
    assert destination.run("nft list table inet lowerduckpond_restore").rc != 0
    assert destination.service("caddy").is_running
    assert destination.service("caddy").is_enabled
    assert destination.service("lowerduckpond-static-reconcile.timer").is_running
    _run_installed_boundary_probe(
        destination,
        UNIT,
        "import os; assert not os.path.exists('/etc/lowerduckpond/archive/credentials.json'); "
        "assert os.path.isfile('/etc/lowerduckpond/backup.env')",
        check_admission=False,
    )
    _run_installed_boundary_probe(
        destination,
        "lowerduckpond-host-restore-archive-installed.service",
        exports._selected_python(
            destination,
            """
import os
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
configuration = load_archive_configuration()
inventory = configuration.remote_store().inventory()
assert len(inventory.versions) == 1 and not inventory.multipart_uploads
assert not os.path.exists('/etc/lowerduckpond/backup.env')
assert not os.path.exists('/etc/caddy/environment')
assert not os.path.exists('/srv/lowerduckpond/sites')
assert os.path.isdir('/restore-state') and os.path.isdir('/restore-archives')
assert os.statvfs('/').f_flag & os.ST_RDONLY
""",
        ),
        check_admission=False,
    )
    result = support._read_state(
        destination, f"{support.STATE_ROOT}/authorization/results/{replay['missingJob']}.json"
    )
    assert result["status"] == "failed" and result["errorCode"] == "restore_input_unavailable"
    # The original snapshot and fenced source bytes remain unchanged, including
    # the still pending source authorization job whose intake was excluded.
    assert fixture.source.file(
        f"{support.STATE_ROOT}/intake/{replay['missingCorrelation']}.artifact"
    ).exists
    descriptor = identity._restic(fixture.source, f"dump {fixture.snapshot} {captures.DESCRIPTOR}")
    assert json.loads(descriptor) == replay["descriptor"]
    path = fixture.root / "destination-operator"
    connection = fixture.connection(path)
    request = dict(replay["request"])
    original_result = dict(replay["result"])
    assert support._submit(path, *connection, request) == original_result
    # Replay binds the old result to the independently rebuilt current runtime;
    # the result itself must retain its historical generation and original bytes.
    binding = support._read_state(
        destination,
        f"{support.STATE_ROOT}/authorization/correlations/{request['correlationId']}.json",
    )
    result_path = f"{support.STATE_ROOT}/authorization/results/{binding['jobId']}.json"
    assert destination.file(result_path).content == fixture.source.file(result_path).content
    export_result = f"{support.STATE_ROOT}/authorization/results/{replay['exportJob']}.json"
    assert destination.file(export_result).content == fixture.source.file(export_result).content
    assert not destination.run(
        "find %s/exports -mindepth 1 -print -quit", support.STATE_ROOT
    ).stdout
    for tenant in tenants:
        manifest = support._read_state(
            destination, f"{support.STATE_ROOT}/tenants/{tenant}/desired.json"
        )
        if (
            manifest["spec"].get("desiredDeployment") is not None
            and manifest["spec"]["desiredState"] != "archived"
        ):
            result = support._submit(
                path, *connection, support._request("archive", str(uuid.uuid7()), tenantId=tenant)
            )
            assert result["status"] == "succeeded", result
        result = support._submit(
            path, *connection, support._request("delete", str(uuid.uuid7()), tenantId=tenant)
        )
        assert result["status"] == "succeeded", result
    assert not archives._remote_versions(destination)
    # A completed retry must not revalidate historical tenant roots after normal
    # work has advanced them, or alter immutable completed recovery evidence.
    journal = destination.file(f"{RECOVERY}/host-restore.json").content
    outcome = destination.run("/usr/local/sbin/restore-static-host --snapshot %s", fixture.snapshot)
    assert outcome.rc == 0 and destination.file(f"{RECOVERY}/host-restore.json").content == journal
    owned.acme_accounting(fixture.environment, fixture.acme_id)
    private_document(
        fixture.root,
        "completed.json",
        {
            "status": "passed",
            "identities": owned.identities(fixture.environment),
            "journalSha256": hashlib.sha256(journal).hexdigest(),
        },
    )
    owned.paired_proof(fixture.environment)
