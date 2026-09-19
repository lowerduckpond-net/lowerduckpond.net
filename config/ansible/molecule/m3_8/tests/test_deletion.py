from __future__ import annotations

import json
from pathlib import Path

import pytest
import test_archive_lifecycle as archives
import test_lifecycle as support
from testinfra.host import Host

_HELPER = "/usr/local/libexec/lowerduckpond/emergency-delete-tenant"
_REASON = "disposable installed M3.10 emergency qualification"
_INTERRUPTED_STATUS = 42


@pytest.fixture(autouse=True)
def require_administrator_fixture(host: Host) -> None:
    administrator = host.user("ldp-admin")
    assert administrator.exists, "Molecule must prepare the cloud-init administrator fixture"
    assert administrator.uid != 0


def _emergency(host: Host, tenant: str, correlation: str) -> dict[str, object]:
    outcome = host.run(
        "runuser -u ldp-admin -- sudo -n %s --tenant %s --correlation %s --reason %s",
        _HELPER,
        tenant,
        correlation,
        _REASON,
    )
    assert outcome.rc == 0, outcome.stderr
    result = json.loads(outcome.stdout)
    assert type(result) is dict
    assert result["provenance"] == {
        "kind": "emergency-administrator",
        "operatorPrincipal": "ldp-admin",
        "reason": _REASON,
    }
    return result


def _assert_absent(host: Host, tenant: str, origin: str) -> None:
    assert not host.file(f"{support.STATE_ROOT}/tenants/{tenant}").exists
    assert not host.file(f"{support.RELEASE_ROOT}/{tenant}").exists
    support._assert_route(host, origin, status=404)


def _interrupt_emergency(host: Host, tenant: str, correlation: str) -> None:
    selected = host.run(
        "readlink --canonicalize /opt/lowerduckpond/static-host-agent/current"
    ).stdout.strip()
    prepare = f"""
import sys
sys.path.insert(0, {(selected + "/site-packages")!r})
from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent.repository import StateRepository
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.emergency_delete import EmergencyDeletion

def interrupt(boundary):
    if boundary == 'authority-sync':
        raise SystemExit({_INTERRUPTED_STATUS})
with (StateRepository(entrypoints._STATE_ROOT, expected_owner=0) as repository,
      ExportSpool(entrypoints._STATE_ROOT, expected_owner=0) as spool,
      entrypoints._open_deployment_release_store() as store,
      entrypoints._open_caddy_control_runtime() as runtime):
    EmergencyDeletion(repository, spool, runtime, store,
        cleanup=lambda *_args: None, hook=interrupt).execute(
        {tenant!r}, {correlation!r},
        operator_principal='ldp-admin', reason={_REASON!r})
"""
    interrupted = host.run("runuser -u root -g caddy -- /usr/bin/python3 -I -B -c %s", prepare)
    assert interrupted.rc == _INTERRUPTED_STATUS, interrupted.stderr


def _recover_emergency(host: Host) -> None:
    recovered = host.run("systemctl start lowerduckpond-static-emergency-reconcile.service")
    if recovered.rc != 0:
        journal = host.run(
            "journalctl -u lowerduckpond-static-emergency-reconcile.service -n 30 --no-pager"
        )
        raise AssertionError(journal.stdout + journal.stderr)


def test_installed_ordinary_and_emergency_deletion(host: Host, tmp_path: Path) -> None:
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    operator, identity, ssh = support._operator_inputs(tmp_path)
    identities = support._ids()
    slug = f"m3-delete-{next(identities).replace('-', '')[-12:]}"

    def create() -> tuple[dict[str, object], dict[str, object]]:
        request = support._request(
            "create", next(identities), slug=slug, quotas={"storageMiB": 100, "entries": 5000}
        )
        result = support._submit(tmp_path, operator, identity, ssh, request)
        assert result["status"] == "succeeded"
        return request, result

    _first_request, first = create()
    delete_request = support._request("delete", next(identities), tenantId=first["tenantId"])
    deleted = support._submit(tmp_path, operator, identity, ssh, delete_request)
    assert deleted["status"] == "succeeded" and "manifest" not in deleted
    _assert_absent(host, str(first["tenantId"]), str(first["canonicalOrigin"]))

    second_request, second = create()
    assert second["tenantId"] != first["tenantId"]
    assert second["canonicalOrigin"] != first["canonicalOrigin"]
    deployed = support._submit(
        tmp_path,
        operator,
        identity,
        ssh,
        support._request("deploy", next(identities), tenantId=second["tenantId"]),
        artifact=support._deployment_zip(b"emergency removal fixture"),
    )
    assert support._lifecycle(deployed) == "active"
    emergency_correlation = next(identities)
    emergency = _emergency(host, str(second["tenantId"]), emergency_correlation)
    _assert_absent(host, str(second["tenantId"]), str(second["canonicalOrigin"]))
    assert _emergency(host, str(second["tenantId"]), emergency_correlation) == emergency
    assert support._submit(tmp_path, operator, identity, ssh, second_request) == second
    assert support._submit(tmp_path, operator, identity, ssh, delete_request) == deleted

    _third_request, third = create()
    recovery_correlation = next(identities)
    _interrupt_emergency(host, str(third["tenantId"]), recovery_correlation)
    _recover_emergency(host)
    _assert_absent(host, str(third["tenantId"]), str(third["canonicalOrigin"]))
    assert _emergency(host, str(third["tenantId"]), recovery_correlation)["status"] == "succeeded"
    assert not host.file(
        f"{support.STATE_ROOT}/authorization/jobs/{recovery_correlation}.json"
    ).exists


def test_installed_emergency_recovery_retires_the_exact_archived_version(
    host: Host, tmp_path: Path
) -> None:
    support._initialize_admission_pacing(host)
    operator, identity, ssh = support._operator_inputs(tmp_path)
    identifiers = support._ids()
    created = support._submit(
        tmp_path,
        operator,
        identity,
        ssh,
        support._request(
            "create",
            next(identifiers),
            slug=f"m3-emergency-archive-{next(identifiers).replace('-', '')[-12:]}",
            quotas={"storageMiB": 1, "entries": 10},
        ),
    )
    assert created["status"] == "succeeded", created
    tenant = str(created["tenantId"])
    deployed = support._submit(
        tmp_path,
        operator,
        identity,
        ssh,
        support._request("deploy", next(identifiers), tenantId=tenant),
        artifact=support._deployment_zip(b"archived emergency recovery fixture"),
    )
    assert deployed["status"] == "succeeded", deployed
    request = support._request("archive", next(identifiers), tenantId=tenant)
    archived = support._submit(tmp_path, operator, identity, ssh, request)
    assert archived["status"] == "succeeded", archived
    record = archived["archiveRecord"]
    assert isinstance(record, dict)
    assert len(archives._remote_versions(host)) == 1
    correlation = next(identifiers)
    _interrupt_emergency(host, tenant, correlation)
    _recover_emergency(host)
    _assert_absent(host, tenant, str(created["canonicalOrigin"]))
    assert not archives._remote_versions(host)
    assert _emergency(host, tenant, correlation)["status"] == "succeeded"
    assert support._submit(tmp_path, operator, identity, ssh, request) == archived
