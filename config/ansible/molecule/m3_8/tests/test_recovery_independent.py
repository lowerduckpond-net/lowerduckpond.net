from __future__ import annotations

import uuid
from pathlib import Path

import pytest
import test_lifecycle as support
import test_transport_recovery as recovery
from independent_fixture import require_owned_fixture
from testinfra.host import Host


def _fresh_recovery_fixture(
    host: Host, tmp_path: Path, request: pytest.FixtureRequest, *, suspended: bool
) -> recovery._RecoveryFixture:
    require_owned_fixture()
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    identities = support._ids()
    slug = f"m3-overlap-{uuid.uuid7().hex[-12:]}"
    stopped = host.run("systemctl stop lowerduckpond-static-reconcile.timer")
    assert stopped.rc == 0, stopped.stderr
    request.addfinalizer(lambda: recovery._start_reconcile_timer(host))
    recovery._await_authorization_quiescent(host)
    created = support._submit(
        tmp_path,
        *connection,
        support._request(
            "create", next(identities), slug=slug, quotas={"storageMiB": 100, "entries": 5000}
        ),
    )
    assert created["status"] == "succeeded"
    tenant_id, origin = str(created["tenantId"]), str(created["canonicalOrigin"])
    deployed = support._submit(
        tmp_path,
        *connection,
        support._request("deploy", next(identities), tenantId=tenant_id),
        artifact=support._deployment_zip(b"bound artifact deployed only after recovery\n"),
    )
    assert deployed["status"] == "succeeded"
    if suspended:
        result = support._submit(
            tmp_path,
            *connection,
            support._request("suspend", next(identities), tenantId=tenant_id),
        )
        assert result["status"] == "succeeded"
        assert support._lifecycle(result) == "suspended"
    return recovery._RecoveryFixture(
        host,
        tmp_path,
        connection,
        identities,
        slug,
        tenant_id,
        origin,
        deployed,
    )


def test_admission_transport_and_caddy_failure_recovery(
    host: Host, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    require_owned_fixture()
    fixture = recovery._exercise_admission_recovery(host, tmp_path, request)
    recovery._exercise_caddy_fault_matrix(fixture)
    recovery._exercise_contested_jobs(fixture)
    recovery._assert_recovery_cleanup(host)


def test_configuration_overlap_with_deploy_rollback_and_suspend(
    host: Host, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    fixture = _fresh_recovery_fixture(host, tmp_path, request, suspended=False)
    recovery._exercise_ansible_deploy_rollback_suspend(fixture)
    recovery._assert_recovery_cleanup(host)


def test_configuration_overlap_with_resume_rename_and_reconcile(
    host: Host, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    fixture = _fresh_recovery_fixture(host, tmp_path, request, suspended=True)
    recovery._exercise_ansible_resume_rename_reconcile(fixture)
    recovery._assert_recovery_cleanup(host)
