from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

import test_lifecycle as support
from independent_fixture import require_owned_fixture
from testinfra.host import Host


def _exercise_configuration(
    host: Host, tmp_path: Path, checks: tuple[Callable[[Host], None], ...]
) -> None:
    require_owned_fixture()
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    slug = f"m3-config-{uuid.uuid7().hex[-12:]}"
    created = support._submit(
        tmp_path,
        *connection,
        support._request(
            "create", str(uuid.uuid7()), slug=slug, quotas={"storageMiB": 1, "entries": 10}
        ),
    )
    assert created["status"] == "succeeded"
    tenant, origin = str(created["tenantId"]), str(created["canonicalOrigin"])
    content = b"configuration must preserve this active tenant\n"
    deployed = support._submit(
        tmp_path,
        *connection,
        support._request("deploy", str(uuid.uuid7()), tenantId=tenant),
        artifact=support._deployment_zip(content),
    )
    assert deployed["status"] == "succeeded"
    desired_path = f"{support.STATE_ROOT}/tenants/{tenant}/desired.json"
    desired = support._read_state(host, desired_path)
    selected = host.run("cat /etc/caddy/active")
    assert selected.rc == 0, selected.stderr
    for check in checks:
        check(host)
        assert support._read_state(host, desired_path) == desired
        assert host.run("cat /etc/caddy/active").stdout == selected.stdout
        support._assert_route(host, origin, status=200, body=content)
        support._assert_route(
            host, f"{slug}.lowerduckpond.com", status=302, redirect=f"https://{origin}/"
        )
        assert host.run("%s job-issuance", support.PUBLICATION_GATE).rc == 0


def test_publication_and_operator_boundaries_preserve_the_live_tenant(
    host: Host, tmp_path: Path
) -> None:
    _exercise_configuration(
        host,
        tmp_path,
        (
            support._assert_ansible_refuses_publication_disable,
            support._assert_ansible_refuses_live_operator_boundary_drift,
        ),
    )


def test_generation_input_and_idempotence_preserve_the_live_tenant(
    host: Host, tmp_path: Path
) -> None:
    _exercise_configuration(
        host,
        tmp_path,
        (
            lambda host: support._reapply_ansible(),
            support._assert_ansible_refuses_generation_input_drift,
        ),
    )
