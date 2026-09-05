from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
import zipfile
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_operator import submit
from testinfra.host import Host

CONTAINER = "lowerduckpond-ubuntu-2604"
OPERATOR_KEY = "/run/lowerduckpond-molecule/operator-key"
PUBLICATION_CONFIGURATION = "/etc/lowerduckpond/static-publication.json"
STATE_ROOT = "/var/lib/lowerduckpond/static"
RELEASE_ROOT = "/srv/lowerduckpond/sites"
UUIDS = (
    "019b1a00-0000-7000-8000-000000000001",
    "019b1a00-0000-7000-8000-000000000002",
    "019b1a00-0000-7000-8000-000000000003",
    "019b1a00-0000-7000-8000-000000000004",
    "019b1a00-0000-7000-8000-000000000005",
    "019b1a00-0000-7000-8000-000000000006",
    "019b1a00-0000-7000-8000-000000000007",
    "019b1a00-0000-7000-8000-000000000008",
    "019b1a00-0000-7000-8000-000000000009",
    "019b1a00-0000-7000-8000-00000000000a",
    "019b1a00-0000-7000-8000-00000000000b",
    "019b1a00-0000-7000-8000-00000000000c",
    "019b1a00-0000-7000-8000-00000000000d",
)
_BURST_CAPACITY = 5
_CORRELATION_INTERVAL_SECONDS = 60.25
_FIRST_CORRELATION_AT: float | None = None
_SEEN_CORRELATIONS: set[str] = set()


def _run(arguments: list[str]) -> str:
    completed = subprocess.run(  # noqa: S603
        arguments,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _deployment_zip(content: bytes) -> bytes:
    stream = BytesIO()
    member = zipfile.ZipInfo("index.html", date_time=(1980, 1, 1, 0, 0, 0))
    member.create_system = 3
    member.external_attr = (stat.S_IFREG | 0o644) << 16
    member.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(stream, mode="w") as archive:
        archive.writestr(member, content)
    return stream.getvalue()


def _enable_disposable_publication(host: Host) -> None:
    payload = (
        b'{"format":"lowerduckpond-static-publication-gate-v1","static_publication_enabled":true}\n'
    )
    encoded = payload.hex()
    command = (
        "import os,pathlib;"
        f"target=pathlib.Path({PUBLICATION_CONFIGURATION!r});"
        "temporary=target.with_name('.static-publication.m3-8');"
        f"temporary.write_bytes(bytes.fromhex({encoded!r}));"
        "temporary.chmod(0o400);"
        "os.chown(temporary,0,0);"
        "descriptor=os.open(temporary,os.O_RDONLY);"
        "os.fsync(descriptor);"
        "os.close(descriptor);"
        "os.replace(temporary,target);"
        "directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY);"
        "os.fsync(directory);"
        "os.close(directory)"
    )
    result = host.run("/usr/bin/python3 -I -B -c %s", command)
    assert result.rc == 0, result.stderr


def _initialize_namespace(host: Host) -> None:
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0, selected.stderr
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": "2026-09-05T12:00:00Z",
    }
    document = canonical_json_bytes(namespace).decode("ascii")
    command = (
        "import json,pathlib,sys;"
        f"sys.path.insert(0,{(selected.stdout.strip() + '/site-packages')!r});"
        "from lowerduckpond_static_host_agent import StateRecordPath,StateRepository;"
        f"repository=StateRepository(pathlib.Path({STATE_ROOT!r}),expected_owner=0);"
        f"repository.create_immutable(StateRecordPath.platform_namespace(),json.loads({document!r}));"
        "repository.close()"
    )
    result = host.run("/usr/bin/python3 -I -B -c %s", command)
    assert result.rc == 0, result.stderr


def _operator_inputs(tmp_path: Path) -> tuple[str, Path, Path]:
    identity = tmp_path / "operator-key"
    identity.write_text(
        _run(["docker", "exec", CONTAINER, "/usr/bin/cat", OPERATOR_KEY]) + "\n",
        encoding="ascii",
    )
    identity.chmod(0o600)
    host = urlsplit(os.environ.get("DOCKER_HOST", "")).hostname or "127.0.0.1"
    ssh = tmp_path / "ssh"
    ssh.write_text(
        "#!/bin/sh\n"
        "exec /usr/bin/ssh -p 2222 -o StrictHostKeyChecking=no "
        '-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$@"\n',
        encoding="ascii",
    )
    ssh.chmod(0o700)
    return host, identity, ssh


def _submit(  # noqa: PLR0913
    tmp_path: Path,
    host: str,
    identity: Path,
    ssh: Path,
    request: dict[str, object],
    *,
    artifact: bytes | None = None,
) -> dict[str, object]:
    _pace_new_correlation(request)
    request_path = tmp_path / f"{request['correlationId']}.json"
    artifact_path = None
    if artifact is not None:
        digest = hashlib.sha256(artifact).hexdigest()
        request["artifact"] = {"size": len(artifact), "sha256": digest}
        artifact_path = tmp_path / f"{request['correlationId']}.zip"
        artifact_path.write_bytes(artifact)
        artifact_path.chmod(0o600)
    request_path.write_bytes(canonical_json_bytes(request))
    request_path.chmod(0o600)
    return submit(
        host=host,
        identity_path=identity,
        request_path=request_path,
        artifact_path=artifact_path,
        ssh_executable=ssh,
    )


def _pace_new_correlation(request: dict[str, object]) -> None:
    global _FIRST_CORRELATION_AT  # noqa: PLW0603 - one ordered integration run

    correlation_id = request["correlationId"]
    assert type(correlation_id) is str
    if correlation_id in _SEEN_CORRELATIONS:
        return

    sequence = len(_SEEN_CORRELATIONS) + 1
    now = time.monotonic()
    if _FIRST_CORRELATION_AT is None:
        _FIRST_CORRELATION_AT = now
    elif sequence > _BURST_CAPACITY:
        target = (
            _FIRST_CORRELATION_AT + (sequence - _BURST_CAPACITY) * _CORRELATION_INTERVAL_SECONDS
        )
        time.sleep(max(0.0, target - now))
    _SEEN_CORRELATIONS.add(correlation_id)


def _request(operation: str, correlation_id: str, **fields: object) -> dict[str, object]:
    return {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": operation,
        "correlationId": correlation_id,
        **fields,
    }


def _manifest(result: dict[str, object]) -> dict[str, object]:
    manifest = result["manifest"]
    assert type(manifest) is dict
    return manifest


def _desired_deployment(result: dict[str, object]) -> str:
    spec = _manifest(result)["spec"]
    assert type(spec) is dict
    desired = spec["desiredDeployment"]
    assert type(desired) is dict
    deployment_id = desired["id"]
    assert type(deployment_id) is str
    return deployment_id


def _lifecycle(result: dict[str, object]) -> str:
    spec = _manifest(result)["spec"]
    assert type(spec) is dict
    state = spec["desiredState"]
    assert type(state) is str
    return state


def _ids() -> Iterator[str]:
    return iter(UUIDS)


def test_installed_core_lifecycle(  # noqa: PLR0915 - ordered installed-host lifecycle table
    host: Host, tmp_path: Path
) -> None:
    _initialize_namespace(host)
    _enable_disposable_publication(host)
    operator_host, identity, ssh = _operator_inputs(tmp_path)
    identities = _ids()

    create_request = _request(
        "create",
        next(identities),
        slug="m3-eight",
        quotas={"storageMiB": 100, "entries": 5000},
    )
    created = _submit(tmp_path, operator_host, identity, ssh, create_request)
    assert created["status"] == "succeeded"
    assert _lifecycle(created) == "undeployed"
    tenant_id = created["tenantId"]
    assert type(tenant_id) is str

    replay = _submit(tmp_path, operator_host, identity, ssh, dict(create_request))
    assert replay == created

    first = _deployment_zip(b"first installed M3.8 release\n")
    first_deploy_request = _request("deploy", next(identities), tenantId=tenant_id)
    deployed = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        first_deploy_request,
        artifact=first,
    )
    first_deployment = _desired_deployment(deployed)
    assert _lifecycle(deployed) == "active"
    assert (
        _submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(first_deploy_request),
            artifact=first,
        )
        == deployed
    )

    suspended = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("suspend", next(identities), tenantId=tenant_id),
    )
    assert _lifecycle(suspended) == "suspended"

    second = _deployment_zip(b"second installed M3.8 release\n")
    suspended_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=second,
    )
    second_deployment = _desired_deployment(suspended_deploy)
    assert _lifecycle(suspended_deploy) == "suspended"
    assert second_deployment != first_deployment

    suspended_rollback = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request(
            "rollback",
            next(identities),
            tenantId=tenant_id,
            deploymentId=first_deployment,
        ),
    )
    assert _lifecycle(suspended_rollback) == "suspended"
    assert _desired_deployment(suspended_rollback) == first_deployment

    resumed = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("resume", next(identities), tenantId=tenant_id),
    )
    assert _lifecycle(resumed) == "active"
    assert _desired_deployment(resumed) == first_deployment

    renamed = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("rename", next(identities), tenantId=tenant_id, slug="m3-eight-renamed"),
    )
    metadata = _manifest(renamed)["metadata"]
    assert type(metadata) is dict
    assert metadata["slug"] == "m3-eight-renamed"

    reconciled = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("reconcile", next(identities), tenantId=tenant_id),
    )
    assert _manifest(reconciled) == _manifest(renamed)

    third = _deployment_zip(b"third installed M3.8 release\n")
    third_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=third,
    )
    third_deployment = _desired_deployment(third_deploy)

    fourth = _deployment_zip(b"fourth installed M3.8 release\n")
    fourth_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=fourth,
    )
    fourth_deployment = _desired_deployment(fourth_deploy)

    fifth = _deployment_zip(b"fifth installed M3.8 release\n")
    fifth_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=fifth,
    )
    fifth_deployment = _desired_deployment(fifth_deploy)

    releases = host.run(
        f"find {RELEASE_ROOT}/{tenant_id}/releases -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'"
    )
    assert releases.rc == 0
    assert set(releases.stdout.splitlines()) == {
        third_deployment,
        fourth_deployment,
        fifth_deployment,
    }

    active_rollback_request = _request(
        "rollback",
        next(identities),
        tenantId=tenant_id,
        deploymentId=fourth_deployment,
    )
    active_rollback = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        active_rollback_request,
    )
    assert _lifecycle(active_rollback) == "active"
    assert _desired_deployment(active_rollback) == fourth_deployment
    assert (
        _submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(active_rollback_request),
        )
        == active_rollback
    )

    reused = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request(
            "create",
            next(identities),
            slug="m3-eight",
            quotas={"storageMiB": 100, "entries": 5000},
        ),
    )
    assert reused["status"] == "succeeded"
    reused_tenant_id = reused["tenantId"]
    assert type(reused_tenant_id) is str
    assert reused_tenant_id != tenant_id

    assert host.run("systemctl is-active --quiet caddy.service").rc == 0
    assert host.run("find /etc/caddy/intents -mindepth 1 -print -quit").stdout == ""
    assert host.run(f"find {RELEASE_ROOT}/.staging -mindepth 1 -print -quit").stdout == ""
    assert host.run(f"find {STATE_ROOT}/intents -mindepth 1 -print -quit").stdout == ""
    releases = host.run(
        f"find {RELEASE_ROOT}/{tenant_id}/releases -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'"
    )
    assert releases.rc == 0
    assert set(releases.stdout.splitlines()) == {
        third_deployment,
        fourth_deployment,
    }
