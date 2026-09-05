from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import time
import uuid
import zipfile
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from lowerduckpond_static_contracts import canonical_json_bytes, manifest_digest
from lowerduckpond_static_operator import OperatorClientError, submit
from testinfra.host import Host

CONTAINER = "lowerduckpond-ubuntu-2604"
OPERATOR_KEY = "/run/lowerduckpond-molecule/operator-key"
ORIGIN_PULL_CLIENT_CERTIFICATE = "/run/lowerduckpond-molecule/origin-pull-client.pem"
ORIGIN_PULL_CLIENT_KEY = "/run/lowerduckpond-molecule/origin-pull-client.key"
ORIGIN_PULL_CA_CERTIFICATE = "/etc/caddy/origin-pull-ca-0.pem"
PUBLICATION_CONFIGURATION = "/etc/lowerduckpond/static-publication.json"
PUBLICATION_GATE = "/usr/local/libexec/lowerduckpond/static-publication-gate"
STATE_ROOT = "/var/lib/lowerduckpond/static"
RELEASE_ROOT = "/srv/lowerduckpond/sites"
_BURST_CAPACITY = 5
_CORRELATION_INTERVAL_SECONDS = 60.25
_BURST_REFILL_SECONDS = _BURST_CAPACITY * _CORRELATION_INTERVAL_SECONDS
_AVAILABLE_CORRELATION_TOKENS = float(_BURST_CAPACITY)
_CORRELATION_TOKENS_UPDATED_AT: float | None = None
_SEEN_CORRELATIONS: set[str] = set()
_RETRYABLE_BUSY = "operator transport failed: tenant-state.lock is busy"
_BUSY_RETRY_ATTEMPTS = 50
_BUSY_RETRY_SECONDS = 0.1


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


def _initialize_namespace(host: Host) -> bool:
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0, selected.stderr
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": "2026-09-05T12:00:00Z",
    }
    document = canonical_json_bytes(namespace).decode("ascii")
    command = f"""
import json
import pathlib
import sys

sys.path.insert(0, {(selected.stdout.strip() + "/site-packages")!r})
from lowerduckpond_static_host_agent import StateRecordPath, StateRepository

repository = StateRepository(pathlib.Path({STATE_ROOT!r}), expected_owner=0)
path = StateRecordPath.platform_namespace()
expected = json.loads({document!r})
try:
    existing = repository.read(path).document
except FileNotFoundError:
    repository.create_immutable(path, expected)
    print("created")
else:
    if existing != expected:
        raise RuntimeError("existing platform namespace disagrees with the fixture")
    print("existing")
finally:
    repository.close()
"""
    result = host.run("/usr/bin/python3 -I -B -c %s", command)
    assert result.rc == 0, result.stderr
    assert result.stdout.strip() in {"created", "existing"}
    return result.stdout.strip() == "created"


def _prepare_edge_probe(host: Host) -> None:
    result = host.run("/usr/sbin/ip address replace 173.245.48.1/32 dev lo")
    assert result.rc == 0, result.stderr


def _await_persisted_admission_burst(host: Host) -> None:
    command = f"""
import datetime
import json
import pathlib

timestamps = []
root = pathlib.Path({(STATE_ROOT + "/authorization/correlations")!r})
for path in root.glob("*.json"):
    document = json.loads(path.read_text(encoding="ascii"))
    timestamps.append(
        datetime.datetime.fromisoformat(
            document["acceptedAt"].replace("Z", "+00:00")
        )
    )
if timestamps:
    elapsed = (datetime.datetime.now(datetime.UTC) - max(timestamps)).total_seconds()
    print(max(0.0, {_BURST_REFILL_SECONDS!r} - elapsed))
else:
    print(0.0)
"""
    result = host.run("/usr/bin/python3 -I -B -c %s", command)
    assert result.rc == 0, result.stderr
    time.sleep(float(result.stdout.strip()))


def _assert_route(
    host: Host,
    origin: str,
    *,
    status: int,
    body: bytes | None = None,
    redirect: str = "",
) -> None:
    command = " ".join(
        (
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--cacert",
            shlex.quote(ORIGIN_PULL_CA_CERTIFICATE),
            "--interface",
            "173.245.48.1",
            "--cert",
            shlex.quote(ORIGIN_PULL_CLIENT_CERTIFICATE),
            "--key",
            shlex.quote(ORIGIN_PULL_CLIENT_KEY),
            "--resolve",
            shlex.quote(f"{origin}:443:127.0.0.1"),
            "--write-out",
            shlex.quote("\\n%{http_code}\\n%{redirect_url}"),
            shlex.quote(f"https://{origin}/"),
        )
    )
    result = host.run(command)
    assert result.rc == 0, result.stderr
    response_body, response_status, response_redirect = result.stdout.rsplit("\n", 2)
    assert int(response_status) == status
    assert response_redirect == redirect
    if body is not None:
        assert response_body.encode() == body


def _assert_unauthenticated_route_rejected(host: Host, origin: str) -> None:
    command = " ".join(
        (
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--cacert",
            shlex.quote(ORIGIN_PULL_CA_CERTIFICATE),
            "--interface",
            "173.245.48.1",
            "--resolve",
            shlex.quote(f"{origin}:443:127.0.0.1"),
            "--output",
            "/dev/null",
            "--write-out",
            shlex.quote("%{http_code}"),
            shlex.quote(f"https://{origin}/"),
        )
    )
    result = host.run(command)
    assert result.rc != 0
    assert result.stdout == "000"


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


def _read_state(host: Host, path: str) -> dict[str, object]:
    result = host.run("/usr/bin/cat %s", path)
    assert result.rc == 0, result.stderr
    document = json.loads(result.stdout)
    assert type(document) is dict
    return document


def _replace_state(host: Host, path: str, document: dict[str, object]) -> None:
    encoded = canonical_json_bytes(document).hex()
    command = (
        "import os,pathlib;"
        f"target=pathlib.Path({path!r});"
        "temporary=target.with_name('.m3-8-drift');"
        f"temporary.write_bytes(bytes.fromhex({encoded!r}));"
        "temporary.chmod(0o600);"
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


def _issue_without_handoff(host: Host, request: dict[str, object]) -> str:
    new_correlation = _pace_new_correlation(request)
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0, selected.stderr
    request_hex = canonical_json_bytes(request).hex()
    command = f"""
import os
import pathlib
import sys
from datetime import UTC, datetime

sys.path.insert(0, {(selected.stdout.strip() + "/site-packages")!r})
from lowerduckpond_static_host_agent import (
    AuthorizationIssuer,
    CommandPublicationGate,
    StateRepository,
)

with StateRepository(pathlib.Path({STATE_ROOT!r}), expected_owner=0) as repository:
    issued = AuthorizationIssuer(
        repository,
        gate=CommandPublicationGate(pathlib.Path({PUBLICATION_GATE!r})),
        entropy=os.getrandom,
    ).issue(
        bytes.fromhex({request_hex!r}),
        operator_principal="molecule-m3-8-operator-v1",
        now=datetime.now(UTC),
        artifact=None,
    )
    print(issued.job_id)
"""
    try:
        result = host.run("/usr/bin/python3 -I -B -c %s", command)
    finally:
        _complete_correlation_pacing(new_correlation)
    assert result.rc == 0, result.stderr
    return result.stdout.strip()


def _execute_issued_job(host: Host, job_id: str) -> dict[str, object]:
    result = host.run(
        "/usr/bin/systemctl start --wait lowerduckpond-static-worker@%s.service",
        job_id,
    )
    document = _read_state(host, f"{STATE_ROOT}/authorization/results/{job_id}.json")
    assert result.rc == 0 or document["status"] == "failed", result.stderr
    return document


def _run_ansible_reapply(
    *, cloudflare_api_token: str | None = None
) -> subprocess.CompletedProcess[str]:
    project = Path(__file__).resolve().parents[3]
    uv = shutil.which("uv")
    assert uv is not None
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("MOLECULE_")
    }
    environment["M3_8_STATIC_PUBLICATION_ENABLED"] = "true"
    if cloudflare_api_token is not None:
        environment["M3_8_CLOUDFLARE_API_TOKEN"] = cloudflare_api_token
    return subprocess.run(  # noqa: S603 - resolved trusted tool path
        [uv, "run", "molecule", "converge", "--scenario-name", "m3_8"],
        cwd=project,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _reapply_ansible() -> None:
    result = _run_ansible_reapply()
    assert result.returncode == 0, result.stdout + result.stderr


def _assert_ansible_refuses_generation_input_drift(host: Host) -> None:
    selected_before = host.run("cat /etc/caddy/active")
    environment_before = host.run("sha256sum /etc/caddy/environment")
    assert selected_before.rc == 0, selected_before.stderr
    assert environment_before.rc == 0, environment_before.stderr

    result = _run_ansible_reapply(cloudflare_api_token="1" * 40)
    assert result.returncode != 0, result.stdout + result.stderr
    assert (
        "refusing to alter staged inputs without a tenant-capable generation migration"
        in result.stdout
    )

    selected_after = host.run("cat /etc/caddy/active")
    environment_after = host.run("sha256sum /etc/caddy/environment")
    assert selected_after.rc == 0, selected_after.stderr
    assert environment_after.rc == 0, environment_after.stderr
    assert selected_after.stdout == selected_before.stdout
    assert environment_after.stdout == environment_before.stdout
    assert host.run("systemctl is-active --quiet caddy.service").rc == 0


def _restart_installed_services(host: Host) -> None:
    stopped = host.run("/usr/bin/systemctl stop caddy.service")
    assert stopped.rc == 0, stopped.stderr
    reconciled = host.run("/usr/bin/systemctl restart lowerduckpond-static-reconcile.service")
    assert reconciled.rc == 0, reconciled.stderr
    started = host.run("/usr/bin/systemctl start caddy.service")
    assert started.rc == 0, started.stderr


def _submit(  # noqa: PLR0913
    tmp_path: Path,
    host: str,
    identity: Path,
    ssh: Path,
    request: dict[str, object],
    *,
    artifact: bytes | None = None,
) -> dict[str, object]:
    new_correlation = _pace_new_correlation(request)
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
    try:
        for attempt in range(_BUSY_RETRY_ATTEMPTS):
            try:
                return submit(
                    host=host,
                    identity_path=identity,
                    request_path=request_path,
                    artifact_path=artifact_path,
                    ssh_executable=ssh,
                )
            except OperatorClientError as error:
                if str(error) != _RETRYABLE_BUSY or attempt == _BUSY_RETRY_ATTEMPTS - 1:
                    raise
                time.sleep(_BUSY_RETRY_SECONDS)
    finally:
        _complete_correlation_pacing(new_correlation)
    raise AssertionError(
        "busy retry loop exhausted without a terminal response"
    )  # pragma: no cover


def _pace_new_correlation(request: dict[str, object]) -> bool:
    global _AVAILABLE_CORRELATION_TOKENS  # noqa: PLW0603 - one integration run
    global _CORRELATION_TOKENS_UPDATED_AT  # noqa: PLW0603 - one integration run

    correlation_id = request["correlationId"]
    assert type(correlation_id) is str
    if correlation_id in _SEEN_CORRELATIONS:
        return False

    now = time.monotonic()
    if _CORRELATION_TOKENS_UPDATED_AT is not None:
        _AVAILABLE_CORRELATION_TOKENS = min(
            float(_BURST_CAPACITY),
            _AVAILABLE_CORRELATION_TOKENS
            + (now - _CORRELATION_TOKENS_UPDATED_AT) / _CORRELATION_INTERVAL_SECONDS,
        )
    if _AVAILABLE_CORRELATION_TOKENS < 1.0:
        time.sleep((1.0 - _AVAILABLE_CORRELATION_TOKENS) * _CORRELATION_INTERVAL_SECONDS)
        now = time.monotonic()
        _AVAILABLE_CORRELATION_TOKENS = 1.0

    _AVAILABLE_CORRELATION_TOKENS -= 1.0
    _CORRELATION_TOKENS_UPDATED_AT = now
    _SEEN_CORRELATIONS.add(correlation_id)
    return True


def _complete_correlation_pacing(new_correlation: bool) -> None:
    global _CORRELATION_TOKENS_UPDATED_AT  # noqa: PLW0603 - one integration run

    if new_correlation:
        # Admission happens before the response completes. Discarding that elapsed
        # time keeps the test-side bucket slightly more conservative than the host.
        _CORRELATION_TOKENS_UPDATED_AT = time.monotonic()


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
    while True:
        yield str(uuid.uuid7())


def test_installed_core_lifecycle(  # noqa: PLR0915 - ordered installed-host lifecycle table
    host: Host, tmp_path: Path
) -> None:
    _initialize_namespace(host)
    assert not _initialize_namespace(host)
    _enable_disposable_publication(host)
    _reapply_ansible()
    _prepare_edge_probe(host)
    _await_persisted_admission_burst(host)
    operator_host, identity, ssh = _operator_inputs(tmp_path)
    identities = _ids()
    slug = f"m3-eight-{str(uuid.uuid7()).replace('-', '')[-12:]}"
    renamed_slug = f"{slug}-renamed"

    create_request = _request(
        "create",
        next(identities),
        slug=slug,
        quotas={"storageMiB": 100, "entries": 5000},
    )
    created = _submit(tmp_path, operator_host, identity, ssh, create_request)
    assert created["status"] == "succeeded"
    assert _lifecycle(created) == "undeployed"
    tenant_id = created["tenantId"]
    assert type(tenant_id) is str
    canonical_origin = created["canonicalOrigin"]
    assert type(canonical_origin) is str
    original_alias = f"{slug}.lowerduckpond.com"
    renamed_alias = f"{renamed_slug}.lowerduckpond.com"

    replay = _submit(tmp_path, operator_host, identity, ssh, dict(create_request))
    assert replay == created

    first_content = b"first installed M3.8 release\n"
    first = _deployment_zip(first_content)
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
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(
        host,
        original_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    _assert_unauthenticated_route_rejected(host, canonical_origin)
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

    first_manifest_path = f"{STATE_ROOT}/tenants/{tenant_id}/desired.json"
    first_manifest = _read_state(host, first_manifest_path)
    selected_generation = host.run("cat /etc/caddy/active")
    assert selected_generation.rc == 0, selected_generation.stderr
    selected_generation_id = selected_generation.stdout.strip()

    _reapply_ansible()
    assert _read_state(host, first_manifest_path) == first_manifest
    assert host.run("cat /etc/caddy/active").stdout.strip() == selected_generation_id
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(
        host,
        original_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )

    _assert_ansible_refuses_generation_input_drift(host)
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(
        host,
        original_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )

    _restart_installed_services(host)
    assert _read_state(host, first_manifest_path) == first_manifest
    assert host.run("cat /etc/caddy/active").stdout.strip() == selected_generation_id
    recovery = host.run(
        "systemctl show lowerduckpond-static-reconcile.service "
        "--property=ActiveState --property=Result"
    )
    assert recovery.rc == 0, recovery.stderr
    assert set(recovery.stdout.splitlines()) == {
        "ActiveState=inactive",
        "Result=success",
    }
    assert host.run("systemctl is-active --quiet caddy.service").rc == 0
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(
        host,
        original_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    for path in (
        "/etc/caddy/intents",
        f"{RELEASE_ROOT}/.staging",
        f"{STATE_ROOT}/intents",
    ):
        cleanup = host.run(f"find {path} -mindepth 1 -print -quit")
        assert cleanup.rc == 0
        assert cleanup.stdout == ""

    second_content = b"second installed M3.8 release\n"
    second = _deployment_zip(second_content)
    active_second_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=second,
    )
    second_deployment = _desired_deployment(active_second_deploy)
    assert _lifecycle(active_second_deploy) == "active"
    assert second_deployment != first_deployment
    _assert_route(host, canonical_origin, status=200, body=second_content)

    delayed_rollback_request = _request(
        "rollback",
        next(identities),
        tenantId=tenant_id,
        deploymentId=first_deployment,
    )
    delayed_rollback_job = _issue_without_handoff(host, delayed_rollback_request)

    suspend_request = _request("suspend", next(identities), tenantId=tenant_id)
    suspended = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        suspend_request,
    )
    assert _lifecycle(suspended) == "suspended"
    _assert_route(host, canonical_origin, status=404)
    _assert_route(host, original_alias, status=404)
    assert _submit(tmp_path, operator_host, identity, ssh, dict(suspend_request)) == suspended

    delayed_rollback = _execute_issued_job(host, delayed_rollback_job)
    assert delayed_rollback["status"] == "failed"
    assert delayed_rollback["errorCode"] == "state_drift"
    assert _read_state(host, f"{STATE_ROOT}/tenants/{tenant_id}/desired.json") == _manifest(
        suspended
    )
    _assert_route(host, canonical_origin, status=404)
    _assert_route(host, original_alias, status=404)

    third = _deployment_zip(b"third installed M3.8 release\n")
    suspended_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=third,
    )
    third_deployment = _desired_deployment(suspended_deploy)
    assert _lifecycle(suspended_deploy) == "suspended"
    assert third_deployment not in {first_deployment, second_deployment}

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
    _assert_route(host, canonical_origin, status=404)
    _assert_route(host, original_alias, status=404)

    resume_request = _request("resume", next(identities), tenantId=tenant_id)
    resumed = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        resume_request,
    )
    assert _lifecycle(resumed) == "active"
    assert _desired_deployment(resumed) == first_deployment
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(
        host,
        original_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    assert _submit(tmp_path, operator_host, identity, ssh, dict(resume_request)) == resumed

    conflicting_create = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request(
            "create",
            next(identities),
            slug=slug,
            quotas={"storageMiB": 100, "entries": 5000},
        ),
    )
    assert conflicting_create["status"] == "failed"
    assert conflicting_create["errorCode"] == "state_drift"

    occupied_slug = f"{slug}-occupied"
    occupied = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request(
            "create",
            next(identities),
            slug=occupied_slug,
            quotas={"storageMiB": 100, "entries": 5000},
        ),
    )
    occupied_tenant_id = occupied["tenantId"]
    occupied_origin = occupied["canonicalOrigin"]
    assert type(occupied_tenant_id) is str
    assert type(occupied_origin) is str
    occupied_alias = f"{occupied_slug}.lowerduckpond.com"
    occupied_content = b"isolated installed M3.8 tenant\n"
    occupied_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=occupied_tenant_id),
        artifact=_deployment_zip(occupied_content),
    )
    occupied_deployment = _desired_deployment(occupied_deploy)
    assert _lifecycle(occupied_deploy) == "active"

    occupied_manifest_path = f"{STATE_ROOT}/tenants/{occupied_tenant_id}/desired.json"
    first_before_conflicts = _read_state(host, first_manifest_path)
    occupied_before_conflicts = _read_state(host, occupied_manifest_path)
    cross_tenant_rollback = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request(
            "rollback",
            next(identities),
            tenantId=tenant_id,
            deploymentId=occupied_deployment,
        ),
    )
    assert cross_tenant_rollback["status"] == "failed"
    assert cross_tenant_rollback["errorCode"] == "state_drift"
    assert _read_state(host, first_manifest_path) == first_before_conflicts
    assert _read_state(host, occupied_manifest_path) == occupied_before_conflicts
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(host, occupied_origin, status=200, body=occupied_content)

    occupied_rename = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request(
            "rename",
            next(identities),
            tenantId=tenant_id,
            slug=occupied_slug,
        ),
    )
    assert occupied_rename["status"] == "failed"
    assert occupied_rename["errorCode"] == "state_drift"
    assert _read_state(host, first_manifest_path) == first_before_conflicts
    assert _read_state(host, occupied_manifest_path) == occupied_before_conflicts
    _assert_route(
        host,
        occupied_alias,
        status=302,
        redirect=f"https://{occupied_origin}/",
    )
    _assert_route(
        host,
        original_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )

    observed_path = f"{STATE_ROOT}/tenants/{tenant_id}/observed.json"
    pre_rename_observed = _read_state(host, observed_path)
    rename_request = _request(
        "rename",
        next(identities),
        tenantId=tenant_id,
        slug=renamed_slug,
    )
    renamed = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        rename_request,
    )
    metadata = _manifest(renamed)["metadata"]
    assert type(metadata) is dict
    assert metadata["slug"] == renamed_slug
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(host, original_alias, status=404)
    _assert_route(
        host,
        renamed_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    assert _submit(tmp_path, operator_host, identity, ssh, dict(rename_request)) == renamed

    _replace_state(host, observed_path, pre_rename_observed)
    drifted_observed = _read_state(host, observed_path)
    expected_manifest_digest = manifest_digest(_manifest(renamed)).to_dict()
    assert drifted_observed["desiredManifestDigest"] != expected_manifest_digest
    reconcile_request = _request("reconcile", next(identities), tenantId=tenant_id)
    reconciled = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        reconcile_request,
    )
    assert _manifest(reconciled) == _manifest(renamed)
    repaired_observed = _read_state(host, observed_path)
    assert repaired_observed["desiredManifestDigest"] == expected_manifest_digest
    assert repaired_observed["observedState"] == "active"
    assert repaired_observed["activeDeploymentId"] == first_deployment
    _assert_route(host, canonical_origin, status=200, body=first_content)
    _assert_route(host, original_alias, status=404)
    _assert_route(
        host,
        renamed_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    assert _submit(tmp_path, operator_host, identity, ssh, dict(reconcile_request)) == reconciled

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

    fifth_content = b"fifth installed M3.8 release\n"
    fifth = _deployment_zip(fifth_content)
    fifth_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=fifth,
    )
    fifth_deployment = _desired_deployment(fifth_deploy)

    sixth = _deployment_zip(b"sixth installed M3.8 release\n")
    sixth_deploy = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        _request("deploy", next(identities), tenantId=tenant_id),
        artifact=sixth,
    )
    sixth_deployment = _desired_deployment(sixth_deploy)

    releases = host.run(
        f"find {RELEASE_ROOT}/{tenant_id}/releases -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'"
    )
    assert releases.rc == 0
    assert set(releases.stdout.splitlines()) == {
        fourth_deployment,
        fifth_deployment,
        sixth_deployment,
    }

    active_rollback_request = _request(
        "rollback",
        next(identities),
        tenantId=tenant_id,
        deploymentId=fifth_deployment,
    )
    active_rollback = _submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        active_rollback_request,
    )
    assert _lifecycle(active_rollback) == "active"
    assert _desired_deployment(active_rollback) == fifth_deployment
    _assert_route(host, canonical_origin, status=200, body=fifth_content)
    _assert_route(
        host,
        renamed_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
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
            slug=slug,
            quotas={"storageMiB": 100, "entries": 5000},
        ),
    )
    assert reused["status"] == "succeeded"
    reused_tenant_id = reused["tenantId"]
    assert type(reused_tenant_id) is str
    assert reused_tenant_id != tenant_id

    assert host.run("systemctl is-active --quiet caddy.service").rc == 0
    _assert_route(host, canonical_origin, status=200, body=fifth_content)
    _assert_route(host, occupied_origin, status=200, body=occupied_content)
    _assert_route(
        host,
        renamed_alias,
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    _assert_route(host, original_alias, status=404)
    for path in (
        "/etc/caddy/intents",
        f"{RELEASE_ROOT}/.staging",
        f"{STATE_ROOT}/intents",
    ):
        cleanup = host.run(f"find {path} -mindepth 1 -print -quit")
        assert cleanup.rc == 0
        assert cleanup.stdout == ""
    releases = host.run(
        f"find {RELEASE_ROOT}/{tenant_id}/releases -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'"
    )
    assert releases.rc == 0
    assert set(releases.stdout.splitlines()) == {
        fourth_deployment,
        fifth_deployment,
    }
