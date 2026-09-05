from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest
import test_lifecycle as support
from lowerduckpond_static_contracts import (
    FrameHeader,
    FrameKind,
    canonical_json_bytes,
    encode_header,
)
from testinfra.host import Host

_WORKER_DROP_IN_DIRECTORY = "/etc/systemd/system/lowerduckpond-static-worker@.service.d"
_WORKER_DELAY_DROP_IN = f"{_WORKER_DROP_IN_DIRECTORY}/m3-8-delay.conf"
_CADDY_ADMIN_SOCKET = "/run/caddy/admin.sock"


@dataclass(frozen=True, slots=True)
class _CaddyReloadFault:
    unit: str
    script_path: str
    ready_path: str
    blocked_path: str
    release_path: str


def _issue_artifact_without_handoff(
    host: Host,
    request: dict[str, object],
    artifact: bytes,
) -> str:
    digest = hashlib.sha256(artifact).hexdigest()
    request["artifact"] = {"size": len(artifact), "sha256": digest}
    new_correlation = support._pace_new_correlation(request)
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0, selected.stderr
    request_hex = canonical_json_bytes(request).hex()
    artifact_hex = artifact.hex()
    command = f"""
import os
import pathlib
import sys
from datetime import UTC, datetime
from io import BytesIO

sys.path.insert(0, {(selected.stdout.strip() + "/site-packages")!r})
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    AuthorizationIssuer,
    CommandPublicationGate,
    StateRepository,
    VerifiedArtifact,
)

raw_request = bytes.fromhex({request_hex!r})
payload = bytes.fromhex({artifact_hex!r})
declared = VerifiedArtifact(size=len(payload), sha256={digest!r})
with (
    StateRepository(pathlib.Path({support.STATE_ROOT!r}), expected_owner=0) as repository,
    ArtifactIntake(pathlib.Path({support.STATE_ROOT!r}), expected_owner=0) as intake,
):
    with intake.admit(
        operation="deploy",
        correlation_id={request["correlationId"]!r},
        declared=declared,
        read=BytesIO(payload).read,
        blocking=True,
    ) as lease:
        issued = AuthorizationIssuer(
            repository,
            gate=CommandPublicationGate(pathlib.Path({support.PUBLICATION_GATE!r})),
            entropy=os.getrandom,
        ).issue(
            raw_request,
            operator_principal="molecule-m3-8-operator-v1",
            now=datetime.now(UTC),
            artifact=lease.artifact.verified,
            blocking=True,
        )
        lease.commit()
        print(issued.job_id)
"""
    try:
        result = host.run("/usr/bin/python3 -I -B -c %s", command)
    finally:
        support._complete_correlation_pacing(new_correlation)
    assert result.rc == 0, result.stderr
    return result.stdout.strip()


def _replace_intake_artifact(host: Host, correlation_id: str, artifact: bytes) -> None:
    path = f"{support.STATE_ROOT}/intake/{correlation_id}.artifact"
    encoded = artifact.hex()
    command = (
        "import os,pathlib;"
        f"target=pathlib.Path({path!r});"
        "temporary=target.with_name('.m3-8-replacement');"
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


def _await_result(host: Host, job_id: str, *, timeout: float = 60.0) -> dict[str, object]:
    path = f"{support.STATE_ROOT}/authorization/results/{job_id}.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = host.run("test -f %s", shlex.quote(path))
        if result.rc == 0:
            return support._read_state(host, path)
        time.sleep(0.1)
    raise AssertionError(f"authorization result {job_id} did not become durable")


def _start_reconcile_timer(host: Host) -> None:
    started = host.run("systemctl start lowerduckpond-static-reconcile.timer")
    assert started.rc == 0, started.stderr


def _install_worker_delay(host: Host, *, seconds: int) -> None:
    content = f"[Service]\nExecStartPre=/usr/bin/sleep {seconds}\n"
    command = (
        f"install -d -o root -g root -m 0755 {shlex.quote(_WORKER_DROP_IN_DIRECTORY)} && "
        f"printf %s {shlex.quote(content)} > {shlex.quote(_WORKER_DELAY_DROP_IN)} && "
        f"chmod 0644 {shlex.quote(_WORKER_DELAY_DROP_IN)} && "
        "systemctl daemon-reload"
    )
    result = host.run(command)
    assert result.rc == 0, result.stderr


def _remove_worker_delay(host: Host) -> None:
    result = host.run(
        "find %s -maxdepth 1 -type f -name m3-8-delay.conf -delete && systemctl daemon-reload",
        _WORKER_DROP_IN_DIRECTORY,
    )
    assert result.rc == 0, result.stderr


def _start_operator_session(
    *,
    operator_host: str,
    identity: Path,
    ssh: Path,
    request: dict[str, object],
) -> subprocess.Popen[bytes]:
    canonical = canonical_json_bytes(request)
    process = subprocess.Popen(  # noqa: S603 - fixture-controlled executable and arguments
        [
            os.fspath(ssh),
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "-i",
            os.fspath(identity),
            f"ldp-operator@{operator_host}",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    assert process.stdin is not None
    process.stdin.write(
        encode_header(FrameHeader(FrameKind.REQUEST, len(canonical), None)) + canonical
    )
    process.stdin.close()
    return process


def _await_worker_start(host: Host, job_id: str, *, timeout: float = 30.0) -> None:
    unit = f"lowerduckpond-static-worker@{job_id}.service"
    result_path = f"{support.STATE_ROOT}/authorization/results/{job_id}.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = host.run("systemctl show --property=ActiveState --value %s", shlex.quote(unit))
        assert state.rc == 0, state.stderr
        if state.stdout.strip() == "activating":
            absent = host.run("test ! -e %s", shlex.quote(result_path))
            assert absent.rc == 0
            return
        time.sleep(0.1)
    raise AssertionError(f"worker {job_id} did not enter its delayed start")


def _job_id_for_correlation(host: Host, correlation_id: str) -> str:
    path = f"{support.STATE_ROOT}/authorization/correlations/{correlation_id}.json"
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        exists = host.run("test -f %s", shlex.quote(path))
        if exists.rc == 0:
            record = support._read_state(host, path)
            job_id = record["jobId"]
            assert type(job_id) is str
            return job_id
        time.sleep(0.1)
    raise AssertionError(f"correlation {correlation_id} was not admitted")


def _install_caddy_reload_fault(host: Host, *, block_on_load: bool = False) -> _CaddyReloadFault:
    identity = str(uuid.uuid7()).replace("-", "")
    unit = f"lowerduckpond-m3-8-caddy-fault-{identity}.service"
    script_path = f"/run/lowerduckpond-m3-8-caddy-fault-{identity}.py"
    ready_path = f"/run/lowerduckpond-m3-8-caddy-fault-{identity}.ready"
    blocked_path = f"/run/lowerduckpond-m3-8-caddy-fault-{identity}.blocked"
    release_path = f"/run/lowerduckpond-m3-8-caddy-fault-{identity}.release"
    real_socket = f"{_CADDY_ADMIN_SOCKET}.m3-8-{identity}"
    script = f"""import os
import pathlib
import pwd
import socket
import time

admin_path = {str(_CADDY_ADMIN_SOCKET)!r}
real_path = {real_socket!r}
ready_path = {ready_path!r}
blocked_path = {blocked_path!r}
release_path = {release_path!r}
block_on_load = {block_on_load!r}


def request(path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(path)
        client.sendall(payload)
        chunks = []
        while chunk := client.recv(65536):
            chunks.append(chunk)
    response = b"".join(chunks)
    head, separator, body = response.partition(b"\\r\\n\\r\\n")
    if not separator or not head.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
        raise RuntimeError("source Caddy admin response was invalid")
    return body


def receive(connection):
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        chunk = connection.recv(65536)
        if not chunk:
            raise RuntimeError("incomplete fault request")
        data += chunk
    head, separator, body = data.partition(b"\\r\\n\\r\\n")
    lengths = [
        line.split(b":", 1)[1].strip()
        for line in head.split(b"\\r\\n")[1:]
        if line.lower().startswith(b"content-length:")
    ]
    expected = int(lengths[0]) if lengths else 0
    while len(body) < expected:
        chunk = connection.recv(65536)
        if not chunk:
            raise RuntimeError("incomplete fault request body")
        body += chunk
    return head.split(b"\\r\\n", 1)[0], body


source = request(
    admin_path,
    b"GET /config/ HTTP/1.0\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n",
)
os.rename(admin_path, real_path)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    server.bind(admin_path)
    account = pwd.getpwnam("caddy")
    os.chown(admin_path, account.pw_uid, account.pw_gid)
    os.chmod(admin_path, 0o620)
    server.listen(1)
    pathlib.Path(ready_path).write_text("ready\\n", encoding="ascii")
    expected = (
        b"GET /config/ HTTP/1.0",
        b"GET /config/ HTTP/1.0",
        b"POST /load HTTP/1.0",
        b"POST /load HTTP/1.0",
        b"GET /config/ HTTP/1.0",
    )
    for index, expected_line in enumerate(expected):
        connection, _ = server.accept()
        with connection:
            request_line, _body = receive(connection)
            if request_line != expected_line:
                raise RuntimeError("unexpected Caddy fault request")
            if index == 2:
                if block_on_load:
                    pathlib.Path(blocked_path).write_text("blocked\\n", encoding="ascii")
                    while not pathlib.Path(release_path).exists():
                        time.sleep(0.01)
                try:
                    connection.sendall(
                        b"HTTP/1.0 500 Injected Failure\\r\\n"
                        b"Content-Length: 0\\r\\nConnection: close\\r\\n\\r\\n"
                    )
                except (BrokenPipeError, ConnectionResetError):
                    if not block_on_load:
                        raise
                if block_on_load:
                    break
            else:
                body = source if index in (0, 1, 4) else b""
                response = (
                    b"HTTP/1.0 200 OK\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: close\\r\\n\\r\\n"
                    + body
                )
                connection.sendall(response)
finally:
    server.close()
    pathlib.Path(admin_path).unlink(missing_ok=True)
    if pathlib.Path(real_path).exists():
        os.rename(real_path, admin_path)
"""
    encoded = script.encode("utf-8").hex()
    command = (
        "import pathlib;"
        f"path=pathlib.Path({script_path!r});"
        f"path.write_bytes(bytes.fromhex({encoded!r}));"
        "path.chmod(0o700)"
    )
    installed = host.run("/usr/bin/python3 -I -B -c %s", command)
    assert installed.rc == 0, installed.stderr
    started = host.run(
        "/usr/bin/systemd-run --unit=%s --property=Type=exec /usr/bin/python3 -I -B %s",
        shlex.quote(unit.removesuffix(".service")),
        shlex.quote(script_path),
    )
    assert started.rc == 0, started.stderr
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if host.run("test -f %s", shlex.quote(ready_path)).rc == 0:
            return _CaddyReloadFault(
                unit,
                script_path,
                ready_path,
                blocked_path,
                release_path,
            )
        state = host.run("systemctl is-failed --quiet %s", shlex.quote(unit))
        assert state.rc != 0, host.run("journalctl -u %s --no-pager", unit).stdout
        time.sleep(0.1)
    raise AssertionError("Caddy reload fault did not become ready")


def _remove_caddy_reload_fault(host: Host, fault: _CaddyReloadFault) -> None:
    identity = fault.unit.removeprefix("lowerduckpond-m3-8-caddy-fault-").removesuffix(".service")
    real_socket = f"{_CADDY_ADMIN_SOCKET}.m3-8-{identity}"
    result = host.run(
        "systemctl stop %s >/dev/null 2>&1 || true; "
        "if test -S %s; then rm -f %s; fi; "
        "if test -S %s; then mv %s %s; fi; "
        "rm -f %s %s %s %s; systemctl reset-failed %s >/dev/null 2>&1 || true",
        shlex.quote(fault.unit),
        shlex.quote(real_socket),
        shlex.quote(_CADDY_ADMIN_SOCKET),
        shlex.quote(real_socket),
        shlex.quote(real_socket),
        shlex.quote(_CADDY_ADMIN_SOCKET),
        shlex.quote(fault.script_path),
        shlex.quote(fault.ready_path),
        shlex.quote(fault.blocked_path),
        shlex.quote(fault.release_path),
        shlex.quote(fault.unit),
    )
    assert result.rc == 0, result.stderr


def _await_caddy_reload_fault(host: Host, unit: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        state = host.run(
            "systemctl show --property=ActiveState --property=Result --property=ExecMainStatus %s",
            shlex.quote(unit),
        )
        assert state.rc == 0, state.stderr
        properties = set(state.stdout.splitlines())
        if "ActiveState=inactive" in properties:
            assert {"Result=success", "ExecMainStatus=0"} <= properties
            return
        assert "ActiveState=failed" not in properties, state.stdout
        time.sleep(0.1)
    raise AssertionError("Caddy reload fault did not complete")


def test_installed_transport_and_admission_recovery(  # noqa: PLR0915 - ordered fault table
    host: Host,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    support._initialize_namespace(host)
    support._enable_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._await_persisted_admission_burst(host)
    operator_host, identity, ssh = support._operator_inputs(tmp_path)
    identities = support._ids()
    slug = f"m3-eight-transport-{str(uuid.uuid7()).replace('-', '')[-12:]}"
    timer_stopped = host.run("systemctl stop lowerduckpond-static-reconcile.timer")
    assert timer_stopped.rc == 0, timer_stopped.stderr
    request.addfinalizer(lambda: _start_reconcile_timer(host))

    lost_handoff_request = support._request(
        "create",
        next(identities),
        slug=slug,
        quotas={"storageMiB": 100, "entries": 5000},
    )
    lost_handoff_job = support._issue_without_handoff(host, lost_handoff_request)
    result_path = f"{support.STATE_ROOT}/authorization/results/{lost_handoff_job}.json"
    assert host.run("test ! -e %s", shlex.quote(result_path)).rc == 0
    reconciled = host.run("systemctl start --wait lowerduckpond-static-reconcile.service")
    assert reconciled.rc == 0, reconciled.stderr
    recovered_create = _await_result(host, lost_handoff_job)
    assert recovered_create["status"] == "succeeded"
    assert support._lifecycle(recovered_create) == "undeployed"
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(lost_handoff_request),
        )
        == recovered_create
    )

    tenant_id = recovered_create["tenantId"]
    canonical_origin = recovered_create["canonicalOrigin"]
    assert type(tenant_id) is str
    assert type(canonical_origin) is str
    desired_path = f"{support.STATE_ROOT}/tenants/{tenant_id}/desired.json"
    undeployed = support._read_state(host, desired_path)

    replaced_payload = support._deployment_zip(b"bound artifact deployed only after recovery\n")
    replaced_request = support._request(
        "deploy",
        next(identities),
        tenantId=tenant_id,
    )
    replaced_job = _issue_artifact_without_handoff(
        host,
        replaced_request,
        replaced_payload,
    )
    _replace_intake_artifact(
        host,
        str(replaced_request["correlationId"]),
        b"x" * len(replaced_payload),
    )
    rejected_replacement = host.run(
        "/usr/bin/systemctl start --wait lowerduckpond-static-worker@%s.service",
        replaced_job,
    )
    assert rejected_replacement.rc != 0
    replaced_result_path = f"{support.STATE_ROOT}/authorization/results/{replaced_job}.json"
    assert host.run("test ! -e %s", shlex.quote(replaced_result_path)).rc == 0
    assert support._read_state(host, desired_path) == undeployed
    _replace_intake_artifact(
        host,
        str(replaced_request["correlationId"]),
        replaced_payload,
    )
    recovered = host.run("systemctl start --wait lowerduckpond-static-reconcile.service")
    assert recovered.rc == 0, recovered.stderr
    recovered_deploy = _await_result(host, replaced_job)
    assert recovered_deploy["status"] == "succeeded"
    assert support._lifecycle(recovered_deploy) == "active"
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(replaced_request),
            artifact=replaced_payload,
        )
        == recovered_deploy
    )
    support._assert_route(
        host, canonical_origin, status=200, body=b"bound artifact deployed only after recovery\n"
    )

    caddy_failure_request = support._request(
        "rename",
        next(identities),
        tenantId=tenant_id,
        slug=f"{slug}-reloaded",
    )
    caddy_failure_job = support._issue_without_handoff(host, caddy_failure_request)
    caddy_failure_result_path = (
        f"{support.STATE_ROOT}/authorization/results/{caddy_failure_job}.json"
    )
    desired_before_caddy_failure = support._read_state(host, desired_path)
    observed_before_caddy_failure = support._read_state(
        host, f"{support.STATE_ROOT}/tenants/{tenant_id}/observed.json"
    )
    generation_before_caddy_failure = host.run("cat /etc/caddy/active")
    assert generation_before_caddy_failure.rc == 0, generation_before_caddy_failure.stderr
    fault = _install_caddy_reload_fault(host)
    try:
        rejected_reload = host.run(
            "/usr/bin/systemctl start --wait lowerduckpond-static-worker@%s.service",
            caddy_failure_job,
        )
        assert rejected_reload.rc != 0
        _await_caddy_reload_fault(host, fault.unit)
    finally:
        _remove_caddy_reload_fault(host, fault)
    assert host.run("test ! -e %s", shlex.quote(caddy_failure_result_path)).rc == 0
    assert support._read_state(host, desired_path) == desired_before_caddy_failure
    assert (
        support._read_state(host, f"{support.STATE_ROOT}/tenants/{tenant_id}/observed.json")
        == observed_before_caddy_failure
    )
    assert host.run("cat /etc/caddy/active").stdout == generation_before_caddy_failure.stdout
    assert host.run("systemctl is-active --quiet caddy.service").rc == 0
    support._assert_route(
        host, canonical_origin, status=200, body=b"bound artifact deployed only after recovery\n"
    )
    recovered_reload = host.run("systemctl start --wait lowerduckpond-static-reconcile.service")
    assert recovered_reload.rc == 0, recovered_reload.stderr
    renamed_after_reload_failure = _await_result(host, caddy_failure_job)
    assert renamed_after_reload_failure["status"] == "succeeded"
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(caddy_failure_request),
        )
        == renamed_after_reload_failure
    )
    support._assert_route(
        host, canonical_origin, status=200, body=b"bound artifact deployed only after recovery\n"
    )

    disconnect_request = support._request(
        "suspend",
        next(identities),
        tenantId=tenant_id,
    )
    new_correlation = support._pace_new_correlation(disconnect_request)
    _install_worker_delay(host, seconds=10)
    process: subprocess.Popen[bytes] | None = None
    try:
        process = _start_operator_session(
            operator_host=operator_host,
            identity=identity,
            ssh=ssh,
            request=disconnect_request,
        )
        disconnect_job = _job_id_for_correlation(host, str(disconnect_request["correlationId"]))
        _await_worker_start(host, disconnect_job)
        process.kill()
        process.wait(timeout=10)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        _remove_worker_delay(host)
        support._complete_correlation_pacing(new_correlation)
    disconnected_result = _await_result(host, disconnect_job)
    assert disconnected_result["status"] == "succeeded"
    assert support._lifecycle(disconnected_result) == "suspended"
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(disconnect_request),
        )
        == disconnected_result
    )
    support._assert_route(host, canonical_origin, status=404)

    termination_request = support._request(
        "resume",
        next(identities),
        tenantId=tenant_id,
    )
    termination_job = support._issue_without_handoff(host, termination_request)
    termination_result_path = f"{support.STATE_ROOT}/authorization/results/{termination_job}.json"
    fault = _install_caddy_reload_fault(host, block_on_load=True)
    worker_unit = f"lowerduckpond-static-worker@{termination_job}.service"
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            worker_future = executor.submit(
                host.run,
                "/usr/bin/systemctl start --wait %s",
                worker_unit,
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if host.run("test -f %s", shlex.quote(fault.blocked_path)).rc == 0:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("worker did not reach the blocked Caddy reload")

            active_intent = host.run(
                "find %s -mindepth 1 -maxdepth 1 -type f -print -quit",
                f"{support.STATE_ROOT}/intents",
            )
            assert active_intent.rc == 0, active_intent.stderr
            assert active_intent.stdout.strip() != ""
            killed = host.run(
                "/usr/bin/systemctl kill --kill-whom=all --signal=KILL %s",
                worker_unit,
            )
            assert killed.rc == 0, killed.stderr
            released = host.run("touch %s", shlex.quote(fault.release_path))
            assert released.rc == 0, released.stderr
            terminated_worker = worker_future.result(timeout=30)
        assert terminated_worker.rc != 0
        _await_caddy_reload_fault(host, fault.unit)
    finally:
        host.run("touch %s", shlex.quote(fault.release_path))
        _remove_caddy_reload_fault(host, fault)

    assert host.run("test ! -e %s", shlex.quote(termination_result_path)).rc == 0
    desired_after_termination = support._read_state(host, desired_path)
    desired_after_termination_spec = desired_after_termination["spec"]
    assert type(desired_after_termination_spec) is dict
    assert desired_after_termination_spec["desiredState"] == "suspended"
    support._assert_route(host, canonical_origin, status=404)
    recovered_termination = host.run(
        "systemctl start --wait lowerduckpond-static-reconcile.service"
    )
    assert recovered_termination.rc == 0, recovered_termination.stderr
    terminated_result = _await_result(host, termination_job)
    assert terminated_result["status"] == "succeeded"
    assert support._lifecycle(terminated_result) == "active"
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(termination_request),
        )
        == terminated_result
    )
    support._assert_route(
        host, canonical_origin, status=200, body=b"bound artifact deployed only after recovery\n"
    )
    for intent_root in ("/etc/caddy/intents", f"{support.STATE_ROOT}/intents"):
        remaining_intent = host.run("find %s -mindepth 1 -maxdepth 1 -print -quit", intent_root)
        assert remaining_intent.rc == 0, remaining_intent.stderr
        assert remaining_intent.stdout == ""

    contested_slug = f"{slug}-contested"
    contested = [
        support._request(
            "create",
            next(identities),
            slug=contested_slug,
            quotas={"storageMiB": 100, "entries": 5000},
        )
        for _ in range(2)
    ]
    contested_jobs = [support._issue_without_handoff(host, request) for request in contested]
    _install_worker_delay(host, seconds=2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    host.run,
                    "/usr/bin/systemctl start --wait lowerduckpond-static-worker@%s.service",
                    job_id,
                )
                for job_id in contested_jobs
            ]
            worker_results = [future.result() for future in futures]
    finally:
        _remove_worker_delay(host)

    contested_results = [_await_result(host, job_id) for job_id in contested_jobs]
    assert all(
        worker.rc == 0 or result["status"] == "failed"
        for worker, result in zip(worker_results, contested_results, strict=True)
    )

    succeeded = [result for result in contested_results if result["status"] == "succeeded"]
    failed = [result for result in contested_results if result["status"] == "failed"]
    assert len(succeeded) == 1
    assert len(failed) == 1
    assert failed[0]["errorCode"] == "state_drift"
    results_by_correlation = {result["correlationId"]: result for result in contested_results}
    assert set(results_by_correlation) == {request["correlationId"] for request in contested}
    winning_request = next(
        request
        for request in contested
        if results_by_correlation[request["correlationId"]]["status"] == "succeeded"
    )
    assert (
        support._submit(
            tmp_path,
            operator_host,
            identity,
            ssh,
            dict(winning_request),
        )
        == results_by_correlation[winning_request["correlationId"]]
    )
    reconciled = host.run("systemctl start --wait lowerduckpond-static-reconcile.service")
    assert reconciled.rc == 0, reconciled.stderr
    assert [_await_result(host, job_id) for job_id in contested_jobs] == contested_results

    assert host.run("systemctl is-active --quiet caddy.service").rc == 0
    _start_reconcile_timer(host)
    assert host.run("systemctl is-active --quiet lowerduckpond-static-reconcile.timer").rc == 0
    assert host.run("test ! -e %s", shlex.quote(_WORKER_DELAY_DROP_IN)).rc == 0
    intake = host.run(
        "find %s -mindepth 1 -maxdepth 1 -print -quit", f"{support.STATE_ROOT}/intake"
    )
    assert intake.rc == 0, intake.stderr
    assert intake.stdout == ""
