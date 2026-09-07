from __future__ import annotations

import json
import shlex
import uuid
from pathlib import Path

import test_lifecycle as support
from testinfra.host import Host

_EXPECTATION_PATH = "/root/lowerduckpond-m3-8-reboot-expectation.json"
_RUNTIME_MARKER = "/run/lowerduckpond-m3-8-reboot-marker"
_FIXTURE_BACKUP_ROOT = "/root/lowerduckpond-m3-8-reboot-fixtures"
_RUNTIME_FIXTURE_ROOT = "/run/lowerduckpond-molecule"
_RUNTIME_FIXTURE_NAMES = (
    "operator-key",
    "operator-key.pub",
    "origin-pull-client.key",
    "origin-pull-client.pem",
)
_DURABLE_ROOTS = (support.STATE_ROOT, support.RELEASE_ROOT, "/etc/caddy")


def _remote_snapshot(host: Host) -> dict[str, object]:
    script = f"""
import hashlib
import json
import pathlib
import stat


def tree_snapshot(root_value):
    root = pathlib.Path(root_value)
    if not root.is_dir():
        raise RuntimeError(f"durable root is absent: {{root}}")
    digest = hashlib.sha256()
    entries = 0
    paths = [root, *sorted(root.rglob("*"), key=lambda value: value.as_posix())]
    for path in paths:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        entry = {{
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "path": relative,
            "uid": metadata.st_uid,
        }}
        if stat.S_ISDIR(metadata.st_mode):
            entry["type"] = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            payload = path.read_bytes()
            entry.update(
                {{
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "type": "file",
                }}
            )
        elif stat.S_ISLNK(metadata.st_mode):
            entry.update({{"target": path.readlink().as_posix(), "type": "symlink"}})
        else:
            raise RuntimeError(f"unsupported durable entry: {{path}}")
        encoded = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("ascii")
        digest.update(encoded + b"\\n")
        entries += 1
    return {{"entries": entries, "sha256": digest.hexdigest()}}


state_root = pathlib.Path({support.STATE_ROOT!r})
origins = []
for path in sorted((state_root / "tenants").glob("*/desired.json")):
    document = json.loads(path.read_text(encoding="ascii"))
    metadata = document.get("metadata")
    spec = document.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise RuntimeError(f"tenant manifest shape drifted: {{path}}")
    if spec.get("desiredState") != "active":
        continue
    canonical = metadata.get("canonicalOrigin")
    slug = metadata.get("slug")
    if not isinstance(canonical, str) or not isinstance(slug, str):
        raise RuntimeError(f"active tenant identity drifted: {{path}}")
    origins.extend((canonical, f"{{slug}}.lowerduckpond.com"))

print(
    json.dumps(
        {{
            "origins": sorted(set(origins)),
            "trees": {{root: tree_snapshot(root) for root in {_DURABLE_ROOTS!r}}},
        }},
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""
    result = host.run("/usr/bin/python3 -I -B -c %s", script)
    assert result.rc == 0, result.stderr
    snapshot = json.loads(result.stdout)
    assert isinstance(snapshot, dict)
    return snapshot


def _property(host: Host, unit: str, name: str) -> str:
    result = host.run(
        "/usr/bin/systemctl show --property=%s --value %s",
        shlex.quote(name),
        shlex.quote(unit),
    )
    assert result.rc == 0, result.stderr
    value = result.stdout.strip()
    assert value
    return value


def _pid_one_start_ticks(host: Host) -> str:
    result = host.run(
        "/usr/bin/python3 -I -B -c %s",
        "from pathlib import Path; print(Path('/proc/1/stat').read_text().split()[21])",
    )
    assert result.rc == 0, result.stderr
    value = result.stdout.strip()
    assert value.isdigit()
    return value


def _route_observation(host: Host, origin: str) -> str:
    command = " ".join(
        (
            "/usr/bin/curl",
            "--silent",
            "--show-error",
            "--cacert",
            shlex.quote(support.ORIGIN_PULL_CA_CERTIFICATE),
            "--interface",
            "173.245.48.1",
            "--cert",
            shlex.quote(support.ORIGIN_PULL_CLIENT_CERTIFICATE),
            "--key",
            shlex.quote(support.ORIGIN_PULL_CLIENT_KEY),
            "--resolve",
            shlex.quote(f"{origin}:443:127.0.0.1"),
            "--write-out",
            shlex.quote("\\n%{http_code}\\n%{redirect_url}"),
            shlex.quote(f"https://{origin}/"),
        )
    )
    result = host.run(command)
    assert result.rc == 0, result.stderr
    return result.stdout


def _write_expectation(host: Host, expectation: dict[str, object]) -> None:
    encoded = json.dumps(expectation, sort_keys=True, separators=(",", ":")).encode().hex()
    script = f"""
import os
import pathlib

path = pathlib.Path({_EXPECTATION_PATH!r})
temporary = path.with_name(path.name + ".tmp")
temporary.write_bytes(bytes.fromhex({encoded!r}))
temporary.chmod(0o600)
descriptor = os.open(temporary, os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.replace(temporary, path)
descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
"""
    result = host.run("/usr/bin/python3 -I -B -c %s", script)
    assert result.rc == 0, result.stderr


def _read_expectation(host: Host) -> dict[str, object]:
    result = host.run("/usr/bin/cat %s", shlex.quote(_EXPECTATION_PATH))
    assert result.rc == 0, result.stderr
    expectation = json.loads(result.stdout)
    assert isinstance(expectation, dict)
    return expectation


def _preserve_volatile_test_fixtures(host: Host) -> None:
    script = f"""
import os
import pathlib

source_root = pathlib.Path({_RUNTIME_FIXTURE_ROOT!r})
target_root = pathlib.Path({_FIXTURE_BACKUP_ROOT!r})
target_root.mkdir(mode=0o700, exist_ok=True)
for name in {_RUNTIME_FIXTURE_NAMES!r}:
    source = source_root / name
    target = target_root / name
    payload = source.read_bytes()
    target.write_bytes(payload)
    target.chmod(0o600)
    descriptor = os.open(target, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
descriptor = os.open(target_root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
"""
    result = host.run("/usr/bin/python3 -I -B -c %s", script)
    assert result.rc == 0, result.stderr


def _restore_volatile_test_fixtures(host: Host) -> None:
    script = f"""
import pathlib

source_root = pathlib.Path({_FIXTURE_BACKUP_ROOT!r})
target_root = pathlib.Path({_RUNTIME_FIXTURE_ROOT!r})
target_root.mkdir(mode=0o700, exist_ok=False)
for name in {_RUNTIME_FIXTURE_NAMES!r}:
    target = target_root / name
    target.write_bytes((source_root / name).read_bytes())
    target.chmod(0o600)
"""
    result = host.run("/usr/bin/python3 -I -B -c %s", script)
    assert result.rc == 0, result.stderr


def _assert_service_state(host: Host, unit: str, expected: set[str]) -> None:
    result = host.run(
        "/usr/bin/systemctl show --property=ActiveState --property=SubState "
        "--property=Result --property=ExecMainStatus %s",
        shlex.quote(unit),
    )
    assert result.rc == 0, result.stderr
    assert expected <= set(result.stdout.splitlines())


def test_capture_installed_reboot_state(host: Host, tmp_path: Path) -> None:
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._await_persisted_admission_burst(host)
    operator_host, identity, ssh = support._operator_inputs(tmp_path)
    slug = f"m3-eight-reboot-{str(uuid.uuid7()).replace('-', '')[-12:]}"
    created = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=slug,
            quotas={"storageMiB": 100, "entries": 5000},
        ),
    )
    tenant_id = created["tenantId"]
    canonical_origin = created["canonicalOrigin"]
    assert isinstance(tenant_id, str)
    assert isinstance(canonical_origin, str)
    content = b"persisted across the installed-host reboot\n"
    deployed = support._submit(
        tmp_path,
        operator_host,
        identity,
        ssh,
        support._request("deploy", str(uuid.uuid7()), tenantId=tenant_id),
        artifact=support._deployment_zip(content),
    )
    assert deployed["status"] == "succeeded"
    assert support._lifecycle(deployed) == "active"
    support._assert_route(host, canonical_origin, status=200, body=content)
    support._assert_route(
        host,
        f"{slug}.lowerduckpond.com",
        status=302,
        redirect=f"https://{canonical_origin}/",
    )
    reconciled = host.run("/usr/bin/systemctl start --wait lowerduckpond-static-reconcile.service")
    assert reconciled.rc == 0, reconciled.stderr
    snapshot = _remote_snapshot(host)
    origins = snapshot["origins"]
    assert isinstance(origins, list)
    assert origins
    assert all(isinstance(origin, str) for origin in origins)
    selected = host.run("/usr/bin/cat /etc/caddy/active")
    assert selected.rc == 0, selected.stderr
    assert selected.stdout.strip()
    expectation = {
        "pidOneStartTicks": _pid_one_start_ticks(host),
        "reconcileInvocation": _property(
            host, "lowerduckpond-static-reconcile.service", "InvocationID"
        ),
        "routes": {
            origin: _route_observation(host, origin)
            for origin in origins
            if isinstance(origin, str)
        },
        "selectedGeneration": selected.stdout.strip(),
        "snapshot": snapshot,
    }
    _preserve_volatile_test_fixtures(host)
    marker = host.run("/usr/bin/touch %s", shlex.quote(_RUNTIME_MARKER))
    assert marker.rc == 0, marker.stderr
    _write_expectation(host, expectation)


def test_verify_installed_reboot_state(host: Host) -> None:
    expectation = _read_expectation(host)
    assert host.run("/usr/bin/test ! -e %s", shlex.quote(_RUNTIME_MARKER)).rc == 0
    for name in _RUNTIME_FIXTURE_NAMES:
        assert (
            host.run(
                "/usr/bin/test ! -e %s",
                shlex.quote(f"{_RUNTIME_FIXTURE_ROOT}/{name}"),
            ).rc
            == 0
        )
    assert _pid_one_start_ticks(host) != expectation["pidOneStartTicks"]
    assert (
        _property(host, "lowerduckpond-static-reconcile.service", "InvocationID")
        != expectation["reconcileInvocation"]
    )
    _assert_service_state(
        host,
        "caddy-recovery.service",
        {"ActiveState=inactive", "SubState=dead", "Result=success", "ExecMainStatus=0"},
    )
    _assert_service_state(
        host,
        "caddy.service",
        {
            "ActiveState=active",
            "SubState=running",
            "Result=success",
            "ExecMainStatus=0",
        },
    )
    _assert_service_state(
        host,
        "lowerduckpond-static-reconcile.service",
        {"ActiveState=inactive", "SubState=dead", "Result=success", "ExecMainStatus=0"},
    )
    assert (
        host.run("/usr/bin/systemctl is-active --quiet lowerduckpond-static-reconcile.timer").rc
        == 0
    )
    selected = host.run("/usr/bin/cat /etc/caddy/active")
    assert selected.rc == 0, selected.stderr
    assert selected.stdout.strip() == expectation["selectedGeneration"]
    assert _remote_snapshot(host) == expectation["snapshot"]
    _restore_volatile_test_fixtures(host)
    support._prepare_edge_probe(host)
    routes = expectation["routes"]
    assert isinstance(routes, dict)
    assert routes
    for origin, expected in routes.items():
        assert isinstance(origin, str)
        assert isinstance(expected, str)
        assert _route_observation(host, origin) == expected
    for root in (
        "/etc/caddy/intents",
        f"{support.RELEASE_ROOT}/.staging",
        f"{support.STATE_ROOT}/intents",
    ):
        result = host.run("/usr/bin/find %s -mindepth 1 -print -quit", shlex.quote(root))
        assert result.rc == 0, result.stderr
        assert result.stdout == ""
