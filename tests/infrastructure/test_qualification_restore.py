from __future__ import annotations

import importlib
import io
import json
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import qualification_restore as restore
from scripts import qualification_retirement as retirement
from scripts.m3_11_combined_inputs import allocate
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.qualification_case import private_document
from scripts.qualification_context import (
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    RUN_ENV,
    resource_names,
)
from scripts.qualification_local import FORMAT as FIXTURE_FORMAT
from scripts.qualification_probe import document


@pytest.fixture
def environment(tmp_path: Path) -> dict[str, str]:
    values = {
        **resource_names(uuid.uuid7().hex),
        ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
    }
    restore.directory(values).mkdir(mode=0o700)
    return values


@pytest.fixture(params=["live", "local"])
def observed_run(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    endpoint = "unix:///original-fixture.sock"
    if request.param == "live":
        values = allocate(tmp_path, {"DOCKER_HOST": endpoint})
    else:
        values = {
            **resource_names(uuid.uuid7().hex),
            ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
            "MOLECULE_EPHEMERAL_DIRECTORY": str(tmp_path / "fixture/molecule"),
        }
        private_document(
            tmp_path,
            "fixture.json",
            {
                "format": FIXTURE_FORMAT,
                "run_id": values[RUN_ENV],
                "environment": values,
                "host": values[HOST_ENV],
                "archive": values[ARCHIVE_ENV],
                "docker_endpoint": endpoint,
            },
        )
    root = restore.directory(values)
    root.mkdir(mode=0o700)
    for kind, digit in zip(("source", *restore.KINDS), "abc", strict=True):
        private_document(
            root,
            f"{kind}.json",
            {
                "id": digit * 64,
                "name": "/" + values[HOST_ENV] if kind == "source" else f"/fixture-{kind}",
                "owner": values[RUN_ENV],
                "image": "sha256:" + "d" * 64,
            },
        )
    return tmp_path


@pytest.mark.parametrize("fault", ["none", "id", "name", "owner", "image", "missing"])
def test_reconstruction_observes_original_live_or_local_identities_only(
    observed_run: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///unrelated-daemon.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "unrelated-context")
    monkeypatch.setenv("SPACES_SECRET_ACCESS_KEY", "private-credential-canary")
    rows = {
        kind: document(observed_run / "restore" / f"{kind}.json")
        for kind in ("source", *restore.KINDS)
    }
    probes: list[str] = []

    def command(arguments: list[str], **kwargs: object) -> bytes | None:
        environment = kwargs["environment"]
        assert isinstance(environment, dict)
        assert environment["DOCKER_HOST"] == "unix:///original-fixture.sock"
        assert "DOCKER_CONTEXT" not in environment
        assert "SPACES_SECRET_ACCESS_KEY" not in environment
        if arguments[:2] == ["docker", "inspect"]:
            kind = next(kind for kind, row in rows.items() if row["id"] == arguments[-1])
            value = dict(rows[kind])
            if kind == "destination":
                if fault == "missing":
                    return None
                if fault != "none":
                    value[fault] = "e" * 64
            return json.dumps(value).encode()
        assert arguments[:3] == ["docker", "exec", "--interactive"]
        assert arguments[4:] == ["/usr/bin/python3", "-I", "-B", "-"]
        assert kwargs["timeout"] == 20  # noqa: PLR2004 - bounded observation contract
        assert (
            kwargs["stdin"]
            == Path(restore.__file__).with_name("qualification_restore_probe.py").read_bytes()
        )
        probes.append(arguments[3])
        return b'{"phase":"validated","gate_present":true,"units":{}}'

    monkeypatch.setattr(restore, "bounded_command", command)
    result = restore.observations_for(observed_run)
    expected = {"phase": "validated", "gate_present": True, "units": {}}
    assert result["source"] == result["acme"] == expected
    assert result["destination"] == (expected if fault == "none" else "unknown")
    assert probes == (["a" * 64, "b" * 64, "c" * 64] if fault == "none" else ["a" * 64, "c" * 64])


@pytest.mark.parametrize("fault", ["format", "path", "endpoint", "permissions", "canonical"])
def test_live_reconstruction_rejects_changed_coordinates_before_observing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    allocate(tmp_path, {"DOCKER_HOST": "unix:///original-fixture.sock"})
    path = tmp_path / "fixture.json"
    manifest = json.loads(path.read_bytes())
    if fault == "format":
        manifest["format"] = "unknown-format"
    elif fault == "path":
        manifest["environment"][ARTIFACT_ENV] = str(tmp_path / "other/artifact.tar")
    elif fault == "endpoint":
        manifest["environment"]["DOCKER_HOST"] = "tcp://remote.invalid:2375"
    path.write_bytes(canonical_bytes(manifest))
    if fault == "permissions":
        path.chmod(0o644)
    elif fault == "canonical":
        path.write_text(json.dumps(manifest))
    monkeypatch.setattr(restore, "observations", lambda _: pytest.fail("invalid context observed"))
    with pytest.raises(ValueError):
        restore.observations_for(tmp_path)


@pytest.fixture
def idempotence_source(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> dict[str, object]:
    artifact = Path(environment[ARTIFACT_ENV])
    artifact.parent.mkdir()
    artifact.write_bytes(b"selected source artifact")
    identity: dict[str, object] = {
        "id": "c" * 64,
        "name": "/" + environment[HOST_ENV],
        "owner": environment[RUN_ENV],
        "image": "sha256:" + "d" * 64,
        "running": True,
    }
    monkeypatch.setattr(restore, "inspect", lambda *_: dict(identity))
    return identity


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "missing",
        "run_id",
        "id",
        "image",
        "artifact",
        "publication",
        "recovery",
        "rotation",
        "changed",
        "unreachable",
        "failed",
        "extra",
    ],
)
@pytest.mark.parametrize("archived_prefix", [False, True])
def test_source_idempotence_is_bound_to_final_configuration_and_owned_artifact(
    environment: dict[str, str],
    idempotence_source: dict[str, object],
    fault: str,
    *,
    archived_prefix: bool,
) -> None:
    receipt = restore.source_idempotence_receipt(environment, archived_prefix=archived_prefix)
    if fault in {"id", "image"}:
        idempotence_source[fault] = "e" * 64
    elif fault == "artifact":
        Path(environment[ARTIFACT_ENV]).write_bytes(b"different artifact")
    elif fault == "rotation":
        receipt[fault] = not archived_prefix
    elif fault in {"publication", "recovery"}:
        receipt[fault] = False
    elif fault in {"changed", "unreachable", "failed"}:
        receipt[fault] = 1
    elif fault in {"run_id", "extra"}:
        receipt[fault] = "invalid"
    if fault != "missing":
        (restore.directory(environment).parent / "source-idempotence.json").write_text(
            json.dumps(receipt)
        )
    if fault == "none":
        restore.require_source_idempotence(environment, archived_prefix=archived_prefix)
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            restore.require_source_idempotence(environment, archived_prefix=archived_prefix)


@pytest.mark.parametrize("fault", ["none", "activation", "reapply", "changed", "missing-recap"])
@pytest.mark.parametrize("archived_prefix", [False, True])
def test_activation_writes_idempotence_receipt_only_after_successful_zero_change_reapply(
    environment: dict[str, str],
    idempotence_source: dict[str, object],
    fault: str,
    *,
    archived_prefix: bool,
) -> None:
    # Molecule's standalone test modules share names with component tests.
    # A fresh interpreter keeps both suites' imports independent in the full run.
    code = """
import json, runpy, sys, pytest
inputs = json.load(sys.stdin)
module = runpy.run_path(sys.argv[1])
with pytest.MonkeyPatch.context() as patch:
    patch.setattr(module['restore'], 'inspect', lambda *_: inputs['identity'])
    module['assert_source_activation'](
        inputs['environment'], patch, inputs['fault'], archived_prefix=inputs['rotation'])
"""
    result = subprocess.run(  # noqa: S603 - fixed isolated assertion probe, no host access
        [sys.executable, "-c", code, str(Path(__file__).resolve())],
        cwd=Path(__file__).resolve().parents[2],
        input=json.dumps(
            {
                "environment": environment,
                "identity": idempotence_source,
                "fault": fault,
                "rotation": archived_prefix,
            }
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def assert_source_activation(
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    *,
    archived_prefix: bool,
) -> None:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "config/ansible/molecule/m3_8/tests"))
    scenarios = importlib.import_module("restore_scenarios")
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(scenarios.support, "CONTAINER", environment[HOST_ENV])
    monkeypatch.setattr(scenarios.support, "_initialize_namespace", lambda _: True)
    calls = []

    def reapply(**options: bool) -> subprocess.CompletedProcess[str]:
        calls.append(options)
        activation = len(calls) == 1
        changed = 1 if activation or fault == "changed" else 0
        output = (
            f"{environment[HOST_ENV]} : ok=100 changed={changed} unreachable=0 failed=0 "
            "skipped=10 rescued=0 ignored=0\n"
        )
        status = int(fault == ("activation" if activation else "reapply"))
        return subprocess.CompletedProcess(
            ["molecule", "converge"], status, "" if fault == "missing-recap" else output, ""
        )

    monkeypatch.setattr(scenarios.support, "_run_ansible_reapply", reapply)
    host = SimpleNamespace(run=lambda *args: SimpleNamespace(rc=0))
    path = restore.directory(environment).parent / "source-idempotence.json"
    if fault != "none":
        with pytest.raises(AssertionError):
            scenarios.activate_source(host, archived_prefix=archived_prefix)
        assert not path.exists()
        return
    scenarios.activate_source(host, archived_prefix=archived_prefix)
    assert (
        calls == [{"backup_recovery_enabled": True, "audit_rotation_enabled": archived_prefix}] * 2
    )
    restore.require_source_idempotence(environment, archived_prefix=archived_prefix)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        scenarios.activate_source(host, archived_prefix=archived_prefix)
    assert path.read_bytes() == original


@pytest.mark.parametrize("negative", [False, True])
@pytest.mark.parametrize("destination_requests", [0, 1])
def test_acme_accounting_distinguishes_startup_probes_from_destination_requests(
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    *,
    negative: bool,
    destination_requests: int,
) -> None:
    baseline = 6  # Successful startup may include a retried directory probe.
    identity = "a" * 64
    (restore.directory(environment) / "acme-readiness.json").write_text(
        json.dumps(
            {
                "identity": identity,
                "acmeRequests": baseline,
            }
        )
    )
    status = {
        "fault": "none",
        "created": 0 if negative else 4,
        "deleted": 0 if negative else 4,
        "remaining": 0,
        "acmeRequests": baseline + destination_requests,
    }
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(json.dumps(status).encode())
    )

    def command(_: object, *args: str) -> bytes:
        assert args[:3] == ("docker", "exec", identity)
        exec(args[-1], {})  # noqa: S102 - execute the fixed native accounting probe
        return b""

    monkeypatch.setattr(restore, "command", command)
    if negative == (destination_requests == 0):
        restore.acme_accounting(environment, identity, negative=negative)
    else:
        with pytest.raises(AssertionError):
            restore.acme_accounting(environment, identity, negative=negative)
    with pytest.raises(ValueError, match="unbound"):
        restore.acme_accounting(environment, "b" * 64, negative=negative)


@pytest.mark.parametrize(
    "fault", ["none", "idempotence", "source", "local", "activation", "acme", "receipt"]
)
def test_paired_accounting_requires_fresh_source_destination_and_dns_proofs(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    pair = {"destination": "a" * 64, "acme": "b" * 64}
    receipt = {"identities": pair, "status": "failed" if fault == "receipt" else "passed"}
    (restore.directory(environment) / "completed.json").write_text(json.dumps(receipt))
    monkeypatch.setattr(restore, "identities", lambda _: pair)
    events = []

    def prove(name: str) -> None:
        events.append(name)
        if fault == name:
            raise ValueError("unavailable")

    monkeypatch.setattr(restore, "source_fenced", lambda _: prove("source"))
    monkeypatch.setattr(restore, "require_source_idempotence", lambda _: prove("idempotence"))

    def local(*_: object) -> str:
        prove("local")
        return "quiescent-installed"

    monkeypatch.setattr(retirement, "local_proof", local)
    monkeypatch.setattr(restore, "acme_accounting", lambda *_: prove("acme"))
    monkeypatch.setattr(
        restore,
        "command",
        lambda *args: json.dumps(
            {
                "phase": "complete",
                "activationPending": fault == "activation",
            }
        ).encode(),
    )
    if fault == "none":
        assert restore.paired_proof(environment) == pair
        assert events == ["idempotence", "source", "local", "acme"]
    else:
        with pytest.raises(ValueError):
            restore.paired_proof(environment)


def test_two_resource_retirement_cannot_orphan_a_reconstruction_pair(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="fenced source"):
        retirement.retire(restore.directory(environment).parent)


@pytest.mark.parametrize("kind", ["acme", "destination"])
def test_owned_service_startup_preserves_destination_systemd_and_defers_acme_inputs(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(restore, "source_fenced", lambda _: None)
    monkeypatch.setattr(
        restore,
        "inspect",
        lambda *_: {
            "id": "a" * 64,
            "image": "sha256:" + "b" * 64,
            "name": f"/ldp-m3-{environment[RUN_ENV]}-{kind}",
            "running": False,
        },
    )

    def command(_: object, *arguments: str) -> bytes:
        calls.append(arguments)
        return b"a" * 64

    monkeypatch.setattr(restore, "command", command)
    assert restore.create(environment, kind) == "a" * 64
    create = calls[0]
    assert create[:2] == ("docker", "create")
    assert create[-1] == kind
    if kind == "acme":
        assert "--init" in create and "--privileged" not in create
        assert create[create.index("--stop-signal") + 1] == "SIGTERM"
        assert len(calls) == 1  # Fixed service inputs must be copied before starting PID 1.
    else:
        assert "--privileged" in create and "--init" not in create
        assert calls[1] == ("docker", "start", "a" * 64)
