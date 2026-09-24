from __future__ import annotations

import importlib
import io
import json
import subprocess
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import qualification_restore as restore
from scripts import qualification_retirement as retirement
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV, RUN_ENV, resource_names


@pytest.fixture
def environment(tmp_path: Path) -> dict[str, str]:
    values = {
        **resource_names(uuid.uuid7().hex),
        ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
    }
    restore.directory(values).mkdir(mode=0o700)
    return values


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
        lambda *_: {"id": "a" * 64, "image": "sha256:" + "b" * 64},
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
