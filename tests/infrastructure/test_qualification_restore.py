from __future__ import annotations

import io
import json
import urllib.request
import uuid
from pathlib import Path

import pytest

from scripts import qualification_restore as restore
from scripts import qualification_retirement as retirement
from scripts.qualification_context import ARTIFACT_ENV, resource_names


@pytest.fixture
def environment(tmp_path: Path) -> dict[str, str]:
    values = {
        **resource_names(uuid.uuid7().hex),
        ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
    }
    restore.directory(values).mkdir(mode=0o700)
    return values


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


@pytest.mark.parametrize("fault", ["none", "source", "local", "activation", "acme", "receipt"])
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
        assert events == ["source", "local", "acme"]
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
