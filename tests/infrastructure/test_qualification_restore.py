from __future__ import annotations

import json
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


@pytest.mark.parametrize("fault", ["proof", "stop", "none"])
def test_paired_removal_stops_before_deletion_without_authoritative_proof(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    pair = {"destination": "a" * 64, "acme": "b" * 64}
    events = []

    def proof(_: dict[str, str]) -> dict[str, str]:
        if fault == "proof":
            raise ValueError("unproven")
        return pair

    def command(_: dict[str, str], *args: str, **kwargs: object) -> bytes:
        events.append(args)
        if fault == "stop":
            raise ValueError("failed to stop")
        return b""

    monkeypatch.setattr(restore, "paired_proof", proof)
    monkeypatch.setattr(restore, "command", command)
    monkeypatch.setattr(restore, "inspect", lambda *_: {"running": False})
    if fault != "none":
        with pytest.raises(ValueError):
            restore.remove_pair(environment, pair)
        assert not any("rm" in args for args in events)
        assert not (restore.directory(environment) / "removed.json").exists()
    else:
        restore.remove_pair(environment, pair)
        assert events == [
            ("docker", "stop", "--time", "20", pair["destination"]),
            ("docker", "rm", "--volumes", pair["destination"]),
            ("docker", "stop", "--time", "20", pair["acme"]),
            ("docker", "rm", "--volumes", pair["acme"]),
        ]


def test_two_resource_retirement_cannot_orphan_a_reconstruction_pair(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="fenced source"):
        retirement.retire(restore.directory(environment).parent)
